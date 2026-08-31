package secagg

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"security-ai-gateway/secagg/shares"
)

// DefaultMaxConcurrency 默认并发扇出上限（0 = 无限制，无限并发）。
const DefaultMaxConcurrency = 0

// Aggregator 聚合服务器：路由消息、驱动协议阶段、计算聚合结果。
// 服务器仅通过消息接口与参与方交互，永不接触参与方明文输入、
// 私钥或未授权的份额（双掩码交付规则由 party.unmask 保证）。
//
// 安全模型：配置 TrustedSignKeys 时启用恶意敌手模式
// （通告签名校验 + 种子承诺校验 + 身份绑定）；
// TrustedSignKeys 为 nil 时降级为半诚实模型（仅身份一致性校验）。
//
// 并发：所有协议轮次均并行扇出（通过 runPhase），并发度由
// SetMaxConcurrency 限制；context 贯穿每一轮，支持超时与取消。
type Aggregator struct {
	cfg            Config
	maxConcurrency int // 每阶段最大并发数（0 = 无限并发）
	audit          AuditSink
}

// NewAggregator 构造聚合服务器。若 cfg.SessionID 为空，自动生成 128 位随机会话 ID。
func NewAggregator(cfg Config) (*Aggregator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// 自动生成会话 ID（未显式设置时）
	if len(cfg.SessionID) == 0 {
		sid := make([]byte, SessionIDLen)
		if _, err := rand.Read(sid); err != nil {
			return nil, fmt.Errorf("secagg: 生成会话 ID 失败: %w", err)
		}
		cfg.SessionID = sid
	}
	return &Aggregator{cfg: cfg, maxConcurrency: DefaultMaxConcurrency, audit: NoopAuditSink{}}, nil
}

// SetAuditSink 注入审计日志接收器（nil 恢复为丢弃）。可在 Run 前调用。
func (a *Aggregator) SetAuditSink(s AuditSink) {
	if s == nil {
		a.audit = NoopAuditSink{}
		return
	}
	a.audit = s
}

// emit 写入一条审计事件（sessionID 副本，避免调用方持有共享缓冲）。
func (a *Aggregator) emit(ctx context.Context, round Round, partyID int, cat Category, msg string) {
	a.audit.Emit(ctx, AuditEvent{
		Time:      time.Now(),
		SessionID: a.SessionID(),
		Round:     round,
		PartyID:   partyID,
		Category:  cat,
		Message:   msg,
	})
}

// SetMaxConcurrency 设置每阶段最大并发扇出数（0 = 无限并发，默认）。
// 生产环境 n ≥ 20 时建议设置为 10~50，避免资源耗尽。
func (a *Aggregator) SetMaxConcurrency(n int) {
	if n < 0 {
		n = 0
	}
	a.maxConcurrency = n
}

// SessionID 返回当前会话 ID（副本）。
func (a *Aggregator) SessionID() []byte {
	return append([]byte(nil), a.cfg.SessionID...)
}

// Run 驱动完整安全聚合协议（Round 0/1/2/3/4），使用 context.Background()。
func (a *Aggregator) Run(parties []PartyDriver) (*Result, error) {
	return a.RunContext(context.Background(), parties)
}

// RunContext 驱动完整安全聚合协议，支持上下文取消与超时。
//
// parties 须与 cfg.NumParties 匹配且 ID 唯一；每个 party 的输入
// 已在构造时校验。任何阶段在线集合不足阈值 t 时返回
// ErrInsufficientParties（安全中止，绝不输出部分结果）。
//
// 审计：会话开始、各阶段完成与最终结果/失败均写入 AuditSink。
func (a *Aggregator) RunContext(ctx context.Context, parties []PartyDriver) (*Result, error) {
	a.emit(ctx, -1, -1, CategoryUnknown, "session_start")
	res, err := a.run(ctx, parties)
	if err != nil {
		a.emit(ctx, -1, -1, Classify(err), "session_failed: "+err.Error())
		return nil, err
	}
	a.emit(ctx, -1, -1, CategoryUnknown,
		fmt.Sprintf("session_success online=%d rounds=%d", len(res.OnlineIDs), res.Rounds))
	return res, nil
}

// run 协议主流程（见 RunContext 文档）。
func (a *Aggregator) run(ctx context.Context, parties []PartyDriver) (*Result, error) {
	if len(parties) != a.cfg.NumParties {
		return nil, fmt.Errorf("secagg: 参与方数量 %d 与配置 %d 不符", len(parties), a.cfg.NumParties)
	}

	// ---- Round 0: AdvertiseKeys ----
	// 一次性收集所有通告：校验身份一致性（adv.ID == partyID）与 ID 唯一性。
	// 启用 TrustedSignKeys 时额外校验 Ed25519 签名（恶意敌手防御）。
	idx0 := phaseIndex(parties, Round0Advertise)
	advResults, err := runPhase(ctx, a.sem(), idx0, func(i int) (advResult, error) {
		adv, err := parties[i].advertise(ctx)
		return advResult{id: parties[i].partyID(), adv: adv}, err
	})
	if err != nil {
		return nil, err
	}
	advertises := make(map[int]advertiseMsg)
	for _, r := range advResults {
		// S4 防御：通告中的 ID 必须与驱动身份一致
		if r.adv.ID != r.id {
			return nil, fmt.Errorf("secagg: 参与方 %d 通告 ID %d 与身份不符（身份冒充攻击）", r.id, r.adv.ID)
		}
		if _, exists := advertises[r.adv.ID]; exists {
			return nil, fmt.Errorf("secagg: 重复参与方 ID %d", r.adv.ID)
		}
		// 恶意敌手模式：签名 + 公钥校验
		if a.cfg.TrustedSignKeys != nil {
			trusted, ok := a.cfg.TrustedSignKeys[r.adv.ID]
			if !ok {
				return nil, fmt.Errorf("secagg: 参与方 %d 不在可信密钥表中", r.adv.ID)
			}
			if len(r.adv.SignPub) != len(trusted) || string(r.adv.SignPub) != string(trusted) {
				return nil, fmt.Errorf("secagg: 参与方 %d 通告公钥与可信表不符", r.adv.ID)
			}
			if !verifyAdvertiseSig(a.cfg.SessionID, r.adv) {
				return nil, fmt.Errorf("%w: 参与方 %d 通告签名无效", ErrSignatureVerification, r.adv.ID)
			}
		}
		advertises[r.adv.ID] = r.adv
	}
	if len(advertises) < a.cfg.Threshold {
		return nil, ErrInsufficientParties
	}
	a.emit(ctx, Round0Advertise, -1, CategoryUnknown, fmt.Sprintf("advertised=%d", len(advertises)))

	// ---- Round 1: ShareSeeds ----
	idx1 := phaseIndex(parties, Round1ShareSeeds)
	idx1 = filterPhase(idx1, func(i int) bool {
		_, ok := advertises[parties[i].partyID()]
		return ok
	})
	ssResults, err := runPhase(ctx, a.sem(), idx1, func(i int) (ssResult, error) {
		bs, comm, err := parties[i].shareSeeds(ctx, advertises)
		return ssResult{id: parties[i].partyID(), bundles: bs, comm: comm}, err
	})
	if err != nil {
		return nil, err
	}
	var bundles []shareBundleCipher
	submitted := make(map[int]bool)
	commitments := make(map[int]seedCommitments)
	for _, r := range ssResults {
		bundles = append(bundles, r.bundles...)
		submitted[r.id] = true
		commitments[r.id] = r.comm
	}
	if len(submitted) < a.cfg.Threshold {
		return nil, ErrInsufficientParties
	}
	a.emit(ctx, Round1ShareSeeds, -1, CategoryUnknown, fmt.Sprintf("share_seeds_submitted=%d", len(submitted)))

	// U2 参与方的通告集合（y_u 只对 U2 用户加掩码）
	u2Advertises := make(map[int]advertiseMsg)
	for id, adv := range advertises {
		if submitted[id] {
			u2Advertises[id] = adv
		}
	}

	// 路由份额密文
	routed := make(map[int][]shareBundleCipher)
	for _, b := range bundles {
		if _, ok := submitted[b.To]; !ok {
			continue
		}
		routed[b.To] = append(routed[b.To], b)
	}
	// 并行下发份额包
	idxRB := make([]int, 0, len(parties))
	for i, p := range parties {
		if len(routed[p.partyID()]) > 0 {
			idxRB = append(idxRB, i)
		}
	}
	if _, err := runPhase(ctx, a.sem(), idxRB, func(i int) (struct{}, error) {
		return struct{}{}, parties[i].receiveBundles(ctx, routed[parties[i].partyID()])
	}); err != nil {
		return nil, err
	}

	// ---- Round 2: MaskedInput ----
	idx2 := filterPhase(idx1, func(i int) bool {
		return !parties[i].dropped(Round2MaskedInput)
	})
	miResults, err := runPhase(ctx, a.sem(), idx2, func(i int) (miResult, error) {
		y, err := parties[i].maskedInput(ctx, u2Advertises)
		return miResult{id: parties[i].partyID(), y: y}, err
	})
	if err != nil {
		return nil, err
	}
	masked := make(map[int][]uint64)
	for _, r := range miResults {
		masked[r.id] = r.y
	}
	if len(masked) < a.cfg.Threshold {
		return nil, ErrInsufficientParties
	}
	a.emit(ctx, Round2MaskedInput, -1, CategoryUnknown, fmt.Sprintf("masked_input_online=%d", len(masked)))
	online := make(map[int]bool, len(masked))
	for id := range masked {
		online[id] = true
	}

	// ---- Round 3: ConsistencyCheck ----
	// 签名模式下，Round 3 已在 Round 0 完成（通告时附带签名，聚合器即时校验）。
	// 种子承诺校验在 Round 4 finalize 中执行（重构后比对承诺）。

	// ---- Round 4: Unmask ----
	idx4 := filterPhase(idx2, func(i int) bool {
		_, ok := masked[parties[i].partyID()]
		return ok && !parties[i].dropped(Round4Unmask)
	})
	umResults, err := runPhase(ctx, a.sem(), idx4, func(i int) (umResult, error) {
		um, err := parties[i].unmask(ctx, online)
		return umResult{id: parties[i].partyID(), msg: um}, err
	})
	if err != nil {
		return nil, err
	}
	var unmasks []unmaskMsg
	for _, r := range umResults {
		unmasks = append(unmasks, r.msg)
	}
	if len(unmasks) < a.cfg.Threshold {
		return nil, ErrInsufficientParties
	}
	a.emit(ctx, Round4Unmask, -1, CategoryUnknown, fmt.Sprintf("unmask_submitted=%d", len(unmasks)))

	return a.finalize(masked, requireThreshold(a.cfg, masked, "Round2"), unmasks, commitments)
}

// ---------- 阶段并发辅助 ----------

// advResult / ssResult / miResult / umResult 各阶段收集结果。
type advResult struct {
	id  int
	adv advertiseMsg
}
type ssResult struct {
	id      int
	bundles []shareBundleCipher
	comm    seedCommitments
}
type miResult struct {
	id int
	y  []uint64
}
type umResult struct {
	id  int
	msg unmaskMsg
}

// phaseIndex 返回某一轮次在线（未 dropped）的参与方下标列表。
func phaseIndex(parties []PartyDriver, round Round) []int {
	idx := make([]int, 0, len(parties))
	for i, p := range parties {
		if !p.dropped(round) {
			idx = append(idx, i)
		}
	}
	return idx
}

// filterPhase 按谓词过滤下标列表。
func filterPhase(idx []int, keep func(int) bool) []int {
	out := make([]int, 0, len(idx))
	for _, i := range idx {
		if keep(i) {
			out = append(out, i)
		}
	}
	return out
}

// sem 返回并发信号量（maxConcurrency<=0 时为 nil = 无限并发）。
func (a *Aggregator) sem() chan struct{} {
	if a.maxConcurrency <= 0 {
		return nil
	}
	return make(chan struct{}, a.maxConcurrency)
}

// runPhase 并行执行 fn（下标 i 对应输入切片元素）。
// sem 非 nil 时并发受信号量限制；ctx 取消时 fn 应返回错误（RPC 层保证）。
// 任一 fn 失败立即返回该错误；所有 goroutine 均被等待，无泄漏。
func runPhase[T any](ctx context.Context, sem chan struct{}, idx []int, fn func(i int) (T, error)) ([]T, error) {
	if len(idx) == 0 {
		return nil, nil
	}
	results := make([]T, len(idx))
	var wg sync.WaitGroup
	errCh := make(chan error, len(idx))
	for j, i := range idx {
		wg.Add(1)
		go func(j, i int) {
			defer wg.Done()
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					errCh <- ctx.Err()
					return
				}
			}
			r, err := fn(i)
			if err != nil {
				errCh <- err
				return
			}
			results[j] = r
		}(j, i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

// requireThreshold 校验集合大小 ≥ t 并返回在线 ID 列表（升序）。
func requireThreshold[T any](cfg Config, set map[int]T, round string) []int {
	if len(set) < cfg.Threshold {
		return nil
	}
	ids := make([]int, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// finalize 去掩码并输出聚合结果：
//
//	z = Σ_{u∈U3} y_u − Σ_{u∈U3} PRG(b_u) + Σ_{u∈U3, v∈D} sign(v,u)·PRG(seed_{v,u})  (mod R)
//
// 正确性：成对掩码在在线集合内两两抵消，掉线者贡献经份额重构扣除，
// 故 z ≡ Σ x_u (mod R)。
//
// 启用 TrustedSignKeys 时，每个重构后的种子均校验 SHA-256 承诺；
// 不匹配则返回 ErrCommitmentMismatch（恶意份额被检测到）。
func (a *Aggregator) finalize(
	masked map[int][]uint64,
	u3 []int,
	unmasks []unmaskMsg,
	commitments map[int]seedCommitments,
) (*Result, error) {
	t := a.cfg.Threshold
	mod := a.cfg.Modulus
	dim := a.cfg.Dimension

	// 汇总份额：b 份额（v → 收集者份额列表）与 seed 份额（(v,u) → 份额列表）
	selfMaskShares := make(map[int][]*shares.Part)
	droppedSeedShares := make(map[int]map[int][]*shares.Part) // v → u → shares
	for _, um := range unmasks {
		for v, raw := range um.SelfMaskShares {
			part, err := decodePart(raw)
			if err != nil {
				return nil, fmt.Errorf("secagg: 反序列化 b 份额失败: %w", err)
			}
			selfMaskShares[v] = append(selfMaskShares[v], part)
		}
		for v, inner := range um.DroppedSeedShares {
			if droppedSeedShares[v] == nil {
				droppedSeedShares[v] = make(map[int][]*shares.Part)
			}
			for u, raw := range inner {
				part, err := decodePart(raw)
				if err != nil {
					return nil, fmt.Errorf("secagg: 反序列化种子份额失败: %w", err)
				}
				droppedSeedShares[v][u] = append(droppedSeedShares[v][u], part)
			}
		}
	}

	// z = Σ y_u
	z := make([]uint64, dim)
	for _, u := range u3 {
		y := masked[u]
		if len(y) != dim {
			return nil, fmt.Errorf("secagg: 参与方 %d 输入维度 %d 与配置 %d 不符", u, len(y), dim)
		}
		for i := range z {
			z[i] = addMod(z[i], y[i], mod)
		}
	}

	// 扣除在线者自掩码 Σ PRG(b_u)
	for _, u := range u3 {
		parts := selfMaskShares[u]
		if len(parts) < t {
			return nil, fmt.Errorf("secagg: 用户 %d 的自掩码份额不足（%d < t=%d）", u, len(parts), t)
		}
		bSeed, err := shares.Reconstruct(parts, t)
		if err != nil {
			return nil, fmt.Errorf("secagg: 重构用户 %d 自掩码失败: %w", u, err)
		}
		// 承诺校验（恶意敌手模式）
		if a.cfg.TrustedSignKeys != nil {
			comm, ok := commitments[u]
			if !ok {
				return nil, fmt.Errorf("%w: 用户 %d 无自掩码承诺", ErrCommitmentMismatch, u)
			}
			if !constBytesEqual(sha256sum(bSeed), comm.SelfMask) {
				return nil, fmt.Errorf("%w: 用户 %d 自掩码重构结果与承诺不匹配", ErrCommitmentMismatch, u)
			}
		}
		pMask, err := maskVector(bSeed, mod, dim)
		if err != nil {
			return nil, err
		}
		for i := range z {
			z[i] = subMod(z[i], pMask[i], mod)
		}
	}

	// 恢复掉线者成对掩码贡献 Σ sign(v,u)·PRG(seed_{v,u})
	for v, inner := range droppedSeedShares {
		for u, parts := range inner {
			if len(parts) < t {
				return nil, fmt.Errorf("secagg: 种子份额不足（v=%d u=%d: %d < t=%d）", v, u, len(parts), t)
			}
			seed, err := shares.Reconstruct(parts, t)
			if err != nil {
				return nil, fmt.Errorf("secagg: 重构种子失败（v=%d u=%d）: %w", v, u, err)
			}
			// 承诺校验（恶意敌手模式）
			if a.cfg.TrustedSignKeys != nil {
				comm, ok := commitments[v]
				if !ok {
					return nil, fmt.Errorf("%w: 掉线用户 %d 无种子承诺（u=%d）", ErrCommitmentMismatch, v, u)
				}
				expected, ok := comm.Seeds[u]
				if !ok {
					return nil, fmt.Errorf("%w: 掉线用户 %d 无针对 u=%d 的种子承诺", ErrCommitmentMismatch, v, u)
				}
				if !constBytesEqual(sha256sum(seed), expected) {
					return nil, fmt.Errorf("%w: 掉线用户 %d 种子（u=%d）重构与承诺不匹配", ErrCommitmentMismatch, v, u)
				}
			}
			pvu, err := maskVector(seed, mod, dim)
			if err != nil {
				return nil, err
			}
			for i := range z {
				if v < u {
					z[i] = addMod(z[i], pvu[i], mod)
				} else {
					z[i] = subMod(z[i], pvu[i], mod)
				}
			}
		}
	}

	ids := append([]int(nil), u3...)
	return &Result{Sum: z, OnlineIDs: ids, Rounds: 5}, nil
}

// constBytesEqual 常数时间字节比较。
func constBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// decodePart 反序列化份额。
func decodePart(raw []byte) (*shares.Part, error) {
	p := &shares.Part{}
	if err := gobDecode(raw, p); err != nil {
		return nil, err
	}
	if p.X == nil || p.Y == nil {
		return nil, errors.New("secagg: 份额字段缺失")
	}
	return p, nil
}
