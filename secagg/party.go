package secagg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"sort"

	"security-ai-gateway/cipher/kex"
	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/internal/memzero"
	"security-ai-gateway/secagg/shares"
)

// advertiseMsg Round 0 公钥通告（c 加密密钥对 + s 扰动密钥对 + Ed25519 身份签名）。
// 字段导出并带 JSON tag：wire/gRPC 层经 JSON codec 传输。
// 签名覆盖：sessionID || ID || cPK || sPK，绑定到具体会话防止重放。
type advertiseMsg struct {
	ID      int    `json:"id"`
	CPK     []byte `json:"cpk"`
	SPK     []byte `json:"spk"`
	SignPub []byte `json:"sign_pub"` // Ed25519 身份公钥
	Sig     []byte `json:"sig"`      // Ed25519 签名
}

// seedCommitments 种子承诺集合（SHA-256 哈希承诺，用于 Round 4 重构校验）。
// 恶意参与方提交垃圾份额时，重构结果与承诺不匹配，协议安全中止。
type seedCommitments struct {
	// SelfMask 自掩码种子 b 的承诺：H(b_seed)
	SelfMask []byte `json:"self_mask"`
	// Seeds 成对扰动种子承诺：u → H(seed_{self,u})
	Seeds map[int][]byte `json:"seeds"`
}

// shareBundleCipher Round 1 份额密文包（From → To，经服务器路由）。
type shareBundleCipher struct {
	From int    `json:"from"`
	To   int    `json:"to"`
	CT   []byte `json:"ct"`
}

// sharePackage 份额包明文（From 生成，To 解密后持有）。
type sharePackage struct {
	From          int            `json:"from"`
	To            int            `json:"to"`
	SelfMaskShare []byte         `json:"self_mask_share"`
	SeedShares    map[int][]byte `json:"seed_shares"` // u → seed_{From,u} 的份额
}

// unmaskMsg Round 4 份额提交（用户 → 服务器）。
type unmaskMsg struct {
	ID                int                    `json:"id"`
	SelfMaskShares    map[int][]byte         `json:"self_mask_shares"`    // v ∈ U3 在线者
	DroppedSeedShares map[int]map[int][]byte `json:"dropped_seed_shares"` // v ∈ D 掉线者 → u → 份额
}

// party 客户端状态机。私有状态（私钥、种子、份额、明文）完全隔离，
// 仅通过消息方法对外暴露协议允许可见的信息。
type party struct {
	cfg    Config
	id     int
	x      []uint64
	dropAt Round // 该轮次起不再响应（测试注入掉线）；默认永不

	cKeys *kex.KeyPair // ECDH 加密密钥对
	sKeys *kex.KeyPair // ECDH 扰动密钥对

	signPriv ed25519.PrivateKey // Ed25519 身份私钥（签名通告）
	signPub  ed25519.PublicKey  // Ed25519 身份公钥

	bSeed []byte // 自掩码种子（32 字节，随机）

	// 自持份额（份额覆盖 U1 全体，含自己；掉线时保证在线用户 ≥ t 份）
	selfMaskShare  []byte
	selfSeedShares map[int][]byte // u → seed_{self,u} 的自持份额

	// 种子承诺（Round 1 生成，供 Round 4 校验）
	commitments seedCommitments

	bundles         map[int]*shareBundleCipher // 收到的份额密文（from →）
	decryptedShares map[int]*sharePackage      // 解密后的份额包（from →）
}

// NewParty 构造参与方（x 须满足 0 ≤ x_i < R，id ∈ [0, n)）。
//
// signKey 为可选 Ed25519 身份私钥；为 nil 时自动生成（适合测试/演示）。
// 生产环境应使用预置身份密钥并将对应公钥注册到 Aggregator.TrustedSignKeys。
func NewParty(id int, x []uint64, cfg Config, signKey ed25519.PrivateKey) (*party, error) {
	if id < 0 || id >= cfg.NumParties {
		return nil, fmt.Errorf("secagg: 参与方 ID %d 非法（必须 ∈ [0, %d)）", id, cfg.NumParties)
	}
	if err := (PartyInput{ID: id, X: x}).Validate(cfg.Modulus); err != nil {
		return nil, err
	}
	if len(x) != cfg.Dimension {
		return nil, fmt.Errorf("secagg: 参与方 %d 输入维度 %d 与配置 %d 不符", id, len(x), cfg.Dimension)
	}
	cKeys, err := kex.Generate(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secagg: 生成加密密钥失败: %w", err)
	}
	sKeys, err := kex.Generate(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secagg: 生成扰动密钥失败: %w", err)
	}

	// 身份密钥：外部提供或本地生成
	var spub ed25519.PublicKey
	var spriv ed25519.PrivateKey
	if signKey != nil {
		if len(signKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("secagg: 身份私钥长度非法")
		}
		spriv = signKey
		spub = spriv.Public().(ed25519.PublicKey)
	} else {
		spub, spriv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("secagg: 生成身份密钥失败: %w", err)
		}
	}

	return &party{
		cfg:             cfg,
		id:              id,
		x:               append([]uint64(nil), x...),
		dropAt:          999, // 永不掉线
		cKeys:           cKeys,
		sKeys:           sKeys,
		signPriv:        spriv,
		signPub:         spub,
		bundles:         make(map[int]*shareBundleCipher),
		decryptedShares: make(map[int]*sharePackage),
	}, nil
}

// SignPub 返回身份公钥（供外部注册到可信密钥表）。
func (p *party) SignPub() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), p.signPub...)
}

// partyID 返回参与方 ID。
func (p *party) partyID() int { return p.id }

// dropped 判断该参与方是否在指定轮次已掉线。
func (p *party) dropped(round Round) bool {
	return int(round) >= int(p.dropAt)
}

// advertise Round 0：通告双公钥 + 身份签名。
// 签名覆盖 sessionID || ID || cPK || sPK，绑定到具体会话防重放。
func (p *party) advertise(_ context.Context) (advertiseMsg, error) {
	cpk := p.cKeys.PublicBytes()
	spk := p.sKeys.PublicBytes()

	// 构造签名原文：sessionID || ID(4字节大端) || cPK || sPK
	msg := buildSignMsg(p.cfg.SessionID, p.id, cpk, spk)
	sig := ed25519.Sign(p.signPriv, msg)

	return advertiseMsg{
		ID:      p.id,
		CPK:     append([]byte(nil), cpk...),
		SPK:     append([]byte(nil), spk...),
		SignPub: append([]byte(nil), p.signPub...),
		Sig:     append([]byte(nil), sig...),
	}, nil
}

// buildSignMsg 构造通告签名原文：sessionID || ID(big-endian uint32) || cPK || sPK。
func buildSignMsg(sessionID []byte, id int, cpk, spk []byte) []byte {
	buf := make([]byte, 0, len(sessionID)+4+len(cpk)+len(spk))
	buf = append(buf, sessionID...)
	buf = append(buf, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	buf = append(buf, cpk...)
	buf = append(buf, spk...)
	return buf
}

// verifyAdvertiseSig 校验通告签名是否有效。
func verifyAdvertiseSig(sessionID []byte, adv advertiseMsg) bool {
	if len(adv.SignPub) != ed25519.PublicKeySize || len(adv.Sig) != ed25519.SignatureSize {
		return false
	}
	msg := buildSignMsg(sessionID, adv.ID, adv.CPK, adv.SPK)
	return ed25519.Verify(adv.SignPub, msg, adv.Sig)
}

// shareSeeds Round 1：采样自掩码种子，生成并加密所有份额包 + 种子承诺。
func (p *party) shareSeeds(_ context.Context, advertises map[int]advertiseMsg) ([]shareBundleCipher, seedCommitments, error) {
	u1 := sortedIDs(advertises)
	if len(u1) < p.cfg.Threshold {
		return nil, seedCommitments{}, ErrInsufficientParties
	}

	bSeed := make([]byte, 32)
	if _, err := rand.Read(bSeed); err != nil {
		return nil, seedCommitments{}, fmt.Errorf("secagg: 采样自掩码种子失败: %w", err)
	}
	p.bSeed = bSeed

	// 自掩码份额：b 的 (t,n) 份额，第 w 份归属用户 w（含自己）
	bParts, err := shares.Split(bSeed, p.cfg.Threshold, p.cfg.NumParties)
	if err != nil {
		return nil, seedCommitments{}, fmt.Errorf("secagg: 自掩码份额失败: %w", err)
	}
	selfMask, err := encodePart(bParts[p.id])
	if err != nil {
		return nil, seedCommitments{}, err
	}
	p.selfMaskShare = selfMask

	// 每对 (self, u) 的扰动种子份额
	seedParts := make(map[int][]*shares.Part, len(u1)-1)
	seedValues := make(map[int][]byte, len(u1)-1)
	p.selfSeedShares = make(map[int][]byte, len(u1)-1)
	for _, u := range u1 {
		if u == p.id {
			continue
		}
		seed, err := p.sKeys.DeriveSeed(advertises[u].SPK)
		if err != nil {
			return nil, seedCommitments{}, fmt.Errorf("secagg: 派生扰动种子失败: %w", err)
		}
		parts, err := shares.Split(seed, p.cfg.Threshold, p.cfg.NumParties)
		if err != nil {
			return nil, seedCommitments{}, fmt.Errorf("secagg: 扰动种子份额失败: %w", err)
		}
		seedParts[u] = parts
		seedValues[u] = seed
		ownShare, err := encodePart(parts[p.id])
		if err != nil {
			return nil, seedCommitments{}, err
		}
		p.selfSeedShares[u] = ownShare
	}

	// 为每个对端 w 构造并加密份额包
	var bundles []shareBundleCipher
	for _, w := range u1 {
		if w == p.id {
			continue
		}
		bw, err := encodePart(bParts[w])
		if err != nil {
			return nil, seedCommitments{}, err
		}
		pack := &sharePackage{
			From:          p.id,
			To:            w,
			SelfMaskShare: bw,
			SeedShares:    make(map[int][]byte, len(seedParts)),
		}
		for u, parts := range seedParts {
			sw, err := encodePart(parts[w])
			if err != nil {
				return nil, seedCommitments{}, err
			}
			pack.SeedShares[u] = sw
		}
		raw, err := gobEncode(pack)
		if err != nil {
			return nil, seedCommitments{}, err
		}
		ct, err := sealShare(p.cKeys, advertises[w].CPK, raw)
		if err != nil {
			return nil, seedCommitments{}, err
		}
		bundles = append(bundles, shareBundleCipher{From: p.id, To: w, CT: ct})
	}

	// 生成种子承诺（SHA-256）：H(b_seed) 与各 H(seed_{self,u})
	commitments := seedCommitments{
		SelfMask: sha256sum(bSeed),
		Seeds:    make(map[int][]byte, len(seedValues)),
	}
	for u, seed := range seedValues {
		commitments.Seeds[u] = sha256sum(seed)
	}
	p.commitments = commitments

	// 清理：扰动种子仅保留到份额打包与承诺生成完毕；
	// 自掩码种子 p.bSeed 保留至 maskedInput 使用完毕后清零。
	for _, seed := range seedValues {
		zero(seed)
	}
	_ = seedValues
	return bundles, commitments, nil
}

// sha256sum 计算 SHA-256 哈希（32 字节承诺）。
func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// receiveBundles 接收服务器路由的份额密文（Round 1 → 2 之间）。
func (p *party) receiveBundles(_ context.Context, bundles []shareBundleCipher) error {
	for _, b := range bundles {
		if b.To != p.id {
			return fmt.Errorf("secagg: 份额包接收方 %d 与自身 %d 不符", b.To, p.id)
		}
		p.bundles[b.From] = &shareBundleCipher{From: b.From, To: b.To, CT: append([]byte(nil), b.CT...)}
	}
	return nil
}

// maskedInput Round 2：解密份额包、计算双掩码后的输入 y_u。
func (p *party) maskedInput(_ context.Context, advertises map[int]advertiseMsg) ([]uint64, error) {
	u2 := sortedIDs(advertises)
	if len(u2) < p.cfg.Threshold {
		return nil, ErrInsufficientParties
	}

	// 解密收到的份额包并验证完整性
	for from, bundle := range p.bundles {
		adv, ok := advertises[from]
		if !ok {
			continue // 对端未进入 U2，其份额包无意义
		}
		raw, err := openShare(p.cKeys, adv.CPK, bundle.CT)
		if err != nil {
			return nil, fmt.Errorf("secagg: 解密 %d 的份额包失败: %w", from, err)
		}
		pack := &sharePackage{}
		if err := gobDecode(raw, pack); err != nil {
			return nil, fmt.Errorf("secagg: 份额包反序列化失败: %w", err)
		}
		if pack.From != from || pack.To != p.id {
			return nil, errors.New("secagg: 份额包身份校验失败")
		}
		p.decryptedShares[from] = pack
		zero(raw)
	}

	// y_u = x_u + PRG(b_u) + Σ_{v∈U2∖{u}} sign(u,v)·PRG(seed_{u,v})  (mod R)
	y := append([]uint64(nil), p.x...)

	if p.bSeed == nil {
		return nil, errors.New("secagg: 自掩码种子缺失（shareSeeds 未执行）")
	}
	pMask, err := maskVector(p.bSeed, p.cfg.Modulus, p.cfg.Dimension)
	if err != nil {
		return nil, err
	}
	for i := range y {
		y[i] = addMod(y[i], pMask[i], p.cfg.Modulus)
	}

	for _, v := range u2 {
		if v == p.id {
			continue
		}
		seed, err := p.sKeys.DeriveSeed(advertises[v].SPK)
		if err != nil {
			return nil, err
		}
		pm, err := maskVector(seed, p.cfg.Modulus, p.cfg.Dimension)
		if err != nil {
			return nil, err
		}
		for i := range y {
			if p.id < v {
				y[i] = addMod(y[i], pm[i], p.cfg.Modulus)
			} else {
				y[i] = subMod(y[i], pm[i], p.cfg.Modulus)
			}
		}
		zero(seed)
	}
	// 清理
	zero(p.bSeed)
	zeroU64(pMask)
	return append([]uint64(nil), y...), nil
}

// unmask Round 4：按交付规则提交份额。
//
//	对在线者 v∈U3：交 b_v 份额；
//	对掉线者 v∈D：交 seed_{v,u} 份额（u ∈ U3）。
//
// 双掩码安全性质：服务器对任一 v 只能获得 b_v 或成对掩码之一，无法同时获得两者。
func (p *party) unmask(_ context.Context, online map[int]bool) (unmaskMsg, error) {
	msg := unmaskMsg{
		ID:                p.id,
		SelfMaskShares:    make(map[int][]byte),
		DroppedSeedShares: make(map[int]map[int][]byte),
	}
	for v, pack := range p.decryptedShares {
		if online[v] {
			msg.SelfMaskShares[v] = append([]byte(nil), pack.SelfMaskShare...)
		} else {
			inner := make(map[int][]byte)
			for u, share := range pack.SeedShares {
				if online[u] {
					inner[u] = append([]byte(nil), share...)
				}
			}
			msg.DroppedSeedShares[v] = inner
		}
	}
	// 自持份额：自己的 b 份额与自己的种子份额
	if online[p.id] {
		if p.selfMaskShare != nil {
			msg.SelfMaskShares[p.id] = append([]byte(nil), p.selfMaskShare...)
		}
	} else {
		inner := make(map[int][]byte)
		for u, share := range p.selfSeedShares {
			if online[u] {
				inner[u] = append([]byte(nil), share...)
			}
		}
		msg.DroppedSeedShares[p.id] = inner
	}
	return msg, nil
}

// --- 工具函数 ---

// maskVector 由种子派生维度为 dim 的 [0, r) 掩码向量。
func maskVector(seed []byte, r uint64, dim int) ([]uint64, error) {
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, fmt.Errorf("secagg: 构造掩码流失败: %w", err)
	}
	buf := make([]uint64, dim)
	if err := s.Fill(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func addMod(a, b, mod uint64) uint64 { return (a + b) % mod }

func subMod(a, b, mod uint64) uint64 { return (a + mod - b%mod) % mod }

// encodePart 序列化单个份额（x,y 域元素）。
func encodePart(p *shares.Part) ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("secagg: 份额序列化失败: %w", err)
	}
	return buf.Bytes(), nil
}

func gobEncode(v any) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(v); err != nil {
		return nil, fmt.Errorf("secagg: 编码失败: %w", err)
	}
	return buf.Bytes(), nil
}

func gobDecode(data []byte, v any) error {
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(v); err != nil {
		return fmt.Errorf("secagg: 解码失败: %w", err)
	}
	return nil
}

func sortedIDs(m map[int]advertiseMsg) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func zero(b []byte) {
	memzero.Bytes(b)
}

func zeroU64(b []uint64) {
	memzero.Uint64(b)
}
