// 审计日志模块（M9，审计数据模型）
//
// 实现哈希链防篡改：每条事件含 prev_hash（前一条审计的 SHA-256），
// 任何历史记录被篡改都会导致链断裂，可被检测。
// MVP 为内存存储（WORM 持久化 + 公证锚定后续实现）。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

// AuditEvent 审计事件。
type AuditEvent struct {
	EventID    string `json:"event_id"`
	Timestamp  int64  `json:"timestamp"` // UTC 纳秒
	TenantID   string `json:"tenant_id"`
	UserID     string `json:"user_id,omitempty"`
	RequestID  string `json:"request_id"`
	Action     string `json:"action"` // key_issue / infer / deny
	TokensIn   int    `json:"tokens_in,omitempty"`
	TokensOut  int    `json:"tokens_out,omitempty"`
	Result     string `json:"result"` // ok / deny
	PayloadSHA string `json:"payload_hash"`
	PrevHash   string `json:"prev_hash"` // 哈希链
	// P2a：改造后明文哈希（装饰/脱敏后的引擎实收内容；附加证据字段）。
	// 不进 hash()（保持 WORM 旧链向后兼容）——链完整性由 PayloadSHA 段保障，
	// TransformedHash 供"引擎实际收到什么"回溯（双 hash 审计）。
	TransformedHash string `json:"transformed_hash,omitempty"`
	// GF.4.1：精确缓存命中标记（演示实现）。同样不进 hash()，仅作审计证据字段。
	CacheHit bool `json:"cache_hit,omitempty"`
	// GF.4.2：服务商 key 指纹（sha256 前 8 hex，多账号消耗归属；不暴露明文 key）。
	// 租户维度（tenant_id，配额/计费）与平台维度（key_fp，成本核算）双口径分离。
	// 同样不进 hash()（证据字段）。
	KeyFP string `json:"key_fp,omitempty"`
	// GF.2.4：计量口径标记（estimate=估算未校准 / tokenizer=真机已校准）。
	// 证据字段，不进 hash()。
	MeteringMode string `json:"metering_mode,omitempty"`
	// GA-计费 P0-1：模型/引擎维度（分价计费数据基础；key_fp 平台成本与
	// tenant 租户账单双口径分离下的第三个维度）。证据字段，不进 hash()。
	EngineType string `json:"engine_type,omitempty"`
	Model      string `json:"model,omitempty"`
	// S5（判据 6）：写入本事件的进程实例标识（证据字段，不进 hash()）。
	// 用途：对账差异分类——同一审计链中出现**异实例**事件 ⇒ 多实例共写
	// （multi_instance）。omitempty 保证旧 WORM 行反序列化兼容（旧行无该字段，
	// 不参与异实例判定）。
	InstanceID string `json:"instance_id,omitempty"`
	// S5（判据 4）：影子命中维度（rpm/tpm/daily_budget，多命中逗号分隔）。
	// 仅 action=shadow、result=would_reject 的事件携带。证据字段，不进 hash()
	// （链完整性由 Action/Result 段保障：would_reject 本身进 hash）。
	ShadowRule string `json:"shadow_rule,omitempty"`
	// GA-输出侧内容审查（OG-3）：输出侧审查证据字段（一律 omitempty、不进 hash()，§4.10）。
	// OGCategory 取值目标为内部类目 ID（A1-06 形态，§5.8 #2）；OG-2 映射表落地前，
	// M1 骨架暂存 L1 原生标签，OG-7 的 Result/字段规范化一并收敛。
	OGCategory      string `json:"category,omitempty"`
	OGMode          string `json:"mode,omitempty"`           // shadow|enforcing
	OGPolicyVersion string `json:"policy_version,omitempty"` // 聚合策略版本（manifest.policy_version）
	// OG-9：策略热加载留痕（仅 action=output_guard_policy_reload 携带；证据字段，不进 hash()，§4.10）。
	// OGOldVersion ＝ 热加载前在效版本（rolled_back 时即保留版本）；
	// OGPolicySHA256 ＝ 本次 manifest.json 的自锚定摘要（applied/rolled_back 均尽量携带，供外部锚定追溯）。
	OGOldVersion   string `json:"old_version,omitempty"`
	OGPolicySHA256 string `json:"sha256,omitempty"`
	// OG-7：被拦截/遮蔽的产出量（token 口径，§4.9 计费口径）。证据字段，omitempty、不进 hash()。
	// 仅 action=output_blocked/output_masked 事件携带（M4 OG-17/18 才有发射点；R3 已裁决）；
	// M1 只落字段不填值，shadow 事件恒不携带（零值即不序列化）。填值与 /usage 聚合归 M4 OG-19。
	FilteredTokens int `json:"filtered_tokens,omitempty"`
}

// hash 计算事件哈希（不含 prev_hash 字段本身）。
// 使用长度前缀编码消除字段拼接歧义（防止 tenant="ab"+request="cd" 与 tenant="a"+request="bcd" 同 hash）。
func (e *AuditEvent) hash() string {
	h := sha256.New()
	writeLP := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	writeLP(e.EventID)
	writeLP(fmt.Sprint(e.Timestamp))
	writeLP(e.TenantID)
	writeLP(e.UserID)
	writeLP(e.RequestID)
	writeLP(e.Action)
	writeLP(fmt.Sprint(e.TokensIn))
	writeLP(fmt.Sprint(e.TokensOut))
	writeLP(e.Result)
	writeLP(e.PayloadSHA)
	return hex.EncodeToString(h.Sum(nil))
}

// auditChain 哈希链审计存储。
// 支持两种后端：
// - 内存模式（默认）：与 MVP 行为一致
// - WORM 文件模式：JSON Lines 只追加（O_APPEND），启动时从文件恢复链，
// 提供 anchor 锚定（链尾哈希落盘，独立文件）与 verify 篡改检测
type auditChain struct {
	mu      sync.Mutex
	events  []AuditEvent
	lastHex string
	file    *os.File  // 非 nil = WORM 持久化模式（只追加）
	anchor  *os.File  // 非 nil = 锚定文件（只追加）
	tsa     TSASigner // RFC 3161 可信时间戳服务
	// S5：本进程实例标识（构造时生成，写入每条事件的 instance_id 证据字段）。
	// 只读，构造后不再变更。
	instanceID string
}

// newInstanceID 生成本进程实例标识（"inst-" + 8 hex）。
func newInstanceID() string { return "inst-" + randHex(8) }

// newAuditChain 构造内存审计链。
func newAuditChain() *auditChain { return &auditChain{instanceID: newInstanceID()} }

// newAuditChainWithTSA 构造内存审计链（绑定 RFC 3161 TSA）。
func newAuditChainWithTSA(tsa TSASigner) *auditChain {
	return &auditChain{tsa: tsa, instanceID: newInstanceID()}
}

// newAuditChainWORM 构造 WORM 持久化审计链：打开（或创建）事件文件并恢复既有链。
// 文件以 O_APPEND 只追加打开，任何历史行被篡改都会在 verify() 中断链。
func newAuditChainWORM(path, anchorPath string) (*auditChain, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开事件文件失败: %w", err)
	}
	c := &auditChain{file: f, instanceID: newInstanceID()}
	if err := c.load(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	if anchorPath != "" {
		a, err := os.OpenFile(anchorPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: 打开锚定文件失败: %w", err)
		}
		c.anchor = a
	}
	return c, nil
}

// load 从事件文件恢复链（逐行 JSON，重建 events 与 lastHex）。
func (c *auditChain) load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("audit: 读取事件文件失败: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("audit: 事件文件第 %d 行解析失败: %w", len(c.events)+1, err)
		}
		// 链式校验：恢复过程同时检测历史篡改
		if e.PrevHash != c.lastHex {
			return fmt.Errorf("audit: 事件文件第 %d 行哈希链断裂（历史被篡改）", len(c.events)+1)
		}
		c.lastHex = e.hash()
		c.events = append(c.events, e)
	}
	return scanner.Err()
}

// append 追加审计事件（自动计算哈希链；WORM 模式同步写文件）。
// 返回落链后的终态事件（EventID/Timestamp 已定，供计费 Webhook 等下游对齐幂等键）。
func (c *auditChain) append(e AuditEvent) AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.PrevHash = c.lastHex
	e.Timestamp = time.Now().UnixNano()
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt-%d", e.Timestamp)
	}
	if e.InstanceID == "" {
		e.InstanceID = c.instanceID // S5：标识写入实例（证据字段，不进 hash）
	}
	if c.file != nil {
		line, _ := json.Marshal(e)
		if _, err := c.file.Write(append(line, '\n')); err != nil {
			// WORM 写入失败：告警日志（审计完整性受损，不应静默忽略）
			log.Printf("[audit] WORM 写入失败（审计完整性受损）: %v", err)
		}
	}
	c.events = append(c.events, e)
	c.lastHex = e.hash()
	return e
}

// AnchorRecord 锚定记录。
type AnchorRecord struct {
	Timestamp int64  `json:"timestamp"`
	Events    int    `json:"events"`
	ChainHash string `json:"chain_hash"`
	TST       *TST   `json:"tst,omitempty"` // RFC 3161 可信时间戳令牌
}

// anchorNow 将当前链尾哈希追加写入锚定文件（WORM 语义：只追加）。
// 返回锚定记录；锚定文件未启用时返回 nil。
// 锚定记录绑定 RFC 3161 时间戳令牌（TST），使第三方可验证锚定时间的可信性。
func (c *auditChain) anchorNow() *AnchorRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.anchor == nil {
		return nil
	}
	rec := AnchorRecord{
		Timestamp: time.Now().UnixNano(),
		Events:    len(c.events),
		ChainHash: c.lastHex,
	}
	// 绑定 TST：对锚定哈希签发可信时间戳（TSA 不可用 → fail-closed 不锚定）
	if c.tsa != nil {
		imprint := sha256.Sum256([]byte(rec.ChainHash))
		tst, err := c.tsa.Sign(imprint[:])
		if err != nil {
			log.Printf("[audit] TST 签发失败（锚定中止）: %v", err)
			return nil
		}
		rec.TST = tst
	}
	line, _ := json.Marshal(rec)
	if _, err := c.anchor.Write(append(line, '\n')); err != nil {
		log.Printf("[audit] 锚定文件写入失败: %v", err)
		return nil
	}
	return &rec
}

// verifyTST 校验锚定记录的时间戳令牌（第三方独立验证锚定时间可信性）。
func (c *auditChain) verifyTST(rec *AnchorRecord) error {
	if rec == nil || rec.TST == nil {
		return errors.New("audit: 锚定记录无 TST")
	}
	if c.tsa == nil {
		return errors.New("audit: TSA 未配置")
	}
	// 校验 TST 内 imprint 与锚定哈希一致（防锚定记录被替换）
	want := sha256.Sum256([]byte(rec.ChainHash))
	if rec.TST.MessageImprint != hex.EncodeToString(want[:]) {
		return errors.New("audit: TST imprint 与锚定哈希不匹配")
	}
	return c.tsa.Verify(rec.TST)
}

// Close 关闭底层文件（仅 WORM 模式）。
func (c *auditChain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		_ = c.file.Close()
	}
	if c.anchor != nil {
		_ = c.anchor.Close()
	}
	return nil
}

// verify 校验哈希链完整性（从第 0 条重放）。
func (c *auditChain) verify() (bool, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := ""
	for i, e := range c.events {
		if e.PrevHash != prev {
			return false, i
		}
		prev = e.hash()
	}
	return true, len(c.events)
}

// query 返回审计事件（JSON）。
func (c *auditChain) query(tenant string) []AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tenant == "" {
		out := make([]AuditEvent, len(c.events))
		copy(out, c.events)
		return out
	}
	var out []AuditEvent
	for _, e := range c.events {
		if e.TenantID == tenant {
			out = append(out, e)
		}
	}
	return out
}

// len 返回当前链长度（可观测性：otpmask_audit_events）。
func (c *auditChain) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// countByAction 统计指定动作的事件数。
func (c *auditChain) countByAction(action string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// instanceIDOf 返回本链的实例标识（构造后不变，无需加锁）。
func (c *auditChain) instanceIDOf() string { return c.instanceID }

// foreignInstances 返回**窗口内**（Timestamp >= since，UTC 纳秒）由非本实例写入的
// 实例标识（升序去重）。空标识（旧 WORM 行）不计入。
// 对账用途：非空 ⇒ 与另一实例**同时**在写同一审计链（多实例共写）；重启前的旧实例
// 事件已在窗口之外，不会被误判。
func (c *auditChain) foreignInstances(since int64) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, e := range c.events {
		if e.InstanceID == "" || e.InstanceID == c.instanceID || e.Timestamp < since || seen[e.InstanceID] {
			continue
		}
		seen[e.InstanceID] = true
		out = append(out, e.InstanceID)
	}
	sort.Strings(out)
	return out
}

// sha256hex 负载摘要（审计只记哈希不记内容，）。
func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var _ = json.Marshal
