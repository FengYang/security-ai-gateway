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
	file    *os.File // 非 nil = WORM 持久化模式（只追加）
	anchor  *os.File // 非 nil = 锚定文件（只追加）
	tsa     TSASigner // RFC 3161 可信时间戳服务
}

// newAuditChain 构造内存审计链。
func newAuditChain() *auditChain { return &auditChain{} }

// newAuditChainWithTSA 构造内存审计链（绑定 RFC 3161 TSA）。
func newAuditChainWithTSA(tsa TSASigner) *auditChain { return &auditChain{tsa: tsa} }

// newAuditChainWORM 构造 WORM 持久化审计链：打开（或创建）事件文件并恢复既有链。
// 文件以 O_APPEND 只追加打开，任何历史行被篡改都会在 verify() 中断链。
func newAuditChainWORM(path, anchorPath string) (*auditChain, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开事件文件失败: %w", err)
	}
	c := &auditChain{file: f}
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
func (c *auditChain) append(e AuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.PrevHash = c.lastHex
	e.Timestamp = time.Now().UnixNano()
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt-%d", e.Timestamp)
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

// sha256hex 负载摘要（审计只记哈希不记内容，）。
func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var _ = json.Marshal
