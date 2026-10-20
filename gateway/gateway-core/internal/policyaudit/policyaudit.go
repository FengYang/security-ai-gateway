// Package policyaudit — 策略变更审计链（Phase 1 门禁 #7 / 判据 7）。
//
// 定位：记录限流/预算策略的**每一次变更**（谁、何时、哪条规则、旧值→新值、生效版本），
// 支持按 version 回滚后留痕，与 D8 高敏变更复核同一口径（谁/何时/哪条/旧→新）。
//
// 与 tee-infer / admin-service 的链**同构**：SHA-256 哈希链（prev_hash 串接）+ 可选 WORM
// 文件（JSON Lines 只追加）、启动恢复即链式校验（损坏即拒绝启动，由调用方 fail-closed）。
//
// ⚠️ 硬约束：hash() 的字段序与编码必须与 gateway/audit-verify/schema.go 的 "core" schema
// 逐字段一致（外部验证器据此独立重算），任一端改动都必须同步两侧 + 固定测试向量。
package policyaudit

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// 变更动作与类型（落链字段取值）。
const (
	ActionApply    = "apply"    // 策略表更新
	ActionRollback = "rollback" // 按 version 回滚
	// ActionMCPTrackChanged MCP 工具敏感度（Track）变更——独立留痕（T-6 / §4.6.2），
	// 防「静默改判 → 工具跨轨迁移」。action 取值不受 audit-verify "core" schema 约束
	// （schema 仅固定字段序），故新增不破链、旧链哈希逐字节不变。
	ActionMCPTrackChanged = "mcp_track_changed"
	// ActionMCPServerChanged T-3：联邦后端注册变更（新增/摘除/逐字段更新；VersionFrom/To
	// 对应目录重签版本区间）。action 取值同样不受 audit-verify "core" schema 约束，新增不破链。
	ActionMCPServerChanged = "mcp_server_changed"
	// ActionTTFTReset P1-6 M3.6：TTFT 统计重置（运维；§6.2）。action 取值同 MCP-变更口径，
	// 不受 audit-verify "core" schema 约束（schema 仅固定字段序），新增不破链。
	ActionTTFTReset = "route_ttft_reset"
	ChangeAdded     = "added"
	ChangeUpdated   = "updated"
	ChangeRemoved   = "removed"
	ResultOK        = "ok"
	ResultRejected  = "rejected"
)

// Event 策略变更事件（一条 = 一个规则的某个字段变更，或规则增删）。
type Event struct {
	EventID     string `json:"event_id"`
	Timestamp   int64  `json:"timestamp"` // UTC 纳秒
	Actor       string `json:"actor"`     // 变更发起人（调用方经 X-Actor 传入；未知 = "unknown"）
	Action      string `json:"action"`    // apply | rollback
	VersionFrom int    `json:"version_from"`
	VersionTo   int    `json:"version_to"`
	RuleID      string `json:"rule_id"`
	Change      string `json:"change"`              // added | updated | removed
	Field       string `json:"field,omitempty"`     // updated 时为变更字段名
	OldValue    string `json:"old_value,omitempty"` // 旧值（added 时为空）
	NewValue    string `json:"new_value,omitempty"` // 新值（removed 时为空）
	RequestID   string `json:"request_id"`
	Result      string `json:"result"` // ok | rejected
	// HashAlg P0-4 §5.2.2：本条事件哈希算法自述（**证据字段，不进 hash()**，B-5.2-1）。
	// R-13：空/缺省 = SHA-256；"sm3" = SM3；R-12：其它值非法（验证器须拒绝）。
	// 注：写入端打标随服务 profile 接线落地（B4）；本批先建分派机制。
	HashAlg  string `json:"hash_alg,omitempty"`
	PrevHash string `json:"prev_hash"`

	// ---- A2A 注册中心扩展元数据（证据字段，**不进 hash()**）----
	//
	// 冻结清单 §5.7 要求 A2A 审计事件携带 actor_tenant/target_tenant/agent/provider/
	// old_revision/new_revision/content_hash/reason/trace_id 等元数据级字段。
	// core schema 的哈希字段序是跨包硬约束（audit-verify "core" schema 逐字段一致，
	// 见包注释），**不得增删 hash() 覆盖的字段**；故这些扩展字段一律作为
	// "证据字段"挂在 Event 上（同 HashAlg 口径）——不进 hash、随事件落 WORM、
	// 由 audit-verify 按 JSON key 自行读取。
	//
	// ⚠️ 空值一律 omitempty：未使用该扩展的既有事件（限流/路由/MCP）序列化结果
	// 逐字节不变，旧链哈希恒定。
	ActorTenant  string `json:"actor_tenant,omitempty"`
	TargetTenant string `json:"target_tenant,omitempty"`
	Agent        string `json:"agent,omitempty"`
	Provider     string `json:"provider,omitempty"`
	OldRevision  int    `json:"old_revision,omitempty"`
	NewRevision  int    `json:"new_revision,omitempty"`
	ContentHash  string `json:"content_hash,omitempty"`
	Reason       string `json:"reason,omitempty"`
	TraceID      string `json:"trace_id,omitempty"`
}

// ---- 算法分派（P0-4 §5.2.2）：与进程 profile 解耦（intl 进程亦须能复算 sm 事件）----

var (
	hashProvSHA256 = mustProv(cryptop.ProfileIntl)
	hashProvSM3    = mustProv(cryptop.ProfileSMSW)
	// profileProvider 本进程档 provider（`CRYPTO_PROFILE`，默认 intl）——仅用于**写入端打标**。
	profileProvider = mustProv(cryptoProfile())
)

// cryptoProfile 取本进程 profile（P0-4 §12.3 `crypto_profile`；缺省 intl，与现役 SHA-256 等价）。
func cryptoProfile() cryptop.Profile {
	if p := os.Getenv("CRYPTO_PROFILE"); p != "" {
		return cryptop.Profile(p)
	}
	return cryptop.ProfileIntl
}

// hashAlgTag 写入端 `hash_alg` 取值（intl → ""（缺省=SHA-256，R-13）；sm-* → "sm3"）。
func hashAlgTag() string {
	if profileProvider.Profile() == cryptop.ProfileIntl {
		return ""
	}
	return "sm3"
}

func mustProv(p cryptop.Profile) cryptop.Provider {
	prov, err := cryptop.New(p)
	if err != nil {
		panic("policyaudit: 初始化 " + string(p) + " provider 失败: " + err.Error())
	}
	return prov
}

// hashByAlg 按事件自述算法哈希（R-13 缺省 = SHA-256；R-12 未知值 → 错误，不静默回退）。
func hashByAlg(alg string, data []byte) ([]byte, error) {
	switch alg {
	case "":
		return hashProvSHA256.Hash(data), nil
	case "sm3":
		return hashProvSM3.Hash(data), nil
	default:
		return nil, fmt.Errorf("policyaudit: 未知 hash_alg %q（R-12：验证失败）", alg)
	}
}

// hash 计算事件哈希（不含 prev_hash）。字段序＝audit-verify "core" schema，**逐字节不变**。
func (e *Event) hash() string {
	h, err := e.hashWithErr()
	if err != nil {
		panic("policyaudit: " + err.Error())
	}
	return h
}

// hashWithErr 同 hash()，未知 `hash_alg` 作为错误返回（R-12，供 load/Append fail-closed）。
func (e *Event) hashWithErr() (string, error) {
	var buf bytes.Buffer
	writeLP := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf.Write(l[:])
		buf.WriteString(s)
	}
	writeLP(e.EventID)
	writeLP(fmt.Sprint(e.Timestamp))
	writeLP(e.Actor)
	writeLP(e.Action)
	writeLP(fmt.Sprint(e.VersionFrom))
	writeLP(fmt.Sprint(e.VersionTo))
	writeLP(e.RuleID)
	writeLP(e.Change)
	writeLP(e.Field)
	writeLP(e.OldValue)
	writeLP(e.NewValue)
	writeLP(e.RequestID)
	writeLP(e.Result)
	sum, err := hashByAlg(e.HashAlg, buf.Bytes())
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
}

// Chain 策略变更审计链（内存 + 可选 WORM 文件）。
type Chain struct {
	mu      sync.Mutex
	events  []Event
	lastHex string
	file    *os.File
}

// New 构造链：filePath 非空 → WORM 持久化（打开/创建并恢复既有链，损坏即报错，调用方须 fail-closed）。
func New(filePath string) (*Chain, error) {
	c := &Chain{}
	if filePath == "" {
		return c, nil
	}
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("policyaudit: 打开审计文件失败: %w", err)
	}
	c.file = f
	if err := c.load(filePath); err != nil {
		_ = f.Close()
		return nil, err
	}
	return c, nil
}

// load 从文件恢复链（逐行 JSON，恢复过程即做链式校验）。
func (c *Chain) load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policyaudit: 读取审计文件失败: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("policyaudit: 审计文件第 %d 行解析失败: %w", len(c.events)+1, err)
		}
		if e.PrevHash != c.lastHex {
			return fmt.Errorf("policyaudit: 审计文件第 %d 行哈希链断裂（历史被篡改）", len(c.events)+1)
		}
		h, herr := e.hashWithErr()
		if herr != nil {
			return fmt.Errorf("policyaudit: 审计文件第 %d 行哈希算法非法: %w", len(c.events)+1, herr)
		}
		c.lastHex = h
		c.events = append(c.events, e)
	}
	return scanner.Err()
}

// Append 追加一条变更事件（自动填 EventID/Timestamp/PrevHash；WORM 模式同步落盘）。
// WORM 写失败返回错误——调用方须拒绝 2xx（变更不留痕即不可接受）。
func (c *Chain) Append(e Event) (Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.PrevHash = c.lastHex
	e.Timestamp = time.Now().UnixNano()
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("pol-%d-%d", e.Timestamp, len(c.events)+1)
	}
	// §5.2.2 写入端打标：按本进程 profile（intl → ""（缺省=SHA-256），sm-* → "sm3"）。
	if e.HashAlg == "" {
		e.HashAlg = hashAlgTag()
	}
	// R-12：算法非法即拒绝落链（不得把不可复算的事件写入 WORM）
	if _, herr := e.hashWithErr(); herr != nil {
		return Event{}, fmt.Errorf("policyaudit: 事件哈希算法非法（变更不留痕不可接受）: %w", herr)
	}
	if c.file != nil {
		line, _ := json.Marshal(e)
		if _, err := c.file.Write(append(line, '\n')); err != nil {
			return Event{}, fmt.Errorf("policyaudit: 审计落盘失败（变更不留痕）: %w", err)
		}
	}
	c.events = append(c.events, e)
	c.lastHex = e.hash()
	return e, nil
}

// Verify 校验链完整性（从第 0 条重放）。
func (c *Chain) Verify() (bool, int) {
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

// List 返回最近 limit 条事件（limit <= 0 = 全部），按时间正序。
func (c *Chain) List(limit int) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := 0
	if limit > 0 && len(c.events) > limit {
		start = len(c.events) - limit
	}
	out := make([]Event, len(c.events)-start)
	copy(out, c.events[start:])
	return out
}

// Len 返回链长度。
func (c *Chain) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// Close 关闭底层文件（仅 WORM 模式）。
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}
