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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// 变更动作与类型（落链字段取值）。
const (
	ActionApply    = "apply"    // 策略表更新
	ActionRollback = "rollback" // 按 version 回滚
	ChangeAdded    = "added"
	ChangeUpdated  = "updated"
	ChangeRemoved  = "removed"
	ResultOK       = "ok"
	ResultRejected = "rejected"
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
	PrevHash    string `json:"prev_hash"`
}

// hash 计算事件哈希（不含 prev_hash）。字段序＝audit-verify "core" schema。
func (e *Event) hash() string {
	h := sha256.New()
	writeLP := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
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
	return hex.EncodeToString(h.Sum(nil))
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
		c.lastHex = e.hash()
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
