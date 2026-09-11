// Package main — G1 凭据/配额写操作审计链（apiTokens Secret 化 M2）。
//
// 设计：docs/管理门户-apiTokens-Secret化-M2-B3-审计链接入评估.md §3.4/§5。
//
// 与 tee-infer 审计链的关系（决策门 #5：按 B-3 建议部分接入）：
//   - 本服务自建独立 SHA-256 哈希链，与 tee-infer 链通过 request_id 关联但互不共享，
//     避免审计可用性耦合数据面；
//   - 结构照搬 gateway/tee-infer-service/audit.go（长度前缀哈希 + WORM 只追加 +
//     启动恢复校验 + 锚定），但 **append 返回 error 实现 fail-closed**：
//     tee-infer 写失败仅告警（数据面可用性优先），本链写失败 = 拒绝该次凭据变更
//     （审计完整性优先，见 broker_secret.go upsert/remove 落链点）。
//
// 安全约束：
//   - 只记 Key 指纹（SHA-256 前 8 位），绝不明文入链/入日志；
//   - 失败路径不落链（链上 Result 恒为成功事件；失败已由 HTTP 错误响应与指标另行暴露）；
//   - 文件 O_APPEND 只追加（WORM），任何历史行被篡改都会在启动恢复时报链断裂，
//     fail-closed 拒绝启动；
//   - 锚定文件写失败仅告警（不阻断主链，B-3 定案）。
//
// 配置：ADMIN_AUDIT_FILE（事件文件，未配置 = 审计关闭）/ ADMIN_AUDIT_ANCHOR_FILE
// （锚定文件，可选）。启用后每 8192 条事件锚定一次链尾哈希（独立文件只追加）。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// 审计动作常量（凭据 CRUD 由 broker_secret.go 落链；quota_set 由 A-2' 配额写复用本链）。
const (
	auditActionCredentialUpsert = "credential_upsert"
	auditActionCredentialDelete = "credential_delete"
	auditActionQuotaSet         = "quota_set"
)

// auditAnchorInterval 每追加 N 条事件锚定一次链尾哈希。
const auditAnchorInterval = 8192

// auditSettings 审计链配置（环境变量 ADMIN_AUDIT_FILE / ADMIN_AUDIT_ANCHOR_FILE）。
type auditSettings struct {
	file       string
	anchorFile string
}

// loadAuditSettings 读取审计链配置（未配置 = 审计关闭，写操作不落链）。
func loadAuditSettings() *auditSettings {
	return &auditSettings{
		file:       os.Getenv("ADMIN_AUDIT_FILE"),
		anchorFile: os.Getenv("ADMIN_AUDIT_ANCHOR_FILE"),
	}
}

// adminAuditEvent 管理面审计事件（只记指纹与变更结果，绝不含 Key 明文）。
type adminAuditEvent struct {
	EventID        string `json:"event_id"`
	Timestamp      int64  `json:"timestamp"` // UTC 纳秒
	Actor          string `json:"actor"`     // 操作人登录名（JWT sub）
	Action         string `json:"action"`    // credential_upsert / credential_delete / quota_set
	Provider       string `json:"provider,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"` // SHA-256 前 8 位（不可逆推）
	Tenant         string `json:"tenant,omitempty"`          // quota_set 用
	MaxTokens      int64  `json:"max_tokens,omitempty"`      // quota_set 用
	Target         string `json:"target,omitempty"`          // 目标资源名（M3-A 账号管理：目标账号；其余动作为空）
	RequestID      string `json:"request_id"`
	Result         string `json:"result"` // 恒 "ok"（失败路径不落链）
	PrevHash       string `json:"prev_hash"`
}

// hash 计算事件哈希（不含 PrevHash 本身）。
// 长度前缀编码消除字段拼接歧义（与 tee-infer audit.go 同法）。
// 注：新链无向后兼容负担，全部内容字段进 hash。
func (e *adminAuditEvent) hash() string {
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
	writeLP(e.Provider)
	writeLP(e.KeyFingerprint)
	writeLP(e.Tenant)
	writeLP(fmt.Sprint(e.MaxTokens))
	// Target 条件编码（M3-A）：空时不进哈希——既有事件（无此字段）哈希不变，
	// 重启恢复时旧链校验不受影响；新事件带值才写入。长度前缀已消除拼接歧义。
	if e.Target != "" {
		writeLP(e.Target)
	}
	writeLP(e.RequestID)
	writeLP(e.Result)
	return hex.EncodeToString(h.Sum(nil))
}

// auditAnchorRecord 锚定记录（链尾哈希独立落盘，供第三方校验链完整性）。
type auditAnchorRecord struct {
	Timestamp int64  `json:"timestamp"`
	Events    int    `json:"events"`
	ChainHash string `json:"chain_hash"`
}

// adminAuditChain 管理面审计哈希链（WORM 文件持久化）。
type adminAuditChain struct {
	mu          sync.Mutex
	events      []adminAuditEvent
	lastHex     string
	file        *os.File
	anchor      *os.File
	sinceAnchor int // 距上次锚定的事件数
}

// newAdminAuditChain 构造 WORM 审计链：打开（或创建）事件文件并恢复既有链。
//
// file 为空串 → 返回 (nil, nil)（审计关闭）；打开/恢复/链校验失败 → 返回错误
// （调用方 main fail-closed 拒绝启动：宁可不起，不起一条无审计校验的凭据写路径）。
func newAdminAuditChain(file, anchorFile string) (*adminAuditChain, error) {
	if file == "" {
		return nil, nil
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开事件文件失败: %w", err)
	}
	c := &adminAuditChain{file: f}
	if err := c.load(file); err != nil {
		_ = f.Close()
		return nil, err
	}
	if anchorFile != "" {
		a, err := os.OpenFile(anchorFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: 打开锚定文件失败: %w", err)
		}
		c.anchor = a
	}
	return c, nil
}

// load 从事件文件恢复链（逐行 JSON），恢复过程同时做链式校验：
// 任何历史行被篡改/删除都会导致 PrevHash 断裂 → 返回错误（fail-closed 拒绝启动）。
func (c *adminAuditChain) load(path string) error {
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
		var e adminAuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("audit: 事件文件第 %d 行解析失败: %w", len(c.events)+1, err)
		}
		if e.PrevHash != c.lastHex {
			return fmt.Errorf("audit: 事件文件第 %d 行哈希链断裂（历史被篡改）", len(c.events)+1)
		}
		c.lastHex = e.hash()
		c.events = append(c.events, e)
	}
	return scanner.Err()
}

// append 追加审计事件并落盘。
//
// fail-closed 语义（与 tee-infer 版的关键差异）：写入失败 → 返回 error 且**不推进
// 内存链**（文件上该事件未持久化，若更新内存会导致后续事件 PrevHash 悬空），
// 调用方（broker_secret.go upsert/remove）必须拒绝该次业务变更。
// 成功后更新指标并按间隔锚定。
func (c *adminAuditChain) append(e adminAuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.PrevHash = c.lastHex
	e.Timestamp = time.Now().UnixNano()
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt-%d", e.Timestamp)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: 事件序列化失败: %w", err)
	}
	if _, err := c.file.Write(append(line, '\n')); err != nil {
		// 内存链不推进：失败事件未持久化，保持与文件一致
		return fmt.Errorf("audit: 事件文件写入失败: %w", err)
	}
	c.events = append(c.events, e)
	c.lastHex = e.hash()
	c.sinceAnchor++
	metrics.setAuditEvents(len(c.events))
	if c.anchor != nil && c.sinceAnchor >= auditAnchorInterval {
		c.writeAnchorLocked()
	}
	return nil
}

// writeAnchorLocked 将当前链尾哈希追加写入锚定文件（须持锁调用）。
// 锚定失败仅告警 + 指标，不阻断主链（B-3 定案：锚定是增强手段）。
func (c *adminAuditChain) writeAnchorLocked() {
	rec := auditAnchorRecord{
		Timestamp: time.Now().UnixNano(),
		Events:    len(c.events),
		ChainHash: c.lastHex,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		log.Printf("[audit] 锚定记录序列化失败: %v", err)
		return
	}
	if _, err := c.anchor.Write(append(line, '\n')); err != nil {
		log.Printf("[audit] 锚定文件写入失败（仅告警，不阻断主链）: %v", err)
		return
	}
	c.sinceAnchor = 0
}

// verify 从内存重放校验哈希链完整性（测试/运维自检用）。
func (c *adminAuditChain) verify() (bool, int) {
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

// len 返回当前链长度。
func (c *adminAuditChain) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// Close 关闭底层文件（测试用；进程生命周期内审计链常开）。
func (c *adminAuditChain) Close() error {
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
