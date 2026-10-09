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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// 审计动作常量（凭据 CRUD 由 broker_secret.go 落链；quota_set 由 A-2' 配额写复用本链）。
const (
	auditActionCredentialUpsert = "credential_upsert"
	auditActionCredentialDelete = "credential_delete"
	auditActionQuotaSet         = "quota_set"
	// P0-3 计费域动作（§4.3.5）。
	auditActionPlanUpsert  = "plan_upsert"
	auditActionPlanBind    = "plan_bind"
	auditActionBillFreeze  = "bill_freeze"
	auditActionBillUnfreeze = "bill_unfreeze"
	auditActionBillIssue   = "bill_issue"
	auditActionBillExport  = "bill_export"
	auditActionBillVerify  = "bill_verify"
	// P0-4 §4.3.10：密码 profile/mask_prg 切换（B5-c）。
	auditActionCryptopProfileSwitch = "cryptop.profile.switch"
	// P1-4 租户自助门户动作（附录 D 审计动作清单）。
	auditActionTenantRegister = "tenant_register"
	auditActionTenantLogout   = "tenant_logout"
	auditActionPasswordReset  = "password_reset"
	// P1-4 M3 API Key 动作（附录 D；只记 key_id + 指纹前 8，明文绝不入链）。
	auditActionAPIKeyCreate = "api_key_create"
	auditActionAPIKeyRotate = "api_key_rotate"
	auditActionAPIKeyRevoke = "api_key_revoke"
	// P1-4 M5 策略/模型动作（附录 D；策略仅存条目数/类目数摘要，不存具体词）。
	auditActionPolicyUpdate      = "policy_update"
	auditActionPolicyApply       = "policy_apply"
	auditActionModelConfigUpdate = "model_config_update"
	// P1-4 M7 套餐动作（附录 D）。
	auditActionPlanUpgrade   = "plan_upgrade"
	auditActionPlanDowngrade = "plan_downgrade"
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
	// P0-4 §4.3.10：profile 切换事件明细（B5-c；空时不进 hash，旧链逐字节不变）。
	ProfileFrom string `json:"profile_from,omitempty"` // 切换前 profile
	ProfileTo   string `json:"profile_to,omitempty"`   // 目标 profile
	SwitchMode  string `json:"switch_mode,omitempty"`  // restart / hot
	MaskPRG     string `json:"mask_prg,omitempty"`     // hmac-sha256 / sm4 / bridge（仅切换事件）
	// HashAlg P0-4 §5.2.2：本条事件哈希算法自述（**证据字段，不进 hash()**，B-5.2-1）。
	// R-13：空/缺省 = SHA-256；"sm3" = SM3；R-12：其它值非法。
	// 注：`KeyFingerprint` 为**标识类**字段（API 可见、跨服务引用），恒 SHA-256，不随本标签迁移。
	// 写入端打标随服务 profile 接线落地（B4）；本批先建分派机制。
	HashAlg  string `json:"hash_alg,omitempty"`
	// Detail M5（策略/模型变更摘要，附录 D）：**证据字段，不进 hash()**（与 HashAlg 同法），
	// 保持既有链格式不变；空 = 不写。
	Detail   string `json:"detail,omitempty"`
	PrevHash string `json:"prev_hash"`
}

// ---- 算法分派（P0-4 §5.2.2）：与进程 profile 解耦 ----

var (
	hashProvSHA256 = mustProv(cryptop.ProfileIntl)
	hashProvSM3    = mustProv(cryptop.ProfileSMSW)
)

func mustProv(p cryptop.Profile) cryptop.Provider {
	prov, err := cryptop.New(p)
	if err != nil {
		panic("audit: 初始化 " + string(p) + " provider 失败: " + err.Error())
	}
	return prov
}

// hashByAlg 按事件自述算法哈希（R-13 缺省 = SHA-256；R-12 未知值 → 错误，不静默回退）。
// 双读：若实际使用的算法与当前进程主 profile 的默认算法不一致，记一次 cryptop_dualread_total{artifact=audit}。
func hashByAlg(alg string, data []byte) ([]byte, error) {
	switch alg {
	case "":
		if cryptoProvider.Profile() != cryptop.ProfileIntl {
			metrics.incDualRead("audit")
		}
		return hashProvSHA256.Hash(data), nil
	case "sm3":
		if cryptoProvider.Profile() == cryptop.ProfileIntl {
			metrics.incDualRead("audit")
		}
		return hashProvSM3.Hash(data), nil
	default:
		return nil, fmt.Errorf("audit: 未知 hash_alg %q（R-12：验证失败）", alg)
	}
}

// hash 计算事件哈希（不含 PrevHash 本身）。长度前缀编码消除字段拼接歧义（与 tee-infer 同法）。
// 注：新链无向后兼容负担，全部内容字段进 hash。算法由自述 `hash_alg` 分派（§5.2.2）。
func (e *adminAuditEvent) hash() string {
	h, err := e.hashWithErr()
	if err != nil {
		panic("audit: " + err.Error())
	}
	return h
}

// hashWithErr 同 hash()，未知 `hash_alg` 作为错误返回（R-12，供 load/append fail-closed）。
func (e *adminAuditEvent) hashWithErr() (string, error) {
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
	writeLP(e.Provider)
	writeLP(e.KeyFingerprint)
	writeLP(e.Tenant)
	writeLP(fmt.Sprint(e.MaxTokens))
	// Target 条件编码（M3-A）：空时不进哈希——既有事件（无此字段）哈希不变，
	// 重启恢复时旧链校验不受影响；新事件带值才写入。长度前缀已消除拼接歧义。
	if e.Target != "" {
		writeLP(e.Target)
	}
	// §4.3.10 切换明细同法条件编码：空值（既有事件）不进哈希，旧链逐字节不变。
	if e.ProfileFrom != "" {
		writeLP(e.ProfileFrom)
		writeLP(e.ProfileTo)
		writeLP(e.SwitchMode)
		writeLP(e.MaskPRG)
	}
	writeLP(e.RequestID)
	writeLP(e.Result)
	sum, err := hashByAlg(e.HashAlg, buf.Bytes())
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
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
		h, herr := e.hashWithErr()
		if herr != nil {
			return fmt.Errorf("audit: 事件文件第 %d 行哈希算法非法: %w", len(c.events)+1, herr)
		}
		c.lastHex = h
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
	// §5.2.2 写入端打标：按本进程 profile（intl → ""（缺省=SHA-256），sm-* → "sm3"）。
	// 注：`KeyFingerprint` 恒 SHA-256（标识类），故 sm 档该字段与链哈希算法不同档——见 §5.2.2 例外条。
	if e.HashAlg == "" {
		e.HashAlg = hashAlgTag()
	}
	// R-12：算法非法即拒绝落链（凭据变更不留痕/不可复算不可接受）
	if _, herr := e.hashWithErr(); herr != nil {
		return fmt.Errorf("audit: 事件哈希算法非法: %w", herr)
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

// list 返回事件分页副本（**倒序：最新在前**）与总数（M3-B 安全中心审计链查询）。
func (c *adminAuditChain) list(limit, offset int) ([]adminAuditEvent, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := len(c.events)
	if offset < 0 {
		offset = 0
	}
	if offset >= total || limit <= 0 {
		return []adminAuditEvent{}, total
	}
	// 实际取用条数（容量按需分配，避免大 limit 触发巨额预分配）。
	n := total - offset
	if n > limit {
		n = limit
	}
	// 倒序：内存链按追加序存储，反向切片取 [offset, offset+n)
	out := make([]adminAuditEvent, 0, n)
	for i := total - 1 - offset; i >= 0 && len(out) < n; i-- {
		out = append(out, c.events[i])
	}
	return out, total
}

// lastHash 返回当前链尾哈希（空链 = 空串）。导出/状态视图用。
func (c *adminAuditChain) lastHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHex
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
