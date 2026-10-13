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

// auditMetrics 包级指标指针（启动时由 main.go 构造处赋值），供脱敏/容量等模块计数。
// 仅用于指标递增，nil 时安全跳过（单测可不设）。
var auditMetrics *otpmaskMetrics

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
	// HashAlg P0-4 §5.2.2：本条事件**所有哈希类字段**所用算法的自述标签
	// （链哈希 + 请求载荷摘要同档）。**证据字段，不进 hash()**（B-5.2-1；否则历史链全废）。
	// R-13：空/缺省 = SHA-256（不写字段以保 WORM 旧行逐字节不变）；"sm3" = SM3；R-12：其它值非法。
	HashAlg  string `json:"hash_alg,omitempty"`
	PrevHash string `json:"prev_hash"` // 哈希链
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
	// GA-输出侧内容审查（OG-3/OG-7）：输出侧审查证据字段（一律 omitempty、不进 hash()，§4.10）。
	// OGCategory 存内部类目 ID（A1-06 形态，§5.8 #2；L1 原生类目经 l1CategoryMap 映射后写入），
	// Result 形如 would_reject_A1-07（OG-7 已规范化为内部类目 ID）。
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
	// GA-计费 P0-3（A-23/A-29）：重试归因标记。由数据面经请求头
	// `X-Otpmask-Retry-Attempt` 下行（唯一数据面改动），tee-infer 解析后落审计。
	// **证据字段，不进 hash()**（保持 WORM 旧链向后兼容）；重试 token 归平台成本
	// （不计用户金额，M9），/usage 由此字段按 net/retry 分列（A-35）。
	IsRetry bool `json:"is_retry,omitempty"`
	// P1-2 全链路 tracing（D-5）：trace_id 证据字段，关联审计事件与 trace。
	// **证据字段，不进 hash()**（保持 WORM 旧链逐字节不变）。
	// omitempty：tracing 未启用或无 trace 时不写入，旧行零差异。
	TraceID string `json:"trace_id,omitempty"`
	// T-9 / V-6：MCP 敏感轨 tools/call 审计证据字段（**证据字段，不进 hash()**，C-4；
	// 仅记决策元数据与参数 hash，**无明文**）。omitempty：旧 WORM 行零差异。
	MCPTool          string `json:"mcp_tool,omitempty"`
	MCPReason        string `json:"mcp_reason,omitempty"`
	MCPPolicyVersion int    `json:"mcp_policy_version,omitempty"`
	// ---- P1-7 全流量审计改造（T1，§6.1(B) 证据字段）----
	// 以下字段全部为证据字段、omitempty、**不进 hash()**（保持 WORM 旧链逐字节不变，C-3/D-1）。
	// Path 请求路径（规范化、去 query 值，由 T4 redact 处理）；PathMode = plain|encrypted。
	Path string `json:"path,omitempty"`
	// PathMode 请求路径密态标记；Path 为规范化路径（不含 query 值）。
	PathMode string `json:"path_mode,omitempty"` // plain | encrypted
	// TTFTMs 首 token 时延（ms），与 P0-2 TTFT 口径一致。
	TTFTMs int `json:"ttft_ms,omitempty"`
	// DurMS 请求总耗时（ms）。
	DurMS int `json:"dur_ms,omitempty"`
	// HTTPStatus 对外返回状态码。
	HTTPStatus int `json:"http_status,omitempty"`
	// HitPolicies 命中的安全策略（逗号分隔枚举，全集见 §6.1(B)）；空 = 未命中（分层判定依据）。
	// 枚举值全集（小写 + 下划线命名；实施时做白名单校验，非法值丢弃并告警）：
	//   guardrail_* / rpm_limit / tpm_limit / daily_budget / quota_deny / bad_signature /
	//   replay_attack / cache_negative / output_blocked / output_masked / shadow_reject
	// 仅用于策略维度检索与统计，不作为链哈希的一部分（C-3）。
	HitPolicies string `json:"hit_policies,omitempty"`
	// Origin 事件来源：tee（空）| data-plane（数据面经 /audit/report 上报，D-2）。
	Origin string `json:"origin,omitempty"`
	// Sampled 【v1.11 废弃，不启用；保留定义仅为旧文件反序列化兼容】（D-16，归档不再降采样）。
	// 旧注释"因 sampled 不进 hash，哈希链 prev_hash 仍然一致"已被证伪（归档降采样会断链）；
	// 本字段恒为 false（omitempty 不落 JSON），归档副本与源 WORM 行逐字节一致。
	Sampled bool `json:"sampled,omitempty"`
	// MCPSessionID MCP 敏感轨的回退关联键（A3-07）：request_id 不可得时的兜底（由 sess.ID 派生）。
	MCPSessionID string `json:"mcp_session_id,omitempty"`
	// ReporterID 数据面上报端实例标识（A3-10）：由上报令牌绑定的 reporter 身份在服务端写入，
	// 不信任请求体自报值，用于上报对账与审计投毒溯源。
	ReporterID string `json:"reporter_id,omitempty"`
	// TenantIDResolution 租户解析方式（v1.12 新增，D-18）：仅回灌事件（origin=data-plane 且
	// 由 T2c 采集器上报）写入，取值 consumer_map（X-Mse-Consumer→映射表解析为真实租户）/
	// unauthenticated（无服务端认证身份，落哨兵租户 _unauthenticated）；不进 hash。
	// 插件侧上报事件不写本字段（其租户由令牌绑定，见 §6.5 分型①）。
	TenantIDResolution string `json:"tenant_id_resolution,omitempty"`
}

// hash 计算事件哈希（不含 prev_hash 字段本身）。
// 算法由事件自述 `hash_alg` 分派（§5.2.2）；**字段序与长度前缀方案逐字节不变** ⇒ intl 旧链哈希恒定。
// 内部断言语义：`HashAlg` 由本进程生成、且 load 入口已校验 ⇒ 非法值不可达（见 hashWithErr）。
func (e *AuditEvent) hash() string {
	h, err := e.hashWithErr()
	if err != nil {
		panic("audit: " + err.Error())
	}
	return h
}

// hashWithErr 同 hash()，但把未知 `hash_alg` 作为错误返回（R-12，供 load/写入路径 fail-closed）。
//
// ⚠️ 哈希字段清单锁定（P1-7 T1，C-3/D-1）：以下 10 个字段及其顺序**永久冻结**，
// 任何新增字段（含 §6.1(B) 全部证据字段）一律 omitempty 且**不得**加入本清单，
// 否则历史 WORM 链哈希将改变、audit-verify 全链断裂。变更本清单须走评审并双写兼容迁移。
//   1 EventID   2 Timestamp   3 TenantID   4 UserID   5 RequestID
//   6 Action    7 TokensIn    8 TokensOut  9 Result   10 PayloadSHA
func (e *AuditEvent) hashWithErr() (string, error) {
	var buf bytes.Buffer
	writeLP := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf.Write(l[:])
		buf.WriteString(s)
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
	return hashHexByAlg(e.HashAlg, buf.Bytes())
}

// auditChain 哈希链审计存储。
// 支持多种后端：
// - 内存模式（默认）：与 MVP 行为一致
// - WORM 后端（WormBackend 接口）：fileWorm（本地 JSONL）/ 对象存储 WORM 等，
//   只追加语义，启动时从文件恢复链，提供 anchor 锚定与 verify 篡改检测
//
// T5（GAP-09）新增：fail-closed 模式与 WormBackend 抽象。
// - append 签名不变（既有 30 处调用点零改动，方案甲）
// - appendOrFail：业务变更类落链点调用，写失败且 failClosed=true 时返回 error
type auditChain struct {
	mu      sync.Mutex
	events  []AuditEvent
	lastHex string
	file    *os.File  // 非 nil = 旧 WORM 持久化模式（只追加；向后兼容，保留供 load/恢复用）
	anchor  *os.File  // 非 nil = 锚定文件（只追加）
	tsa     TSASigner // RFC 3161 可信时间戳服务
	// S5：本进程实例标识（构造时生成，写入每条事件的 instance_id 证据字段）。
	// 只读，构造后不再变更。
	instanceID string
	// P0-2 §9.1 #16 / B-7.5-1：审计链写入失败回调（不阻塞缓存写入）。
	// 启动期一次性设置（SetWriteFailureHook），此后只读。
	onWriteFail func()
	// ---- P1-8 T5（GAP-09）fail-closed 与 WormBackend ----
	// worm：WORM 持久化后端（nil = 纯内存模式，不落盘）。
	// 与旧 file 字段的关系：file 保留供 load 恢复用；写入走 worm 接口。
	worm WormBackend
	// failClosed：true = 写失败时拒绝业务请求（fail-closed）；
	// false = 写失败仅告警（fail-open，兼容旧行为）。
	// 启动期设置，运行时可通过 SetFailClosed 动态切换（灰度/回退）。
	failClosed bool
	// onWormWriteFail：WORM 写入失败回调（M-7 指标，policy=fail_closed|fail_open）。
	// 唯一生产点：appendOrFail。append 内部的旧 file 写入失败仍走 onWriteFail。
	onWormWriteFail func(policy string)
	// onFailClosedReject：fail-closed 模式下因写失败拒绝请求的计数（M-8 指标）。
	// 唯一生产点：appendOrFail。
	onFailClosedReject func()
}

// SetWriteFailureHook 设置审计链写入失败回调（启动期调用；P0-2 §9.1 #16）。
func (c *auditChain) SetWriteFailureHook(fn func()) { c.onWriteFail = fn }

// ---- P1-8 T5（GAP-09）fail-closed 与 WormBackend 设置 ----

// SetWormBackend 设置 WORM 持久化后端（nil = 纯内存）。
// 启动期一次性设置，此后只读。
func (c *auditChain) SetWormBackend(wb WormBackend) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.worm = wb
}

// SetFailClosed 设置 fail-closed 模式（可运行时动态切换，用于灰度/回退）。
// true = WORM 写失败时拒绝业务请求；false = 仅告警（默认，兼容旧行为）。
func (c *auditChain) SetFailClosed(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failClosed = v
}

// FailClosed 返回当前 fail-closed 模式。
func (c *auditChain) FailClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failClosed
}

// SetWormWriteFailHook 设置 WORM 写入失败回调（M-7 指标，policy=fail_closed|fail_open）。
// 启动期一次性设置。
func (c *auditChain) SetWormWriteFailHook(fn func(policy string)) { c.onWormWriteFail = fn }

// SetFailClosedRejectHook 设置 fail-closed 拒绝回调（M-8 指标）。
// 启动期一次性设置。
func (c *auditChain) SetFailClosedRejectHook(fn func()) { c.onFailClosedReject = fn }

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
		// R-12：未知 hash_alg → fail-closed 拒绝启动（不得静默按 SHA-256 重算）
		h, herr := e.hashWithErr()
		if herr != nil {
			return fmt.Errorf("audit: 事件文件第 %d 行哈希算法非法: %w", len(c.events)+1, herr)
		}
		c.lastHex = h
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
	// P1-7 T2a（§6.5）：调用方显式设置 Timestamp（数据面上报携带 timestamp_ns）时
	// 予以保留（取证用原始上报时刻）；否则取落链时刻。零值判定保证既有 30 处
	// 调用点（均未预置 Timestamp）行为不变，哈希链逐字节兼容（C-3/D-1）。
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixNano()
	}
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt-%d", e.Timestamp)
	}
	if e.InstanceID == "" {
		e.InstanceID = c.instanceID // S5：标识写入实例（证据字段，不进 hash）
	}
	// R-12：算法非法即不落链（fail-safe 保链完整；按构造不可达——HashAlg 仅由本进程 hashAlgTag() 生成）
	if _, herr := e.hashWithErr(); herr != nil {
		log.Printf("[audit] 事件哈希算法非法，拒绝落链: %v", herr)
		return e
	}
	if c.file != nil {
		line, _ := json.Marshal(e)
		if _, err := c.file.Write(append(line, '\n')); err != nil {
			// WORM 写入失败：告警日志（审计完整性受损，不应静默忽略）+ 指标回调（§9.1 #16）
			log.Printf("[audit] WORM 写入失败（审计完整性受损）: %v", err)
			if c.onWriteFail != nil {
				c.onWriteFail()
			}
		}
	}
	c.events = append(c.events, e)
	c.lastHex = e.hash()
	return e
}

// appendOrFail 追加审计事件（业务变更类落链点专用）。
//
// 与 append 的差异：
//   - 写 WORM 失败时，按 failClosed 决定是否返回 error：
//     - failClosed=true → 返回 error（调用方应拒绝业务请求，M-8 计数）
//     - failClosed=false → 仅告警 + 落内存链（兼容旧行为，M-7 计数 policy=fail_open）
//   - 返回落链后的终态事件（与 append 一致）+ error。
//
// 指标唯一生产点（M-7 / M-8，D-11 去重）：
//   - M-7 otpmask_worm_write_failed_total{policy}：onWormWriteFail(policy)
//   - M-8 otpmask_audit_failclosed_rejected_total：onFailClosedReject()
//
// 注意：
//   - append 签名不变（既有 30 处调用点零改动，方案甲）
//   - 仅"业务变更类落链点"调用本函数；查询/观测/启动类继续用 append
//   - worm 为 nil（纯内存）时始终成功（无持久化失败场景）
func (c *auditChain) appendOrFail(e AuditEvent) (AuditEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.PrevHash = c.lastHex
	e.Timestamp = time.Now().UnixNano()
	if e.EventID == "" {
		e.EventID = fmt.Sprintf("evt-%d", e.Timestamp)
	}
	if e.InstanceID == "" {
		e.InstanceID = c.instanceID
	}
	// R-12：算法非法即不落链（fail-safe 保链完整）
	if _, herr := e.hashWithErr(); herr != nil {
		log.Printf("[audit] 事件哈希算法非法，拒绝落链: %v", herr)
		return e, herr
	}
	// 写 WORM 后端（若有）
	var writeErr error
	if c.worm != nil {
		if werr := c.worm.Append(e); werr != nil {
			writeErr = werr
			log.Printf("[audit] WORM 写入失败（审计完整性受损）: %v", werr)
			policy := "fail_open"
			if c.failClosed {
				policy = "fail_closed"
			}
			if c.onWormWriteFail != nil {
				c.onWormWriteFail(policy) // M-7 唯一计数点
			}
		}
	}
	// fail-closed：写失败且开启 failClosed → 不落入内存链（保持链一致），返回 error
	if writeErr != nil && c.failClosed {
		if c.onFailClosedReject != nil {
			c.onFailClosedReject() // M-8 唯一计数点
		}
		return e, fmt.Errorf("audit: WORM 写入失败，fail-closed 拒绝: %w", writeErr)
	}
	// 正常路径（或 fail-open 下写失败仍落内存链）
	c.events = append(c.events, e)
	c.lastHex = e.hash()
	return e, nil
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
		// imprint 随档（§5.2.2「imprint 哈希随 profile 分派」）；`TST.Algorithm` 即版本标签
		imprint, ierr := hashByAlg(hashAlgTag(), []byte(rec.ChainHash))
		if ierr != nil {
			log.Printf("[audit] TST imprint 算法非法（锚定中止）: %v", ierr)
			return nil
		}
		tst, err := c.tsa.Sign(imprint)
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
	// 校验 TST 内 imprint 与锚定哈希一致（防锚定记录被替换）。
	// imprint 算法由令牌自述 `algorithm` 分派（§5.2.2 判定口径：**仅** `=="sm3"` 判 SM3；
	// 空/其它值一律按 SHA-256，fail-safe 防伪造字段绕过）。
	alg := ""
	if rec.TST.Algorithm == "sm3" {
		alg = "sm3"
	}
	want, werr := hashHexByAlg(alg, []byte(rec.ChainHash))
	if werr != nil || rec.TST.MessageImprint != want {
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
