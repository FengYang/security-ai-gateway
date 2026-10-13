// Package main — 可观测性指标。
//
// 用标准库手写 Prometheus 文本格式暴露 /metrics（零外部依赖），
// 指标名与标签与生产 prometheus/client_golang 方案保持一致，
// 后续替换 client_golang 时无需改动仪表板。
//
// 指标族：
// otpmask_inference_requests_total{tenant,result}  推理请求计数（ok/deny 结果）
// otpmask_tokens_in_total{tenant}                  输入 token（向量数）计数
// otpmask_tokens_out_total{tenant}                 输出 token 计数
// otpmask_denies_total{tenant,reason}              拒绝计数（bad_signature/replay/guardrail_* 等）
// otpmask_quota_denies_total{tenant,window}        配额拒绝计数（按触发维度归因：minute|day|total，B 项）
// otpmask_shadow_reports_total{result}             数据面明文影子窗口级上报计数（accepted/deduped/rejected，A 项）
// otpmask_guard_classifier_total{backend,result}   语义分类器调用（ok=侧车判定可用 / degraded=侧车不可用，已按 fail-closed 拒答）
// otpmask_key_issue_total{tenant}                  密钥签发计数
// otpmask_reconcile_mismatch_total{reason}         审计-计量对账不一致次数（按差异分类，S5）
// otpmask_shadow_would_reject_total{tenant,rule}   影子命中计数（只计数不拒绝，S5 判据 4）
// otpmask_reconcile_diff_tokens{reason}            对账偏差 token 量级累计（按差异分类，S5）
// otpmask_billing_blocked_total{reason}            对外出账阻断置位次数（按差异分类，S5）
// otpmask_billing_suppressed_total{reason}         被阻断抑制的计费推送事件数（S5）
// otpmask_billing_blocked                          对外出账是否被阻断（gauge 0/1，S5）
// otpmask_reconcile_last_run_timestamp_seconds     最近一次对账时刻（gauge，S5）
// otpmask_audit_events                             审计链当前长度（gauge）
//
// 跨源指标（P0-4 §10.1 #7/#8；与 cryptop sidecar 同名异进程，见 §10.3）：
// cryptop_key_rotations_total{scope="tenant_master"}  二级租户主密钥轮换（TenantKeyManager.RotateTenant）
// cryptop_key_destroy_total{scope="tenant_master"}    二级租户主密钥销毁（TenantKeyManager.DestroyTenant）
package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// otpmaskMetrics 指标集合（按标签维度 map 累加，线程安全）。
type otpmaskMetrics struct {
	mu              sync.Mutex
	requests        map[string]int64 // tenant|result
	tokensIn        map[string]int64 // tenant
	tokensOut       map[string]int64 // tenant
	denies          map[string]int64 // tenant|reason
	keyIssues       map[string]int64 // tenant
	reconcile       map[string]int64 // reason（对账不一致次数，S5 起按差异分类）
	tokenTraffic    map[string]int64 // tenant
	recomputeOps    map[string]int64 // op（补算调用计数）
	recomputeDur    map[string]int64 // op（补算耗时累计，毫秒）
	guardClassifier map[string]int64 // backend|result（语义分类器调用）
	// 侧车不可用已按 fail-closed 拒答的计数（backend|reason；2026-09-26）。
	guardFailClosed map[string]int64
	// 输入侧侧车健康状态 gauge（未配置侧车时不输出该指标；2026-09-26）。
	guardSidecarConfigured bool
	guardSidecarHealthy    int64
	// 审计/日志留存期声明（gauge；0=未声明）。声明式，服务不删除审计数据。
	auditRetentionDays int
	// S5（判据 6）对账/出账阻断可观测
	reconcileDiff     map[string]int64 // reason（偏差 token 量级累计）
	reconcileLastRun  int64            // gauge：上次对账时刻（UTC 秒）
	billingBlocked    int64            // gauge 0/1：对外出账是否被阻断
	billingBlockCount map[string]int64 // reason（阻断置位次数）
	billingSuppressed map[string]int64 // reason（被阻断抑制的推送事件数）
	// S5（判据 4）：影子 would_reject 计数（tenant|rule）
	shadowWouldReject map[string]int64
	// B 项：配额拒绝按触发维度归因（tenant|window，window=minute|day|total）
	quotaDenies map[string]int64
	// A 项：数据面明文影子窗口级上报计数（result=accepted|deduped|rejected）
	shadowReports map[string]int64
	// GA-输出侧内容审查（OG-3 M1 骨架；§4.10 唯一目录）
	// X-2：核心 counter 增加 field 标签（低基数：text / tool_input），用于 T6 三字段覆盖归因
	ogRequests         map[string]int64 // mode|field（审查过的请求数）
	ogL1Hit            map[string]int64 // category|field（L1 规则层命中）
	ogWouldReject      map[string]int64 // category|field（shadow 命中=本该拦截）
	ogForcedSplit      map[string]int64 // reason（缓冲强切：max_unit|first_unit，OG-4）
	ogUnmapped         map[string]int64 // backend|category_raw（后端类目未映射，M2）
	ogBlocked          map[string]int64 // category|mode|field（命中且动作=block，enforcing）
	ogMasked           map[string]int64 // category|field（命中且动作=mask/rewrite）
	ogFirstChunkSkipL2 int64            // S3-2 策略 C：首段安全后跳过 L2 的请求数（gauge）
	// P1-8 安全加固（M-7/M-8，source=tee）：审计 WORM 写入失败与 fail-closed 拒绝
	wormWriteFail          map[string]int64 // policy（fail_closed|fail_open）：M-7 otpmask_worm_write_failed_total
	auditFailClosedReject  int64            // M-8 otpmask_audit_failclosed_rejected_total
	// ---- P1-7 全流量审计改造（T7，MOD5 容量管控；附加指标族，既有族不变，C-9）----
	// 字节量（gauge，单调递增；每次 WORM 写入累加事件字节数）。
	auditBytes int64
	// 各层记录数（gauge，按 tier=hot|warm|cold）。
	auditRecordsTier map[string]int64
	// 读取/导出侧降采样计数（counter，仅未命中事件）。
	auditSampled int64
	// WORM 写失败计数（counter；挂既有 SetWriteFailureHook，onWriteFail 路径）。
	auditWriteFailures int64
	// 归档失败计数（counter）。
	auditArchiveFailures int64
	// 归档去重（三元组）计数（counter）。
	auditDuplicateRequests int64
	// 脱敏截断计数（counter；T4 超长字段截断）。
	auditRedactTruncated int64
	// 数据面上报队列丢弃计数（counter，reason=queue_full|send_failed|invalid|replay_failed，A3-14）。
	auditReportDropped map[string]int64
	// TEE 侧非登记 result 取值计数（counter，A3-20/R-17；不改链、不拒落链，仅登记告警）。
	auditUnregisteredResult int64
	// C 类豁免出口计数（counter，handler|reason；T3b §7.3③：豁免项以聚合指标计数而非逐条落链）。
	auditExemptExit map[string]int64
	ogCanaryProbe      int64            // P0-3 策略 C：canary 探测句走完整 L2 的次数
	ogCanaryReattach   int64            // P0-3 策略 C：canary 命中底线触发回挂的次数
	ogPolicyRollback   map[string]int64 // reason（策略热加载回退事件）
	// S1-4（G21）：策略版本库显式引用/回滚事件（action|result|reason）。
	ogPolicyActivate  map[string]int64
	ogDegraded        map[string]int64 // backend|reason（后端降级事件，M2）
	ogInflightBytes   int64            // gauge：在飞缓冲字节数（M1）
	ogLatencyMs       *histogram       // 单请求审查总延迟（手写桶，M1）
	ogFirstFrameDelay *histogram       // 首帧延迟增量（M2）
	ogMode            string           // gauge：当前运行模式（off|shadow|enforcing）
	ogPolicyVersion   string           // gauge：当前生效策略版本
	// L2 级联相关（M3 骨架；指标名与标签预定义，零值不可见属正常）
	ogL2Call           map[string]int64 // category|result（L2 调用次数，M3）
	ogL2OnlyHit        map[string]int64 // category（L1未命中+L2命中=L2专属贡献，M3）
	ogBufferFull       int64            // counter：队列溢出/超并发容量阀触发次数（M3）
	ogBufferQueueDepth int64            // gauge：等待L2结果的句队列深度（M3）
	ogL2DurationSec    *histogram       // L2 单句调用延迟（秒，手写桶，M3）
	// M3 OG-13：派生 gauge 的分子/分母（不单独暴露指标；§4.10 只有两个派生 gauge）。
	ogSentences      int64 // 判定句总数（l2_cascade_ratio / failclosed_sentences_ratio 分母）
	ogFailclosedSent int64 // 按 P-DEGRADE（fail-closed）处置的句数
	ogL2CallsStarted int64 // 已发起的 L2 调用数（含 L1 命中后的画像调用）
	// S2-6：输出侧审查重启检测（gauge 0/1；对账器检测到审计链早于启动时刻事件时置 1）
	ogRestartDetected int64
	// B1 强标标识（GB 45438-2025）：enabled gauge（required 常驻）+ 请求/标识帧计数（conditional）。
	contentLabelEnabled  int64            // gauge 0/1：当前是否启用强标标识
	contentLabelRequests int64            // counter：启用标识的请求数（conditional）
	contentLabelFrames   map[string]int64 // position（head|repeat|tail；conditional）
	// P0-4 §10.1 #7/#8 跨源行（scope 固定 tenant_master，由 teecore TenantKeyManager 驱动）。
	tenantKeyRotations int64
	tenantKeyDestroys  int64
	// P0-4 §10.1 双读计数：用非主 profile 套件成功解封 enclave 密封数据（含旧格式回退）。
	enclaveDualReads int64
	// P0-4 §10.1 #15 跨源兼容模式：当前 mask_prg 是否 bridge（0/1 gauge）。
	cryptopCompatMode map[string]int64
	// P0-2 §9.1 #20：TTFT 首帧时延（histogram，按 mode|cache=hit|miss；M4）
	ttftMu sync.Mutex
	ttft   map[string]*histogram
	// T-7：MCP 敏感轨方法调用计数（按 mcp_method：server/discover|tools/list|tools/call）。
	// 口径＝调用计数，不含 token 计费（P0-3 边界）；懒注册（无调用则无样本，故清单标 conditional）。
	mcpMethod map[string]int64
}

func newMetrics() *otpmaskMetrics {
	return &otpmaskMetrics{
		requests:           make(map[string]int64),
		tokensIn:           make(map[string]int64),
		tokensOut:          make(map[string]int64),
		denies:             make(map[string]int64),
		keyIssues:          make(map[string]int64),
		reconcile:          make(map[string]int64),
		tokenTraffic:       make(map[string]int64),
		recomputeOps:       make(map[string]int64),
		recomputeDur:       make(map[string]int64),
		guardClassifier:    make(map[string]int64),
		guardFailClosed:    make(map[string]int64),
		reconcileDiff:      make(map[string]int64),
		billingBlockCount:  make(map[string]int64),
		billingSuppressed:  make(map[string]int64),
		shadowWouldReject:  make(map[string]int64),
		quotaDenies:        make(map[string]int64),
		shadowReports:      make(map[string]int64),
		ogRequests:         make(map[string]int64),
		ogL1Hit:            make(map[string]int64),
		ogWouldReject:      make(map[string]int64),
		ogForcedSplit:      make(map[string]int64),
		ogUnmapped:         make(map[string]int64),
		ogBlocked:          make(map[string]int64),
		ogMasked:           make(map[string]int64),
		ogPolicyRollback:   make(map[string]int64),
		ogPolicyActivate:   make(map[string]int64),
		ogDegraded:         make(map[string]int64),
		ogLatencyMs:        newHistogram(latencyMsBuckets),
		ogFirstFrameDelay:  newHistogram(firstFrameDelayBuckets),
		ttft:               make(map[string]*histogram),
		ogL2Call:           make(map[string]int64),
		ogL2OnlyHit:        make(map[string]int64),
		ogL2DurationSec:    newHistogram(l2DurationSecBuckets),
		contentLabelFrames: make(map[string]int64),
		cryptopCompatMode:  make(map[string]int64),
		mcpMethod:          make(map[string]int64),
		// P1-7 容量管控指标
		auditRecordsTier:   make(map[string]int64),
		auditReportDropped: make(map[string]int64),
		// P1-7 T3b：C 类豁免出口计数
		auditExemptExit: make(map[string]int64),
	}
}

// setOutputGuardMode 记录当前输出侧审查模式与策略版本（启动时一次；供 mode/policy_version gauge）。
// 同时为 requests_total 预置当前模式的零值序列——保证 required 指标始终有样本（门禁 #9
// 要求：来源可达时 required 指标必须存在；零样本会使其缺失而误判为失败，§4.10 零样本可见性）。
func (m *otpmaskMetrics) setOutputGuardMode(mode, version string) {
	m.mu.Lock()
	m.ogMode = mode
	m.ogPolicyVersion = version
	// 零值预置：保证 field=text 默认组合有样本（required 指标可观测性）
	key := mode + "|text"
	if _, ok := m.ogRequests[key]; !ok {
		m.ogRequests[key] = 0
	}
	m.mu.Unlock()
}

// setOGRestartDetected 输出侧审查重启检测 gauge 置位（S2-6）。
// 对账器检测到审计链含早于本进程启动时刻的事件时调用，置 1；进程重启后天然归零。
func (m *otpmaskMetrics) setOGRestartDetected(v int64) {
	m.mu.Lock()
	m.ogRestartDetected = v
	m.mu.Unlock()
}

// incOGRequest 记录一次被输出侧审查的请求（按模式与字段）。
// X-2：field 标签（text / tool_input）用于 T6 三字段覆盖归因。
func (m *otpmaskMetrics) incOGRequest(mode, field string) {
	m.mu.Lock()
	m.ogRequests[mode+"|"+field]++
	m.mu.Unlock()
}

// incMCPMethod 记录一次 MCP 敏感轨方法调用（按 mcp_method：server/discover|tools/list|tools/call）。
// T-7：口径＝调用计数（不含 token 计费）。
func (m *otpmaskMetrics) incMCPMethod(method string) {
	if method == "" {
		return
	}
	m.mu.Lock()
	m.mcpMethod[method]++
	m.mu.Unlock()
}

// incWormWriteFail 记录一次 WORM 写入失败（M-7，policy=fail_closed|fail_open）。
func (m *otpmaskMetrics) incWormWriteFail(policy string) {
	if policy == "" {
		return
	}
	m.mu.Lock()
	if m.wormWriteFail == nil {
		m.wormWriteFail = make(map[string]int64)
	}
	m.wormWriteFail[policy]++
	m.mu.Unlock()
}

// incAuditFailClosedReject 记录一次因审计写失败触发 fail-closed 拒绝（M-8）。
func (m *otpmaskMetrics) incAuditFailClosedReject() {
	m.mu.Lock()
	m.auditFailClosedReject++
	m.mu.Unlock()
}

// ---- P1-7 全流量审计改造（T7，MOD5 容量管控；附加指标族）----

// incAuditBytes 累加已写入 WORM 的审计字节数（gauge，单调递增）。
func (m *otpmaskMetrics) incAuditBytes(n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.auditBytes += n
	m.mu.Unlock()
}

// incAuditRecordsTier 记录某层记录数（gauge，tier=hot|warm|cold）。
func (m *otpmaskMetrics) incAuditRecordsTier(tier string, n int64) {
	if tier == "" {
		tier = "hot"
	}
	m.mu.Lock()
	m.auditRecordsTier[tier] += n
	m.mu.Unlock()
}

// incAuditSampled 记录一次读取/导出侧降采样（仅未命中事件）。
func (m *otpmaskMetrics) incAuditSampled() {
	m.mu.Lock()
	m.auditSampled++
	m.mu.Unlock()
}

// incAuditWriteFailure 记录一次 WORM 写失败（挂 SetWriteFailureHook）。
func (m *otpmaskMetrics) incAuditWriteFailure() {
	m.mu.Lock()
	m.auditWriteFailures++
	m.mu.Unlock()
}

// incAuditArchiveFailure 记录一次归档失败。
func (m *otpmaskMetrics) incAuditArchiveFailure() {
	m.mu.Lock()
	m.auditArchiveFailures++
	m.mu.Unlock()
}

// incAuditDuplicateRequest 记录一次归档去重（三元组 (instance_id,request_id,action)）。
func (m *otpmaskMetrics) incAuditDuplicateRequest() {
	m.mu.Lock()
	m.auditDuplicateRequests++
	m.mu.Unlock()
}

// incAuditRedactTruncated 记录一次脱敏截断（T4，超长字段）。
func (m *otpmaskMetrics) incAuditRedactTruncated() {
	m.mu.Lock()
	m.auditRedactTruncated++
	m.mu.Unlock()
}

// incAuditReportDropped 记录一次数据面上报队列丢弃（reason=queue_full|send_failed|invalid|replay_failed）。
func (m *otpmaskMetrics) incAuditReportDropped(reason string) {
	if reason == "" {
		reason = "invalid"
	}
	m.mu.Lock()
	m.auditReportDropped[reason]++
	m.mu.Unlock()
}

// incAuditUnregisteredResult 记录一次 TEE 侧非登记 result 取值（A3-20/R-17）。
func (m *otpmaskMetrics) incAuditUnregisteredResult() {
	m.mu.Lock()
	m.auditUnregisteredResult++
	m.mu.Unlock()
}

// incAuditExemptExit 记录一次 C 类豁免出口（T3b §7.3③；handler|reason）。
// 豁免项不逐条落链，只以聚合指标计数，保证"出口 100% 登记"可被观测。
func (m *otpmaskMetrics) incAuditExemptExit(handler, reason string) {
	if handler == "" {
		return
	}
	if reason == "" {
		reason = "exempt"
	}
	m.mu.Lock()
	m.auditExemptExit[handler+"|"+reason]++
	m.mu.Unlock()
}

// setContentLabelEnabled 记录强标标识开关（B1 gauge；启动与热切换时调用，required 常驻）。
func (m *otpmaskMetrics) setContentLabelEnabled(enabled bool) {
	m.mu.Lock()
	if enabled {
		m.contentLabelEnabled = 1
	} else {
		m.contentLabelEnabled = 0
	}
	m.mu.Unlock()
}

// incContentLabelRequest 记录一次启用强标标识的请求（B1 conditional counter）。
func (m *otpmaskMetrics) incContentLabelRequest() {
	m.mu.Lock()
	m.contentLabelRequests++
	m.mu.Unlock()
}

// incContentLabelFrame 记录一帧强标标识（B1 conditional counter，按位置：head|repeat|tail）。
func (m *otpmaskMetrics) incContentLabelFrame(position string) {
	m.mu.Lock()
	m.contentLabelFrames[position]++
	m.mu.Unlock()
}

// incOGL1Hit 记录一次 L1 规则层命中（分类目与字段）。
// X-2：field 标签（text / tool_input）。
func (m *otpmaskMetrics) incOGL1Hit(category, field string) {
	m.mu.Lock()
	m.ogL1Hit[category+"|"+field]++
	m.mu.Unlock()
}

// incOGWouldReject 记录一次 shadow 命中（本该拦截；分类目与字段）。
// X-2：field 标签（text / tool_input）。
func (m *otpmaskMetrics) incOGWouldReject(category, field string) {
	m.mu.Lock()
	m.ogWouldReject[category+"|"+field]++
	m.mu.Unlock()
}

// incOGForcedSplit 记录一次缓冲强切（OG-4；reason=max_unit|first_unit，§4.3.1）。
func (m *otpmaskMetrics) incOGForcedSplit(reason string) {
	m.mu.Lock()
	m.ogForcedSplit[reason]++
	m.mu.Unlock()
}

// incOGUnmapped 记录一次后端类目未映射（M2；P-DEGRADE 诊断指标）。
// label 格式：backend|category_raw（与指标定义一致）。
func (m *otpmaskMetrics) incOGUnmapped(backend, rawCat string) {
	m.mu.Lock()
	m.ogUnmapped[backend+"|"+rawCat]++
	m.mu.Unlock()
}

// incShadowWouldReject 记录影子命中（判据 4：只计数不拒绝；rule = rpm|tpm|daily_budget）。
func (m *otpmaskMetrics) incShadowWouldReject(tenant, rule string) {
	m.mu.Lock()
	m.shadowWouldReject[tenant+"|"+rule]++
	m.mu.Unlock()
}

// incGuardClassifier 记录语义分类器调用结果（GF.4.3）。
// result=ok：侧车判定可用；result=degraded：侧车不可用，**已按 fail-closed 拒答**
// （2026-09-26 收口：不再回退关键词规则；须可观测、可告警）。
func (m *otpmaskMetrics) incGuardClassifier(backend, result string) {
	m.mu.Lock()
	m.guardClassifier[backend+"|"+result]++
	m.mu.Unlock()
}

// incGuardFailClosed 记录一次"侧车不可用 → fail-closed 拒答"（按后端与归因）。
func (m *otpmaskMetrics) incGuardFailClosed(backend, reason string) {
	m.mu.Lock()
	m.guardFailClosed[backend+"|"+reason]++
	m.mu.Unlock()
}

// setGuardSidecarHealthy 更新输入侧语义分类器侧车健康状态（"侧车故障→readiness 摘流"
// 必须可被指标观测，否则运维只能靠日志推断）。
func (m *otpmaskMetrics) setGuardSidecarHealthy(healthy bool) {
	m.mu.Lock()
	m.guardSidecarConfigured = true
	if healthy {
		m.guardSidecarHealthy = 1
	} else {
		m.guardSidecarHealthy = 0
	}
	m.mu.Unlock()
}

// incReconcileMismatch 记录一次对账不一致（reason = 差异分类）及其偏差量级（token）。
// S5 起该计数器语义为"对账不一致次数"（此前为偏差累加，标签值固定 "mismatch"）。
func (m *otpmaskMetrics) incReconcileMismatch(reason string, diffTokens int64) {
	m.mu.Lock()
	m.reconcile[reason]++
	m.reconcileDiff[reason] += diffTokens
	m.mu.Unlock()
}

// setReconcileRun 记录最近一次对账时刻（UTC 纳秒 → 秒）与出账阻断状态。
func (m *otpmaskMetrics) setReconcileRun(runAtUnixNano int64, blocked bool) {
	m.mu.Lock()
	m.reconcileLastRun = runAtUnixNano / 1e9
	if blocked {
		m.billingBlocked = 1
	} else {
		m.billingBlocked = 0
	}
	m.mu.Unlock()
}

// setBillingBlocked 记录对外出账阻断状态翻转（blocked=true 时按 reason 计数）。
func (m *otpmaskMetrics) setBillingBlocked(reason string, blocked bool) {
	m.mu.Lock()
	if blocked {
		m.billingBlockCount[reason]++
		m.billingBlocked = 1
	} else {
		m.billingBlocked = 0
	}
	m.mu.Unlock()
}

// incBillingSuppressed 记录因对账不一致被抑制的计费推送事件数（按差异分类）。
func (m *otpmaskMetrics) incBillingSuppressed(reason string) {
	m.mu.Lock()
	m.billingSuppressed[reason]++
	m.mu.Unlock()
}

// incAttestTokenTraffic 记录 token 模式流量。
func (m *otpmaskMetrics) incAttestTokenTraffic(tenant string) {
	m.mu.Lock()
	m.tokenTraffic[tenant]++
	m.mu.Unlock()
}

// incRecompute 记录补算调用计数与耗时（毫秒累计）。
func (m *otpmaskMetrics) incRecompute(op string, durationMs int64) {
	m.mu.Lock()
	m.recomputeOps[op]++
	m.recomputeDur[op] += durationMs
	m.mu.Unlock()
}

func (m *otpmaskMetrics) incRequest(tenant, result string) {
	m.mu.Lock()
	m.requests[tenant+"|"+result]++
	m.mu.Unlock()
}

func (m *otpmaskMetrics) addTokens(tenant string, in, out int64) {
	m.mu.Lock()
	m.tokensIn[tenant] += in
	m.tokensOut[tenant] += out
	m.mu.Unlock()
}

func (m *otpmaskMetrics) incDeny(tenant, reason string) {
	m.mu.Lock()
	m.denies[tenant+"|"+reason]++
	m.mu.Unlock()
}

// incQuotaDeny 记录一次配额拒绝并归因到触发维度（B 项：window = minute|day，"" 归一为 total
// ＝累计维度，避免空标签值在面板/告警里不可读）。
func (m *otpmaskMetrics) incQuotaDeny(tenant, window string) {
	if window == "" {
		window = "total"
	}
	m.mu.Lock()
	m.quotaDenies[tenant+"|"+window]++
	m.mu.Unlock()
}

// incShadowReport 记录窗口级影子上报的处理结果（A 项：result = accepted|deduped|rejected）。
// n<=0 不计数（避免无意义样本）。
func (m *otpmaskMetrics) incShadowReport(result string, n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.shadowReports[result] += n
	m.mu.Unlock()
}

func (m *otpmaskMetrics) incKeyIssue(tenant string) {
	m.mu.Lock()
	m.keyIssues[tenant]++
	m.mu.Unlock()
}

// IncTenantRotation 实现 teecore.TenantMetrics：#7 scope=tenant_master 轮换计数。
func (m *otpmaskMetrics) IncTenantRotation() {
	m.mu.Lock()
	m.tenantKeyRotations++
	m.mu.Unlock()
}

// IncTenantDestroy 实现 teecore.TenantMetrics：#8 scope=tenant_master 销毁计数。
func (m *otpmaskMetrics) IncTenantDestroy() {
	m.mu.Lock()
	m.tenantKeyDestroys++
	m.mu.Unlock()
}

// IncEnclaveDualRead 记录一次 enclave 双读（用非主 profile 套件 / 旧格式回退成功解封）。
func (m *otpmaskMetrics) IncEnclaveDualRead() {
	m.mu.Lock()
	m.enclaveDualReads++
	m.mu.Unlock()
}

// SetCryptopCompatMode 设置兼容/桥接模式标志（#15；与 sidecar 同名指标异进程发射）。
func (m *otpmaskMetrics) SetCryptopCompatMode(feature string, on bool) {
	m.mu.Lock()
	if on {
		m.cryptopCompatMode[feature] = 1
	} else {
		m.cryptopCompatMode[feature] = 0
	}
	m.mu.Unlock()
}

// setAuditRetentionDays 落审计留存期声明（gauge；启动期一次）。
func (m *otpmaskMetrics) setAuditRetentionDays(days int) {
	m.mu.Lock()
	m.auditRetentionDays = days
	m.mu.Unlock()
}

// render 输出完整 Prometheus 文本（审计链长度由调用方经 auditEvents 注入）。
func (m *otpmaskMetrics) render(w io.Writer, auditEvents int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writeCounter(w, "otpmask_inference_requests_total", "推理请求计数（按租户与结果）", m.requests, []string{"tenant", "result"})
	writeCounter(w, "otpmask_tokens_in_total", "输入 token 计数（按租户）", m.tokensIn, []string{"tenant"})
	writeCounter(w, "otpmask_tokens_out_total", "输出 token 计数（按租户）", m.tokensOut, []string{"tenant"})
	writeCounter(w, "otpmask_denies_total", "拒绝计数（按租户与原因）", m.denies, []string{"tenant", "reason"})
	writeCounter(w, "otpmask_quota_denies_total", "配额拒绝计数（按租户与触发维度：minute|day|total）", m.quotaDenies, []string{"tenant", "window"})
	writeCounter(w, "otpmask_shadow_reports_total", "数据面明文影子窗口级上报计数（accepted/deduped/rejected）", m.shadowReports, []string{"result"})
	writeCounter(w, "otpmask_guard_classifier_total", "语义分类器调用（ok=侧车判定可用 / degraded=侧车不可用已按 fail-closed 拒答）", m.guardClassifier, []string{"backend", "result"})
	writeCounter(w, "otpmask_guard_failclosed_total", "侧车不可用导致 fail-closed 拒答的次数（按后端与归因：unreachable|timeout|http_status|bad_response）", m.guardFailClosed, []string{"backend", "reason"})
	if m.guardSidecarConfigured {
		fmt.Fprintf(w, "# HELP otpmask_guard_sidecar_healthy 输入侧语义分类器侧车健康（1=健康；0=不健康，实例按 readiness 摘流）\n# TYPE otpmask_guard_sidecar_healthy gauge\n")
		fmt.Fprintf(w, "otpmask_guard_sidecar_healthy %d\n", m.guardSidecarHealthy)
	}
	fmt.Fprintf(w, "# HELP otpmask_audit_retention_days 审计/日志留存期声明值（天；0=未声明）。声明式：服务不删除审计数据（WORM 链完整），删除由存储层生命周期策略按本值执行\n# TYPE otpmask_audit_retention_days gauge\n")
	fmt.Fprintf(w, "otpmask_audit_retention_days %d\n", m.auditRetentionDays)
	// P1-8 M-7/M-8：审计 WORM 写入失败与 fail-closed 拒绝（source=tee）
	writeCounter(w, "otpmask_worm_write_failed_total", "WORM 写入失败次数（policy=fail_closed 表示因写失败触发 fail-closed 拒绝；policy=fail_open 表示仅告警未拒答）", m.wormWriteFail, []string{"policy"})
	if m.auditFailClosedReject > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_failclosed_rejected_total 审计 fail-closed 模式下因 WORM 写入失败拒绝的请求数\n# TYPE otpmask_audit_failclosed_rejected_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_failclosed_rejected_total %d\n", m.auditFailClosedReject)
	}
	// ---- P1-7 全流量审计改造（T7，MOD5 容量管控；附加指标族，既有族不变，C-9）----
	fmt.Fprintf(w, "# HELP otpmask_audit_bytes 审计 WORM 累计写入字节数（gauge，单调递增）\n# TYPE otpmask_audit_bytes gauge\n")
	fmt.Fprintf(w, "otpmask_audit_bytes %d\n", m.auditBytes)
	if len(m.auditRecordsTier) > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_records_tier 各层审计记录数（gauge，tier=hot|warm|cold）\n# TYPE otpmask_audit_records_tier gauge\n")
		for _, tier := range []string{"hot", "warm", "cold"} {
			if v, ok := m.auditRecordsTier[tier]; ok {
				fmt.Fprintf(w, "otpmask_audit_records_tier{tier=%q} %d\n", tier, v)
			}
		}
	}
	if m.auditSampled > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_sampled_total 读取/导出侧降采样事件数（仅未命中事件；配置/策略变更类恒保留）\n# TYPE otpmask_audit_sampled_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_sampled_total %d\n", m.auditSampled)
	}
	if m.auditWriteFailures > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_write_failures_total WORM 写入失败次数（审计完整性受损；挂 SetWriteFailureHook）\n# TYPE otpmask_audit_write_failures_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_write_failures_total %d\n", m.auditWriteFailures)
	}
	if m.auditArchiveFailures > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_archive_failures_total 归档/迁移失败次数\n# TYPE otpmask_audit_archive_failures_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_archive_failures_total %d\n", m.auditArchiveFailures)
	}
	if m.auditDuplicateRequests > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_duplicate_requests_total 归档去重（三元组 instance_id,request_id,action）丢弃的重复事件数\n# TYPE otpmask_audit_duplicate_requests_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_duplicate_requests_total %d\n", m.auditDuplicateRequests)
	}
	if m.auditRedactTruncated > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_redact_truncated_total 脱敏阶段超长字段截断次数（T4；默认上限 1024 字节）\n# TYPE otpmask_audit_redact_truncated_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_redact_truncated_total %d\n", m.auditRedactTruncated)
	}
	writeCounter(w, "otpmask_audit_report_dropped_total", "数据面上报队列丢弃计数（reason=queue_full|send_failed|invalid|replay_failed；A3-14 丢弃率>0 即告警）", m.auditReportDropped, []string{"reason"})
	if m.auditUnregisteredResult > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_unregistered_result_total TEE 侧非登记 result 取值次数（A3-20/R-17；不改链、不拒落链，仅登记告警）\n# TYPE otpmask_audit_unregistered_result_total counter\n")
		fmt.Fprintf(w, "otpmask_audit_unregistered_result_total %d\n", m.auditUnregisteredResult)
	}
	// P1-7 T3b §7.3③：C 类豁免出口计数（豁免项不逐条落链，以聚合指标登记，V-14）。
	writeCounter(w, "otpmask_audit_exempt_exit_total", "C 类豁免出口计数（handler × reason：method_not_allowed|health|common_writer|stream_ok|ok_write；不逐条落链，V-14 登记口径）", m.auditExemptExit, []string{"handler", "reason"})
	writeCounter(w, "otpmask_key_issue_total", "密钥签发计数（按租户）", m.keyIssues, []string{"tenant"})
	writeCounter(w, "otpmask_reconcile_mismatch_total", "审计-计量对账不一致次数（按差异分类）", m.reconcile, []string{"reason"})
	writeCounter(w, "otpmask_shadow_would_reject_total", "影子命中计数（只计数不拒绝；按租户与维度）", m.shadowWouldReject, []string{"tenant", "rule"})
	writeCounter(w, "otpmask_reconcile_diff_tokens", "审计-计量对账偏差 token 量级累计（按差异分类）", m.reconcileDiff, []string{"reason"})
	writeCounter(w, "otpmask_billing_blocked_total", "对外出账阻断置位次数（按差异分类）", m.billingBlockCount, []string{"reason"})
	writeCounter(w, "otpmask_billing_suppressed_total", "因对账不一致被抑制的计费推送事件数（按差异分类）", m.billingSuppressed, []string{"reason"})
	writeCounter(w, "otpmask_attest_token_traffic_total", "token 证明模式流量", m.tokenTraffic, []string{"tenant"})
	writeCounter(w, "otpmask_recompute_ops_total", "补算调用计数（按算子）", m.recomputeOps, []string{"op"})
	writeCounter(w, "otpmask_recompute_duration_ms_total", "补算耗时累计（按算子，毫秒）", m.recomputeDur, []string{"op"})
	// T-7 MCP 敏感轨（source=tee）：按 mcp_method 维度（server/discover|tools/list|tools/call）。
	writeCounter(w, "otpmask_mcp_requests_total", "MCP 敏感轨方法调用计数（按 mcp_method）", m.mcpMethod, []string{"mcp_method"})
	// ---- GA-输出侧内容审查（OG-3 M1 骨架；§4.10 唯一目录）----
	writeCounter(w, "otpmask_output_guard_requests_total", "输出侧内容审查请求计数（按模式与字段）", m.ogRequests, []string{"mode", "field"})
	writeCounter(w, "otpmask_output_guard_l1_hit_total", "L1 规则层命中次数（按类目与字段）", m.ogL1Hit, []string{"category", "field"})
	writeCounter(w, "otpmask_output_guard_would_reject_total", "shadow 模式命中（本该拦截）计数（按类目与字段）", m.ogWouldReject, []string{"category", "field"})
	writeCounter(w, "otpmask_output_guard_blocked_total", "命中且动作=block 的次数（enforcing 生效，按类目、模式与字段）", m.ogBlocked, []string{"category", "mode", "field"})
	writeCounter(w, "otpmask_output_guard_masked_total", "命中且动作=mask/rewrite 的次数（按类目与字段）", m.ogMasked, []string{"category", "field"})
	writeCounter(w, "otpmask_output_guard_forced_split_total", "缓冲强制切分次数（按原因：max_unit|first_unit）", m.ogForcedSplit, []string{"reason"})
	writeCounter(w, "otpmask_output_guard_unmapped_total", "后端返回类目未映射到内部31类的次数（按后端与原生类目）", m.ogUnmapped, []string{"backend", "category_raw"})
	writeCounter(w, "otpmask_output_guard_degraded_total", "后端降级事件次数（按后端与原因）", m.ogDegraded, []string{"backend", "reason"})
	writeCounter(w, "otpmask_output_guard_policy_rollback_total", "策略热加载回退事件次数（按原因）", m.ogPolicyRollback, []string{"reason"})
	// S1-4（G21）：版本库显式引用/回滚结果（reason="-" 表示成功）
	writeCounter(w, "otpmask_output_guard_policy_activate_total", "策略版本库显式引用/回滚事件次数（action=activate|rollback；result=applied|rejected；reason 为拒绝原因枚举）", m.ogPolicyActivate, []string{"action", "result", "reason"})
	// ---- L2 级联相关（M3 骨架；零样本时不输出，属正常）----
	writeCounter(w, "otpmask_output_guard_l2_call_total", "L2 语义层调用次数（按类目与结果：hit/miss/timeout/error）", m.ogL2Call, []string{"category", "result"})
	writeCounter(w, "otpmask_output_guard_l2_only_hit_total", "L1未命中且L2命中的次数（L2专属贡献，按类目）", m.ogL2OnlyHit, []string{"category"})
	// gauge：缓冲队列深度（等待 L2 结果的句数，M3）
	fmt.Fprintf(w, "# HELP otpmask_output_guard_buffer_queue_depth 当前等待L2结果的句队列深度\n# TYPE otpmask_output_guard_buffer_queue_depth gauge\n")
	fmt.Fprintf(w, "otpmask_output_guard_buffer_queue_depth %d\n", m.ogBufferQueueDepth)
	// counter：队列溢出/超并发容量阀触发次数
	fmt.Fprintf(w, "# HELP otpmask_output_guard_buffer_full_total 缓冲队列溢出或超并发容量阀触发次数\n# TYPE otpmask_output_guard_buffer_full_total counter\n")
	fmt.Fprintf(w, "otpmask_output_guard_buffer_full_total %d\n", m.ogBufferFull)
	// counter：判定单元总数（句级降级率告警的分母；P0-1 修复新增）
	if m.ogSentences > 0 {
		fmt.Fprintf(w, "# HELP otpmask_output_guard_sentences_total 判定单元（句/窗）总数\n# TYPE otpmask_output_guard_sentences_total counter\n")
		fmt.Fprintf(w, "otpmask_output_guard_sentences_total %d\n", m.ogSentences)
	}
	// histogram：L2 单句调用延迟（M3 启用后才有样本）
	writeHistogram(w, "otpmask_output_guard_l2_duration_seconds", "L2语义层单句调用延迟（秒）", m.ogL2DurationSec, "")
	// 派生 gauge（M3 OG-13）：分子/分母为进程级累计（§4.10 诊断指标，不设阈值闸门）。
	writeDerivedRatioGauge(w, "otpmask_output_guard_l2_cascade_ratio",
		"L2 调用数 / 总判定句数（级联占比；诊断指标）", m.ogL2CallsStarted, m.ogSentences)
	writeDerivedRatioGauge(w, "otpmask_output_guard_failclosed_sentences_ratio",
		"按 P-DEGRADE 处置的句数 / 总判定句数（容量健康度；诊断指标）", m.ogFailclosedSent, m.ogSentences)
	// gauge：在飞缓冲字节数（M1，与 P-MAX-INFLIGHT-BYTES 配套）
	fmt.Fprintf(w, "# HELP otpmask_output_guard_inflight_bytes 当前在飞缓冲字节总数\n# TYPE otpmask_output_guard_inflight_bytes gauge\n")
	fmt.Fprintf(w, "otpmask_output_guard_inflight_bytes %d\n", m.ogInflightBytes)
	// histogram：单请求审查总延迟（手写桶）
	writeHistogram(w, "otpmask_output_guard_latency_ms", "单请求输出侧审查总延迟（毫秒）", m.ogLatencyMs, "")
	// histogram：首帧延迟增量（M2 启用后才有样本）
	writeHistogram(w, "otpmask_output_guard_first_frame_delay_seconds", "输出侧审查引入的首帧延迟增量（秒）", m.ogFirstFrameDelay, "")
	// P0-2 §9.1 #20：TTFT（mode|cache=hit|miss）
	m.renderTTFT(w)
	if m.ogMode != "" {
		fmt.Fprintf(w, "# HELP otpmask_output_guard_mode 当前输出侧内容审查运行模式（1=当前模式）\n# TYPE otpmask_output_guard_mode gauge\n")
		fmt.Fprintf(w, "otpmask_output_guard_mode{mode=%q} 1\n", m.ogMode)
	}
	if m.ogPolicyVersion != "" {
		fmt.Fprintf(w, "# HELP otpmask_output_guard_policy_version 当前生效的输出侧内容审查策略版本号\n# TYPE otpmask_output_guard_policy_version gauge\n")
		fmt.Fprintf(w, "otpmask_output_guard_policy_version{version=%q} 1\n", m.ogPolicyVersion)
	}
	// S2-6：重启检测 gauge（对账器检测到审计链早于启动时刻事件后置 1；进程重启天然归零）
	fmt.Fprintf(w, "# HELP otpmask_output_guard_restart_detected 输出侧审查进程是否检测到重启（审计链含启动前事件，1=是）\n# TYPE otpmask_output_guard_restart_detected gauge\n")
	fmt.Fprintf(w, "otpmask_output_guard_restart_detected %d\n", m.ogRestartDetected)
	// S3-2 策略 C：首段安全后跳过 L2 的请求数（首段门触发次数，单调递增）
	if m.ogFirstChunkSkipL2 > 0 {
		fmt.Fprintf(w, "# HELP otpmask_output_guard_c_first_chunk_skip_l2_total 策略C首段预审门触发次数（首段安全后跳过L2的请求数）\n# TYPE otpmask_output_guard_c_first_chunk_skip_l2_total counter\n")
		fmt.Fprintf(w, "otpmask_output_guard_c_first_chunk_skip_l2_total %d\n", m.ogFirstChunkSkipL2)
		// P0-3：canary 探测数（有首段门触发才可能产生探测）
		fmt.Fprintf(w, "# HELP otpmask_output_guard_canary_probe_total 策略C首段安全后canary探测句走完整L2的次数\n# TYPE otpmask_output_guard_canary_probe_total counter\n")
		fmt.Fprintf(w, "otpmask_output_guard_canary_probe_total %d\n", m.ogCanaryProbe)
		if m.ogCanaryReattach > 0 {
			fmt.Fprintf(w, "# HELP otpmask_output_guard_canary_reattach_total 策略C canary探测命中12项底线触发回挂（块内补判+恢复全级联）的次数\n# TYPE otpmask_output_guard_canary_reattach_total counter\n")
			fmt.Fprintf(w, "otpmask_output_guard_canary_reattach_total %d\n", m.ogCanaryReattach)
		}
	}
	// ---- B1 强标标识（GB 45438-2025）----
	// enabled gauge 常驻（required，门禁 #9）；请求/标识帧计数 conditional（零样本不输出属正常）。
	fmt.Fprintf(w, "# HELP otpmask_content_label_enabled 强标标识（GB 45438-2025）是否启用\n# TYPE otpmask_content_label_enabled gauge\n")
	fmt.Fprintf(w, "otpmask_content_label_enabled %d\n", m.contentLabelEnabled)
	if m.contentLabelRequests > 0 {
		fmt.Fprintf(w, "# HELP otpmask_content_label_requests_total 启用强标标识的请求计数\n# TYPE otpmask_content_label_requests_total counter\n")
		fmt.Fprintf(w, "otpmask_content_label_requests_total %d\n", m.contentLabelRequests)
	}
	writeCounter(w, "otpmask_content_label_frames_total", "强标标识帧计数（按位置 head|repeat|tail）", m.contentLabelFrames, []string{"position"})
	fmt.Fprintf(w, "# HELP otpmask_billing_blocked 对外出账是否被对账结果阻断（1=阻断）\n# TYPE otpmask_billing_blocked gauge\n")
	fmt.Fprintf(w, "otpmask_billing_blocked %d\n", m.billingBlocked)
	if m.reconcileLastRun > 0 {
		fmt.Fprintf(w, "# HELP otpmask_reconcile_last_run_timestamp_seconds 最近一次审计-计量对账时刻（UTC 秒）\n# TYPE otpmask_reconcile_last_run_timestamp_seconds gauge\n")
		fmt.Fprintf(w, "otpmask_reconcile_last_run_timestamp_seconds %d\n", m.reconcileLastRun)
	}
	if auditEvents > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_events 审计哈希链当前长度\n# TYPE otpmask_audit_events gauge\n")
		fmt.Fprintf(w, "otpmask_audit_events %d\n", auditEvents)
	}
	// ---- P0-4 #7/#8 跨源行（scope 固定 tenant_master；恒输出供注册门禁，见 §10.3）----
	fmt.Fprintf(w, "# HELP cryptop_key_rotations_total 密钥轮换计数（按 scope；本行由 tee 进程发射）\n# TYPE cryptop_key_rotations_total counter\n")
	fmt.Fprintf(w, "cryptop_key_rotations_total{scope=\"tenant_master\"} %d\n", m.tenantKeyRotations)
	fmt.Fprintf(w, "# HELP cryptop_key_destroy_total 密钥销毁计数（按 scope；本行由 tee 进程发射）\n# TYPE cryptop_key_destroy_total counter\n")
	fmt.Fprintf(w, "cryptop_key_destroy_total{scope=\"tenant_master\"} %d\n", m.tenantKeyDestroys)
	// 跨源：cryptop_dualread_total{artifact=enclave}（双读：非主 profile 套件 / 旧格式回退解封成功）
	fmt.Fprintf(w, "# HELP cryptop_dualread_total 双读计数（用非主 profile 算法成功解算 wire/hash/signature）\n# TYPE cryptop_dualread_total counter\n")
	fmt.Fprintf(w, "cryptop_dualread_total{artifact=\"enclave\"} %d\n", m.enclaveDualReads)
	// 跨源：cryptop_compat_mode{feature}（与 sidecar 同名指标异进程发射）
	if len(m.cryptopCompatMode) > 0 {
		fmt.Fprintf(w, "# HELP cryptop_compat_mode 兼容/桥接模式开启标志（feature=mask_bridge；1=on/0=off）\n# TYPE cryptop_compat_mode gauge\n")
		keys := make([]string, 0, len(m.cryptopCompatMode))
		for k := range m.cryptopCompatMode {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "cryptop_compat_mode{feature=%q} %d\n", k, m.cryptopCompatMode[k])
		}
	}
}

// writeCounter 输出一个 counter 指标族（labels 决定标签维度）。
func writeCounter(w io.Writer, name, help string, data map[string]int64, labels []string) {
	if len(data) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s} %d\n", name, labelPairs(labels, splitKey(k)), data[k])
	}
}

// splitKey "a|b|c" → [a b c]（按 | 分割；无分隔符 → [k]）。
func splitKey(k string) []string {
	return strings.Split(k, "|")
}

// labelPairs 生成 `label1="v1",label2="v2"` 片段。
func labelPairs(labels, values []string) string {
	if len(labels) != len(values) {
		return ""
	}
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%s=%q", l, values[i])
	}
	return out
}

// ObserveTTFT 记录一次 TTFT（秒；§9.1 #20 / M4）。
// mode = 缓存运行模式（off|exact|semantic|full）；cache = hit|miss（非 hit 一律归 miss）。
func (m *otpmaskMetrics) ObserveTTFT(mode, cache string, seconds float64) {
	if mode == "" {
		mode = "off"
	}
	if cache != "hit" {
		cache = "miss"
	}
	key := mode + "|" + cache
	m.ttftMu.Lock()
	h := m.ttft[key]
	if h == nil {
		h = newHistogram(ttftBuckets)
		m.ttft[key] = h
	}
	h.observe(seconds)
	m.ttftMu.Unlock()
}

// ttftBuckets TTFT 桶（秒），覆盖缓存命中（毫秒级）到未命中（数十秒）。
var ttftBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30}

// renderTTFT 渲染 TTFT（§9.1 #20）；无样本时不输出。
func (m *otpmaskMetrics) renderTTFT(w io.Writer) {
	m.ttftMu.Lock()
	keys := make([]string, 0, len(m.ttft))
	for k := range m.ttft {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m.ttftMu.Unlock()
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP otpmask_ttft_seconds 首帧时延（秒，按缓存模式与 cache=hit|miss）\n# TYPE otpmask_ttft_seconds histogram\n")
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 2)
		mode, cache := parts[0], "miss"
		if len(parts) == 2 {
			cache = parts[1]
		}
		m.ttftMu.Lock()
		h := m.ttft[k]
		m.ttftMu.Unlock()
		if h == nil {
			continue
		}
		labels := fmt.Sprintf("mode=%q,cache=%q", mode, cache)
		var cum int64
		for i, b := range h.upperBounds {
			cum += h.buckets[i]
			fmt.Fprintf(w, "otpmask_ttft_seconds_bucket{%s,le=\"%g\"} %d\n", labels, b, cum)
		}
		fmt.Fprintf(w, "otpmask_ttft_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, h.count)
		fmt.Fprintf(w, "otpmask_ttft_seconds_sum{%s} %g\n", labels, h.sum)
		fmt.Fprintf(w, "otpmask_ttft_seconds_count{%s} %d\n", labels, h.count)
	}
}

// ---- histogram（手写桶，零依赖）----

// histogram 直方图指标：累积桶计数 + sum + count。
// 桶边界由 upperBounds 定义（严格递增，不含 +Inf；渲染时自动追加 +Inf）。
type histogram struct {
	upperBounds []float64 // 桶上边界（含）
	buckets     []int64   // 各桶累计计数（≤ upperBounds[i] 的样本数）
	sum         float64   // 所有样本值之和
	count       int64     // 样本总数
}

// newHistogram 构造空直方图。
func newHistogram(upperBounds []float64) *histogram {
	return &histogram{upperBounds: upperBounds, buckets: make([]int64, len(upperBounds))}
}

// observe 记录一个样本值。
// 桶计数 =「该桶区间内的样本数」（区间：(prev, curr]；首个桶：(-inf, bound[0]]）。
// 渲染时按累积输出（Prometheus 格式要求）。
func (h *histogram) observe(v float64) {
	h.count++
	h.sum += v
	for i, b := range h.upperBounds {
		if v <= b {
			h.buckets[i]++
			return // 只落入第一个满足的桶（区间分桶，互不重叠）
		}
	}
	// 超过所有桶上界 → 只进 +Inf 桶，不进任何命名桶。
}

// 输出侧审查延迟桶（ms）：1/5/20/50/100/500/1000/5000/+Inf
// 对齐 §4.10：桶选择覆盖 shadow 预期（P99 < 10ms）与 enforcing 最坏（L2 秒级）。
var latencyMsBuckets = []float64{1, 5, 20, 50, 100, 500, 1000, 5000}

// 首帧延迟增量桶（秒）：0.01/0.05/0.1/0.2/0.5/0.8/1.0/2.0/+Inf
// 对齐 §4.5：首帧延迟增量 P50 ≤ 300ms / P99 ≤ 800ms（M3→M4 唯一硬闸门）。
var firstFrameDelayBuckets = []float64{0.01, 0.05, 0.1, 0.2, 0.5, 0.8, 1.0, 2.0}

// L2 单句调用延迟桶（秒）：0.05/0.1/0.2/0.5/1.0/2.0/5.0/10.0/+Inf
// 覆盖 shadow 侧车预期（~500ms）与 enforcing 最坏（秒级），对齐 §4.10 L2 级联指标。
var l2DurationSecBuckets = []float64{0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0}

// writeHistogram 渲染 histogram（Prometheus text 格式；自动追加 +Inf 桶）。
func writeHistogram(w io.Writer, name, help string, h *histogram, extraLabels string) {
	if h == nil || h.count == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	// 按累积输出：bucket_i = Σ_{0..i} buckets[j]
	cum := int64(0)
	for i, b := range h.upperBounds {
		cum += h.buckets[i]
		le := fmt.Sprintf("%g", b)
		labels := `le="` + le + `"`
		if extraLabels != "" {
			labels = extraLabels + "," + labels
		}
		fmt.Fprintf(w, "%s_bucket{%s} %d\n", name, labels, cum)
	}
	labels := `le="+Inf"`
	if extraLabels != "" {
		labels = extraLabels + "," + labels
	}
	fmt.Fprintf(w, "%s_bucket{%s} %d\n", name, labels, h.count)
	fmt.Fprintf(w, "%s_sum %g\n", name, h.sum)
	fmt.Fprintf(w, "%s_count %d\n", name, h.count)
}

// ---- 输出侧新指标方法 ----

// incOGBlocked 记录一次 block 命中（enforcing 模式；category|mode|field）。
// X-2：field 标签（text / tool_input）。
func (m *otpmaskMetrics) incOGBlocked(category, mode, field string) {
	m.mu.Lock()
	m.ogBlocked[category+"|"+mode+"|"+field]++
	m.mu.Unlock()
}

// incOGMasked 记录一次 mask 命中（按类目与字段）。
// X-2：field 标签（text / tool_input）。
func (m *otpmaskMetrics) incOGMasked(category, field string) {
	m.mu.Lock()
	m.ogMasked[category+"|"+field]++
	m.mu.Unlock()
}

// incOGFirstChunkSkipL2 记录一次策略 C 首段安全跳过 L2 的请求。
func (m *otpmaskMetrics) incOGFirstChunkSkipL2() {
	m.mu.Lock()
	m.ogFirstChunkSkipL2++
	m.mu.Unlock()
}

// incOGCanaryProbe 记录一次 canary 探测句走完整 L2。
func (m *otpmaskMetrics) incOGCanaryProbe() {
	m.mu.Lock()
	m.ogCanaryProbe++
	m.mu.Unlock()
}

// incOGCanaryReattach 记录一次 canary 命中底线触发回挂。
func (m *otpmaskMetrics) incOGCanaryReattach() {
	m.mu.Lock()
	m.ogCanaryReattach++
	m.mu.Unlock()
}

// incOGPolicyRollback 记录一次策略热加载回退（按原因）。
func (m *otpmaskMetrics) incOGPolicyRollback(reason string) {
	m.mu.Lock()
	m.ogPolicyRollback[reason]++
	m.mu.Unlock()
}

// incOGPolicyActivate 记录一次策略版本库显式引用/回滚事件（S1-4 / G21）。
// 键＝action|result|reason（reason 为空表示成功，序列化时归为 "-"）。
func (m *otpmaskMetrics) incOGPolicyActivate(action, result, reason string) {
	if reason == "" {
		reason = "-"
	}
	m.mu.Lock()
	m.ogPolicyActivate[action+"|"+result+"|"+reason]++
	m.mu.Unlock()
}

// incOGDegraded 记录一次后端降级事件（M2；P-DEGRADE 诊断）。
func (m *otpmaskMetrics) incOGDegraded(backend, reason string) {
	m.mu.Lock()
	m.ogDegraded[backend+"|"+reason]++
	m.mu.Unlock()
}

// addOGInflightBytes 在飞字节增减（正=增加，负=减少）。
func (m *otpmaskMetrics) addOGInflightBytes(delta int64) {
	m.mu.Lock()
	m.ogInflightBytes += delta
	if m.ogInflightBytes < 0 {
		m.ogInflightBytes = 0 // 防御：不出现负值
	}
	m.mu.Unlock()
}

// observeOGLatencyMs 记录一次单请求审查总延迟（ms）。
func (m *otpmaskMetrics) observeOGLatencyMs(ms float64) {
	m.mu.Lock()
	m.ogLatencyMs.observe(ms)
	m.mu.Unlock()
}

// observeOGFirstFrameDelaySeconds 记录一次首帧延迟增量（秒）。
func (m *otpmaskMetrics) observeOGFirstFrameDelaySeconds(s float64) {
	m.mu.Lock()
	m.ogFirstFrameDelay.observe(s)
	m.mu.Unlock()
}

// ---- L2 级联指标方法（M3 骨架，M3 接入后才会有非零样本）----

// incOGL2Call 记录一次 L2 语义层调用（按类目与结果：hit/miss/timeout/error）。
func (m *otpmaskMetrics) incOGL2Call(category, result string) {
	m.mu.Lock()
	m.ogL2Call[category+"|"+result]++
	m.mu.Unlock()
}

// incOGL2OnlyHit 记录一次 L1 未命中 + L2 命中（L2 专属贡献，评估 L2 增量价值）。
func (m *otpmaskMetrics) incOGL2OnlyHit(category string) {
	m.mu.Lock()
	m.ogL2OnlyHit[category]++
	m.mu.Unlock()
}

// incOGBufferFull 记录一次缓冲队列溢出或超并发容量阀触发。
func (m *otpmaskMetrics) incOGBufferFull() {
	m.mu.Lock()
	m.ogBufferFull++
	m.mu.Unlock()
}

// addOGBufferQueueDepth 聚合调整全进程当前等待 L2 结果的句队列深度（gauge）。
// 各请求级 cascade 以发起 +1 / 收敛 −1 / 关闭按残留差值扣减配对记账；
// 多请求共享同一进程总量（OG-13 缺陷2：原 set 覆写式会被并发请求互相覆盖致失真）。
func (m *otpmaskMetrics) addOGBufferQueueDepth(delta int64) {
	m.mu.Lock()
	m.ogBufferQueueDepth += delta
	if m.ogBufferQueueDepth < 0 {
		m.ogBufferQueueDepth = 0 // 守恒兜底：配对正确时不触发
	}
	m.mu.Unlock()
}

// observeOGL2DurationSeconds 记录一次 L2 单句调用延迟（秒）。
func (m *otpmaskMetrics) observeOGL2DurationSeconds(s float64) {
	m.mu.Lock()
	m.ogL2DurationSec.observe(s)
	m.mu.Unlock()
}

// incOGSentence 记录一次判定句（OG-13 级联；两个派生 gauge 的分母）。
func (m *otpmaskMetrics) incOGSentence() {
	m.mu.Lock()
	m.ogSentences++
	m.mu.Unlock()
}

// incOGFailClosedSentence 记录一次按 P-DEGRADE（fail-closed）处置的句
// （supercapacity/超槽位/超时/L2 失败/类目未映射/置信度缺失；failclosed_sentences_ratio 分子）。
// 注意：M3 shadow 下 fail-closed 只计数与留痕，内容拦截属 M4 enforcing。
func (m *otpmaskMetrics) incOGFailClosedSentence() {
	m.mu.Lock()
	m.ogFailclosedSent++
	m.mu.Unlock()
}

// incOGL2CallStarted 记录一次已发起的 L2 调用（含 L1 命中后的画像调用；l2_cascade_ratio 分子）。
func (m *otpmaskMetrics) incOGL2CallStarted() {
	m.mu.Lock()
	m.ogL2CallsStarted++
	m.mu.Unlock()
}

// writeDerivedRatioGauge 输出派生比值 gauge（分母 0 → 0，避免 NaN；§4.10 诊断用，不设阈值闸门）。
func writeDerivedRatioGauge(w io.Writer, name, help string, num, den int64) {
	v := 0.0
	if den > 0 {
		v = float64(num) / float64(den)
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
}
