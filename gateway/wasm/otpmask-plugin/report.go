package main

// report.go — P1-7 T2b（§6.5 / D-2 / D-13）：数据面未达 TEE 流量上报通道（插件侧）。
//
// 复用 rpm-shadow-plugin 的成熟队列范式（有界队列 + tick 批量投递 + 失败重入队 +
// 溢出丢弃计数），但投递目标为 tee-infer 的 POST /audit/report（逐笔请求事件），
// 并按 D-13 组装请求体签名（X-Audit-Report-Sig）与 timestamp_ns。
//
// 签名求值位置（R-11 对齐，2026-10-19 修订）：**经 cryptop sidecar `/v1/hmac`**
// （`symmetricHMAC`；密钥字节恒驻 sidecar，C-5），插件侧零密码——原实现直算 HMAC
// 违反 §9.1「Wasm 内无密码运算」（wasm-guard ①a），已迁移。sidecar 不可用 ⇒
// **不签名不投递**（批次重入队等下个 tick，fail-closed，A3-14 可见）。
// 部署约束：`audit_report_token` 须为 **32 字节**（签名密钥 = 令牌 UTF-8 字节，hex 登记
// `otpmask/audit-sign/v1`；cryptop R-16 对称键长校验；部署件 cryptopsvc-sidecar-patch.yaml）。
//
// 设计要点：
//   - **有界队列**（缺省 32，§6.5 队列三要素）：溢出**丢弃并计数**（otpmask_audit_report_dropped_total）；
//   - 投递失败 → 重新入队（下个 tick 重试），连续失败超阈值仍丢弃并计数；
//   - 请求 body 仅组装元数据（不传 body），签名防篡改；
//   - **不阻塞请求主路径**：入队在请求路径、HTTP 投递只在 tick；
//   - 仅当 audit_report_token 配置时启用（缺省关闭，零行为变化，符合插件惯例）。
//
// 触发点（D-15，仅两类）：数据面缓存命中（result=cache_hit_dataplane）、
// 非推理请求（result=non_infer）。具体信号见 onHttpRequestHeaders / onHttpResponseHeaders 的接线处。

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// defaultAuditReportQueueMax 上报队列缺省容量（§6.5 队列三要素，与 rpm-shadow 对齐）。
const defaultAuditReportQueueMax = 32

// auditInfoLog / auditWarnLog 日志宿（默认直连 proxywasm）；经包级变量收口，单测可覆写以断言调用。
//
// 修复（G-5）：原实现 `auditInfof`/`auditWarnf` 在守卫放行分支内**调用自身**（自递归，
// 无终止条件）——生产态（`metricsHostGuard=false`）触达即无限递归栈溢出。此处改为直连
// `proxywasm.LogInfof/LogWarnf`。
var (
	auditInfoLog = func(format string, args ...interface{}) { proxywasm.LogInfof(format, args...) }
	auditWarnLog = func(format string, args ...interface{}) { proxywasm.LogWarnf(format, args...) }
)

// auditInfof / auditWarnf 上报通道日志（host 单测下 no-op，防 proxywasm hostcall panic；
// 复用 metrics.go 的 metricsHostGuard 作为"非 Wasm 运行态"守卫）。
func auditInfof(format string, args ...interface{}) {
	if metricsHostGuard {
		return
	}
	auditInfoLog(format, args...)
}

func auditWarnf(format string, args ...interface{}) {
	if metricsHostGuard {
		return
	}
	auditWarnLog(format, args...)
}

// auditReportTimeoutMs 单次上报 HTTP 超时（与 rpm-shadow-plugin reportTimeoutMs 同法：无类型常量，
// 供 cli.Post 形参 uint32 隐式转换）。
const auditReportTimeoutMs = 2000

// auditReportCacheHitHeader / auditReportCacheHitValue 缓存命中信号（Envoy response-cache
// 默认注入 X-Cache: HIT）。⚠️ 须结合目标集群实测确认信号头/值（T2b 验收＝本地集群留证）。
const (
	auditReportCacheHitHeader = "X-Cache"
	auditReportCacheHitValue  = "HIT"
)

// inferencePaths 视作"推理请求"的路径集合（到达 TEE，不按 non_infer 上报）。
// 其余流经插件的路径按 non_infer 上报。⚠️ 若网关另有非推理 API（如管理/健康检查），
// 其路径未在此集合内即会被上报为 non_infer——符合 D-15「非推理请求」语义。
var inferencePaths = map[string]bool{
	"/v1/infer":     true,
	"/infer":        true,
	"/v1/recompute": true,
	"/embed":        true,
}

// auditReportItemDTO 单条上报（字段与 tee-infer /audit/report 的 auditReportItem 对齐）。
type auditReportItemDTO struct {
	RequestID   string `json:"request_id"`
	TenantID    string `json:"tenant_id,omitempty"`
	Path        string `json:"path,omitempty"`
	PathMode    string `json:"path_mode,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	Result      string `json:"result"`
	HitPolicies string `json:"hit_policies,omitempty"`
	TimestampNS int64  `json:"timestamp_ns,omitempty"`
	DurMS       int    `json:"dur_ms,omitempty"`
	Model       string `json:"model,omitempty"`
}

// auditReportPayload 上报请求体。
type auditReportPayload struct {
	Reports []auditReportItemDTO `json:"reports"`
}

// auditReportQueue 有界 FIFO 上报队列（与 rpm-shadow-plugin reportQueue 同构）。
type auditReportQueue struct {
	mu    sync.Mutex
	items []auditReportItemDTO
	max   int
}

func newAuditReportQueue(max int) *auditReportQueue {
	if max <= 0 {
		max = defaultAuditReportQueueMax
	}
	return &auditReportQueue{max: max}
}

// push 入队（溢出丢弃并计 dropped）；返回本次丢弃条数（便于单测核 A3-14 计数）。
func (q *auditReportQueue) push(items []auditReportItemDTO) int {
	if len(items) == 0 {
		return 0
	}
	q.mu.Lock()
	dropped := 0
	for _, it := range items {
		if len(q.items) >= q.max {
			dropped++
			continue
		}
		q.items = append(q.items, it)
	}
	q.mu.Unlock()
	metricAuditReportDropped.add(uint64(dropped))
	if dropped > 0 {
		auditWarnf("otpmask-plugin: 审计上报队列溢出，丢弃 %d 条（链上可能缺报，A3-14）", dropped)
	}
	return dropped
}

// takeAll 取出全部待上报并清空队列。
func (q *auditReportQueue) takeAll() []auditReportItemDTO {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	out := q.items
	q.items = nil
	return out
}

// length 当前队列长度（测试/诊断用）。
func (q *auditReportQueue) length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// auditReportRuntime 上报通道运行态（tick 函数读取，parseConfig 写入）。
type auditReportRuntime struct {
	token   string
	signRef string // 上报签名 KeyRef（D-13；HMAC 求值经 cryptop sidecar，R-11）
	teeSvc  string
	teePort int64
}

var (
	auditReportQ   *auditReportQueue // nil = 通道未启用
	auditReportCfg auditReportRuntime
	auditReportMu  sync.Mutex
)

// requeueAuditReports 失败重投（下个 tick 重试）；通道已被热更新关闭（queue=nil）时丢弃（不 panic）。
func requeueAuditReports(items []auditReportItemDTO) {
	if auditReportQ == nil {
		return
	}
	auditReportQ.push(items)
}

// enqueueDataPlaneReport 将一条数据面未达 TEE 事件入队（请求路径调用，非阻塞）。
// 通道未启用（auditReportQ==nil）时静默 no-op（零行为变化）。
func enqueueDataPlaneReport(item auditReportItemDTO) {
	if auditReportQ == nil {
		return
	}
	if item.TimestampNS == 0 {
		item.TimestampNS = time.Now().UnixNano()
	}
	auditReportQ.push([]auditReportItemDTO{item})
}

// sendAuditReports 批量投递（**仅 tick 调用**，不在请求路径）。
// 流程：组装 body → 经 cryptop sidecar 求签（R-11）→ POST；任一步失败重入队重试。
func sendAuditReports(items []auditReportItemDTO) {
	if len(items) == 0 {
		return
	}
	cfg := auditReportCfg
	payload := auditReportPayload{Reports: items}
	body, err := json.Marshal(payload)
	if err != nil {
		metricAuditReportFail.add(uint64(len(items)))
		requeueAuditReports(items) // 编码失败仍重入队（极端情况）
		auditWarnf("otpmask-plugin: 审计上报编码失败（重新入队）: %v", err)
		return
	}
	// R-11（插件零密码）：请求体签名求值经 cryptop sidecar（/v1/hmac）；
	// sidecar 不可用 ⇒ 不签名不投递（fail-closed，重入队等下个 tick）。
	symmetricHMAC(cfg.signRef, body, func(mac []byte, herr error) {
		if herr != nil {
			metricAuditReportFail.add(uint64(len(items)))
			requeueAuditReports(items)
			auditWarnf("otpmask-plugin: 审计上报签名不可用（重新入队；R-11/C-4）: %v", herr)
			return
		}
		postAuditReport(cfg, items, body, hex.EncodeToString(mac))
	})
}

// postAuditReport 投递已签名批次（自签名回调进入；失败重入队）。
func postAuditReport(cfg auditReportRuntime, items []auditReportItemDTO, body []byte, sig string) {
	headers := [][2]string{
		{"Content-Type", "application/json"},
		{"X-Admin-Token", cfg.token},
		{"X-Audit-Report-Sig", sig},
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: cfg.teeSvc, Port: cfg.teePort})
	err := cli.Post("/audit/report", headers, body,
		func(statusCode int, _ http.Header, respBody []byte) {
			if statusCode == http.StatusOK {
				metricAuditReportSent.add(uint64(len(items)))
				return
			}
			metricAuditReportFail.add(uint64(len(items)))
			requeueAuditReports(items) // 失败重投（request_id 确定性 ⇒ tee-infer 幂等去重，不会重复落链）
			auditWarnf("otpmask-plugin: 审计上报返回 %d（已重新入队，body=%s）",
				statusCode, truncateReport(string(respBody), 120))
		}, auditReportTimeoutMs)
	if err != nil {
		metricAuditReportFail.add(uint64(len(items)))
		requeueAuditReports(items)
		auditWarnf("otpmask-plugin: 审计上报触发失败（已重新入队）: %v", err)
	}
}

// onAuditReportFlushTick 取出全部并批量投递（tick 触发）。
func onAuditReportFlushTick() {
	if auditReportQ == nil {
		return
	}
	sendAuditReports(auditReportQ.takeAll())
}

// initAuditReportChannel 配置审计上报通道（仅当 token 配置时）。parseConfig 每次
// OnPluginStart/热更新调用（须重新注册 tick，不可 sync.Once，见 routefetch.go 注释）。
func initAuditReportChannel(cfg PluginConfig) {
	if cfg.AuditReportToken == "" {
		// 未配置 → 关闭通道（防御性：热更新移除令牌时也清零）。
		auditReportMu.Lock()
		auditReportQ = nil
		auditReportMu.Unlock()
		return
	}
	flushMs := cfg.AuditReportFlushMs
	if flushMs <= 0 {
		flushMs = 1000 // 缺省 1s
	}
	teeSvc := cfg.TEEService
	if teeSvc == "" {
		teeSvc = "tee-infer.higress-system.svc.cluster.local"
	}
	teePort := cfg.TEEPort
	if teePort == 0 {
		teePort = 19090
	}
	auditReportMu.Lock()
	auditReportCfg = auditReportRuntime{token: cfg.AuditReportToken, signRef: auditReportSignKeyRef(cfg), teeSvc: teeSvc, teePort: teePort}
	auditReportQ = newAuditReportQueue(int(cfg.AuditReportQueueMax))
	auditReportMu.Unlock()
	wrapper.RegisterTickFunc(flushMs, onAuditReportFlushTick)
	auditInfof("otpmask-plugin: 审计上报通道已启用 → %s:%d（flush_ms=%d queue_max=%d）",
		teeSvc, teePort, flushMs, cfg.AuditReportQueueMax)
}

// truncateReport 截断日志文本（避免超长 body 打爆日志）。
func truncateReport(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s...(len=%d)", s[:n], len(s))
}

// isInferencePath 判定请求路径是否到达 TEE 推理（命中则不按 non_infer 上报）。
func isInferencePath(path string) bool {
	p := strings.Split(path, "?")[0] // 去 query
	if inferencePaths[p] {
		return true
	}
	// MCP 敏感轨（/mcp 前缀）也视为推理类（经 TEE 裁决），不按 non_infer 上报。
	return strings.HasPrefix(p, "/mcp")
}

// 落链 result 枚举（§6.5 冻结全集 6 项中本任务负责的 2 项；T2c 负责 rate_limited/auth_failed/ip_blocked）。
const (
	resultCacheHitDataPlane = "cache_hit_dataplane" // 数据面缓存命中（→ miss）
	resultNonInfer          = "non_infer"           // 非推理请求（→ miss）
)

// isCacheHitResponse 读取响应头判定数据面缓存命中（Envoy response-cache 默认 X-Cache: HIT）。
// ⚠️ 信号头/值须结合目标集群实测确认（T2b 验收＝本地集群留证）。
func isCacheHitResponse() bool {
	v, err := proxywasm.GetHttpResponseHeader(auditReportCacheHitHeader)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), auditReportCacheHitValue)
}

// reportPath 规范化上报路径（去 query 值，§6.1：path 不含 query）。
func reportPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// pathModeOf 判定路径模式（§6.1：plain／encrypted）。
// 依据：MCP 敏感轨（不透明信封）记为 encrypted；其余（含推理明文入口的元数据）记为 plain。
// ⚠️ 与 T3a 落链侧口径须最终一致（T2b 只做数据面未达 TEE 两类触发点）。
func pathModeOf(path string) string {
	if isSecureMCPPathStr(reportPath(path)) {
		return "encrypted"
	}
	return "plain"
}

// resolveReportRequestID 取得本轮请求 ID（D-15 幂等键）。
// 优先 body 阶段已确证的 pendingRequestID（推理/密态路径已生成）；否则读 Envoy 注入的
// X-Request-Id 头（FD-1 统一型）；再缺则自生成回退（非推理旁路请求无 Envoy ID 时）。
func resolveReportRequestID() string {
	if pendingRequestID != "" {
		return pendingRequestID
	}
	if id, err := proxywasm.GetHttpRequestHeader(hdrRequestID); err == nil && id != "" {
		return id
	}
	return newRequestID()
}

// maybeReportDataPlane 响应头阶段判定"数据面未达 TEE"流量并按 D-15 上报（T2b）。
//
// 仅两类触发点（其余不在本任务范围）：
//   - 数据面缓存命中 → result=cache_hit_dataplane（优先于推理判定：缓存命中即未达 TEE）；
//   - 非推理请求     → result=non_infer。
//
// 推理请求且未命中缓存 ⇒ 已到达 TEE，由 TEE 侧自行落链，此处不重复上报。
// 通道未启用（auditReportQ==nil）⇒ 立即返回，零行为变化；入队不阻塞请求主路径。
func maybeReportDataPlane(ctx wrapper.HttpContext, config PluginConfig) {
	if auditReportQ == nil {
		return
	}
	path, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		path = ""
	}
	var result string
	switch {
	// 触发点①：数据面缓存命中（无论是否推理路径，命中即未达 TEE）。
	case isCacheHitResponse():
		result = resultCacheHitDataPlane
	// 触发点②：非推理请求（路径不在推理集合，未被前序插件短路）。
	case path != "" && !isInferencePath(path):
		result = resultNonInfer
	default:
		return // 推理路径且未命中缓存 → 已到达 TEE，不在此上报
	}
	item := auditReportItemDTO{
		RequestID:   resolveReportRequestID(),
		TenantID:    tenantHeaderValue(ctx),
		Path:        reportPath(path),
		PathMode:    pathModeOf(path),
		HTTPStatus:  atoiSafe(respStatusCached(ctx)),
		Result:      result,
		TimestampNS: time.Now().UnixNano(),
		Model:       config.Model,
	}
	enqueueDataPlaneReport(item)
	auditInfof("otpmask-plugin: 数据面未达 TEE 上报入队 result=%s path=%q req=%s",
		result, item.Path, item.RequestID)
}

// atoiSafe 解析十进制整数；失败返回 0（omitempty 即不写该字段）。
func atoiSafe(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
