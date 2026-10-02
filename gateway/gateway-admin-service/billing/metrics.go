package billing

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ---------- 计费域指标（T10，§9.1） ----------
//
// 零外部依赖手写注册表（对齐 admin-service 既有 metrics.go 风格）。
// 全部指标为 conditional（billing.enabled=true 且事件触发后才出现样本）——
// 关闭时渲染为空，不影响既有 /metrics 输出（R-1/M10）。

// metricKind 指标类型。
type metricKind int

const (
	kindCounter metricKind = iota
	kindGauge
	kindHistogram
)

// metricSeries 单个标签组合的序列值。
type metricSeries struct {
	labels map[string]string
	value  float64            // counter/gauge
	sum    float64            // histogram
	count  uint64             // histogram
	bucket map[float64]uint64 // histogram（上界 → 累计计数）
}

// metricFamily 同名指标族。
type metricFamily struct {
	name    string
	help    string
	kind    metricKind
	buckets []float64 // histogram 桶上界
	series  map[string]*metricSeries
}

// Registry 指标注册表（并发安全）。
type Registry struct {
	mu          sync.Mutex
	families    map[string]*metricFamily
	order       []string
	histBuckets map[string][]float64 // 指标名 → 自定义直方图桶（未登记 = defaultBuckets）
}

// NewRegistry 构造空注册表。
func NewRegistry() *Registry {
	return &Registry{families: map[string]*metricFamily{}, histBuckets: map[string][]float64{}}
}

// DefaultMetrics 计费域默认注册表（进程级单例；供 /metrics 渲染）。
var DefaultMetrics = NewRegistry()

func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(labels[k])
	}
	return sb.String()
}

func (r *Registry) family(name, help string, kind metricKind, buckets []float64) *metricFamily {
	f := r.families[name]
	if f == nil {
		f = &metricFamily{name: name, help: help, kind: kind, buckets: buckets, series: map[string]*metricSeries{}}
		r.families[name] = f
		r.order = append(r.order, name)
	}
	return f
}

// IncCounter 计数器 +v。
func (r *Registry) IncCounter(name string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.family(name, "", kindCounter, nil)
	s := f.series[labelKey(labels)]
	if s == nil {
		s = &metricSeries{labels: labels}
		f.series[labelKey(labels)] = s
	}
	s.value += v
}

// SetGauge 设置 gauge 值。
func (r *Registry) SetGauge(name string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.family(name, "", kindGauge, nil)
	s := f.series[labelKey(labels)]
	if s == nil {
		s = &metricSeries{labels: labels}
		f.series[labelKey(labels)] = s
	}
	s.value = v
}

// defaultBuckets 默认直方图桶（秒）。
var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// RegisterHistogram 为指定直方图登记**自定义桶**（SLA 跨度显著大于默认上限者，如 M6 配额热生效 ≤60s）。
//
// ⚠️ 必须在**首次观测前**调用：样本按桶边界累计，事后改桶会使历史计数与新边界不一致。
// 空名/空切片 = no-op。登记后，对该指标名的 `ObserveHistogram` 一律使用自定义桶。
func (r *Registry) RegisterHistogram(name string, buckets []float64) {
	if name == "" || len(buckets) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := append([]float64(nil), buckets...)
	r.histBuckets[name] = cp
	if f := r.families[name]; f != nil {
		f.buckets = cp // 兼容"先观测后登记"（不推荐，见上）
	}
}

// histogramBuckets 某直方图应使用的桶（自定义优先，否则默认）。调用方须持 r.mu。
func (r *Registry) histogramBuckets(name string) []float64 {
	if b, ok := r.histBuckets[name]; ok {
		return b
	}
	return defaultBuckets
}

// ObserveHistogram 记录一个观测值。
func (r *Registry) ObserveHistogram(name string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.family(name, "", kindHistogram, r.histogramBuckets(name))
	key := labelKey(labels)
	s := f.series[key]
	if s == nil {
		s = &metricSeries{labels: labels, bucket: map[float64]uint64{}}
		f.series[key] = s
	}
	s.sum += v
	s.count++
	for _, b := range f.buckets {
		if v <= b {
			s.bucket[b]++
		}
	}
}

// Render 渲染 Prometheus 文本格式（无 HELP 时省略 # HELP 行）。
func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range r.order {
		f := r.families[name]
		if len(f.series) == 0 {
			continue
		}
		typeStr := "counter"
		switch f.kind {
		case kindGauge:
			typeStr = "gauge"
		case kindHistogram:
			typeStr = "histogram"
		}
		if f.help != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", f.name, f.help)
		}
		fmt.Fprintf(w, "# TYPE %s %s\n", f.name, typeStr)
		keys := make([]string, 0, len(f.series))
		for k := range f.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := f.series[k]
			switch f.kind {
			case kindHistogram:
				var cum uint64
				for _, b := range f.buckets {
					cum = s.bucket[b]
					fmt.Fprintf(w, "%s_bucket{%s} %d\n", f.name, mergeLabels(s.labels, "le", fmt.Sprintf("%g", b)), cum)
				}
				fmt.Fprintf(w, "%s_bucket{%s} %d\n", f.name, mergeLabels(s.labels, "le", "+Inf"), s.count)
				fmt.Fprintf(w, "%s_sum%s %g\n", f.name, renderLabels(s.labels), s.sum)
				fmt.Fprintf(w, "%s_count%s %d\n", f.name, renderLabels(s.labels), s.count)
			default:
				fmt.Fprintf(w, "%s%s %g\n", f.name, renderLabels(s.labels), s.value)
			}
		}
	}
}

func renderLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, labels[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func mergeLabels(labels map[string]string, k, v string) string {
	m := make(map[string]string, len(labels)+1)
	for kk, vv := range labels {
		m[kk] = vv
	}
	m[k] = v
	keys := make([]string, 0, len(m))
	for kk := range m {
		keys = append(keys, kk)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, kk := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", kk, m[kk]))
	}
	return strings.Join(parts, ",")
}

// RenderMetrics 渲染默认注册表（供 /metrics 追加）。
func RenderMetrics(w io.Writer) { DefaultMetrics.Render(w) }

// ---------- 生产者辅助（§9.1.1 唯一生产者） ----------

// IncLedgerEntries 账本入账条目数（#2）。
func IncLedgerEntries(n int) { DefaultMetrics.IncCounter("gateway_admin_billing_ledger_entries_total", nil, float64(n)) }

// SetLedgerHeadSeq 账本链尾序号（#3）。
func SetLedgerHeadSeq(seq uint64) {
	DefaultMetrics.SetGauge("gateway_admin_billing_ledger_head_seq", nil, float64(seq))
}

// SetChainBroken 链断裂标志（#4；S-6 Verify 结果）。
// 同时置进程内标志，供出账门禁读取（S-6「断裂 → 停出账」，fail-closed）。
func SetChainBroken(broken bool) {
	v := 0.0
	if broken {
		v = 1
	}
	DefaultMetrics.SetGauge("gateway_admin_billing_ledger_chain_broken", nil, v)
	chainBrokenFlag.Store(broken)
}

// chainBrokenFlag 链断裂进程内标志（S-6 → CloseDaily/CloseMonthly 门禁）。
var chainBrokenFlag atomic.Bool

// ChainBroken 返回链断裂标志（真 = 停止出账，fail-closed）。
func ChainBroken() bool { return chainBrokenFlag.Load() }

// SetAuditChainBroken 置 tee-infer **审计链**断裂标志（REC-6/B-6.12-4）。
//
// 独立的进程内标志：审计链断裂视为 L2 不可信 → **全局**停出账（所有租户）。
// 与账本链（`SetChainBroken`，指标 #4）是**两条不同的链**，互不覆盖；本标志暂无专用
// 指标/告警（§9.1 未定义），仅日志留证（如需告警可后续单批补指标）。
func SetAuditChainBroken(broken bool) { auditChainBrokenFlag.Store(broken) }

// auditChainBrokenFlag 审计链断裂进程内标志（REC-6 → 出账门禁）。
var auditChainBrokenFlag atomic.Bool

// AuditChainBroken 返回审计链断裂标志（真 = 全局停出账，fail-closed）。
func AuditChainBroken() bool { return auditChainBrokenFlag.Load() }

// IncPull 拉取轮次（#5；result=ok|error）。
func IncPull(result string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_pull_total", map[string]string{"result": result}, 1)
}

// IncPush 推送消费（#6；result=ok|frozen|error|unknown_result）。
func IncPush(result string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_push_total", map[string]string{"result": result}, 1)
}

// IncClockSkew 时钟回拨（#17）。
func IncClockSkew() { DefaultMetrics.IncCounter("gateway_admin_billing_clock_skew_total", nil, 1) }

// IncLedgerError 账本写错误（#23；op=begin|append）。
func IncLedgerError(op string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_ledger_error_total", map[string]string{"op": op}, 1)
}

// ObserveClose 出账耗时（#7；kind=daily|monthly）。
func ObserveClose(kind string, seconds float64) {
	DefaultMetrics.ObserveHistogram("gateway_admin_billing_close_duration_seconds", map[string]string{"kind": kind}, seconds)
}

// ObserveQuotaApply 配额热生效时延（#13，M6，单位秒；§6.4.1）。
// 计时区间＝**套餐变更受理 → 回读确认**（`confirmQuotaApplied`），非 POST 2xx。
func ObserveQuotaApply(seconds float64) {
	DefaultMetrics.ObserveHistogram("gateway_admin_billing_quota_apply_duration_seconds", nil, seconds)
}

// RegisterHistogramBuckets 为默认注册表中的直方图登记自定义桶（须在首次观测前；§9.1）。
func RegisterHistogramBuckets(name string, buckets []float64) {
	DefaultMetrics.RegisterHistogram(name, buckets)
}

// quotaApplyBuckets M6 配额热生效时延桶（秒）：SLA ≤ 60s，跨 3 个数量级——
// 默认桶上限 10s 会使 >10s 的观测全部落 +Inf，无法分位刻画 M6（故需自定义桶）。
var quotaApplyBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45, 60, 90, 180}

// closeBuckets M3/M4 出账耗时桶（秒）：日结预算 20min（1200s）、月结预算 60min（3600s）。
//
// 末尾 1800/3600/7200 的作用：**阈值必须严格落在某桶区间内**——若阈值恰为最高有限桶上界
// （如 3600），`histogram_quantile` 最大只能取到该上界，`> 3600` **永不成立**；故在预算之上
// 各留一档（1800 高于日预算、7200 高于月预算），使 p95 > 1200 / > 3600 可判定。
var closeBuckets = []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200}

func init() {
	RegisterHistogramBuckets("gateway_admin_billing_quota_apply_duration_seconds", quotaApplyBuckets)
	RegisterHistogramBuckets("gateway_admin_billing_close_duration_seconds", closeBuckets)
}

// IncBillIssued 出账计数（#8；kind=daily|monthly|overage）。
func IncBillIssued(kind string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_bill_issued_total", map[string]string{"kind": kind}, 1)
}

// SetReconcileDiff 对账差异率（#11）。
func SetReconcileDiff(tenant string, ratio float64) {
	DefaultMetrics.SetGauge("gateway_admin_billing_reconcile_diff", map[string]string{"tenant": tenant}, ratio)
}

// IncAnomaly 异常计数（#10；kind/severity）。
func IncAnomaly(kind, severity string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_anomaly_total",
		map[string]string{"kind": kind, "severity": severity}, 1)
}

// SetQuotaRemainingRatio 配额剩余比（#12；tenant）。唯一生产者 = S-5 扫描（§6.9.1 ③）。
func SetQuotaRemainingRatio(tenant string, ratio float64) {
	DefaultMetrics.SetGauge("gateway_admin_billing_quota_remaining_ratio",
		map[string]string{"tenant": tenant}, ratio)
}

// IncFreeze 冻结计数（#14）。
func IncFreeze() { DefaultMetrics.IncCounter("gateway_admin_billing_freeze_total", nil, 1) }

// SetFrozen 租户冻结状态（#24；1=冻结 / 0=解冻）。
// 生产者：FreezeController.Freeze/Unfreeze（状态变更即置）＋ AnomalyDetector.SyncFrozenGauge（重启后回填）。
func SetFrozen(tenant string, frozen bool) {
	v := 0.0
	if frozen {
		v = 1
	}
	DefaultMetrics.SetGauge("gateway_admin_billing_frozen", map[string]string{"tenant": tenant}, v)
}

// IncExport 导出计数（#15；format/result）。
func IncExport(format, result string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_export_total",
		map[string]string{"format": format, "result": result}, 1)
}

// IncSignatureVerify 验签结果（#16；result=valid|invalid）。
func IncSignatureVerify(result string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_signature_verify_total",
		map[string]string{"result": result}, 1)
}

// IncPricingMissing 缺单价（#18；model_key）。
func IncPricingMissing(modelKey string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_pricing_missing_total",
		map[string]string{"model_key": modelKey}, 1)
}

// SetPlatformRetryTokens 平台 retry token（#19；tenant）。
func SetPlatformRetryTokens(tenant string, tokens int64) {
	DefaultMetrics.SetGauge("gateway_admin_billing_platform_retry_tokens",
		map[string]string{"tenant": tenant}, float64(tokens))
}

// IncAutoRepull 自动回补重拉（#20）。
func IncAutoRepull() { DefaultMetrics.IncCounter("gateway_admin_billing_auto_repull_total", nil, 1) }

// IncPlanExpiring 套餐到期提醒（#21；days=30|7|0）。
func IncPlanExpiring(days int) {
	DefaultMetrics.IncCounter("gateway_admin_billing_plan_expiring_total",
		map[string]string{"days": fmt.Sprintf("%d", days)}, 1)
}

// IncAssocVerify 关联校验结果（#22；result=pass|fail）。
func IncAssocVerify(result string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_assoc_verify_total",
		map[string]string{"result": result}, 1)
}

// IncBillingRequests 计费 API 请求（#1；method/code）。
func IncBillingRequests(method, code string) {
	DefaultMetrics.IncCounter("gateway_admin_billing_requests_total",
		map[string]string{"method": method, "code": code}, 1)
}

// ObserveAPI 查询 API 耗时（#9；route）。
func ObserveAPI(route string, seconds float64) {
	DefaultMetrics.ObserveHistogram("gateway_admin_billing_api_duration_seconds",
		map[string]string{"route": route}, seconds)
}
