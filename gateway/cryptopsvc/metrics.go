// Package cryptopsvc —— cryptop sidecar 可观测性（P0-4 §10.1）。
//
// 手写 Prometheus 文本格式（零外部依赖，对齐本仓库既有约定：tee-infer-service/metrics.go）。
// 指标名与标签与生产 prometheus/client_golang 方案保持一致，后续替换时无需改动仪表板。
//
// 本文件承载 **source=cryptop** 的指标（§10.1）：
//
//	#1 cryptop_ops_total{op,profile}           运算计数（唯一生产者 = dispatch）
//	#2 cryptop_op_duration_seconds{op}         运算延迟（handler 出口 observe，直方图）
//	#3 cryptop_errors_total{op,code}           按 §4.4 错误码
//	#4 cryptop_call_timeout_total              R-3 超时（sidecar HTTP 中间件）
//	#6 cryptop_key_refs{scope}                 活跃 KeyRef 数（KeyStore.Register/Destroy）
//	#7 cryptop_key_rotations_total{scope}      轮换（**仅 scope∈{session,static}**；tenant_master 归 tee）
//	#8 cryptop_key_destroy_total{scope}        销毁（**仅 scope∈{session,static}**；tenant_master 归 tee）
//	#9 cryptop_profile_info{profile,meets_mpy,compliance_note,active}  P4 如实标注（gauge=1；
//	    **多序列**：每个出现过的 profile 一条序列，active="true" 者为**真实生效档位**——
//	    degrade 时配置档（sm-module）与生效档（sm-software）各占一条，绝不复用同一序列
//    表达两个档位（P1-5 §6.4 R-S3-3 / R-28，2026-10-12 多序列化）
//	#11 cryptop_mask_stream_values_total       /v1/mask/stream 累计元素
//	#15 cryptop_compat_mode{feature}           兼容/桥接模式（mask_prg=bridge → 1）
//
// 跨源指标（#7/#8 的 tenant_master 行、#10、#15 的 tee 行）由其它进程发射，见 §10.1.1/§10.3。
package cryptopsvc

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/cryptop/keystore"
)

// metrics sidecar 指标集合（按标签维度 map 累加，线程安全）。
// 同时实现 keystore.Metrics（AddKeyRefs/IncRotations/IncDestroys）。
type metrics struct {
	mu        sync.Mutex
	ops       map[string]int64 // op|profile（#1）
	durations map[string]*histogram // op（#2）
	errors    map[string]int64 // op|code（#3）
	timeouts  int64            // #4
	keyRefs   map[string]int64 // scope（#6；可为负 delta）
	rotations map[string]int64 // scope（#7）
	destroys  map[string]int64 // scope（#8）
	maskVals  int64            // #11
	compat    map[string]int64 // feature（#15：0/1）

	// profiles #9 多序列（key=profile；R-28 2026-10-12 由单值扩展）。
	// 每个被 setProfileInfo 登记过的 profile 一条序列；active=true 为真实生效档位。
	profiles map[string]profileReg
}

// profileReg #9 单条序列的登记内容（R-S3-3：档位声明与生效状态分离表达）。
type profileReg struct {
	meetsMPY       bool
	complianceNote string
	active         bool // true = 当前真实生效档位（degrade 时随生效档迁移）
}

func newMetrics() *metrics {
	return &metrics{
		ops:       map[string]int64{},
		durations: map[string]*histogram{},
		errors:    map[string]int64{},
		keyRefs:   map[string]int64{},
		rotations: map[string]int64{},
		destroys:  map[string]int64{},
		compat:    map[string]int64{},
		profiles:  map[string]profileReg{},
	}
}

// ---- 生产者（唯一发射点，见 §10.1.1）----

// incOp #1 生产语句：dispatch 入口。
func (m *metrics) incOp(op, profile string) {
	m.mu.Lock()
	m.ops[op+"|"+profile]++
	m.mu.Unlock()
}

// observeOp #2 生产语句：handler 出口 defer。
func (m *metrics) observeOp(op string, sec float64) {
	m.mu.Lock()
	h := m.durations[op]
	if h == nil {
		h = newHistogram(opDurationBuckets)
		m.durations[op] = h
	}
	h.observe(sec)
	m.mu.Unlock()
}

// incError #3 生产语句：§4.4 错误码返回点。
func (m *metrics) incError(op, code string) {
	m.mu.Lock()
	m.errors[op+"|"+code]++
	m.mu.Unlock()
}

// incTimeout #4 生产语句：HTTP 中间件超时分支。
func (m *metrics) incTimeout() {
	m.mu.Lock()
	m.timeouts++
	m.mu.Unlock()
}

// AddKeyRefs #6 生产语句：KeyStore.Register/Destroy（keystore.Metrics 接口）。
func (m *metrics) AddKeyRefs(scope keystore.KeyScope, delta int) {
	m.mu.Lock()
	m.keyRefs[string(scope)] += int64(delta)
	m.mu.Unlock()
}

// IncRotations #7 生产语句：KeyManager.Rotate（仅 session/static）。
func (m *metrics) IncRotations(scope keystore.KeyScope) {
	m.mu.Lock()
	m.rotations[string(scope)]++
	m.mu.Unlock()
}

// IncDestroys #8 生产语句：KeyManager.Destroy（仅 session/static）。
func (m *metrics) IncDestroys(scope keystore.KeyScope) {
	m.mu.Lock()
	m.destroys[string(scope)]++
	m.mu.Unlock()
}

// addMaskValues #11 生产语句：/v1/mask/stream handler。
func (m *metrics) addMaskValues(n int) {
	m.mu.Lock()
	m.maskVals += int64(n)
	m.mu.Unlock()
}

// setCompatMode #15 生产语句：NewServer 配置加载（mask_prg==bridge → 1，否则 0）。
func (m *metrics) setCompatMode(feature string, on bool) {
	m.mu.Lock()
	if on {
		m.compat[feature] = 1
	} else {
		m.compat[feature] = 0
	}
	m.mu.Unlock()
}

// setProfileInfo #9 生产语句：NewServer（R-28 多序列化，2026-10-12）。
//
// 语义：登记并**激活** p 的 profile 序列；其余已登记序列一律降为 active=false——
// 配置档（如 sm-module）与生效档（degrade 后的 sm-software）因此各占一条序列，
// 满足 R-S3-3「不得用同一序列同时表达 sm-module 与 sm-software」。
// degrade 路径在 provider 实际切换后再次调用本方法即可（生效档迁移，配置档保留可见）。
func (m *metrics) setProfileInfo(p cryptop.Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.profiles == nil {
		m.profiles = map[string]profileReg{}
	}
	for k, r := range m.profiles {
		if r.active {
			r.active = false
			m.profiles[k] = r
		}
	}
	name := string(p.Profile())
	m.profiles[name] = profileReg{
		meetsMPY:       p.Profile().MeetsMPY(),
		complianceNote: p.ComplianceNote(),
		active:         true,
	}
}

// ---- 渲染 ----

// opDurationBuckets 运算延迟桶（秒）：0.0001/0.0005/0.001/0.005/0.01/0.05/0.1/0.5。
// 覆盖 §4.5-④ 预算（单次 ≈0.2–0.5ms、6 次 ≈1.2–3ms、P99 ≤ 10ms）。
var opDurationBuckets = []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5}

// render 输出 Prometheus 文本格式（§10.1 source=cryptop 段）。
func (m *metrics) render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	writeCounter(w, "cryptop_ops_total", "密码运算计数（按 op 与 profile）", m.ops, []string{"op", "profile"})
	// #2 直方图：逐 op 输出（标签 op）。
	if len(m.durations) > 0 {
		ops := make([]string, 0, len(m.durations))
		for op := range m.durations {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			writeHistogram(w, "cryptop_op_duration_seconds", "密码运算延迟（秒，按 op）", m.durations[op], fmt.Sprintf("op=%q", op))
		}
	}
	writeCounter(w, "cryptop_errors_total", "密码运算错误计数（按 op 与 §4.4 错误码）", m.errors, []string{"op", "code"})
	writeCounterInt(w, "cryptop_call_timeout_total", "R-3 单次调用超时计数（sidecar 中间件）", m.timeouts)
	writeGaugeMap(w, "cryptop_key_refs", "活跃 KeyRef 数（按 scope；内存泄漏观测）", m.keyRefs, []string{"scope"})
	writeCounter(w, "cryptop_key_rotations_total", "密钥轮换计数（按 scope；tenant_master 由 tee 发射）", m.rotations, []string{"scope"})
	writeCounter(w, "cryptop_key_destroy_total", "密钥销毁计数（按 scope；tenant_master 由 tee 发射）", m.destroys, []string{"scope"})
	// #9 profile 如实标注（多序列 gauge=1；active="true" 为真实生效档位，R-28/R-S3-3）。
	if len(m.profiles) > 0 {
		names := make([]string, 0, len(m.profiles))
		for name := range m.profiles {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(w, "# HELP cryptop_profile_info 当前 profile 合规标注（gauge=1，P4 如实标注；active=true 为真实生效档位）\n# TYPE cryptop_profile_info gauge\n")
		for _, name := range names {
			r := m.profiles[name]
			fmt.Fprintf(w, "cryptop_profile_info{profile=%q,meets_mpy=%q,compliance_note=%q,active=%q} 1\n",
				name, boolStr(r.meetsMPY), r.complianceNote, boolStr(r.active))
		}
	}
	writeCounterInt(w, "cryptop_mask_stream_values_total", "/v1/mask/stream 累计下发掩码元素数（容量观测）", m.maskVals)
	writeGaugeMap(w, "cryptop_compat_mode", "兼容/桥接模式开启标志（feature=mask_bridge；1=on/0=off）", m.compat, []string{"feature"})
}

// ---- 渲染辅助（自足，零外部依赖）----

type histogram struct {
	upperBounds []float64
	buckets     []int64
	sum         float64
	count       int64
}

func newHistogram(upperBounds []float64) *histogram {
	return &histogram{upperBounds: upperBounds, buckets: make([]int64, len(upperBounds))}
}

func (h *histogram) observe(v float64) {
	h.count++
	h.sum += v
	for i, b := range h.upperBounds {
		if v <= b {
			h.buckets[i]++
			return
		}
	}
}

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
		fmt.Fprintf(w, "%s{%s} %d\n", name, labelPairs(labels, strings.Split(k, "|")), data[k])
	}
}

// writeGaugeMap 输出带标签的 gauge（值可为负）。
func writeGaugeMap(w io.Writer, name, help string, data map[string]int64, labels []string) {
	if len(data) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s} %d\n", name, labelPairs(labels, strings.Split(k, "|")), data[k])
	}
}

// writeGaugeInt 输出无标签 gauge（恒输出，供门禁判"已注册"）。
func writeGaugeInt(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	fmt.Fprintf(w, "%s %d\n", name, v)
}

// writeCounterInt 输出无标签 counter（恒输出，供门禁判"已注册"）。
func writeCounterInt(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	fmt.Fprintf(w, "%s %d\n", name, v)
}

func writeHistogram(w io.Writer, name, help string, h *histogram, extraLabels string) {
	if h == nil || h.count == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	cum := int64(0)
	for i, b := range h.upperBounds {
		cum += h.buckets[i]
		labels := fmt.Sprintf(`le=%q`, fmt.Sprintf("%g", b))
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
	// _sum/_count 须与 _bucket 同标签集（否则 Prometheus 视为同名异标签族）。
	if extraLabels != "" {
		fmt.Fprintf(w, "%s_sum{%s} %g\n", name, extraLabels, h.sum)
		fmt.Fprintf(w, "%s_count{%s} %d\n", name, extraLabels, h.count)
	} else {
		fmt.Fprintf(w, "%s_sum %g\n", name, h.sum)
		fmt.Fprintf(w, "%s_count %d\n", name, h.count)
	}
}

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

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
