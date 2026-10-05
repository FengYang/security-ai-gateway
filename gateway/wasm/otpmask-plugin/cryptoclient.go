package main

// cryptoclient.go —— 把 cryptoclient（传输无关的 CPS 客户端，§4.7）接到 proxy-wasm。
//
// 分层（对齐 §4.7/§5.4.5）：
//   - 核心逻辑（端点/错误码/熔断/批处理）在 gateway/wasm/otpmask-plugin/cryptoclient，
//     **不依赖 hostcall**，可原生单测（§4.7 "或经接口抽象以便单测 mock"）。
//   - 本文件是 proxy-wasm 适配层：
//       wrapperTransport     : 出站经 Envoy cluster（wrapper.ClusterClient，§4.5-①）
//       pluginCryptoMetrics  : 指标 #13/#14（counter）与 #5（gauge）
//       newPluginCryptoClient: 工厂
//
// ⚠️ 调用点接线（把 seal/open/hmac/... 从插件内联改为经本客户端）属 §5.4.5 checklist
// 的"业务调用点全量接线"子任务；本文件先建立**唯一 HTTP 面**的适配缝。

import (
	"sync"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
)

// ---- Transport（出站经 Envoy cluster）----

// wrapperTransport 实现 cryptoclient.Transport。
type wrapperTransport struct {
	fqdn string
	port int64
}

func (t wrapperTransport) Post(path string, headers [][2]string, body []byte, cb cryptoclient.ResponseCallback, timeoutMs uint32) error {
	client := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: t.fqdn, Port: t.port})
	return client.Post(path, headers, body, wrapper.ResponseCallback(cb), timeoutMs)
}

func (t wrapperTransport) Get(path string, headers [][2]string, cb cryptoclient.ResponseCallback, timeoutMs uint32) error {
	client := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: t.fqdn, Port: t.port})
	return client.Get(path, headers, wrapper.ResponseCallback(cb), timeoutMs)
}

// ---- Metrics（#13/#14/#5）----
//
// proxy-wasm Counter/Gauge 不支持自定义标签（见 metrics.go:110），故 #13/#14 的
// `{op}` 维度按指标名拆分（otpmask_crypto_call_<op>_total / ..._failclosed_<op>_total）。

var (
	cryptoMetricsMu    sync.Mutex
	cryptoCallCounters = map[string]*pwCounter{}
	cryptoFailCounters = map[string]*pwCounter{}
)

func cryptoOpCounter(byFail bool, op string) *pwCounter {
	cryptoMetricsMu.Lock()
	defer cryptoMetricsMu.Unlock()
	m, prefix := cryptoCallCounters, "otpmask_crypto_call_"
	if byFail {
		m, prefix = cryptoFailCounters, "otpmask_crypto_failclosed_"
	}
	c := m[op]
	if c == nil {
		c = &pwCounter{name: prefix + op + "_total"}
		m[op] = c
	}
	return c
}

// pwGauge 懒初始化的 proxy-wasm gauge（差值 Set；metricsHostGuard 单测守卫）。
type pwGauge struct {
	name    string
	g       proxywasm.MetricGauge
	defined bool
	last    int64
}

func (g *pwGauge) set(open bool) {
	if metricsHostGuard {
		return
	}
	if !g.defined {
		g.g = proxywasm.DefineGaugeMetric(g.name)
		g.defined = true
	}
	want := int64(0)
	if open {
		want = 1
	}
	if d := want - g.last; d != 0 {
		g.g.Add(d)
		g.last = want
	}
}

// cryptoCircuitGauge 指标 #5（0/1）。⚠️ 多 worker 下 Envoy 按累加聚合（见 metrics.go:208），
// 故该 gauge 仅作单 worker 佐证；跨 worker 判据以日志与 fail-closed 计数为准。
var cryptoCircuitGauge = &pwGauge{name: "cryptop_circuit_open"}

// pluginCryptoMetrics 实现 cryptoclient.Metrics。
type pluginCryptoMetrics struct{}

func (pluginCryptoMetrics) Call(op string)        { cryptoOpCounter(false, op).incr() } // #13
func (pluginCryptoMetrics) FailClosed(op string)  { cryptoOpCounter(true, op).incr() }  // #14
func (pluginCryptoMetrics) CircuitOpen(open bool) { cryptoCircuitGauge.set(open) }      // #5

// ---- 工厂 ----

// newPluginCryptoClient 构造插件侧 cryptop sidecar 客户端（唯一 HTTP 面，§4.7）。
// threshold/cooldown 传 ≤0 时取 R-4 默认（5 次 / 30s）。
func newPluginCryptoClient(fqdn string, port int64, timeoutMs uint32, maskVersion string, threshold int, cooldown time.Duration) *cryptoclient.Client {
	br := cryptoclient.NewBreaker(threshold, cooldown)
	return cryptoclient.New(
		wrapperTransport{fqdn: fqdn, port: port},
		br,
		pluginCryptoMetrics{},
		cryptoclient.Config{TimeoutMS: timeoutMs, MaskVersion: maskVersion},
	)
}
