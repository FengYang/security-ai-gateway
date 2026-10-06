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
	"encoding/binary"
	"sync"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
	"security-ai-gateway/protocol/go"
)

// ---- 插件级 sidecar 客户端与运行时状态（§12.3 / §4.7）----
//
// proxy-wasm 单线程回调语义：全局变量按「配置期写入、请求期只读」使用，无需原子。
var (
	// CryptoClient 插件唯一密码 HTTP 面（§4.7）。未配置 crypto_service 时为 nil——
	// 密码路径一律 fail-closed（C-4/R-11：无本地回退）。
	CryptoClient *cryptoclient.Client
	// cryptoSuite wire 信封 suite 字节（1=AES-GCM / 2=SM4-GCM），由 /v1/capabilities 载入（§5.1）。
	cryptoSuite byte = protocol.SuiteAESGCM
	// cryptoProfile sidecar 生效 profile（intl|sm-software|sm-module），供日志/校验。
	cryptoProfile = "intl"
	// cryptoReady 启动期 /v1/capabilities 校验通过（R-17/R-18）——未就绪时密码路径 fail-closed。
	cryptoReady bool
)

// defaultCryptoServicePort sidecar 缺省端口（19097；与 gateway-admin 的 19095/19096 相邻空闲档）。
const defaultCryptoServicePort int64 = 19097

// cryptoCircuitCooldownR4 R-4 缺省熔断冷却（30s）。
const cryptoCircuitCooldownR4 = 30 * time.Second

// initCryptoRuntime 装配 sidecar 客户端并启动期载入 capabilities（R-18）。
//
// ⚠️ parseConfig 同步、proxy-wasm 无阻塞 HTTP：R-18「启动拒」以 **fail-closed 就绪位** 落地——
// capabilities 未成功载入前 `cryptoReady=false`，所有密码调用即拒绝（C-4，不降级），
// 效果等价于启动拒（不下沉任何明文/密文）。
func initCryptoRuntime(config PluginConfig, log logs.Log) {
	// §4.7：向 routeengine 注入随机源接缝（经 sidecar `/v1/rand`；sidecar 未就绪 → 确定性主备回退）。
	routeengine.SetRandSource(routeRand)
	if config.CryptoService == "" {
		CryptoClient = nil
		cryptoReady = false
		log.Warnf("otpmask-plugin: 未配置 crypto_service → 全部密码路径 fail-closed（C-4/R-11）")
		return
	}
	port := config.CryptoServicePort
	if port == 0 {
		port = defaultCryptoServicePort
	}
	timeout := uint32(config.CryptoCallTimeoutMS)
	if timeout == 0 {
		timeout = cryptoclient.DefaultTimeoutMS // R-3
	}
	threshold := int(config.CryptoCircuitThreshold)
	if threshold <= 0 {
		threshold = 5 // R-4
	}
	cooldown := time.Duration(config.CryptoCircuitCooldownMS) * time.Millisecond
	if cooldown <= 0 {
		cooldown = cryptoCircuitCooldownR4 // R-4
	}
	CryptoClient = newPluginCryptoClient(config.CryptoService, port, timeout, config.MaskPRG, threshold, cooldown)
	cryptoReady = false
	CryptoClient.LoadCapabilities(func(caps cryptoclient.Capabilities, err error) {
		if err != nil {
			log.Errorf("otpmask-plugin: sidecar capabilities 载入失败（R-18）: %v（密码路径 fail-closed）", err)
			return
		}
		if caps.Profile != config.CryptoProfile {
			log.Errorf("otpmask-plugin: crypto_profile 不一致：插件=%q sidecar=%q（R-17，密码路径 fail-closed）",
				config.CryptoProfile, caps.Profile)
			return
		}
		cryptoSuite = byte(caps.Suite)
		cryptoProfile = caps.Profile
		cryptoReady = true
		log.Infof("otpmask-plugin: cryptop sidecar 就绪 profile=%s suite=%d mask_prg=%s note=%q",
			caps.Profile, caps.Suite, caps.MaskPRG, caps.ComplianceNote)
	})
}

// cryptoUsable 密码路径可用性（客户端已装配 + 就绪位）。
func cryptoUsable() bool { return CryptoClient != nil && cryptoReady }

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

// ---- 静态 MAC 密钥 KeyRef（§6.3 命名规范 <scope>/<purpose>/v<n>；sidecar 经 crypto_static_keys 登记）----
const (
	// keyRefJWT 门户 JWT（HS256）密钥句柄；配置 jwt_secret_ref 可覆盖。
	keyRefJWT = "otpmask/jwt/v1"
	// keyRefRouteVerify 路由表/限流表验签 K_rx 句柄（与 gateway-core 同一密钥族）；配置 route_verify_key_ref 可覆盖。
	keyRefRouteVerify = "otpmask/route-verify/v1"
)

// jwtVerifyKeyRef 取 JWT 验签密钥句柄（配置优先，缺省 §6.3 约定名）。
func jwtVerifyKeyRef(config PluginConfig) string {
	if config.JWTSecretRef != "" {
		return config.JWTSecretRef
	}
	return keyRefJWT
}

// routeVerifyKeyRef 取路由表/限流表验签密钥句柄（配置优先，缺省 §6.3 约定名）。
func routeVerifyKeyRef(config PluginConfig) string {
	if config.RouteVerifyKeyRef != "" {
		return config.RouteVerifyKeyRef
	}
	return keyRefRouteVerify
}

// symmetricVerifyMAC 经 cryptop sidecar 校验**对称 MAC**（CPS，§5.4.5）：
// 调 `/v1/hmac` 由 sidecar 以 KeyRef 指定的密钥重算 MAC，再在插件侧做**常量时间比较**
// （`macConstEqual` 为纯比较，非密码运算，§4.3.3）——密钥字节恒驻 sidecar（C-5），
// sidecar 不可用一律 fail-closed（C-4，无本地回退）。
//
// 说明：sidecar `/v1/verify` 的 `key_ref` 分支解为 profile 签名算法（intl=Ed25519 / sm=SM2），
// **不能**校验 HMAC（`cryptop.Provider.Verify` 为签名验签）；故对称 MAC 校验经 `/v1/hmac` +
// 常量时间比较落地，与既有 `verifyResponseAsync`（main.go）同一手法。
func symmetricVerifyMAC(keyRef string, data, sig []byte, cb func(ok bool, err error)) {
	if keyRef == "" || !cryptoUsable() {
		cb(false, errCryptoUnavailable)
		return
	}
	CryptoClient.HMAC(cryptoclient.KeyRef(keyRef), data, func(mac []byte, err error) {
		if err != nil {
			cb(false, err)
			return
		}
		cb(macConstEqual(mac, sig), nil)
	})
}

// sidecarTableVerifier 实现 routecache.Verifier / ratelimitcache.Verifier：
// 经 cryptop sidecar 校验表签名（K_rx，§5.4.5；插件侧零密码、密钥字节恒驻 sidecar）。
type sidecarTableVerifier struct{}

func (sidecarTableVerifier) VerifySym(keyRef string, data, sig []byte, cb func(ok bool, err error)) {
	symmetricVerifyMAC(keyRef, data, sig, cb)
}

// ---- routeengine 随机源接缝（§4.7：routeengine 不 import 密码；此处以其注入接缝接 cryptop sidecar）----

// routeRandRefillLen 每次向 sidecar `/v1/rand` 充填的字节数（B-4.6-2；= 32 个 float64，≤ R-8 上限 4096）。
const routeRandRefillLen = 256

// routeRandSource 实现 routeengine.RandSource：以 cryptop sidecar `/v1/rand` 异步充填本地缓冲；
// 缓冲暂空时返回 ok=false（routeengine 按确定性主备回退，不阻塞请求路径、不做本地密码运算）。
type routeRandSource struct {
	buf []byte
}

// routeRand 进程级随机源（wasm 单线程：请求期读写同一实例）。
var routeRand = &routeRandSource{}

func (s *routeRandSource) Float64() (float64, bool) {
	if len(s.buf) < 8 {
		s.refill()
		return 0, false
	}
	n := binary.BigEndian.Uint64(s.buf[:8])
	s.buf = s.buf[8:]
	return float64(n>>11) / (1 << 53), true
}

// refill 异步充填缓冲（best-effort：sidecar 未就绪/失败静默；未取到随机数时由 routeengine 确定性回退）。
func (s *routeRandSource) refill() {
	if !cryptoUsable() {
		return
	}
	CryptoClient.Rand(routeRandRefillLen, func(b []byte, err error) {
		if err != nil {
			return
		}
		s.buf = append(s.buf, b...)
	})
}
