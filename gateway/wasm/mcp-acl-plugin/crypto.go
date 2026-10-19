package main

import (
	"errors"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
)

// keyRefPolicyVerify 目录/策略验签密钥句柄（§6.3 命名 <scope>/<purpose>/v<n>）。
// 复用 otpmask/route-verify/v1：mcpsec 目录/策略与路由/限流表共用同一对称密钥族 K_rx
// （gateway-core 三签名器同 key），cryptop 静态密钥 Secret（cryptop-static-keys）
// 已含该条目；如需独立句柄，向 Secret 增条目并改 route_verify_key_ref。
const keyRefPolicyVerify = "otpmask/route-verify/v1"

// cryptoClient cryptop sidecar 客户端（配置期装配、请求/拉取期只读；wasm 单线程）。
var cryptoClient *cryptoclient.Client

// initCryptoRuntime 装配 sidecar 客户端（fail-closed：未装配时验签一律失败）。
func initCryptoRuntime(config PluginConfig, log logs.Log) {
	cryptoClient = cryptoclient.New(
		sidecarTransport{fqdn: config.CryptoService, port: config.CryptoServicePort},
		cryptoclient.NewBreaker(int(config.CryptoCircuitThreshold), time.Duration(config.CryptoCircuitCooldownMS)*time.Millisecond),
		aclCryptoMetrics{},
		cryptoclient.Config{TimeoutMS: uint32(config.CryptoCallTimeoutMS)},
	)
	log.Infof("mcp-acl: cryptop sidecar 已装配 service=%s:%d key_ref=%s profile=%s",
		config.CryptoService, config.CryptoServicePort, config.RouteVerifyKeyRef, config.CryptoProfile)
}

// sidecarTransport 实现 cryptoclient.Transport：出站经 Envoy cluster（wrapper FQDNCluster）。
type sidecarTransport struct {
	fqdn string
	port int64
}

func (t sidecarTransport) Post(path string, headers [][2]string, body []byte, cb cryptoclient.ResponseCallback, timeoutMs uint32) error {
	client := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: t.fqdn, Port: t.port})
	return client.Post(path, headers, body, wrapper.ResponseCallback(cb), timeoutMs)
}

func (t sidecarTransport) Get(path string, headers [][2]string, cb cryptoclient.ResponseCallback, timeoutMs uint32) error {
	client := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: t.fqdn, Port: t.port})
	return client.Get(path, headers, wrapper.ResponseCallback(cb), timeoutMs)
}

// aclCryptoMetrics 实现 cryptoclient.Metrics（调用/失败计数；熔断状态进日志）。
type aclCryptoMetrics struct{}

func (aclCryptoMetrics) Call(string)       { metricCryptoCall.incr() }
func (aclCryptoMetrics) FailClosed(string) { metricCryptoFailClosed.incr() }

func (aclCryptoMetrics) CircuitOpen(open bool) {
	if open {
		proxywasm.LogWarnf("mcp-acl: cryptop sidecar 熔断开启（验签 fail-closed，策略保留旧对象）")
	}
}

// sidecarVerifier 实现 policycache.Verifier：经 cryptop sidecar 重算 MAC 后做常量时间
// 比较（插件侧零密码运算，R-4/§9.1；密钥字节恒驻 sidecar，C-5）。
type sidecarVerifier struct{}

func (sidecarVerifier) VerifySym(keyRef string, data, sig []byte, cb func(ok bool, err error)) {
	if cryptoClient == nil {
		cb(false, errors.New("mcp-acl: cryptop sidecar 未装配（fail-closed）"))
		return
	}
	cryptoClient.HMAC(cryptoclient.KeyRef(keyRef), data, func(mac []byte, err error) {
		if err != nil {
			cb(false, err)
			return
		}
		cb(macConstEqual(mac, sig), nil)
	})
}

// macConstEqual 常量时间字节比较（纯比较，非密码运算；与 otpmask 同实现）。
func macConstEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
