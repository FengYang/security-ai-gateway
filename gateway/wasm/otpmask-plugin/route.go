package main

// route.go — 推拉结合路由决策接线（设计 GA-Gateway-Core-推拉结合设计.md §6 降级阶梯）。
//
// 阶梯：
//
//	L1 处方（请求头 X-Otp-Route，经共享包 rxroute 验签）→ 采用其 preferred_engine；
//	L2 默认路由表缓存（routecache，防回滚/防篡改；由周期 tick 任务拉取填充）→ 采用
//	   default_engine/target（**降级**）；
//	无命中 → 密态 fail-closed（503，不静默直连）。
//
// 命中后把决策写入请求头 X-Otp-Engine / X-Otp-Target，由 Envoy/Higress 路由规则消费
// （插件不直接切上游，职责边界清晰）。
//
// ⚠️ 请求路径**只读缓存、不发起拉取**：拉取由 ensureRouteFetchLoop（routefetch.go）的
// tick 任务承担——同请求内先 fail-closed 会丢弃挂起的异步回调（2026-09-12 实证）。
//
// ⚠️ 兼容性（关键）：仅当**显式启用**（gateway_core_enabled=true 且 route_verify_key 有效）
// 时才介入请求；未启用 = 行为与接线前完全一致（不改任何请求头、不因路由 fail-closed）。
//
// ⚠️ 已知约束（模型维度）：路由决策发生在**请求头阶段**，而请求体里的 model 要到 body
// 阶段才可见——那时改写请求头已不生效（HeaderContinue 已把请求头放行上游）。故模型维度取
// X-Otp-Model 头（缺省 config.Model）。若将来需按 body 内 model 决策，应把决策前移到
// Envoy 层，或约定客户端携带该头。
//
// 分层：decideRoute 为**纯逻辑**（无 hostcall，可在宿主单测）；applyRouteDecision 负责
// 读请求头/写路由头/计数/日志（依赖 wasm hostcall）。

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

const (
	hdrOtpRoute  = "X-Otp-Route"  // 处方（推路径 L1，JWT）
	hdrOtpEngine = "X-Otp-Engine" // 决策输出：目标引擎（供 Envoy 路由规则）
	hdrOtpTarget = "X-Otp-Target" // 决策输出：显式目标端点
	hdrOtpModel  = "X-Otp-Model"  // 可选输入：模型维度（请求头阶段可得）
)

// routeRuntimeState 路由运行时状态：验签密钥 + 路由表缓存 + 拉取参数（由 parseConfig 初始化）。
type routeRuntimeState struct {
	key            []byte
	cache          *routecache.Cache
	service        string
	port           int64
	pollIntervalMs int64
}

// routeRuntime 运行时单例（含周期拉取参数）。
var routeRuntime routeRuntimeState

// fetchParams 返回拉取所需参数；未启用返回 ok=false。
func (r *routeRuntimeState) fetchParams() (key []byte, service string, port int64, ok bool) {
	if r.key == nil || r.cache == nil || r.service == "" {
		return nil, "", 0, false
	}
	return r.key, r.service, r.port, true
}

// initRouteRuntime 按配置初始化/刷新路由运行时；未启用则置空（决策不介入）。
func initRouteRuntime(config PluginConfig, log logs.Log) {
	routeRuntime.key = nil
	routeRuntime.cache = nil
	routeRuntime.service = ""
	routeRuntime.port = 0
	routeRuntime.pollIntervalMs = 0
	if !config.GatewayCoreEnabled || config.RouteVerifyKeyHex == "" {
		return
	}
	key, err := hex.DecodeString(config.RouteVerifyKeyHex)
	if err != nil || rxroute.ValidateKey(key) != nil {
		log.Warnf("otpmask-plugin: route_verify_key 无效（须 ≥%d 字节 hex），路由决策不启用", rxroute.MinKeyLen)
		return
	}
	routeRuntime.key = key
	routeRuntime.cache = routecache.NewWithOptions(key, routecache.Options{
		MaxStale: time.Duration(config.MaxStaleSeconds) * time.Second,
	})
	routeRuntime.service = config.GatewayCoreService
	routeRuntime.port = config.GatewayCorePort
	routeRuntime.pollIntervalMs = config.PollIntervalSeconds * 1000
	// 注册周期拉取（幂等）：负责冷启动与后续刷新（请求路径不再发起拉取）。
	ensureRouteFetchLoop()
	log.Infof("otpmask-plugin: 路由决策已启用 gateway-core=%s:%d max_stale=%ds poll=%ds",
		config.GatewayCoreService, config.GatewayCorePort, config.MaxStaleSeconds, config.PollIntervalSeconds)
}

// routeEnabled 路由决策是否已启用。
func routeEnabled() bool { return routeRuntime.cache != nil }

// decideRoute 纯逻辑决策（无 hostcall，可单测）：
// 处方验签（rxToken）→ 缓存 → 产出决策；需要 fail-closed 时返回非空原因。
//
// 设计取向（§6）：处方问题（缺失/签名无效/过期）**不直接拒绝请求**，而是降级到 L2；
// 只有 L1/L2 都拿不到路由时才 fail-closed（密态语义不可降级）。
func decideRoute(cache *routecache.Cache, key []byte, tenant, model, rxToken string, now time.Time) (routecache.Decision, error, string) {
	rxEngine := ""
	var rxErr error
	if rxToken != "" {
		p, err := rxroute.VerifyWith(key, rxToken, now)
		if err != nil {
			rxErr = err
		} else if p.Policy != nil {
			rxEngine = p.Policy.PreferredEngine
		}
	}
	d := cache.Decide(tenant, model, rxEngine)
	if d.Source != routecache.SourceNone {
		return d, rxErr, ""
	}
	if d.Stale {
		return d, rxErr, "默认路由表已超 max_stale 且无有效处方——密态 fail-closed（不静默使用陈旧路由）"
	}
	return d, rxErr, "无可用路由（处方缺失且默认路由表未命中）——密态 fail-closed"
}

// applyRouteDecision 读请求维度 → 决策 → 写路由头或 fail-closed（只读缓存，不发起拉取）。
func applyRouteDecision(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	if !routeEnabled() {
		return types.HeaderContinue // 未启用路由：与接线前行为一致
	}
	tenant := tenantHeaderValue(ctx)
	model := requestModelHeader(config)

	d, rxErr, failReason := decideRoute(routeRuntime.cache, routeRuntime.key, tenant, model, reqHeader(hdrOtpRoute), time.Now())
	if rxErr != nil {
		log.Warnf("otpmask-plugin: 处方校验失败，降级 L2: %v", rxErr)
	}
	switch d.Source {
	case routecache.SourceCache:
		metricRouteDegraded.incr() // §6：降级事件可观测
		log.Warnf("otpmask-plugin: 路由降级 L2（处方缺失/失效）tenant=%q model=%q engine=%q", tenant, model, d.Engine)
	case routecache.SourceNone:
		// 缓存未命中即 fail-closed（拉取由周期 tick 任务承担，见 routefetch.go）。
		return failClosed(log, failReason)
	}
	if d.Engine != "" {
		_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpEngine, d.Engine)
	}
	if d.Target != "" {
		_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpTarget, d.Target)
	}
	return types.HeaderContinue
}

// requestModelHeader 取模型维度：优先 X-Otp-Model，缺省 config.Model（见文件头"已知约束"）。
func requestModelHeader(config PluginConfig) string {
	if m := reqHeader(hdrOtpModel); m != "" {
		return m
	}
	return config.Model
}

// reqHeader 读请求头（不存在/异常返回空串）。
func reqHeader(name string) string {
	v, err := proxywasm.GetHttpRequestHeader(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}
