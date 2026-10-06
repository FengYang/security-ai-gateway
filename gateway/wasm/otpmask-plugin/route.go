package main

// route.go — 推拉结合路由决策接线（设计 GA-Gateway-Core-推拉结合设计.md §6 降级阶梯）。
//
// 阶梯：
//
//	L1 处方（请求头 X-Otp-Route，解析经共享包 rxroute（零密码）、**验签经 cryptop sidecar**
//	   `/v1/hmac`（CPS：请求头阶段暂停 → 回调内决策 → Resume，§5.4.6 同源机制））→ 采用其 preferred_engine；
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
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

const (
	hdrOtpRoute     = "X-Otp-Route"     // 处方（推路径 L1，JWT）
	hdrOtpEngine    = "X-Otp-Engine"    // 决策输出：目标引擎（供 Envoy 路由规则）
	hdrOtpTarget    = "X-Otp-Target"    // 决策输出：显式目标端点
	hdrOtpModel     = "X-Otp-Model"     // 可选输入：模型维度（请求头阶段可得）
	hdrOtpEndpoint  = "X-Otp-Endpoint"  // P0-1 新增：选中的端点名称（多端点路由决策输出）
	hdrOtpStrategy  = "X-Otp-Strategy"  // P0-1 新增：使用的路由策略（tracing 关联用）
	hdrOtpCanary    = "X-Otp-Canary"    // P0-1 新增：灰度分组（tracing 关联用）
	hdrRequestID    = "X-Request-Id"    // Envoy 生成的请求 ID（日志-trace 关联用）
)

// routeRuntimeState 路由运行时状态：验签密钥 + 路由表缓存 + 拉取参数（由 parseConfig 初始化）。
// 多端点路由引擎按 tenant|model 隔离，见下方 routingRegistry（不在本结构内，避免跨租户共享状态）。
type routeRuntimeState struct {
	key            []byte
	cache          *routecache.Cache
	service        string
	port           int64
	pollIntervalMs int64
	token          string // gateway-core 拉取通道令牌（Authorization: Bearer；空 = 控制面未启用鉴权）
	// P1-6：路由表更新被拒绝统计（可观测）
	rejectCount       int64  // 累计拒绝次数
	lastRejectReason  string // 最近一次拒绝原因
	lastRejectVersion int    // 最近一次被拒版本号
	// P1-2：处方头防重放守卫（JTI 消费记录）。nil = 未启用（与 P0 行为一致）。
	// Wasm 单线程环境，无需加锁。
	replayGuard *rxroute.ReplayGuard
	replayEnabled bool
	// P1-2：防重放统计（可观测）
	replayRejectCount int64 // 累计重放拒绝次数
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
	// 派发开关每次重解析都复位：未启用路由时不可能有端点决策，故必为 false（零行为变化）。
	routeDispatchEnabled = false
	if !config.GatewayCoreEnabled || config.RouteVerifyKeyHex == "" {
		return
	}
	key, err := hex.DecodeString(config.RouteVerifyKeyHex)
	if err != nil || rxroute.ValidateKey(key) != nil {
		log.Warnf("otpmask-plugin: route_verify_key 无效（须 ≥%d 字节 hex），路由决策不启用", rxroute.MinKeyLen)
		return
	}
	routeRuntime.key = key
	routeRuntime.cache = routecache.NewWithOptions(sidecarTableVerifier{}, routeVerifyKeyRef(config), routecache.Options{
		MaxStale: time.Duration(config.MaxStaleSeconds) * time.Second,
		MaxSize:  int(config.RouteTableMaxSizeBytes),
		OnReject: func(reason string, newVersion int) {
			// P1-6：路由表更新被拒绝计数（可观测）
			// Wasm 单线程环境，无需加锁
			routeRuntime.rejectCount++
			routeRuntime.lastRejectReason = reason
			routeRuntime.lastRejectVersion = newVersion
			log.Warnf("otpmask-plugin: 路由表更新被拒绝 reason=%s new_version=%d", reason, newVersion)
		},
	})
	routeRuntime.service = config.GatewayCoreService
	routeRuntime.port = config.GatewayCorePort
	routeRuntime.pollIntervalMs = config.PollIntervalSeconds * 1000
	routeRuntime.token = config.GatewayCoreToken
	// P1-2：处方头防重放守卫（默认关闭 = 与 P0 行为一致）
	routeRuntime.replayEnabled = config.ReplayGuardEnabled
	if config.ReplayGuardEnabled {
		routeRuntime.replayGuard = rxroute.NewReplayGuard(int(config.ReplayGuardCapacity), int64(rxroute.TimeSkew))
		log.Infof("otpmask-plugin: 处方防重放已启用 capacity=%d window=%ds",
			config.ReplayGuardCapacity, rxroute.TimeSkew)
	} else {
		routeRuntime.replayGuard = nil
	}
	// 注册周期拉取（幂等）：负责冷启动与后续刷新（请求路径不再发起拉取）。
	ensureRouteFetchLoop()
	// 注册运行时周期任务（幂等）：三级降级重评估 + 端点快照可观测（§6.9/§10）。
	ensureRouteRuntimeLoop()
	// 非流式重试（§6.5）仅在路由决策可用时才有意义（需端点决策结果）。
	routeDispatchEnabled = config.RouteDispatchEnabled
	log.Infof("otpmask-plugin: 路由决策已启用 gateway-core=%s:%d max_stale=%ds poll=%ds dispatch=%v",
		config.GatewayCoreService, config.GatewayCorePort, config.MaxStaleSeconds,
		config.PollIntervalSeconds, routeDispatchEnabled)
}

// routeEnabled 路由决策是否已启用。
func routeEnabled() bool { return routeRuntime.cache != nil }

// decideRoute 纯逻辑决策（无 hostcall，可单测）：
// **已验签**的处方引擎（rxEngine）→ 缓存 → 产出决策；需要 fail-closed 时返回非空原因。
//
// 处方**验签**由调用方（applyRouteDecision，经 sidecar）完成后把 preferred_engine 传入；
// rxErr 仅用于日志（处方问题一律**降级 L2**，不直接拒绝请求，§6）。
func decideRoute(cache *routecache.Cache, tenant, model, rxEngine string, rxErr error, now time.Time) (routecache.Decision, error, string) {
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
//
// **阶段约束（P0-4 B4-e）**：处方（L1）验签经 cryptop sidecar（CPS，§5.4.6 同源机制）⇒ 须在
// **请求头阶段**暂停（`ActionPause`），于验签回调内完成决策后 `ResumeHttpRequest` 放行。
// **无 `X-Otp-Route` 处方时不暂停**，与接线前行为完全一致。
func applyRouteDecision(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	if !routeEnabled() {
		return types.HeaderContinue // 未启用路由：与接线前行为一致
	}
	tenant := tenantHeaderValue(ctx)
	model := requestModelHeader(config)
	rxToken := reqHeader(hdrOtpRoute)
	if rxToken == "" {
		// 无处方：同步走 L2/降级（不暂停，零行为变化）
		_ = finishRouteDecision(ctx, log, tenant, model, "", nil)
		return types.HeaderContinue
	}
	// 有处方：异步验签（CPS）→ 回调内决策并放行
	verifyPrescriptionAsync(config, rxToken, time.Now(), func(p *rxroute.RoutePrescription, verr error) {
		engine := ""
		if p != nil && p.Policy != nil {
			engine = p.Policy.PreferredEngine
		}
		if finishRouteDecision(ctx, log, tenant, model, engine, verr) {
			_ = proxywasm.ResumeHttpRequest()
		}
	})
	return types.ActionPause
}

// verifyPrescriptionAsync 经 cryptop sidecar 校验处方（CPS，§5.4.4 组⑫）：
// 解析（`rxroute`，**零密码**）→ `/v1/hmac` 由 sidecar 复算 MAC → 插件侧常量时间比较 → 时效校验。
//
// sidecar 不可用 / 签名无效 / 超时窗 → 回调带 err（调用方**降级 L2**，不因处方问题拒绝请求，§6）。
func verifyPrescriptionAsync(config PluginConfig, rxToken string, now time.Time, cb func(*rxroute.RoutePrescription, error)) {
	p, input, sig, err := rxroute.ParseToken(rxToken)
	if err != nil {
		cb(nil, err)
		return
	}
	symmetricVerifyMAC(routeVerifyKeyRef(config), []byte(input), sig, func(ok bool, verr error) {
		if verr != nil {
			cb(nil, verr)
			return
		}
		if !ok {
			cb(nil, errors.New("route: 处方签名无效"))
			return
		}
		if verr := rxroute.Validate(p, now); verr != nil {
			cb(nil, verr)
			return
		}
		// P1-2：处方头防重放（JTI 一次性消费）。
		// 设计原则：与签名无效同级别处理 → 降级 L2（不直接 503），与 §6 一致。
		// replayEnabled=false 或 replayGuard=nil 时跳过（与 P0 行为一致）。
		if routeRuntime.replayEnabled && routeRuntime.replayGuard != nil && p.JTI != "" {
			if !routeRuntime.replayGuard.Consume(p.JTI, now.Unix()) {
				// 重放：记录指标 + 降级 L2
				routeRuntime.replayRejectCount++
				cb(nil, errors.New("route: 处方重放（JTI 已消费）"))
				return
			}
		}
		cb(p, nil)
	})
}

// finishRouteDecision 决策 + 写路由头；返回 false 表示**已 fail-closed**（本地 503 已发送，
// 调用方不得再 `ResumeHttpRequest`）。
//
// P0-1：路由表配置了多端点（Endpoints 非空）时，在决策引擎之后再做一次端点选择，结果写入
// X-Otp-Endpoint 头。未配置 Endpoints = 行为与接线前完全一致（向后兼容）。
func finishRouteDecision(ctx wrapper.HttpContext, log logs.Log, tenant, model, rxEngine string, rxErr error) bool {
	if rxErr != nil {
		log.Warnf("otpmask-plugin: 处方校验失败，降级 L2: %v", rxErr)
	}
	d, _, failReason := decideRoute(routeRuntime.cache, tenant, model, rxEngine, rxErr, time.Now())
	switch d.Source {
	case routecache.SourceCache:
		metricRouteDegraded.incr() // §6：降级事件可观测
		log.Warnf("otpmask-plugin: 路由降级 L2（处方缺失/失效）tenant=%q model=%q engine=%q", tenant, model, d.Engine)
	case routecache.SourceNone:
		// 缓存未命中即 fail-closed（拉取由周期 tick 任务承担，见 routefetch.go）。
		failClosed(log, failReason)
		return false
	}
	if d.Engine != "" {
		_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpEngine, d.Engine)
	}
	if d.Target != "" {
		_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpTarget, d.Target)
	}

	// === P0-1 多端点路由：Endpoints 非空时由有状态引擎选择端点 ===
	// 引擎按 tenant|model 隔离，维护 EWMA 失败率/熔断/动态权重状态；路由表版本变化时
	// 平滑迁移（保留统计）。Endpoints 为空 → entryFor 返回 nil → 行为与接线前完全一致。
	if e := entryFor(routeRuntime.cache, tenant, model); e != nil {
		epd := e.engine.PickEndpointForTenant(tenant)
		if epd.EndpointName != "" {
			_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpEndpoint, epd.EndpointName)
			// §10.3：tracing 关联属性（写入请求头，由 Envoy tracing 采集）
			_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpStrategy, string(epd.Strategy))
			if epd.CanaryGroup != "" {
				_ = proxywasm.ReplaceHttpRequestHeader(hdrOtpCanary, epd.CanaryGroup)
			}
			// 请求级决策结果挂到上下文，供响应阶段回写 RecordResult（§6.5.8 结果判定）。
			ctx.SetContext(ctxKeyRouteEndpoint, epd.EndpointName)
			ctx.SetContext(ctxKeyRouteEntry, e)
			ctx.SetContext(ctxKeyRouteStart, time.Now().UnixNano()) // §10 #2：延迟观测起点
			log.Debugf("otpmask-plugin: 端点选择 tenant=%q model=%q endpoint=%q strategy=%s reason=%s canary=%s",
				tenant, model, epd.EndpointName, epd.Strategy, epd.Reason, epd.CanaryGroup)
			// §10 #11：灰度请求计数
			switch epd.CanaryGroup {
			case "whitelist":
				metricRouteCanaryWhitelist.incr()
			case "treatment":
				metricRouteCanaryTreatment.incr()
			case "control":
				metricRouteCanaryControl.incr()
			}
		}
	}
	return true
}

// ============================================================
// 多端点路由引擎注册表（P0-1 W3 接线）
// ============================================================

// routingEntry 单个 tenant+model 的有状态路由引擎及其来源路由表版本。
type routingEntry struct {
	engine  *routeengine.Engine
	degrade *routeengine.DegradationManager // 三级降级级别（§6.9，周期 tick 重评估）
	version int
}

// routingRegistry 多端点路由引擎注册表（按 tenant|model 隔离）。
// wasm 单线程执行，仍以互斥锁保护，避免配置热更新与请求路径交叠。
// 条目只增不删（随 tenant×model 规模有界），保证热更新时统计状态不丢失。
type routingRegistry struct {
	mu      sync.Mutex
	entries map[string]*routingEntry
}

var routingEngines = routingRegistry{entries: make(map[string]*routingEntry)}

// entryFor 取（或建）指定 tenant+model 的有状态路由条目。
// 未命中路由表或该条目未配置端点 → 返回 nil（调用方保持既有行为，向后兼容）。
// 路由表版本变化时用 UpdateConfigSmooth 平滑迁移（保留 EWMA/熔断状态）。
func entryFor(cache *routecache.Cache, tenant, model string) *routingEntry {
	if cache == nil {
		return nil
	}
	tr := cache.Lookup(tenant, model)
	if tr == nil || len(tr.Endpoints) == 0 {
		return nil
	}
	ver := cache.Version()
	key := tenant + "\x00" + model

	routingEngines.mu.Lock()
	defer routingEngines.mu.Unlock()
	e := routingEngines.entries[key]
	if e == nil {
		e = &routingEntry{
			engine:  routeengine.NewEngine(buildEngineConfig(tr)),
			degrade: routeengine.NewDegradationManager(routeengine.DegradationConfig{}),
			version: ver,
		}
		routingEngines.entries[key] = e
		return e
	}
	if e.version != ver {
		e.engine.UpdateConfigSmooth(buildEngineConfig(tr))
		e.version = ver
		metricRouteConfigReload.incr() // §10 #12：配置平滑热更新计数
	}
	return e
}

// buildEngineConfig 由路由表条目构造引擎配置。
// 同时注册端点凭证到全局 CredentialManager（方案 §9.2）。
func buildEngineConfig(tr *routecache.TableRoute) routeengine.Config {
	eps := make([]routeengine.EndpointConfig, 0, len(tr.Endpoints))
	for _, ep := range tr.Endpoints {
		if ep.Name == "" {
			continue // 无名端点不参与选择（与既有接线一致）
		}
		// 注册端点凭证（secret_ref 非空时）
		if ep.Auth.SecretRef != "" {
			if err := registerEndpointCredentials(ep.Name, ep.Auth.SecretRef); err != nil {
				proxywasm.LogWarnf("otpmask-plugin: 端点 %q 凭证注册失败: %v", ep.Name, err)
			}
		}
		eps = append(eps, routeengine.EndpointConfig{
			Name:     ep.Name,
			URL:      ep.URL,
			Weight:   ep.Weight,
			Priority: ep.Priority,
			Enabled:  true,
		})
	}
	var canaryCfg routeengine.CanaryConfig
	if tr.Canary != nil {
		canaryCfg = routeengine.CanaryConfig{
			Enabled:            tr.Canary.Enabled,
			TargetEndpoint:     tr.Canary.TargetEndpoint,
			TargetWeight:       tr.Canary.TargetWeight,
			RampStep:           tr.Canary.RampStep,
			RampIntervalMs:     tr.Canary.RampIntervalMs,
			RollbackThreshold:  tr.Canary.RollbackThreshold,
			RollbackMinSamples: tr.Canary.RollbackMinSamples,
			AllowedTenants:     tr.Canary.AllowedTenants,
		}
	}
	return routeengine.Config{
		Strategy:  routeStrategy(tr.Strategy),
		Endpoints: eps,
		Canary:    canaryCfg,
	}
}

// routeStrategy 解析路由策略字符串（大小写与连接符不敏感）。
// 兼容方案 §4.1.3 枚举（priority/weighted/failure-rate-aware）与引擎内部取值；
// 未知/空值回落 priority（主备，最保守）。
func routeStrategy(s string) routeengine.Strategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "weighted", "weight":
		return routeengine.StrategyWeighted
	case "failure-rate-aware", "failure_rate_aware", "failure-rate", "failureaware":
		return routeengine.StrategyFailureAware
	case "primary-backup", "priority", "primary_backup":
		return routeengine.StrategyPriority
	default:
		return routeengine.StrategyPriority
	}
}

// routeEndpointSuccess 判定一次端点响应是否算成功（§6.5.8 错误分类与处理矩阵）：
// 5xx 与 429 计入失败率/熔断；其余（含 4xx 中的 400/401/403）不计入失败。
func routeEndpointSuccess(status int) bool {
	return status < 500 && status != 429
}

// sampleHit 基于时间戳的伪随机采样（percent 为 0-100 的整数）。
// P0 简化实现，避免引入 math/rand 依赖和全局状态。
// 精度：纳秒时间戳模 100，均匀分布在 0-99。
func sampleHit(percent int, seed int64) bool {
	if percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	return (seed % 100) < int64(percent)
}

// recordRouteResult 响应阶段回写端点结果（供 EWMA/熔断/动态权重消费）。
// 未经端点选择的请求（endpoint 缺失/条目缺失）为 no-op。
func recordRouteResult(ctx wrapper.HttpContext, status int) {
	name, ok := ctx.GetContext(ctxKeyRouteEndpoint).(string)
	if !ok || name == "" {
		return
	}
	e, ok := ctx.GetContext(ctxKeyRouteEntry).(*routingEntry)
	if !ok || e == nil {
		return
	}
	metricRouteRequests.incr() // §10 #1：经端点选择的路由请求计数
	success := routeEndpointSuccess(status)
	e.engine.RecordResult(name, success)

	// 计算延迟（§10 #2 / §10.2 路由决策日志共用）
	var latencySec float64
	var latencyMs float64
	startNs, hasStart := ctx.GetContext(ctxKeyRouteStart).(int64)
	if hasStart && startNs > 0 {
		elapsed := float64(time.Now().UnixNano() - startNs)
		latencySec = elapsed / 1e9
		latencyMs = elapsed / 1e6
		observeLatency(latencySec) // §10 #2：端到端延迟 Histogram
	}

	// §6.9 降级迟滞：按优先级组累计连续成功；失败清零（恢复需连续成功达标）。
	if prio, ok := e.engine.EndpointPriority(name); ok {
		if success {
			e.degrade.RecordSuccess(prio)
		} else {
			e.degrade.RecordFailure(prio)
		}
	}
	// §10.2 路由决策日志：成功 5% 采样，失败 100%。
	// P0 简化：用伪随机（时间戳取模）实现采样，避免引入 math/rand 依赖。
	if !success || sampleHit(5, time.Now().UnixNano()) {
		// §10.3：日志-trace 关联（读取 Envoy x-request-id）
		reqID, _ := proxywasm.GetHttpRequestHeader(hdrRequestID)
		proxywasm.LogInfof("route: request_id=%q endpoint=%q status=%d success=%v latency_ms=%.2f degrade=%s",
			reqID, name, status, success, latencyMs, e.degrade.Level())
	}
}

// ============================================================
// 路由运行时周期任务（§6.9 降级重评估 + §10 快照可观测）
// ============================================================

// routeRuntimeLoopOnce 保证运行时 tick 仅注册一次（parseConfig 可能被热更新重复调用）。
var routeRuntimeLoopOnce sync.Once

// routeRuntimeTickIntervalMs 降级/快照评估周期（毫秒）。
// 取 10s：远小于 §6 故障检测目标（<10s 由被动 EWMA + 主动探测承担），
// 且作为纯本地计算开销可忽略。
const routeRuntimeTickIntervalMs = 10000

// ensureRouteRuntimeLoop 注册路由运行时周期任务（幂等）。
func ensureRouteRuntimeLoop() {
	routeRuntimeLoopOnce.Do(func() {
		wrapper.RegisterTickFunc(routeRuntimeTickIntervalMs, routeRuntimeTick)
		proxywasm.LogInfof("otpmask-plugin: 路由运行时周期任务已注册 period_ms=%d", routeRuntimeTickIntervalMs)
	})
}

// routeRuntimeTick 周期任务：对每个已建引擎重评估三级降级级别并输出运行时快照。
// 纯本地计算（无出站 hostcall），不影响请求路径。
func routeRuntimeTick() {
	nowMs := time.Now().UnixMilli()

	routingEngines.mu.Lock()
	entries := make([]*routingEntry, 0, len(routingEngines.entries))
	for _, e := range routingEngines.entries {
		entries = append(entries, e)
	}
	routingEngines.mu.Unlock()

	for _, e := range entries {
		states := e.engine.EndpointStates()
		if e.degrade.Evaluate(states, nowMs) {
			metricRouteDegradeEvents.incr() // §10 P1-7：降级事件计数
			proxywasm.LogWarnf("otpmask-plugin: 路由降级级别变更 level=%s endpoints=%d",
				e.degrade.Level(), len(states))
		}
		// §7.5：灰度放量推进 + 自动回滚检测
		if changed := e.engine.Tick(nowMs); changed {
			if cs, ok := e.engine.CanarySnapshot(); ok {
				proxywasm.LogInfof("otpmask-plugin: 灰度状态变更 state=%s weight=%.4f progress=%.3f reason=%q",
					cs.State.String(), cs.CurrentWeight, cs.CurrentProgress, cs.Reason)
			}
		}
		snap := e.engine.Snapshot()
		for _, es := range snap.Endpoints {
			proxywasm.LogDebugf("otpmask-plugin: 端点快照 name=%q usable=%v weight=%.3f failure=%.4f valid=%v circuit=%d level=%s",
				es.Name, es.Enabled && es.CircuitState != routeengine.CircuitOpen, es.CurrentWeight,
				es.FailureRate, es.FailureValid, es.CircuitState, e.degrade.Level())
		}
	}
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
