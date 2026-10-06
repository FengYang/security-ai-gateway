package main

// routedispatch.go — 非流式重试（方案 §6.5，P0-1 W3 接线④）。
//
// 定位：插件自持出站派发（wrapper.HttpCall → proxywasm.DispatchHttpCall），
// 在派发回调内按 §6.5 判定是否重试；满足则换端点重发（本次请求内失败过的端点不再选中）。
//
// **默认关闭**（route_dispatch_enabled=false，见 initRouteRuntime）：
// 未启用时本文件任何函数都不会被调用，请求路径与接线前完全一致
// （请求体仍经 ReplaceHttpRequestBody + ResumeHttpRequest 交 Envoy 直发）。
//
// 启用后的行为变化（如实声明，已计入本体文档 §6.5 偏差）：
//  1. 已加密的南向协议请求不再经 Envoy 路由直发，改由插件自持派发 →
//     该路径下 X-Otp-Endpoint 头不再被消费（端点由插件直接选定）。
//  2. 响应不再走 onHttpResponseHeaders/onStreamingResponseBody 流水线，改由本文件在派发
//     回调内复用 processOutputBody（信封解密 + 验签 + 解掩码 + SSE 组装）后 SendHttpResponse
//     一次性回写 → **仅覆盖非流式（整包）响应**。
//  3. 流式（SSE 增量外发）不做重发：本 SDK 的 SendHttpResponse 无流式变体，重发后无法
//     增量回写（方案 §6.6 的流式重发在本 SDK 上不可实现，按偏差记录处理）。
//  4. 跨端点重试要求所有端点共享同一 TEE 会话后端：信封会话是服务端**进程内**状态
//     （见 attest.go 会话模型），换到另一 TEE 实例后无法解开信封 → fail-closed
//     （不降级明文，不静默错误）。
//
// 分层：parseDispatchTarget / retryableInferStatus 为**纯逻辑**（可在宿主单测）；
// dispatchState.send 依赖 wasm hostcall。

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
	"security-ai-gateway/protocol/go"
)

// routeDispatchEnabled 插件自持派发开关（initRouteRuntime 按配置设置；默认 false）。
var routeDispatchEnabled bool

// retryAttemptHeader GA-计费 P0-3（A-1）：重试归因请求头（仅重发时下行；tee-infer 解析→IsRetry）。
// 值 = 当前尝试序号（首次=1 不写；重发写 2,3,...）。
const retryAttemptHeader = "X-Otpmask-Retry-Attempt"

// retryAttemptHeaderValue 计算重试头值：attempt<=1（首次）返回 ok=false（不写头）；
// attempt>=2（重发）返回十进制序号。纯逻辑，便于宿主单测。
func retryAttemptHeaderValue(attempt int) (string, bool) {
	if attempt <= 1 {
		return "", false
	}
	return strconv.Itoa(attempt), true
}

// routeDispatchPolicy 非流式重试策略（纯逻辑；预算按端点独立核算，方案 §6.7）。
var routeDispatchPolicy = routeengine.NewRetryPolicy(
	routeengine.RetryConfig{},
	routeengine.NewBudgetManager(routeengine.RetryBudgetConfig{}),
)

// dispatchTimeoutMs 单次派发超时（毫秒）。取 60s：覆盖 text 载荷引擎 256 token 的最坏生成时间
// （quote 会话 TTL 为 5min，不受此值影响）。
const dispatchTimeoutMs = 60000

// retryableInferStatus 判定上游状态码是否可重试（方案 §6.5.8 错误矩阵）。
// 仅列矩阵中标注「切换端点重试」的项：500/502/503/504/429；
// TLS 握手失败/401/403/400 不可重试（交由调用方原样回写）。
func retryableInferStatus(status int) bool {
	switch status {
	case http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

// dispatchTarget 派发目标（端点 URL 的解析结果）。
type dispatchTarget struct {
	host string
	port int64
	path string
}

// parseDispatchTarget 解析端点 URL → 派发三元组。
//
// 最小落地约定（方案 §4.3 Schema 只给出端点 url、未定义 cluster 命名）：
//   - host 取 URL 主机名（必填）；
//   - port 取显式端口，缺省按 scheme 取 https=443 / 其余 80；
//   - path 为空或 "/" 时补推理端点 protocol.EndpointInfer（信封 AAD 与之绑定）。
func parseDispatchTarget(rawURL string) (dispatchTarget, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return dispatchTarget{}, fmt.Errorf("端点 URL 非法: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return dispatchTarget{}, fmt.Errorf("端点 URL 缺少主机名: %q", rawURL)
	}
	var port int64
	if p := u.Port(); p != "" {
		port, err = strconv.ParseInt(p, 10, 64)
		if err != nil || port <= 0 {
			return dispatchTarget{}, fmt.Errorf("端点 URL 端口非法: %q", rawURL)
		}
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	path := u.Path
	if path == "" || path == "/" {
		path = protocol.EndpointInfer
	}
	return dispatchTarget{host: host, port: port, path: path}, nil
}

// rawURL 组装派发 URL（HttpCall 由此推导 :authority 与 :path）。
func (t dispatchTarget) rawURL() string {
	return "http://" + t.host + ":" + strconv.FormatInt(t.port, 10) + t.path
}

// dispatchTargetOf 判定本请求是否走插件自持派发：
// 显式启用 + 已选出端点（X-Otp-Endpoint 决策结果）+ 端点条目存在。
// 任一不满足 → ok=false，调用方走既有路径（行为零变化）。
func dispatchTargetOf(ctx wrapper.HttpContext) (*routingEntry, string, bool) {
	if !routeDispatchEnabled {
		return nil, "", false
	}
	name, ok := ctx.GetContext(ctxKeyRouteEndpoint).(string)
	if !ok || name == "" {
		return nil, "", false
	}
	e, ok := ctx.GetContext(ctxKeyRouteEntry).(*routingEntry)
	if !ok || e == nil {
		return nil, "", false
	}
	return e, name, true
}

// dispatchState 单次请求的派发/重试状态（方案 §6.5.7 RetryContext）。
type dispatchState struct {
	entry  *routingEntry
	state  *routeengine.RetryState
	body   []byte          // 未封信的南向协议明文（每次重发重新封信：sendCounter 递增，避反重放拒绝）
	failed map[string]bool // 本次请求已失败的端点（§6.5.9 #9：同请求内失败过的不再选中）
}

// dispatchInfer 以插件自持派发方式发送推理请求（首个端点为路由决策结果）。
// 成功后明文回写；失败按 §6.5 换端点重发；最终失败按 §7 语义回写错误体/fail-closed。
func dispatchInfer(ctx wrapper.HttpContext, config PluginConfig, entry *routingEntry,
	endpoint string, body []byte, log logs.Log) {
	d := &dispatchState{
		entry:  entry,
		state:  routeengine.NewRetryState(),
		body:   body,
		failed: make(map[string]bool, 2),
	}
	d.send(ctx, config, endpoint, log)
}

// send 向指定端点派发一次；回调内决定继续重发还是回写客户端。
func (d *dispatchState) send(ctx wrapper.HttpContext, config PluginConfig, endpoint string, log logs.Log) {
	urlStr, ok := d.entry.engine.EndpointURL(endpoint)
	if !ok {
		failClosed(log, fmt.Sprintf("路由派发端点未知: %q", endpoint))
		return
	}
	target, err := parseDispatchTarget(urlStr)
	if err != nil {
		failClosed(log, "路由派发端点配置非法: "+err.Error())
		return
	}
	headers := [][2]string{{"Content-Type", "application/octet-stream"}}
	if t := tenantHeaderValue(ctx); t != "" {
		headers = append(headers, [2]string{"X-Tenant-ID", t})
	}
	// GA-计费 P0-3（A-1/A-29）：重试归因标记——仅**重发**时下行（首次 Attempt=1 不写），
	// 使 tee-infer 能把重试流量的 token 归为平台成本（不计用户金额，M9）。
	if v, ok := retryAttemptHeaderValue(d.state.Attempt); ok {
		headers = append(headers, [2]string{retryAttemptHeader, v})
	}
	doSend := func(payload []byte, hdrs [][2]string) {
		err := wrapper.HttpCall(wrapper.FQDNCluster{FQDN: target.host, Port: target.port},
			http.MethodPost, target.rawURL(), hdrs, payload,
			func(statusCode int, hdr http.Header, respBody []byte) {
				// 结果回写（EWMA 失败率/熔断/动态权重/降级迟滞）：与响应头阶段同一入口，语义一致。
				recordRouteResult(ctx, statusCode)
				if retryableInferStatus(statusCode) && d.retry(ctx, config, endpoint, log) {
					return
				}
				d.writeResponse(ctx, config, statusCode, hdr, respBody, log)
			}, dispatchTimeoutMs)
		if err != nil {
			// 连接错误（§6.5.8：连接错误可重试，切换端点；计入失败率）
			recordRouteResult(ctx, http.StatusBadGateway)
			if d.retry(ctx, config, endpoint, log) {
				return
			}
			failClosed(log, fmt.Sprintf("路由派发失败: %v", err))
		}
	}
	// §5.4.6.1：quote 模式信封 seal 经 cryptop sidecar（异步）→ 回调内补 X-Session-ID 后派发。
	if config.AttestMode == "quote" {
		Session.sealPayload(protocol.EndpointInfer, d.body, func(sealed []byte, serr error) {
			if serr != nil {
				failClosed(log, "推理请求加密失败: "+serr.Error())
				return
			}
			hdrs := append(headers, [2]string{"X-Session-ID", Session.SessionID})
			doSend(sealed, hdrs)
		})
		return
	}
	doSend(d.body, headers)
}

// retry 判定并执行一次端点切换重发；返回 true 表示已重发（调用方不再回写）。
//
// 复用 routeengine.RetryPolicy（§6.5.2 前置条件：可重试错误 + 有备用端点 + 未达最大次数 +
// 预算有额度 + 幂等）；熔断打开端点已由 UsableEndpointNames 排除（§6.8 硬约束）。
func (d *dispatchState) retry(ctx wrapper.HttpContext, config PluginConfig, failedEndpoint string, log logs.Log) bool {
	d.failed[failedEndpoint] = true
	avail := d.available()
	if len(avail) == 0 {
		return false
	}
	// isIdempotent=true：LLM 推理 POST 无副作用（方案 §4.3 idempotent_inference 默认约定）。
	dec := routeDispatchPolicy.ShouldRetry(d.state, failedEndpoint, avail, failedEndpoint,
		time.Now().UnixMilli(), true)
	if !dec.ShouldRetry {
		log.Warnf("otpmask-plugin: 路由重试终止 endpoint=%q reason=%s attempts=%d",
			failedEndpoint, dec.Reason, d.state.Attempt)
		return false
	}
	metricRouteRetry.incr()
	log.Warnf("otpmask-plugin: 路由重试 endpoint=%q → %q attempts=%d delay_ms=%d",
		failedEndpoint, dec.RetryEndpoint, d.state.Attempt, dec.DelayMs)
	d.send(ctx, config, dec.RetryEndpoint, log)
	return true
}

// available 本次请求尚未失败过的可用端点（熔断打开/禁用/零权重端点已由引擎排除）。
func (d *dispatchState) available() []string {
	names := d.entry.engine.UsableEndpointNames()
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !d.failed[n] {
			out = append(out, n)
		}
	}
	return out
}

// writeResponse 解密/组装明文并一次性回写客户端（非流式）。
// 复用 processOutputBodyAsync（信封解密 + 验签 + 解掩码 + SSE 组装，均经 sidecar 异步），
// 状态码经上下文传递（body 阶段读不到响应伪头，与既有路径同因）。
func (d *dispatchState) writeResponse(ctx wrapper.HttpContext, config PluginConfig,
	status int, hdr http.Header, body []byte, log logs.Log) {
	ctx.SetContext(ctxKeyRespStatus, strconv.Itoa(status))
	processOutputBodyAsync(ctx, config, body, log, func(out []byte, passthrough, ok bool) {
		if passthrough {
			// 非 200 错误体：原样回写（保留上游 content-type）
			h := make([][2]string, 0, 1)
			if ct := hdr.Get("Content-Type"); ct != "" {
				h = append(h, [2]string{"Content-Type", ct})
			}
			_ = proxywasm.SendHttpResponse(uint32(status), h, out, -1)
			return
		}
		if !ok {
			metricDecryptError.incr()
			failClosed(log, "推理响应解密失败（路由派发路径）")
			return
		}
		// 与 onHttpResponseHeaders 的判定保持一致：quote 成功响应总是 SSE 信封明文。
		ct := "application/json"
		if requestWantsSSE || (config.AttestMode == "quote" && !pendingVectorsPlain) {
			ct = "text/event-stream"
		}
		_ = proxywasm.SendHttpResponse(http.StatusOK, [][2]string{{"Content-Type", ct}}, out, -1)
	})
}