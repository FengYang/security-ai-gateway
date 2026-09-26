package main

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
)

const (
	ctxRequestPrompt = "qwen3guard.request_prompt"
	ctxStreamPartial = "qwen3guard.stream_partial"
	ctxStreamPending = "qwen3guard.stream_pending"
	ctxResponseText  = "qwen3guard.response_text"
	ctxUncheckedText = "qwen3guard.unchecked_text"
	ctxStreamDone    = "qwen3guard.stream_done"
	ctxStreamBlocked = "qwen3guard.stream_blocked"
	ctxStreamBypass  = "qwen3guard.stream_bypass"
	ctxDuringCall    = "qwen3guard.during_call"
	// B1 强标标识（GB 45438-2025）：本流是否已注入标识帧（每流至多一次）。
	ctxStreamLabelled = "qwen3guard.stream_labelled"
)

func main() {}

// ---- B3（合规达标最小集 G13）：明文侧 fail-closed 收口 ----
//
// 口径：审核服务**不可用**（分发失败 / 超时 / 非 200 / 解析失败 / 构造送检体失败）
// ⇒ **一律不放行**。此前为 fail-open 放行，与项目 fail-closed 哲学及备案口径冲突。
// 处置：请求/响应路径以 denyCode + denyMessage 即时拒答；流式路径整流终止（注入拒答 SSE）。
// 例外（不属"不可用"，保持原行为）：请求/响应取不到配置的 content path ⇒ 跳过送检（无可检内容）；
// max_body_bytes 超限 bypass 属资源防护，另行登记，不在此列。
// 可观测：qwen3guard_failclosed_total + Warnf（stage/cause），供告警与趋势观测。
func failClosedDeny(c pluginConfig, lg log.Log, stage, cause string) {
	metricFailClosed.incr()
	lg.Warnf("qwen3guard: %s moderation unavailable (%s), fail closed: deny code=%d", stage, cause, c.denyCode)
	_ = proxywasm.SendHttpResponse(
		uint32(c.denyCode),
		[][2]string{{"content-type", "application/json"}},
		buildChatDenyBody(c.denyMessage),
		-1,
	)
}

// failClosedBlockStream 流式路径整流终止（与命中拦截同形：注入拒答 SSE 并结束流）。
// B1：content_label_on_deny 开启时拒答首帧携带强标标识 meta（拒答文案是否属标识口径由法务定，默认不带）。
func failClosedBlockStream(ctx wrapper.HttpContext, c pluginConfig, lg log.Log, cause string) {
	metricFailClosed.incr()
	lg.Warnf("qwen3guard: streaming moderation unavailable (%s), fail closed: terminate stream", cause)
	ctx.SetContext(ctxStreamBlocked, true)
	ctx.SetContext(ctxStreamPending, "")
	ctx.SetContext(ctxUncheckedText, "")
	proxywasm.InjectEncodedDataToFilterChain(buildStreamDenyBodyWithLabel(c.denyMessage, streamDenyLabel(c)), true)
}

// streamDenyLabel B1：on_deny 开启时返回拒答帧应携带的标识 meta，否则 nil。
func streamDenyLabel(c pluginConfig) *labelMeta {
	if !c.contentLabelOnDeny {
		return nil
	}
	return &labelMeta{Std: defaultContentLabelStd, Position: labelPositionHead}
}

// maybeInjectStreamLabel B1：流首注入判定（每流至多一次）。返回 true 表示本次应注入
// （调用方负责 hostcall 与计数；本函数仅置位，便于宿主单测不触 hostcall）。
// 去重语义：上游已带 label meta 的流本插件无从感知（明文侧无内层信封），qwen3guard 为明文
// 路径的注入点；与 tee-infer/otpmask 同开属双链路部署，按文档单一注入点规则配置。
func maybeInjectStreamLabel(ctx wrapper.HttpContext, c pluginConfig) bool {
	if !c.contentLabelEnabled || ctx.GetBoolContext(ctxStreamLabelled, false) {
		return false
	}
	ctx.SetContext(ctxStreamLabelled, true)
	return true
}

func init() {
	wrapper.SetCtx(
		pluginName,
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBodyBy(onHttpRequestBody),
		wrapper.ProcessResponseHeadersBy(onHttpResponseHeaders),
		wrapper.ProcessStreamingResponseBodyBy(onHttpStreamingResponseBody),
		wrapper.ProcessResponseBodyBy(onHttpResponseBody),
	)
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, c pluginConfig, log log.Log) types.Action {
	ctx.DisableReroute()
	if c.checkResponse {
		_ = proxywasm.RemoveHttpRequestHeader("Accept-Encoding")
	}
	if !c.checkRequest && !c.checkResponse {
		ctx.DontReadRequestBody()
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	if !ctx.HasRequestBody() {
		if c.checkRequest {
			log.Warnf("qwen3guard: request body is empty, skip request moderation")
		}
		return types.ActionContinue
	}
	ctx.SetRequestBodyBufferLimit(c.maxBodyBytes)
	ctx.BufferRequestBody()
	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, c pluginConfig, body []byte, log log.Log) types.Action {
	prompt, ok := extractJSONText(body, c.requestContentJSONPath)
	if ok {
		ctx.SetContext(ctxRequestPrompt, prompt)
	} else {
		log.Warnf("qwen3guard: request content path %q not found, skip request moderation", c.requestContentJSONPath)
	}
	if !c.checkRequest || !ok {
		return types.ActionContinue
	}

	requestBody, err := buildPromptModerationBody(c.model, prompt)
	if err != nil {
		failClosedDeny(c, log, "request", "build_body")
		return types.ActionPause
	}
	if err := c.client.Post(c.requestPath, buildGuardHeaders(c.apiKey), requestBody,
		func(statusCode int, _ http.Header, responseBody []byte) {
			result, err := parseGuardHTTPResponse(statusCode, responseBody)
			if err != nil {
				failClosedDeny(c, log, "request", "bad_response")
				return
			}
			if shouldBlockRisk(result.Safety, c.riskLevelBar) {
				proxywasm.SendHttpResponse(
					uint32(c.denyCode),
					[][2]string{{"content-type", "application/json"}},
					buildChatDenyBody(c.denyMessage),
					-1,
				)
				ctx.DontReadResponseBody()
				return
			}
			proxywasm.ResumeHttpRequest()
		}, c.timeoutMS); err != nil {
		failClosedDeny(c, log, "request", "dispatch")
		return types.ActionPause
	}
	return types.ActionPause
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, c pluginConfig, log log.Log) types.Action {
	if !c.checkResponse {
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}
	status, _ := proxywasm.GetHttpResponseHeader(":status")
	if status != "200" {
		ctx.DontReadResponseBody()
		return types.ActionContinue
	}

	_ = proxywasm.RemoveHttpResponseHeader("content-length")
	ctx.SetResponseBodyBufferLimit(c.maxBodyBytes)
	contentType, _ := proxywasm.GetHttpResponseHeader("content-type")
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		ctx.NeedPauseStreamingResponse()
		ctx.SetContext(ctxStreamDone, false)
		ctx.SetContext(ctxStreamBlocked, false)
		ctx.SetContext(ctxStreamBypass, false)
		ctx.SetContext(ctxDuringCall, false)
		return types.ActionContinue
	}
	ctx.BufferResponseBody()
	return types.HeaderStopIteration
}

func onHttpResponseBody(ctx wrapper.HttpContext, c pluginConfig, body []byte, log log.Log) types.Action {
	responseText, ok := extractJSONText(body, c.responseContentJSONPath)
	if !ok {
		log.Warnf("qwen3guard: response content path %q not found, skip moderation (无可检内容)", c.responseContentJSONPath)
		return types.ActionContinue
	}

	requestBody, err := buildResponseModerationBody(c.model, ctx.GetStringContext(ctxRequestPrompt, ""), responseText)
	if err != nil {
		failClosedDeny(c, log, "response", "build_body")
		return types.ActionPause
	}
	if err := c.client.Post(c.requestPath, buildGuardHeaders(c.apiKey), requestBody,
		func(statusCode int, _ http.Header, responseBody []byte) {
			result, err := parseGuardHTTPResponse(statusCode, responseBody)
			if err != nil {
				failClosedDeny(c, log, "response", "bad_response")
				return
			}
			if shouldBlockRisk(result.Safety, c.riskLevelBar) {
				denyMessage := c.denyMessage
				if c.contentLabelOnDeny {
					// 与流式拒答首帧同口径：on_deny 开启时拒答正文带标识（默认关 → 零行为变化）。
					denyMessage = c.contentLabelText + "\n" + denyMessage
					metricContentLabelInjected.incr()
				}
				proxywasm.SendHttpResponse(
					uint32(c.denyCode),
					[][2]string{{"content-type", "application/json"}},
					buildChatDenyBody(denyMessage),
					-1,
				)
				return
			}
			// S4-1 补口：非流式整包放行路径的标识注入（head＋tail 双锚点）。
			// 仅当 content_label_enabled 且能定位正文时改写；否则原样放行（行为不变）。
			if c.contentLabelEnabled {
				if labelled, ok := labelJSONTextAtPath(body, c.responseContentJSONPath, c.contentLabelText); ok {
					proxywasm.ReplaceHttpResponseBody(labelled)
					metricContentLabelInjected.incr()
				}
			}
			proxywasm.ResumeHttpResponse()
		}, c.timeoutMS); err != nil {
		failClosedDeny(c, log, "response", "dispatch")
		return types.ActionPause
	}
	return types.ActionPause
}

func onHttpStreamingResponseBody(ctx wrapper.HttpContext, c pluginConfig, data []byte, endOfStream bool, log log.Log) []byte {
	if ctx.GetBoolContext(ctxStreamBlocked, false) {
		return []byte{}
	}
	if ctx.GetBoolContext(ctxStreamBypass, false) {
		return data
	}

	// B1 强标标识（GB 45438-2025）：流首注入标识帧（blocked/bypass 检查之后；
	// 标识帧先行下发，序为 标识→内容，deny 时与拒答帧共存语义正确）。
	if maybeInjectStreamLabel(ctx, c) {
		metricContentLabelInjected.incr()
		proxywasm.InjectEncodedDataToFilterChain(buildStreamLabelBody(c.contentLabelText), false)
	}

	pending := ctx.GetStringContext(ctxStreamPending, "")
	combined := ctx.GetStringContext(ctxStreamPartial, "") + string(data)
	if exceedsByteLimit(len(pending), len(combined), c.maxBodyBytes) {
		return bypassStreamingResponse(ctx, pending+combined, c, log)
	}

	complete, leftover := splitCompleteSSE(combined, endOfStream)
	ctx.SetContext(ctxStreamPartial, leftover)
	if complete != "" {
		ctx.SetContext(ctxStreamPending, pending+complete)
		if !collectStreamingText(ctx, c, complete) {
			return bypassStreamingResponse(ctx, pending+complete+leftover, c, log)
		}
	}

	if ctx.GetBoolContext(ctxDuringCall, false) {
		return []byte{}
	}

	uncheckedText := ctx.GetStringContext(ctxUncheckedText, "")
	shouldCheck := uncheckedText != "" &&
		(charCount(uncheckedText) >= c.streamBufferChars || ctx.GetBoolContext(ctxStreamDone, false) || endOfStream)
	if shouldCheck {
		checkStreamingResponse(ctx, c, log)
		return []byte{}
	}

	pending = ctx.GetStringContext(ctxStreamPending, "")
	if endOfStream && pending != "" {
		ctx.SetContext(ctxStreamPending, "")
		return []byte(pending)
	}
	return []byte{}
}

func collectStreamingText(ctx wrapper.HttpContext, c pluginConfig, data string) bool {
	responseText := ctx.GetStringContext(ctxResponseText, "")
	uncheckedText := ctx.GetStringContext(ctxUncheckedText, "")
	for _, payload := range extractSSEDataPayloads(data) {
		if isDonePayload(payload) {
			ctx.SetContext(ctxStreamDone, true)
			continue
		}
		text, ok := extractJSONText([]byte(payload), c.streamingResponseContentJSONPath)
		if !ok {
			continue
		}
		if exceedsByteLimit(len(responseText), len(text), c.maxBodyBytes) {
			return false
		}
		responseText += text
		uncheckedText += text
	}
	ctx.SetContext(ctxResponseText, responseText)
	ctx.SetContext(ctxUncheckedText, uncheckedText)
	return true
}

func checkStreamingResponse(ctx wrapper.HttpContext, c pluginConfig, log log.Log) {
	requestBody, err := buildResponseModerationBody(
		c.model,
		ctx.GetStringContext(ctxRequestPrompt, ""),
		ctx.GetStringContext(ctxResponseText, ""),
	)
	if err != nil {
		failClosedBlockStream(ctx, c, log, "build_body")
		return
	}
	ctx.SetContext(ctxDuringCall, true)
	if err := c.client.Post(c.requestPath, buildGuardHeaders(c.apiKey), requestBody,
		func(statusCode int, _ http.Header, responseBody []byte) {
			ctx.SetContext(ctxDuringCall, false)
			if ctx.GetBoolContext(ctxStreamBypass, false) {
				return
			}
			result, err := parseGuardHTTPResponse(statusCode, responseBody)
			if err != nil {
				failClosedBlockStream(ctx, c, log, "bad_response")
				return
			}
			if shouldBlockRisk(result.Safety, c.riskLevelBar) {
				ctx.SetContext(ctxStreamBlocked, true)
				ctx.SetContext(ctxStreamPending, "")
				ctx.SetContext(ctxUncheckedText, "")
				proxywasm.InjectEncodedDataToFilterChain(buildStreamDenyBodyWithLabel(c.denyMessage, streamDenyLabel(c)), true)
				return
			}
			ctx.SetContext(ctxUncheckedText, "")
			releasePendingStream(ctx, false)
		}, c.timeoutMS); err != nil {
		ctx.SetContext(ctxDuringCall, false)
		failClosedBlockStream(ctx, c, log, "dispatch")
	}
}

func releasePendingStream(ctx wrapper.HttpContext, forceEndStream bool) {
	pending := ctx.GetStringContext(ctxStreamPending, "")
	if pending == "" {
		if forceEndStream {
			proxywasm.ResumeHttpResponse()
		}
		return
	}
	ctx.SetContext(ctxStreamPending, "")
	endStream := forceEndStream || ctx.GetBoolContext(ctxStreamDone, false)
	proxywasm.InjectEncodedDataToFilterChain(bytes.Clone([]byte(pending)), endStream)
}

func bypassStreamingResponse(ctx wrapper.HttpContext, buffered string, c pluginConfig, log log.Log) []byte {
	log.Warnf("qwen3guard: streaming response exceeded max_body_bytes %d, fail open", c.maxBodyBytes)
	ctx.SetContext(ctxStreamBypass, true)
	ctx.SetContext(ctxStreamPartial, "")
	ctx.SetContext(ctxStreamPending, "")
	ctx.SetContext(ctxResponseText, "")
	ctx.SetContext(ctxUncheckedText, "")
	ctx.SetContext(ctxStreamDone, false)
	return []byte(buffered)
}
