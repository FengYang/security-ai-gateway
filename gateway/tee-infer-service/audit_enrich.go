package main

// audit_enrich.go — P1-7 T3a（§3.4 / §6.1(B)）：既有落链点证据字段填充。
//
// 目标：在既有 infer/deny/输出侧落链点补齐 path/path_mode/hit_policies/ttft_ms/dur_ms/http_status，
// 使 §3.4 命中判定式可核。全部字段为**证据字段、omitempty、不进 hash()**（C-3/D-1，旧链逐字节不变）。
//
// 实现口径（对齐 §7.3 T3a）：
//   - **命中判定式**：hit = (hit_policies != "")；不再计算 sampled（D-16）。
//   - **hit_policies**：由**既有拒绝 reason** 映射（复用已算好的判定结果，不重复计算）；
//     非策略类拒绝（协议/引擎/加密错误等）⇒ 空（未命中）。
//   - **path/path_mode**：请求级元数据经 context 传递，入口注入一次（零散点零改动）。
//   - **http_status**：由拒绝 reason 映射（镜像各 handler 的 http.Error 状态码，见 denyHTTPStatus 注释）。
//   - **ttft_ms/dur_ms**：取自 handler 既有计时变量（不新增埋点）。

import (
	"context"
	"strings"
)

// auditReqMeta 请求级审计元数据（规范化路径 + 密态标记），随 context 传递到各落链点。
type auditReqMeta struct {
	Path     string // 规范化路径（不含 query 值）
	PathMode string // plain | encrypted
}

// auditReqMetaKey context 键类型（未导出空结构，避免键冲突）。
type auditReqMetaKey struct{}

// withAuditReqMeta 将请求路径元数据注入 context（请求入口调用一次）。
func withAuditReqMeta(ctx context.Context, path, pathMode string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, auditReqMetaKey{}, auditReqMeta{
		Path:     normalizeAuditPath(path),
		PathMode: pathMode,
	})
}

// auditReqMetaFromCtx 读取请求级审计元数据（缺失返回零值；零值字段 omitempty 不落 JSON）。
func auditReqMetaFromCtx(ctx context.Context) auditReqMeta {
	if ctx == nil {
		return auditReqMeta{}
	}
	if m, ok := ctx.Value(auditReqMetaKey{}).(auditReqMeta); ok {
		return m
	}
	return auditReqMeta{}
}

// normalizeAuditPath 规范化路径（去 query 值；§6.1：path 不含 query）。
func normalizeAuditPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// auditPathMode 路径密态标记（§6.1：plain|encrypted）。
// MCP 敏感轨为不透明信封（密态）；其余 TEE 入口在网关侧为协议信封/明文轨，统一记 plain。
func auditPathMode(path string) string {
	if strings.HasPrefix(path, "/mcp") {
		return "encrypted"
	}
	return "plain"
}

// denyHitPolicy 由拒绝 reason 映射 hit_policies（§6.1(B) 枚举全集；复用既有判定，不重复计算）。
// 返回空串 = 未命中任何安全策略（如协议解码失败/引擎不可用等非策略类拒绝）⇒ 判定式 hit=false。
func denyHitPolicy(reason string) string {
	switch {
	case strings.HasPrefix(reason, "guardrail_"):
		return reason // guardrail_<category>（枚举族 guardrail_*）
	case reason == "bad_signature":
		return "bad_signature"
	case reason == "replay":
		return "replay_attack" // 枚举名 replay_attack（reason 简写 replay）
	case reason == "quota_exceeded":
		return "quota_deny"
	case reason == "cache_negative":
		return "cache_negative"
	case reason == "shadow_reject":
		return "shadow_reject"
	default:
		return "" // 非策略类拒绝
	}
}

// denyHTTPStatus 由拒绝 reason 映射对外状态码（**镜像各 handler `http.Error` 的实参**）。
// ⚠️ 若 handler 状态码调整，须同步本表（单测 TestDenyHTTPStatusMirrorsHandlers 提供回归护栏）。
// 未登记 reason → 0（omitempty 不落 JSON）。
func denyHTTPStatus(reason string) int {
	switch {
	case reason == "bad_signature":
		return 401 // http.StatusUnauthorized
	case reason == "tenant_disposition":
		return 403 // http.StatusForbidden
	case strings.HasPrefix(reason, "guardrail_"):
		if reason == "guardrail_decrypt_error" {
			return 400 // http.StatusBadRequest（解密失败非策略命中）
		}
		return 403 // http.StatusForbidden
	case reason == "quota_exceeded":
		return 429 // http.StatusTooManyRequests
	case reason == "engine_unavailable", reason == "mcp_guard_not_ready":
		return 503 // http.StatusServiceUnavailable
	case reason == "encrypt_error", reason == "encode_error",
		reason == "envelope_seal_error", reason == "keyissue_seal_error":
		return 500 // http.StatusInternalServerError
	case reason == "mcp_tool_deny":
		return 403
	case reason == "replay", reason == "decode_error", reason == "envelope_error",
		reason == "unknown_nonce", reason == "route_rejected", reason == "decrypt_error",
		reason == "text_without_session", reason == "text_payload_invalid",
		reason == "mcp_guard_bad_args", reason == "keyissue_envelope_error",
		reason == "mcp_no_session", reason == "mcp_envelope_error",
		reason == "recompute_layer_mismatch",
		reason == "engine_error":
		return 400 // http.StatusBadRequest
	default:
		return 0
	}
}

// msElapsed 计算自 start 起的毫秒耗时（非负；负值钳为 0）。
func msElapsed(startNanos, nowNanos int64) int {
	d := nowNanos - startNanos
	if d < 0 {
		return 0
	}
	return int(d / 1_000_000)
}

// buildDenyEvent 在既有字段基础上补齐 T3a 证据字段（deny 路径统一入口）。
// base 已含 tenant/requestID/action/result/payloadSHA/hashAlg/traceID。
func buildDenyEvent(ctx context.Context, base AuditEvent, reason string) AuditEvent {
	meta := auditReqMetaFromCtx(ctx)
	base.Path = meta.Path
	base.PathMode = meta.PathMode
	base.HitPolicies = denyHitPolicy(reason)
	base.HTTPStatus = denyHTTPStatus(reason)
	return base
}
