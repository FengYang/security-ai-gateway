package main

// audit_exit.go — P1-7 T3b（§7.3）：失败/拒绝出口落链补齐与豁免计数。
//
// 背景：T3a 只填字段、不新建落链点，因此"成功已落链、失败无痕"的出口不会被修复。
// 本文件提供统一出口落链入口，配合各 handler 逐条补齐：
//   - A 类（协议面/推理面安全拒绝与鉴权失败）→ auditDenyExit / denyAndAuditMCP（action=deny）；
//   - B 类（管理面/数据面接口失败出口）→ auditAdminExit（action 与成功路径同名，result=rejected_*）；
//   - C 类（豁免：405/健康检查/通用写出/200 出口）→ recordExemptExit（聚合指标计数，不逐条落链）。
//
// 硬约束（C-3/D-1）：本文件写入的全部字段均为**证据字段、omitempty、不进 hash()**
// （path/path_mode/http_status/hit_policies/mcp_session_id…），WORM 旧链逐字节不变；
// hash() 的 10 字段序（audit.go）不受影响。
//
// 无 *teeServer 句柄的通用中间件（requireTenant、limitBody）经包级 auditChainRef 落链
// （启动期装配；单测不装配 → 无副作用）。

import (
	"context"
	"net/http"
)

// auditChainRef 包级审计链引用（启动期装配；供无 *teeServer 句柄的通用中间件落链）。
// 与 auditMetrics 同构：单测不装配 → 落链为 no-op，不影响既有测试。
var auditChainRef *auditChain

// setAuditChainRef 装配包级审计链引用（main 启动期一次）。
func setAuditChainRef(c *auditChain) { auditChainRef = c }

// auditExitGlobal 落一条出口审计（包级；审计链未装配时 no-op）。
// 用于 requireTenant（中间件，无服务器句柄）与 limitBody（通用中间件）的失败出口。
// authActor：中间件场景无 actor，留空（omitempty 不落 JSON）。
func auditExitGlobal(tenant, requestID, action, result, payloadSHA string, status int) {
	c := auditChainRef
	if c == nil {
		return
	}
	c.append(AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: action, Result: result,
		PayloadSHA: payloadSHA, HashAlg: hashAlgTag(), HTTPStatus: status,
	})
}

// recordExemptExit C 类豁免出口计数（§7.3 T3b ③）：以聚合指标计数而非逐条落链。
// handler=handler 名；reason=method_not_allowed|health|common_writer|stream_ok|ok_write。
func recordExemptExit(handler, reason string) {
	if auditMetrics != nil {
		auditMetrics.incAuditExemptExit(handler, reason)
	}
}

// auditDenyExit 落一条拒绝出口审计（A 类；action=deny）。
//
// 与 denyAndAuditCtx 的差异：
//   - 由调用方**显式给出对外状态码**（镜像 handler 的 http.Error 实参），避免 reason→status
//     映射对新增 reason 缺登记而丢状态码；
//   - **不改变租户用量计数**（不调 recordUsage）——本出口为审计完整性补齐，不应扰动
//     /usage 的 Requests/Denies 口径（宁可少记，不误记）。
func (s *teeServer) auditDenyExit(ctx context.Context, tenant, requestID, reason, payloadSHA string, status int) {
	if s == nil || s.audit == nil {
		return
	}
	ev := buildDenyEvent(ctx, AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: "deny",
		Result: reason, PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
		TraceID: traceIDFromContext(ctx), // P1-2：trace_id 证据字段
	}, reason)
	if status != 0 {
		ev.HTTPStatus = status
	}
	s.audit.append(ev)
	if s.metrics != nil {
		s.metrics.incDeny(tenant, reason)
	}
}

// auditDenyExitReq auditDenyExit 的便捷形式：从 *http.Request 取 ctx（nil 安全）。
func (s *teeServer) auditDenyExitReq(r *http.Request, tenant, requestID, reason, payloadSHA string, status int) {
	var ctx context.Context
	if r != nil {
		ctx = r.Context()
	}
	s.auditDenyExit(ctx, tenant, requestID, reason, payloadSHA, status)
}

// denyAndAuditMCP 落一条 MCP 敏感轨拒绝事件（A4-05：补 request_id / mcp_session_id）。
//
// 与 denyAndAuditCtx 同构（含 recordUsage 用量口径，保持 MCP 端点既有行为不变），
// 额外写 MCPSessionID（request_id 不可得时的回退关联键）与显式对外状态码。
func (s *teeServer) denyAndAuditMCP(r *http.Request, tenant, requestID, sessionID, reason, payloadSHA string, status int) {
	if s == nil || s.audit == nil {
		return
	}
	var ctx context.Context
	if r != nil {
		ctx = r.Context()
	}
	s.recordUsage(tenant, 0, 0, true)
	ev := buildDenyEvent(ctx, AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: "deny",
		Result: reason, PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
		TraceID: traceIDFromContext(ctx), MCPSessionID: sessionID,
	}, reason)
	if status != 0 {
		ev.HTTPStatus = status
	}
	s.audit.append(ev)
	if s.metrics != nil {
		s.metrics.incDeny(tenant, reason)
	}
}

// auditAdminExit 落一条管理面/数据面接口失败出口审计（B 类）。
//
// action 与成功路径同名（如 output_guard_mode_change），使"谁尝试升 enforcing 被拒"可与
// 成功变更同族检索；result=rejected_<reason>（reason 族见 §6.2 登记矩阵）。
// tenant="-"（管理面非租户上下文，与既有成功路径一致），actor/request_id 取自请求头。
func (s *teeServer) auditAdminExit(r *http.Request, action, result string, status int) {
	if s == nil || s.audit == nil {
		return
	}
	var ctx context.Context
	actor, reqID, path, pathMode := "", "", "", ""
	if r != nil {
		ctx = r.Context()
		actor = r.Header.Get("X-Admin-Actor")
		reqID = r.Header.Get("X-Request-ID")
		meta := auditReqMetaFromCtx(ctx)
		path, pathMode = meta.Path, meta.PathMode
	}
	s.audit.append(AuditEvent{
		TenantID: "-", UserID: actor, RequestID: reqID,
		Action: action, Result: result, HashAlg: hashAlgTag(),
		TraceID: traceIDFromContext(ctx),
		Path:    path, PathMode: pathMode, HTTPStatus: status,
	})
}
