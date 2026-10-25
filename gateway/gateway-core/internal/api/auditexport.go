// P2-4 T-4.2：core 侧审计链导出端点（NDJSON + 链尾/锚点同构，T-4.1 聚合侧消费）。
//
// 路径口径（与 T-4.1 聚合侧 schema=admin|tee|core 对齐）：
//
//	GET /v1/internal/audit/chain/export?schema=core&limit=N
//
// 安全边界（S1(6)，全部由 gateway/auditexport 统一提供）：
//  1. **默认关闭**：仅当显式开关（GATEWAY_CORE_AUDIT_EXPORT_ENABLED=1）启用时
//     才注册本路由；未启用时路由不存在 → 404，零新增攻击面、零回归；
//  2. **授权钩子**：Config.Authorizer，**默认 deny-all**（fail-closed）。
//     真实实现由 **T-2.3 集群身份凭证（签发/校验/轮换/吊销）** 提供并注入
//     （接线点：cmd/main.go setupAuditExport → auditexport.Config.Authorizer），
//     本任务不实现凭证本身；
//  3. **网络边界**：来源 IP CIDR 白名单（GATEWAY_CORE_AUDIT_EXPORT_CIDRS），
//     空 = 不允许任何来源；来源只取 RemoteAddr，不信任 X-Forwarded-For。
//
// 只读语义：导出只调 Chain.Export（内存快照），**不落 WORM、不触发锚定、
// 不改链状态**；拒绝原因不回显细节（授权/白名单失败一律 403 通用文案）。
package api

import (
	"errors"
	"net/http"

	"security-ai-gateway/gateway/auditexport"
)

// auditExportSchema core 侧 schema 标识（T-4.1 聚合侧口径：admin|tee|core）。
const auditExportSchema = "core"

// SetAuditExport 装配审计链导出端点（**仅在此处注册**，默认不注册）。
//
// cfg.Enabled=false → 不注册路由（请求落到 mux 404）；true → 注册并放行门控。
func (s *Server) SetAuditExport(cfg auditexport.Config) {
	s.auditExportCfg = cfg
	if !cfg.Enabled {
		return // 默认关闭：不注册、不放行、零行为变化
	}
	s.mux.HandleFunc("GET /v1/internal/audit/chain/export", s.handleAuditExport)
}

// handleAuditExport 导出策略变更审计链（NDJSON，每行一条事件）。
//
// 响应：body = 纯 NDJSON（与 policyaudit WORM 行格式逐字节一致，可供 audit-verify
// 独立重算）；元信息（schema / 事件数 / 链尾哈希 / 是否截断 / 锚点）经
// X-Audit-Export-* 响应头下发。
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		auditexport.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "仅支持 GET")
		return
	}
	// 门控：未启用 → 404；授权失败 / 来源不在白名单 → 403（不回显具体原因）。
	if err := s.auditExportCfg.Check(r); err != nil {
		if errors.Is(err, auditexport.ErrDisabled) {
			auditexport.WriteError(w, http.StatusNotFound, "not_found", "端点未启用")
			return
		}
		auditexport.WriteError(w, http.StatusForbidden, "forbidden", "导出请求未被授权")
		return
	}
	// schema 口径：缺省 core；显式传非 core（如 tee/admin）→ 400（避免聚合侧误配）。
	schema := r.URL.Query().Get("schema")
	if schema == "" {
		schema = auditExportSchema
	}
	if schema != auditExportSchema {
		auditexport.WriteError(w, http.StatusBadRequest, "bad_schema", "schema 必须为 core")
		return
	}
	limit, clamped, err := auditexport.ParseLimit(r.URL.Query().Get("limit"), s.auditExportCfg.MaxLimit)
	if err != nil {
		auditexport.WriteError(w, http.StatusBadRequest, "bad_limit", "limit 参数非法")
		return
	}
	res, err := s.audit.Export(limit)
	if err != nil {
		auditexport.WriteError(w, http.StatusInternalServerError, "export_failed", "审计链导出失败")
		return
	}
	meta := auditexport.Meta{
		Schema:    auditExportSchema,
		Events:    res.Events,
		Total:     res.Total,
		PrevHash:  res.PrevHash,
		TailHash:  res.TailHash,
		Truncated: res.Truncated || clamped,
		// core 侧策略变更链暂无独立锚定文件（锚点语义 = 链尾哈希 TailHash，
		// 由外部锚定/聚合侧留痕比对）；字段与 tee 侧同构，此处留零值。
	}
	auditexport.WriteNDJSON(w, res.Lines, meta)
}
