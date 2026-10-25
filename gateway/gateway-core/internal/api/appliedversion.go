// P2-4 T-3.4：core 侧「插件 applied 配置版本」接入层（拉取头捕获 + 状态暴露）。
//
// 口径来源：设计 §6.2（L270）+ 评审处置记录 C6(7)：
//
//	插件拉取 /routes 的请求头 X-Config-Version（当前生效版本）
//	  → core 缓存「最近上报版本 + 时间」
//	  → 心跳上报管理面（applied_config_version）／状态查询可见
//
// 本文件（core 侧）的硬边界：
//   - **只如实记录**插件上报了什么，**不做收敛判定**（期望 vs 实际的比较在管理面
//     sync-status，T-3.3）；
//   - **无版本头 = 未上报（unknown）**：不写、不覆盖既有记录；
//   - **非法版本头 = 忽略**：拉取照常成功（业务请求不受影响）。
//
// ⚠️ 插件侧改动（携带该请求头）属 **P1-8 归属**（gateway/wasm/otpmask-plugin/**），
// 本任务不触碰插件代码；此处仅登记接口契约。
//
// ── 与管理面 sync-status 的字段契约（P2-4 T-3.3）──
//
// GET /v1/internal/applied-config-version 是 T-3.3「收敛核对 API sync-status」的
// **core 侧数据源**（实现无需改动，此处仅登记契约）。管理面聚合侧按下列口径消费：
//
//	字段                       含义                             聚合侧处置
//	applied_config_version     最近一次被采纳的上报版本           known=true 时参与"期望 vs 实际"比较
//	known                      是否有有效上报（false = unknown）   false ⇒ 该集群该维度标 **unknown**
//	last_reported_version      最近一次**收到的**上报值（含被拒）   仅排障用，**不参与**比较
//	seq                        采纳计数（单调）                    仅观测
//	reported_at/last_seen_at   采纳时间 / 最近见到上报的时间         仅观测
//
// ⚠️ **unknown 口径（硬约束，聚合侧必须遵守）**：读到 `known=false` 时——
//
//	理由：core 侧只如实记录插件上报了什么；"插件从未上报"与"插件已应用同一版本"
//	在数据上不可区分，若默认收敛，则插件拉取失败/未拉取会被静默掩盖。
//
//  1. 必须把该集群该维度标记为 **unknown**（**不是**"一致"、**不是**"无差异"）；
//  2. **禁止**以「未见差异」默认收敛（"没看到上报" ≠ "已收敛"）；
//  3. 必须触发告警（unknown 是可观测缺口，不是静默通过）。
//
// 心跳侧口径一致：core 心跳上报体为 {"applied_config_version": "<版本>"}，
// 从未上报时为空串；admin-service 侧对空串**不覆盖**既有值（unknown 语义一致）。
package api

import (
	"net/http"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/configversion"
)

// appliedVersionPath 状态查询端点（内部）：暴露最近上报的 applied 配置版本。
const appliedVersionPath = "/v1/internal/applied-config-version"

// captureAppliedVersion 从拉取请求头捕获插件上报的 applied 配置版本。
//
// 口径：
//   - 头缺失/为空 ⇒ 未上报（unknown），**不写、不覆盖**（既有值保持不变）；
//   - 头非法 ⇒ 忽略（仅计数），**不 fail 业务请求**（拉取照常返回表）；
//   - 头合法 ⇒ 记入缓存；陈旧值（低于已采纳值）不被采纳（单调不回退）。
//
// 位置说明：仅在**鉴权通过后**的路由拉取处理链内调用（handleGetRoutes 位于 withAuth
// 之内）⇒ 未授权请求无法污染缓存。
func (s *Server) captureAppliedVersion(r *http.Request) {
	if s.appliedVer == nil || r == nil {
		return
	}
	raw := r.Header.Get(configversion.HeaderName)
	if raw == "" {
		// 无版本头 = 未上报：不写、不覆盖（unknown 语义）。
		return
	}
	// 非法头在这里被忽略（ok=false），不影响后续业务处理。
	s.appliedVer.Report(configversion.SourceRoutes, raw, time.Now())
}

// AppliedConfigVersion 返回最近一次被采纳的 applied 配置版本。
//
// ok=false ⇒ 从未收到有效上报（unknown）。调用方（如心跳上报侧）据此决定是否上报；
// **core 不在此处做收敛判定**（期望 vs 实际属管理面 sync-status 的职责）。
func (s *Server) AppliedConfigVersion() (configversion.Record, bool) {
	if s == nil || s.appliedVer == nil {
		return configversion.Record{Source: configversion.SourceRoutes}, false
	}
	return s.appliedVer.Get(configversion.SourceRoutes)
}

// handleAppliedConfigVersion GET /v1/internal/applied-config-version：状态查询。
//
// 鉴权：与控制面其余端点一致（内网静态 token；未配置 token 时不鉴权，与既有行为同）。
// 语义：如实反映缓存内容；未上报时 applied_config_version 为空串且 known=false
// （调用方据此标 unknown，**禁止**以「未见差异」默认收敛）。
func (s *Server) handleAppliedConfigVersion(w http.ResponseWriter, _ *http.Request) {
	rec, known := s.AppliedConfigVersion()
	out := map[string]any{
		"source":                 configversion.SourceRoutes,
		"applied_config_version": rec.Version,
		"known":                  known,
		"last_reported_version":  rec.LastReportedVersion,
		"seq":                    rec.Seq,
		"accepted_count":         rec.Accepted,
		"rejected_invalid_count": rec.RejectedInvalid,
		"rejected_stale_count":   rec.RejectedStale,
	}
	if !rec.ReportedAt.IsZero() {
		out["reported_at"] = rec.ReportedAt.UTC().Format(time.RFC3339)
	}
	if !rec.LastSeenAt.IsZero() {
		out["last_seen_at"] = rec.LastSeenAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}
