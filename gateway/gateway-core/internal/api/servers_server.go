// T-3 联邦目录治理：/tools/servers*（本体 §6.1/§7.2、D-4、U-5 默认）。
//
// 语义链：注册域变更 → 目录 servers[] 摘要重派生 → 重签 ToolCatalog（版本单调，R-9）→
// `mcp_server_changed` 审计（fail-closed：变更不留痕不接受 2xx）。摘除 → 其工具自目录收敛
// （`tools/list` 不再返回；**Higress 侧生效机制与时效以集群实测登记**§7.2⑤）。
// 边界：控制面只做登记与签发，不代理 MCP 流量（D-2）。
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/mcpsrv"
	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
	"security-ai-gateway/gateway/mcpsec"
)

// catalogVersion 当前目录版本（无目录 = 0）。
func (s *Server) catalogVersion() int {
	if c := s.store.GetToolCatalog(); c != nil {
		return c.Version
	}
	return 0
}

// handleListServers GET /tools/servers：列出后端注册（含状态/命名空间/前缀，§6.1）。
func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"catalog_version": s.catalogVersion(),
		"servers":         s.store.ListMCPServers(),
	})
}

// handleGetServer GET /tools/servers/{id}。
func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sv := s.store.GetMCPServer(id)
	if sv == nil {
		writeError(w, http.StatusNotFound, "not_found", "后端未注册: "+id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": sv, "catalog_version": s.catalogVersion()})
}

// handleUpsertServer POST /tools/servers：注册/更新（按 id upsert；服务端重签目录，版本单调）。
func (s *Server) handleUpsertServer(w http.ResponseWriter, r *http.Request) {
	var in mcpsrv.Server
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体非法")
		return
	}
	if err := mcpsrv.Validate(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := mcpsrv.CheckConflicts(s.store.ListMCPServers(), &in); err != nil {
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	prev := s.store.GetMCPServer(in.ID)
	var old mcpsrv.Server
	isUpdate := prev != nil
	if isUpdate {
		old = *prev // 值快照：旧值仅用于审计 diff
	}
	in.UpdatedAt = time.Now().Unix()
	s.store.SaveMCPServer(&in)

	verFrom := s.catalogVersion()
	cat, err := s.reSignCatalogWithRegistry(in.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_error",
			fmt.Sprintf("后端已登记但目录重签失败（fail-closed）：%v", err))
		return
	}
	var events []policyaudit.Event
	if isUpdate {
		events = serverUpdateEvents(r, &old, &in, verFrom, cat.Version)
	} else {
		events = []policyaudit.Event{serverEvent(r, policyaudit.ChangeAdded, in.ID, "", "", mcpsrv.SummaryLine(&in), verFrom, cat.Version)}
	}
	if err := s.appendServerAudit(events); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_failed",
			fmt.Sprintf("后端已登记且目录已重签但审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"server": in, "catalog_version": cat.Version})
}

// handleDeleteServer DELETE /tools/servers/{id}：摘除（目录收敛 + 审计，§6.1/§7.2⑤）。
func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	prev := s.store.GetMCPServer(id)
	if prev == nil {
		writeError(w, http.StatusNotFound, "not_found", "后端未注册: "+id)
		return
	}
	old := *prev
	// 目录收敛：摘除该后端名下工具（在途调用按既有规则失败；Higress 侧生效时效以实测登记）。
	converged := 0
	if cat := s.store.GetToolCatalog(); cat != nil {
		kept := make([]mcpsec.TableTool, 0, len(cat.Tools))
		for _, t := range cat.Tools {
			if t.Server == id {
				converged++
				continue
			}
			kept = append(kept, t)
		}
		cat.Tools = kept
	}
	s.store.DeleteMCPServer(id)

	verFrom := s.catalogVersion()
	cat, err := s.reSignCatalogWithRegistry(time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_error",
			fmt.Sprintf("后端已摘除但目录重签失败（fail-closed）：%v", err))
		return
	}
	ev := serverEvent(r, policyaudit.ChangeRemoved, id, "", mcpsrv.SummaryLine(&old), "", verFrom, cat.Version)
	if err := s.appendServerAudit([]policyaudit.Event{ev}); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_failed",
			fmt.Sprintf("后端已摘除且目录已收敛但审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"removed":         true,
		"tools_converged": converged,
		"catalog_version": cat.Version,
	})
}

// reSignCatalogWithRegistry 以注册域摘要刷新目录 servers[] 并重签落库（版本单调，R-9）；
// 同时为已登记后端、Namespace 缺省的工具补全命名空间（"工具默认以 server 前缀命名空间化"）。
func (s *Server) reSignCatalogWithRegistry(now int64) (*mcpsec.ToolCatalog, error) {
	cat := s.store.GetToolCatalog()
	if cat == nil {
		cat = mcpsec.NewToolCatalog(0, 0)
	}
	for i := range cat.Tools {
		t := &cat.Tools[i]
		if t.Server == "" || t.Namespace != "" {
			continue
		}
		if sv := s.store.GetMCPServer(t.Server); sv != nil {
			t.Namespace = sv.Prefix
		}
	}
	cat.Servers = mcpsrv.Summaries(s.store.ListMCPServers())
	cat.Version = s.policyVersion("catalog")
	cat.UpdatedAt = now
	cat.Signature = nil
	if err := s.msigner.SignCatalog(cat); err != nil {
		return nil, err
	}
	s.store.SaveToolCatalog(cat)
	return cat, nil
}

// checkCatalogTools 目录 × 注册域联动校验（T-3，fail-closed）：
//   - 工具声明的 server 必须已注册（未注册即 400，防悬空引用）；
//   - Namespace 缺省以该 server 前缀补全（"工具默认以 server 前缀命名空间化"）；
//   - Namespace 非空须匹配 ^[a-z0-9][a-z0-9-]{0,31}$（禁 `_`：保证 "<ns>__<name>" 可无损解析，C-MCP-1 D-3）；
//   - 命名空间名同名冲突 → 409（U-5 默认：前缀命名空间 + 校验拒绝冲突）。
//
// 返回 (status, code, msg)；status == 0 表示通过。
func (s *Server) checkCatalogTools(c *mcpsec.ToolCatalog) (int, string, string) {
	seen := make(map[string]bool, len(c.Tools))
	for i := range c.Tools {
		t := &c.Tools[i]
		if t.Name == "" {
			return http.StatusBadRequest, "invalid_request", "工具 name 不能为空"
		}
		if t.Server != "" {
			sv := s.store.GetMCPServer(t.Server)
			if sv == nil {
				return http.StatusBadRequest, "invalid_request",
					fmt.Sprintf("工具 %q 引用的后端 %q 未注册（先经 POST /tools/servers 登记）", t.Name, t.Server)
			}
			if t.Namespace == "" {
				t.Namespace = sv.Prefix
			}
		}
		if t.Namespace != "" && !mcpsrv.ValidNamespace(t.Namespace) {
			return http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("工具 %q 的 namespace 非法（须 ^[a-z0-9][a-z0-9-]{0,31}$，禁 `_`）: %q", t.Name, t.Namespace)
		}
		key := t.Namespace + "\x00" + t.Name
		if seen[key] {
			return http.StatusConflict, "conflict",
				fmt.Sprintf("同名工具冲突 %q（U-5 默认：前缀命名空间 + 校验拒绝冲突）", t.NamespacedName())
		}
		seen[key] = true
	}
	return 0, "", ""
}

// serverEvent 构造一条 mcp_server_changed 审计事件（谁/何时/哪条/旧→新 + 重签版本区间）。
func serverEvent(r *http.Request, change, id, field, oldV, newV string, verFrom, verTo int) policyaudit.Event {
	return policyaudit.Event{
		Actor: actorOf(r), Action: policyaudit.ActionMCPServerChanged,
		VersionFrom: verFrom, VersionTo: verTo,
		RuleID: id, Change: change, Field: field,
		OldValue: oldV, NewValue: newV,
		RequestID: r.Header.Get("X-Request-ID"), Result: policyaudit.ResultOK,
	}
}

// serverUpdateEvents 逐字段 diff 更新事件（无变化 = 空集，不产生噪声）。
// track 按**有效轨**比较与留痕（空值 ≡ secure，与工具敏感度审计同口径）。
func serverUpdateEvents(r *http.Request, prev, next *mcpsrv.Server, verFrom, verTo int) []policyaudit.Event {
	var evs []policyaudit.Event
	if prev.BaseURL != next.BaseURL {
		evs = append(evs, serverEvent(r, policyaudit.ChangeUpdated, next.ID, "base_url", prev.BaseURL, next.BaseURL, verFrom, verTo))
	}
	if prev.EffectiveTrack() != next.EffectiveTrack() {
		evs = append(evs, serverEvent(r, policyaudit.ChangeUpdated, next.ID, "track", prev.EffectiveTrack(), next.EffectiveTrack(), verFrom, verTo))
	}
	if prev.Namespace != next.Namespace {
		evs = append(evs, serverEvent(r, policyaudit.ChangeUpdated, next.ID, "namespace", prev.Namespace, next.Namespace, verFrom, verTo))
	}
	if prev.Prefix != next.Prefix {
		evs = append(evs, serverEvent(r, policyaudit.ChangeUpdated, next.ID, "prefix", prev.Prefix, next.Prefix, verFrom, verTo))
	}
	if prev.Health != next.Health {
		evs = append(evs, serverEvent(r, policyaudit.ChangeUpdated, next.ID, "health", prev.Health, next.Health, verFrom, verTo))
	}
	return evs
}

// appendServerAudit 逐条写入注册变更审计链（fail-closed：任一失败即错误，调用方拒绝 2xx）。
func (s *Server) appendServerAudit(events []policyaudit.Event) error {
	for _, ev := range events {
		if _, err := s.audit.Append(ev); err != nil {
			return err
		}
	}
	return nil
}
