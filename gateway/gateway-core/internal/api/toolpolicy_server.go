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

// toolPolicyReq 下发工具目录/授权策略的请求体。Kind 区分类型，Data 为原始对象
// （版本/签名由服务端权威重签，客户端提交的 version/signature 不采信）。
type toolPolicyReq struct {
	Kind string          `json:"kind"` // "catalog" | "policy"
	Data json.RawMessage `json:"data"`
}

// policyVersion 当前已存对象的版本号；无则从 1 开始。
func (s *Server) policyVersion(kind string) int {
	if kind == "catalog" {
		if c := s.store.GetToolCatalog(); c != nil {
			return c.Version + 1
		}
	} else if kind == "policy" {
		if p := s.store.GetRBACPolicy(); p != nil {
			return p.Version + 1
		}
	}
	return 1
}

// handleToolPolicy 签发/更新工具目录或授权策略（服务端重签，版本单调自增）。
func (s *Server) handleToolPolicy(w http.ResponseWriter, r *http.Request) {
	var req toolPolicyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体非法")
		return
	}
	now := time.Now().Unix()
	switch req.Kind {
	case "catalog":
		var c mcpsec.ToolCatalog
		if err := json.Unmarshal(req.Data, &c); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "catalog 数据非法")
			return
		}
		// T-3：目录 × 注册域联动（fail-closed）——未注册后端引用拒绝、namespace 缺省补全、
		// 同名冲突拒绝（U-5 默认）；servers[] 摘要为注册域派生值，不采信客户端提交。
		if status, code, msg := s.checkCatalogTools(&c); status != 0 {
			writeError(w, status, code, msg)
			return
		}
		c.Servers = mcpsrv.Summaries(s.store.ListMCPServers())
		// T-6：敏感度（Track）变更须独立留痕（防静默改判 → 工具跨轨迁移，§4.6.2）。
		// 重签落库前先按**有效轨**（ToolTrack()：空值视同 secure）算出跨轨迁移记录。
		prev := s.store.GetToolCatalog()
		trackChanges := diffTrackChanges(prev, &c)
		c.Version = s.policyVersion("catalog")
		c.UpdatedAt = now
		c.Signature = nil
		if err := s.msigner.SignCatalog(&c); err != nil {
			writeError(w, http.StatusInternalServerError, "sign_error", "目录签名失败")
			return
		}
		s.store.SaveToolCatalog(&c)
		// 审计落链 fail-closed（对齐 applyTable 口径）：变更不留痕即不可接受。
		if err := s.appendTrackAudit(r, prev, &c, trackChanges); err != nil {
			writeError(w, http.StatusInternalServerError, "audit_failed",
				fmt.Sprintf("工具目录已在控制面生效但敏感度变更审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
			return
		}
		writeJSON(w, http.StatusCreated, &c)
	case "policy":
		var p mcpsec.RBACPolicy
		if err := json.Unmarshal(req.Data, &p); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "policy 数据非法")
			return
		}
		p.Version = s.policyVersion("policy")
		p.UpdatedAt = now
		p.Signature = nil
		if err := s.msigner.SignPolicy(&p); err != nil {
			writeError(w, http.StatusInternalServerError, "sign_error", "策略签名失败")
			return
		}
		s.store.SaveRBACPolicy(&p)
		writeJSON(w, http.StatusCreated, &p)
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "kind 仅支持 catalog|policy")
	}
}

// handleGetToolPolicy 返回当前已签名工具目录或授权策略（拉路径数据源，恒返回完整签名对象，
// 由消费方本地过滤/校验，避免过滤后签名失效）。
func (s *Server) handleGetToolPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("kind") {
	case "catalog":
		c := s.store.GetToolCatalog()
		if c == nil {
			c = mcpsec.NewToolCatalog(0, 0)
		}
		writeJSON(w, http.StatusOK, c)
	case "policy":
		p := s.store.GetRBACPolicy()
		if p == nil {
			p = mcpsec.NewRBACPolicy(0, 0)
		}
		writeJSON(w, http.StatusOK, p)
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "kind 仅支持 catalog|policy")
	}
}

// trackChange 一条工具敏感度（Track）跨轨迁移记录。
type trackChange struct {
	Tool string
	From string // 有效轨（ToolTrack()）
	To   string
}

// diffTrackChanges 比较新旧目录的**有效轨**（ToolTrack()：空值视同 secure），
// 返回同一工具发生跨轨迁移的记录。新增/删除工具不算 Track 变更（不在此列）。
// 键＝命名空间名（T-3：命名空间化后同名不同空间不串扰）。
func diffTrackChanges(prev, next *mcpsec.ToolCatalog) []trackChange {
	if prev == nil || next == nil {
		return nil
	}
	old := make(map[string]string, len(prev.Tools))
	for i := range prev.Tools {
		old[prev.Tools[i].NamespacedName()] = prev.Tools[i].ToolTrack()
	}
	var out []trackChange
	for i := range next.Tools {
		t := next.Tools[i]
		was, ok := old[t.NamespacedName()]
		if !ok {
			continue // 新增工具：非 Track 变更
		}
		if now := t.ToolTrack(); now != was {
			out = append(out, trackChange{Tool: t.NamespacedName(), From: was, To: now})
		}
	}
	return out
}

// appendTrackAudit 逐条敏感度变更写入控制面审计链（action=mcp_track_changed，T-6 / §4.6.2）。
// 无变更 → 不产生事件（版本单调推进本身由目录签名保障）。
// 含 hash 无明文：事件进哈希链（prev_hash 串接，可经 audit-verify "core" schema 复算），
// 仅记工具标识与轨取值，**不落**工具 schema/参数明文。
func (s *Server) appendTrackAudit(r *http.Request, prev, next *mcpsec.ToolCatalog, changes []trackChange) error {
	if len(changes) == 0 {
		return nil
	}
	from := 0
	if prev != nil {
		from = prev.Version
	}
	actor := actorOf(r)
	reqID := r.Header.Get("X-Request-ID")
	for _, c := range changes {
		ev := policyaudit.Event{
			Actor: actor, Action: policyaudit.ActionMCPTrackChanged,
			VersionFrom: from, VersionTo: next.Version,
			RuleID: c.Tool, Change: policyaudit.ChangeUpdated, Field: "track",
			OldValue: c.From, NewValue: c.To,
			RequestID: reqID, Result: policyaudit.ResultOK,
		}
		if _, err := s.audit.Append(ev); err != nil {
			return err
		}
	}
	return nil
}
