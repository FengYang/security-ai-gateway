package api

import (
	"encoding/json"
	"net/http"
	"time"

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
		c.Version = s.policyVersion("catalog")
		c.UpdatedAt = now
		c.Signature = nil
		if err := s.msigner.SignCatalog(&c); err != nil {
			writeError(w, http.StatusInternalServerError, "sign_error", "目录签名失败")
			return
		}
		s.store.SaveToolCatalog(&c)
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