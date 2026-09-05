// Package api: gateway-core 的 HTTP API 层。
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// Server 组合 HTTP 处理器与依赖。
type Server struct {
	signer  *route.Signer
	msigner *mcpsec.Signer
	store   store.Store
	token   string // 内网静态鉴权 token
	mux     *http.ServeMux
}

// New 构造 API Server。routerTable 为启动时注入的已签名默认路由表（可为空表）。
func New(signer *route.Signer, msigner *mcpsec.Signer, st store.Store, authToken string, routerTable *route.RouteTable) *Server {
	if routerTable != nil {
		st.SaveRouteTable(routerTable)
	}
	s := &Server{signer: signer, msigner: msigner, store: st, token: authToken, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler 暴露给 net/http。
func (s *Server) Handler() http.Handler { return s.mux }

// routes 注册路由。
func (s *Server) routes() {
	s.mux.HandleFunc("POST /prescriptions", s.withAuth(s.handleIssue))
	s.mux.HandleFunc("GET /prescriptions/{id}", s.withAuth(s.handleGet))
	s.mux.HandleFunc("DELETE /prescriptions/{id}", s.withAuth(s.handleDelete))
	s.mux.HandleFunc("GET /prescriptions", s.withAuth(s.handleListByTenant))
	s.mux.HandleFunc("GET /routes", s.withAuth(s.handleGetRoutes))
	s.mux.HandleFunc("POST /tools/policy", s.withAuth(s.handleToolPolicy))
	s.mux.HandleFunc("GET /tools/policy", s.withAuth(s.handleGetToolPolicy))
	s.mux.HandleFunc("GET /health", s.handleHealth)
}

// issueReq 签发请求体。
type issueReq struct {
	Tenant        string       `json:"tenant"`
	Model         string       `json:"model"`
	PreferredEngine string     `json:"preferred_engine,omitempty"`
	FallbackEngine  string     `json:"fallback_engine,omitempty"`
	CostPriority    string     `json:"cost_priority,omitempty"`
}

// issueResp 签发响应。
type issueResp struct {
	PrescriptionID string `json:"prescription_id"`
	SignedToken    string `json:"signed_token"`
	ExpiresAt      int64  `json:"expires_at"`
}

// handleIssue 签发处方。
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体非法")
		return
	}
	if req.Tenant == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant 必填")
		return
	}
	if req.Model == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "model 必填")
		return
	}
	now := time.Now()
	p := &route.RoutePrescription{
		PrescriptionID: newID("rx"),
		Tenant:         req.Tenant,
		Model:          req.Model,
		CreatedAt:      now.Unix(),
		ExpiresAt:      now.Add(time.Duration(route.TimeSkew) * time.Second).Unix(),
		JTI:            newID("jti"),
	}
	if req.PreferredEngine != "" {
		p.Policy = &route.RoutePolicy{
			PreferredEngine: req.PreferredEngine,
			FallbackEngine:  req.FallbackEngine,
			CostPriority:    req.CostPriority,
		}
	}
	if err := s.store.Save(p); err != nil {
		writeError(w, http.StatusConflict, "duplicate", "处方已存在")
		return
	}
	tok, err := s.signer.Issue(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign_error", "处方签名失败")
		return
	}
	writeJSON(w, http.StatusCreated, issueResp{
		PrescriptionID: p.PrescriptionID,
		SignedToken:    tok,
		ExpiresAt:      p.ExpiresAt,
	})
}

// handleGetRoutes 返回当前默认路由表（拉路径 B 的数据源）。
// 始终返回签名校验一致的完整表；插件侧用 Lookup(tenant,model) 本地过滤，
// 避免"过滤后内容与签名不匹配"的失效问题。
func (s *Server) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetRouteTable()
	if tbl == nil {
		tbl = route.NewRouteTable(0, 0)
	}
	writeJSON(w, http.StatusOK, tbl)
}

// handleGet 查询单条处方。
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := s.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "处方不存在")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleDelete 吊销处方。
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.store.Delete(id)
	w.WriteHeader(http.StatusNoContent)
}

// handleListByTenant 列出租户处方。
func (s *Server) handleListByTenant(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant 必填")
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListByTenant(tenant))
}

// handleHealth 健康检查。
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// withAuth 内网静态 token 鉴权。
func (s *Server) withAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			got := r.Header.Get("Authorization")
			if got != "Bearer "+s.token {
				writeError(w, http.StatusUnauthorized, "unauthorized", "未授权")
				return
			}
		}
		h(w, r)
	}
}

// newID 生成 16 字节随机 hex 标识，带前缀。
func newID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, codeStr, msg string) {
	writeJSON(w, code, map[string]string{"code": codeStr, "message": msg})
}