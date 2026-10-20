// Package api: gateway-core 的 HTTP API 层。
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/gateway-core/internal/a2aregistry"
	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// policyHistoryLimit 策略历史保留版本数（回滚可回溯范围；重启后仅剩当前版本）。
const policyHistoryLimit = 16

// Server 组合 HTTP 处理器与依赖。
type Server struct {
	signer   *route.Signer
	msigner  *mcpsec.Signer
	rlsigner *ratelimit.Signer
	teeQuota TeeQuotaApplier // nil = 未配置（不做 TEE 侧配额下发）
	store    store.Store
	token    string // 内网静态鉴权 token
	mux      *http.ServeMux
	audit    *policyaudit.Chain // 策略变更审计链（Phase 1 门禁 #7 / 判据 7；默认内存，可用 SetPolicyAuditFile 落 WORM）
	metrics  *coreMetrics       // 控制面指标（门禁 #7/#9）
	histMu   sync.Mutex
	history  []*ratelimit.Table // 历史版本（含当前），用于按 version 回滚
	// P1-6 M3.1/M3.3：TTFT 聚合（分片环形 + batch_id 去重；控制面非热路径）。
	ttftRing  *route.TTFTRing
	ttftDedup *route.TTFTDedup
	// P1-6 M3.5：stats 下发 generated_at 单调性（毫秒，严格递增）。
	ttftGenMu sync.Mutex
	ttftGenAt int64
	// P1-6 M3.6：reset 水位（epoch）——(tenant|model) → 最近 reset 秒；上报 reported_at 早于水位丢弃。
	ttftResetMu sync.Mutex
	ttftResetAt map[string]int64
	// P2-2 T-2：A2A 注册中心控制面（nil = 未启用；启用后挂载 /v1/a2a/* 与 /internal/a2a/snapshot）。
	a2aReg *a2aregistry.Registry
	// P2-2 T-3：A2A ACL 策略表（独立策略域，R-6）。
	aclSigner *a2aproxy.ACLSigner
	aclMu     sync.Mutex
	aclHist   []*a2aproxy.ACLTable // ACL 历史版本（含当前），用于按 version 回滚
	// P2-2 T-3a：A2A 复合限流表（独立策略域，R-6）。
	rlSigner *a2aproxy.RateLimitSigner
	rlMu     sync.Mutex
	rlHist   []*a2aproxy.RateLimitTable // 限流历史版本（含当前），用于按 version 回滚
}

// New 构造 API Server。routerTable 为启动时注入的已签名默认路由表（可为空表）；
// rateLimitTable 为启动时注入的已签名默认限流表（可为空表，Phase 1 门禁 #7）；
// teeQuota 为 TEE 侧配额下发器（nil = 未配置，此时预算/TPM 仅在响应 Note 中说明）。
func New(signer *route.Signer, msigner *mcpsec.Signer, rlsigner *ratelimit.Signer, teeQuota TeeQuotaApplier,
	st store.Store, authToken string, routerTable *route.RouteTable, rateLimitTable *ratelimit.Table) *Server {
	if routerTable != nil {
		st.SaveRouteTable(routerTable)
	}
	if rateLimitTable != nil {
		st.SaveRateLimitTable(rateLimitTable)
	}
	s := &Server{
		signer: signer, msigner: msigner, rlsigner: rlsigner, teeQuota: teeQuota,
		store: st, token: authToken, mux: http.NewServeMux(),
		audit: &policyaudit.Chain{}, metrics: newCoreMetrics(),
		ttftRing:    route.NewTTFTRing(nil),
		ttftDedup:   route.NewTTFTDedup(),
		ttftResetAt: make(map[string]int64),
	}
	if rateLimitTable != nil {
		s.recordHistory(rateLimitTable)
		s.metrics.setTable(rateLimitTable.Version, ruleDimensionCounts(rateLimitTable))
	}
	s.routes()
	return s
}

// SetPolicyAuditFile 启用策略变更审计的 WORM 持久化（启动时调用一次）。
// 文件损坏/不可写 → 返回错误，调用方应拒绝启动（fail-closed：变更审计不可用即不留痕）。
func (s *Server) SetPolicyAuditFile(path string) error {
	if path == "" {
		return nil
	}
	chain, err := policyaudit.New(path)
	if err != nil {
		return err
	}
	s.audit = chain
	return nil
}

// SetACLSigner 注入 A2A ACL 表签名器（P2-2 T-3）。
//
// 与限流表**同一 K_rx 密钥**、同一分发通道，但 ACL 是**独立策略域**（R-6）：
// 独立端点前缀（/a2a-acls）、独立表对象、独立签名对象。
//
// nil（未注入）时 ACL 端点仍可读，但 PUT/rollback 一律拒绝（无签名器不得签表）。
func (s *Server) SetACLSigner(signer *a2aproxy.ACLSigner) {
	s.aclSigner = signer
}

// recordACLHistory 记录 ACL 历史版本（用于按 version 回滚）。
func (s *Server) recordACLHistory(t *a2aproxy.ACLTable) {
	if t == nil {
		return
	}
	s.aclMu.Lock()
	defer s.aclMu.Unlock()
	s.aclHist = append(s.aclHist, t)
	if len(s.aclHist) > aclHistoryLimit {
		s.aclHist = s.aclHist[len(s.aclHist)-aclHistoryLimit:]
	}
}

// findACLHistory 按 version 查 ACL 历史版本。
func (s *Server) findACLHistory(version int) *a2aproxy.ACLTable {
	s.aclMu.Lock()
	defer s.aclMu.Unlock()
	for _, t := range s.aclHist {
		if t.Version == version {
			return t
		}
	}
	return nil
}

// SetA2ARegistry 挂载 A2A 注册中心控制面（P2-2 T-2；冻结 §5.3）。
//
// 路由（注册到同一 mux，与既有控制面共用监听端口）：
//
//	POST/GET   /v1/a2a/agents
//	GET/PUT/DELETE /v1/a2a/agents/{name}
//	POST       /v1/a2a/agents/{name}/verify
//	POST/GET   /v1/a2a/providers/{provider}/keys
//	POST       /v1/a2a/providers/{provider}/keys/{kid}/revoke
//	DELETE     /v1/a2a/providers/{provider}/keys/{kid}
//	GET        /internal/a2a/snapshot
//
// ⚠️ 认证**不走**本包的 withAuth：A2A 控制面有独立的认证模型（JWT tenant/role，
// 生产；静态 token 仅 DevMode），由 a2aregistry 内部实现（冻结 §5.4），
// 租户一律取自 JWT 授权结果，body/path 不得覆盖。
func (s *Server) SetA2ARegistry(reg *a2aregistry.Registry) {
	if reg == nil {
		return
	}
	s.a2aReg = reg
	reg.Mount(s.mux)
}

// A2ARegistry 返回已挂载的 A2A 注册中心（nil = 未启用）。
func (s *Server) A2ARegistry() *a2aregistry.Registry { return s.a2aReg }

// ClosePolicyAudit 关闭审计链文件（进程退出时调用）。
func (s *Server) ClosePolicyAudit() error { return s.audit.Close() }

// PolicyAuditChain 返回策略变更审计链（供 A2A 注册中心复用同一条链，
// 保证两类变更事件处于同一哈希链，冻结 §5.7「异步上报既有审计链」）。
func (s *Server) PolicyAuditChain() *policyaudit.Chain { return s.audit }

// recordHistory 记录策略表历史版本（保留最近 policyHistoryLimit 版）。
func (s *Server) recordHistory(t *ratelimit.Table) {
	if t == nil {
		return
	}
	s.histMu.Lock()
	defer s.histMu.Unlock()
	s.history = append(s.history, t.Clone())
	if len(s.history) > policyHistoryLimit {
		s.history = s.history[len(s.history)-policyHistoryLimit:]
	}
}

// findHistory 按 version 取历史版本（找不到返回 nil）。
func (s *Server) findHistory(version int) *ratelimit.Table {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	for i := len(s.history) - 1; i >= 0; i-- {
		if s.history[i].Version == version {
			return s.history[i].Clone()
		}
	}
	return nil
}

// ruleDimensionCounts 统计规则维度分布（kind|scope|action → 条数）。
func ruleDimensionCounts(t *ratelimit.Table) map[string]int {
	out := map[string]int{}
	if t == nil {
		return out
	}
	for _, r := range t.Rules {
		out[string(r.Kind)+"|"+string(r.Scope)+"|"+string(r.Action)]++
	}
	return out
}

// actorOf 取变更发起人（调用方经 X-Actor 传入；缺省 "unknown"——如实记录未知发起人，
// 不伪造成某个具体账号）。生产由管理面/控制台在代理时注入登录用户。
func actorOf(r *http.Request) string {
	if a := r.Header.Get("X-Actor"); a != "" {
		return a
	}
	return "unknown"
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
	// 路由配置管理（方案 §4.1，P0-1 W4-2）
	s.mux.HandleFunc("GET /routes/{tenant}/{model}", s.withAuth(s.handleGetRoute))
	// P1-2：路由变更端点包裹 `core.route.change` span（§7.4；tracing 关闭时零开销透传）
	s.mux.HandleFunc("PUT /routes/{tenant}/{model}", s.withAuth(s.withRouteChangeSpan("upsert", s.handleUpsertRoute)))
	s.mux.HandleFunc("DELETE /routes/{tenant}/{model}", s.withAuth(s.withRouteChangeSpan("delete", s.handleDeleteRoute)))
	s.mux.HandleFunc("POST /routes/dry-run", s.withAuth(s.handleDryRun))
	s.mux.HandleFunc("GET /routes/endpoints/status", s.withAuth(s.handleEndpointStatus))
	// P1-6 M3.4：TTFT 上报（数据面 → 控制面；§6.2）
	s.mux.HandleFunc("POST /routes/ttft/report", s.withAuth(s.handleTTFTReport))
	// P1-6 M3.5：TTFT 统计下发（控制面 → 数据面；§6.3）
	s.mux.HandleFunc("GET /routes/ttft/stats", s.withAuth(s.handleTTFTStats))
	// P1-6 M3.6：TTFT 统计重置（运维；§6.2，落 policyaudit）
	s.mux.HandleFunc("POST /routes/ttft/reset", s.withAuth(s.handleTTFTReset))
	s.mux.HandleFunc("POST /routes/rollback", s.withAuth(s.withRouteChangeSpan("rollback", s.handleRouteRollback)))
	s.mux.HandleFunc("GET /routes/history", s.withAuth(s.handleRouteHistory))
	s.mux.HandleFunc("POST /routes/push", s.withAuth(s.handleRoutePush))
	s.mux.HandleFunc("GET /routes/audit", s.withAuth(s.handleRouteAudit))
	// 限流/预算表（Phase 1 门禁 #7）：GET 下发（拉路径）、PUT 策略源（校验+防回滚+签名）、
	// history 变更审计查询、rollback 按版本回滚（判据 7）。
	s.mux.HandleFunc("GET /ratelimits", s.withAuth(s.handleGetRateLimits))
	s.mux.HandleFunc("PUT /ratelimits", s.withAuth(s.handlePutRateLimits))
	s.mux.HandleFunc("GET /ratelimits/history", s.withAuth(s.handleRateLimitHistory))
	s.mux.HandleFunc("POST /ratelimits/rollback", s.withAuth(s.handleRateLimitRollback))
	// P2-2 T-3：A2A ACL 策略表（独立策略域，R-6）——与 /ratelimits 同构：
	// GET 下发（拉路径）、PUT 策略源（校验+防回滚+签名）、history 变更审计、rollback 按版本回滚。
	s.mux.HandleFunc("GET /a2a-acls", s.withAuth(s.handleGetACLs))
	s.mux.HandleFunc("PUT /a2a-acls", s.withAuth(s.handlePutACLs))
	s.mux.HandleFunc("GET /a2a-acls/history", s.withAuth(s.handleACLHistory))
	s.mux.HandleFunc("POST /a2a-acls/rollback", s.withAuth(s.handleACLRollback))
	// P2-2 T-3a：A2A 复合限流表（独立策略域，R-6）——与 /a2a-acls 同构：
	// GET 下发（拉路径）、PUT 策略源（校验+防回滚+签名）、history 变更审计、rollback 按版本回滚。
	s.mux.HandleFunc("GET /a2a-ratelimits", s.withAuth(s.handleGetRateLimitsA2A))
	s.mux.HandleFunc("PUT /a2a-ratelimits", s.withAuth(s.handlePutRateLimitsA2A))
	s.mux.HandleFunc("GET /a2a-ratelimits/history", s.withAuth(s.handleRateLimitHistoryA2A))
	s.mux.HandleFunc("POST /a2a-ratelimits/rollback", s.withAuth(s.handleRateLimitRollbackA2A))
	s.mux.HandleFunc("POST /tools/policy", s.withAuth(s.handleToolPolicy))
	s.mux.HandleFunc("GET /tools/policy", s.withAuth(s.handleGetToolPolicy))
	// T-3 联邦目录治理（D-4/§6.1）：后端注册 CRUD——变更即重签目录（版本单调）+ mcp_server_changed 审计
	s.mux.HandleFunc("GET /tools/servers", s.withAuth(s.handleListServers))
	s.mux.HandleFunc("POST /tools/servers", s.withAuth(s.handleUpsertServer))
	s.mux.HandleFunc("GET /tools/servers/{id}", s.withAuth(s.handleGetServer))
	s.mux.HandleFunc("DELETE /tools/servers/{id}", s.withAuth(s.handleDeleteServer))
	s.mux.HandleFunc("GET /metrics", s.withAuth(s.handleMetrics))
	s.mux.HandleFunc("GET /health", s.handleHealth)
	// P2-2 T-2：冻结 §5.3 的健康端点名为 /healthz；与既有 /health 同一处理器（免鉴权）。
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
}

// issueReq 签发请求体。
type issueReq struct {
	Tenant          string `json:"tenant"`
	Model           string `json:"model"`
	PreferredEngine string `json:"preferred_engine,omitempty"`
	FallbackEngine  string `json:"fallback_engine,omitempty"`
	CostPriority    string `json:"cost_priority,omitempty"`
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
// P2-2 T-2：增补 A2A 注册中心就绪字段（a2a_registry_ready/revision/db，冻结 §5.3）。
// 未启用注册中心时 ready=false、db="disabled"。
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"status": "ok"}
	if s.a2aReg != nil {
		for k, v := range s.a2aReg.Health() {
			out[k] = v
		}
	} else {
		out["a2a_registry_ready"] = false
		out["a2a_registry_revision"] = 0
		out["a2a_registry_db"] = "disabled"
	}
	writeJSON(w, http.StatusOK, out)
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
