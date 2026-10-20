package a2aregistry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
)

// maxControlBodyBytes 是控制面请求体上限（1 MiB，冻结 §5.9）。
const maxControlBodyBytes = 1 << 20

// Handler 返回控制面 HTTP 处理器（/v1/a2a/... 与 /internal/a2a/snapshot）。
//
// 路由（冻结 §5.3）：
//
//	POST   /v1/a2a/agents
//	GET    /v1/a2a/agents
//	GET    /v1/a2a/agents/{name}
//	PUT    /v1/a2a/agents/{name}
//	DELETE /v1/a2a/agents/{name}
//	POST   /v1/a2a/agents/{name}/verify
//	POST   /v1/a2a/providers/{provider}/keys
//	GET    /v1/a2a/providers/{provider}/keys
//	POST   /v1/a2a/providers/{provider}/keys/{kid}/revoke
//	DELETE /v1/a2a/providers/{provider}/keys/{kid}
//	GET    /internal/a2a/snapshot
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	r.Mount(mux)
	return mux
}

// Mount 把控制面路由注册到给定的 mux（供 gateway-core 主 mux 挂载，
// 避免另起监听端口——冻结 §5.3「控制面监听 gateway-core 管理端口」）。
func (r *Registry) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/a2a/agents", r.handleRegister)
	mux.HandleFunc("GET /v1/a2a/agents", r.handleList)
	mux.HandleFunc("GET /v1/a2a/agents/{name}", r.handleGet)
	mux.HandleFunc("PUT /v1/a2a/agents/{name}", r.handleReplace)
	mux.HandleFunc("DELETE /v1/a2a/agents/{name}", r.handleDelete)
	mux.HandleFunc("POST /v1/a2a/agents/{name}/verify", r.handleVerify)
	mux.HandleFunc("POST /v1/a2a/providers/{provider}/keys", r.handleImportKey)
	mux.HandleFunc("GET /v1/a2a/providers/{provider}/keys", r.handleListKeys)
	mux.HandleFunc("POST /v1/a2a/providers/{provider}/keys/{kid}/revoke", r.handleRevokeKey)
	mux.HandleFunc("DELETE /v1/a2a/providers/{provider}/keys/{kid}", r.handleDeleteKey)
	mux.HandleFunc("GET /internal/a2a/snapshot", r.handleSnapshot)
}

// --- 认证 ---

// authenticate 解析调用方身份；失败返回 401/403。
func (r *Registry) authenticate(req *http.Request) (Authn, error) {
	return resolveAuth(req, r.cfg.StaticToken, r.cfg.JWTSecret, r.cfg.DevMode)
}

// actorOf 取变更发起人（X-Actor 优先，其次 JWT sub；缺省 "unknown"）。
func actorOf(req *http.Request, authn Authn) string {
	if a := strings.TrimSpace(req.Header.Get("X-Actor")); a != "" {
		return a
	}
	if authn.Sub != "" {
		return authn.Sub
	}
	return "unknown"
}

// requestIDOf 取请求关联 ID（X-Request-Id；缺省生成）。
func requestIDOf(req *http.Request) string {
	if v := strings.TrimSpace(req.Header.Get("X-Request-Id")); v != "" && len(v) <= 128 {
		return v
	}
	return newEventID()
}

// traceIDOf 取链路追踪 ID（X-Trace-Id；缺省空——冻结 §5.7 字段可缺省）。
func traceIDOf(req *http.Request) string {
	if t := strings.TrimSpace(req.Header.Get("X-Trace-Id")); t != "" && len(t) <= 128 {
		return t
	}
	return ""
}

// --- 处理器 ---

func (r *Registry) handleRegister(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	var body RegisterRequest
	if !decodeJSON(w, req, &body) {
		return
	}
	idemKey := strings.TrimSpace(req.Header.Get("Idempotency-Key"))
	if idemKey != "" && (len(idemKey) < 8 || len(idemKey) > 128) {
		writeRegError(w, req, http.StatusBadRequest, codeInvalidRequest, "Idempotency-Key 长度须为 8..128")
		return
	}
	detail, status, err := r.Register(req.Context(), authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), body, idemKey)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	w.Header().Set("ETag", `"`+agentETag(detail.Name, detail.Revision)+`"`)
	writeJSON(w, status, detail)
}

func (r *Registry) handleList(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	q := req.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	includeDeleted := q.Get("include_deleted") == "true"
	items, status, err := r.List(authn, q.Get("name_prefix"), q.Get("skill"), q.Get("status"), includeDeleted, limit, q.Get("cursor"))
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	writeJSON(w, status, map[string]any{"agents": items})
}

func (r *Registry) handleGet(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	name := req.PathValue("name")
	detail, status, err := r.Get(authn, name)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	etag := `"` + agentETag(detail.Name, detail.Revision) + `"`
	w.Header().Set("ETag", etag)
	if match := req.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, status, detail)
}

func (r *Registry) handleReplace(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	var body RegisterRequest
	if !decodeJSON(w, req, &body) {
		return
	}
	name := req.PathValue("name")
	idemKey := strings.TrimSpace(req.Header.Get("Idempotency-Key"))
	detail, status, err := r.Replace(req.Context(), authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), name,
		strings.TrimSpace(req.Header.Get("If-Match")), body, idemKey)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	w.Header().Set("ETag", `"`+agentETag(detail.Name, detail.Revision)+`"`)
	writeJSON(w, status, detail)
}

func (r *Registry) handleDelete(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	name := req.PathValue("name")
	status, err := r.Delete(authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), name, strings.TrimSpace(req.Header.Get("If-Match")))
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	w.WriteHeader(status)
}

func (r *Registry) handleVerify(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	name := req.PathValue("name")
	status, err := r.Verify(req.Context(), authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), name)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	writeJSON(w, status, map[string]string{"status": "ok"})
}

func (r *Registry) handleImportKey(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	var body ProviderKeyInput
	if !decodeJSON(w, req, &body) {
		return
	}
	provider := req.PathValue("provider")
	status, err := r.ImportKey(authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), provider, body)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	writeJSON(w, status, map[string]string{"status": "ok", "kid": body.Kid})
}

func (r *Registry) handleListKeys(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	provider := req.PathValue("provider")
	keys, status, err := r.ListKeys(authn, provider)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	writeJSON(w, status, map[string]any{"keys": keys})
}

func (r *Registry) handleRevokeKey(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	provider := req.PathValue("provider")
	kid := req.PathValue("kid")
	status, err := r.RevokeKey(req.Context(), authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), provider, kid)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	writeJSON(w, status, map[string]string{"status": "ok"})
}

func (r *Registry) handleDeleteKey(w http.ResponseWriter, req *http.Request) {
	authn, err := r.authenticate(req)
	if err != nil {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	provider := req.PathValue("provider")
	kid := req.PathValue("kid")
	status, err := r.DeleteKey(authn, actorOf(req, authn), requestIDOf(req), traceIDOf(req), provider, kid)
	if err != nil {
		writeErr(w, req, status, err)
		return
	}
	w.WriteHeader(status)
}

// handleSnapshot 输出全量 active 快照（冻结 §5.8）。
//
// 该端点含 backend_url，仅内网可达：要求内部静态 token（SnapshotToken）。
func (r *Registry) handleSnapshot(w http.ResponseWriter, req *http.Request) {
	if r.cfg.SnapshotToken == "" {
		writeRegError(w, req, http.StatusServiceUnavailable, codeRegistryUnavailable, "未配置快照分发令牌")
		return
	}
	tok := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
	if tok == "" || tok != r.cfg.SnapshotToken {
		writeRegError(w, req, http.StatusUnauthorized, codeUnauthorized, "未授权")
		return
	}
	snap, rev, err := r.BuildSnapshot(req.Context())
	if err != nil {
		writeRegError(w, req, http.StatusServiceUnavailable, codeRegistryUnavailable, "构建快照失败")
		return
	}
	etag := `"a2a-registry-` + strconv.Itoa(rev) + `"`
	w.Header().Set("ETag", etag)
	if match := req.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// BuildSnapshot 构建供数据面消费的全量快照（§5.8）。
// 仅包含 active 且验签通过的 agent（fail-closed）。
//
// registry_revision 与记录集在**同一事务**内读取，避免版本号与内容不一致
// （数据面按 revision 单调接受，版本错配会导致拒绝或回退）。
func (r *Registry) BuildSnapshot(ctx context.Context) (*a2aproxy.Snapshot, int, error) {
	tx, err := r.store.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = r.store.Rollback(tx) }()
	recs, err := r.store.ListAgents(tx, "", "", "", "active", false, 1000, "")
	if err != nil {
		return nil, 0, err
	}
	agents := make([]a2aproxy.SnapshotAgent, 0, len(recs))
	for _, rec := range recs {
		if !rec.SignatureVerified {
			continue // 验签失败者不进快照（fail-closed）
		}
		publicURL, discoveryURL := r.agentURLs(rec.Tenant, rec.Name)
		agents = append(agents, snapshotAgentOf(rec, publicURL, discoveryURL))
	}
	rev := getRegistryRevisionTx(tx)
	return &a2aproxy.Snapshot{
		RegistryRevision: uint64(rev),
		GeneratedAt:      time.Now().UTC(),
		Agents:           agents,
	}, rev, nil
}

// --- 辅助 ---

// decodeJSON 读取并解析 JSON 请求体；失败写 400 并返回 false。
func decodeJSON(w http.ResponseWriter, req *http.Request, dst any) bool {
	req.Body = http.MaxBytesReader(w, req.Body, maxControlBodyBytes)
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		writeRegError(w, req, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "请求体超限或不可读")
		return false
	}
	if len(raw) == 0 {
		writeRegError(w, req, http.StatusBadRequest, codeInvalidRequest, "请求体为空")
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		writeRegError(w, req, http.StatusBadRequest, codeInvalidRequest, "请求体 JSON 非法")
		return false
	}
	return true
}

// etagMatches 判断 If-None-Match 是否命中（支持逗号分隔与 *）。
//
// 与 If-Match 不同，If-None-Match 允许 "*"（表示"只要有当前表示即命中"），
// 语义上等价于"资源存在则 304"，符合 RFC 9110 §13.1.2。
func etagMatches(header, etag string) bool {
	want := normalizeETag(etag)
	for _, part := range strings.Split(header, ",") {
		p := strings.TrimSpace(part)
		if p == "*" {
			return true
		}
		if n := normalizeETag(p); n != "" && n == want {
			return true
		}
	}
	return false
}

// writeJSON 写 JSON 响应。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeRegError 写统一错误体 {"error":{code,message,details,request_id}}。
func writeRegError(w http.ResponseWriter, req *http.Request, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    msg,
			"details":    map[string]any{},
			"request_id": requestIDOf(req),
		},
	})
}

// writeErr 将内部错误映射为控制面错误体。
func writeErr(w http.ResponseWriter, req *http.Request, status int, err error) {
	var re *regError
	if errors.As(err, &re) {
		details := re.Details
		if details == nil {
			details = map[string]any{}
		}
		writeJSON(w, re.Status, map[string]any{
			"error": map[string]any{
				"code":       re.Code,
				"message":    re.Message,
				"details":    details,
				"request_id": requestIDOf(req),
			},
		})
		return
	}
	writeRegError(w, req, status, codeInternal, "内部错误")
}
