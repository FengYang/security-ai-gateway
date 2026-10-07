package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"

	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
	"security-ai-gateway/gateway/tee-infer-service/model"
	"security-ai-gateway/protocol/go"
)

// ===== §4.3 管理 API：/cache/*（E4 批次 A：8 端点；warmup 两2端点归后续） =====
//
// 鉴权（E4 决策）：复用 X-Admin-Token 作为 cache-admin 等价鉴权（仓内无角色体系，偏差已登记）。
// 响应：§4.3 统一信封 {ok,data,request_id} / {ok:false,error:{code,message},request_id}。

// cacheAPIError §4.3 错误体。
type cacheAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// cacheAPIResponse §4.3 统一响应信封。
type cacheAPIResponse struct {
	OK        bool           `json:"ok"`
	Data      any            `json:"data,omitempty"`
	Error     *cacheAPIError `json:"error,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

// cacheFeedbackMaxSeen 反馈幂等表的 request_id 上限（防滥用撑爆内存）。
const cacheFeedbackMaxSeen = 4096

// cacheAdminAPI /cache/* 管理 API（持有反馈幂等状态）。
type cacheAdminAPI struct {
	srv *teeServer

	feedbackMu sync.Mutex
	seen       map[string]string // request_id -> verdict（B-6.6-2：同 id 覆盖、不重复计数）
}

// registerCacheAPIRoutes 注册 /cache/* 与 /config/cache（§4.3；挂载于现有 mux，同进程）。
func (s *teeServer) registerCacheAPIRoutes(mux *http.ServeMux) {
	api := &cacheAdminAPI{srv: s, seen: make(map[string]string)}
	mux.HandleFunc("/cache/stats", api.handleStats)
	mux.HandleFunc("/cache/entry/", api.handleInvalidateKey)
	mux.HandleFunc("/cache/tenant/", api.handleInvalidateTenant)
	mux.HandleFunc("/cache/model/", api.handleInvalidateModel)
	mux.HandleFunc("/cache/all", api.handleInvalidateAll)
	mux.HandleFunc("/cache/inspect/", api.handleInspect)
	mux.HandleFunc("/cache/feedback", api.handleFeedback)
	mux.HandleFunc("/config/cache", api.handleConfigSnapshot)
	// E4-B：预热端点（§4.3 #6/#7）
	mux.HandleFunc("/cache/warmup", api.handleWarmupTrigger)
	mux.HandleFunc("/cache/warmup/", api.handleWarmupStatus)
}

// ===== 信封与鉴权 =====

func cacheReqID(r *http.Request) string { return r.Header.Get("X-Request-Id") }

func writeCacheOK(w http.ResponseWriter, r *http.Request, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cacheAPIResponse{OK: true, Data: data, RequestID: cacheReqID(r)})
}

func writeCacheErr(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(cacheAPIResponse{
		OK: false, Error: &cacheAPIError{Code: code, Message: msg}, RequestID: cacheReqID(r),
	})
}

// authorize 鉴权（复用 X-Admin-Token）；失败写出 403 CACHE_FORBIDDEN。
func (a *cacheAdminAPI) authorize(w http.ResponseWriter, r *http.Request) bool {
	if !a.srv.checkAdmin(r) {
		writeCacheErr(w, r, http.StatusForbidden, "CACHE_FORBIDDEN", "管理认证失败（需 cache-admin 等价权限：X-Admin-Token）")
		return false
	}
	return true
}

// enabled 运营端点门控：引擎未装配或 mode=off → 409 CACHE_DISABLED。
func (a *cacheAdminAPI) enabled(w http.ResponseWriter, r *http.Request) bool {
	if a.srv.cacheEngine == nil || a.srv.cacheEngine.Stats().Mode == string(cacheengine.ModeOff) {
		writeCacheErr(w, r, http.StatusConflict, "CACHE_DISABLED", "缓存未启用（mode=off 或引擎未装配）")
		return false
	}
	return true
}

// requireMethod 方法守卫；不匹配写出 405。
func requireCacheMethod(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		writeCacheErr(w, r, http.StatusMethodNotAllowed, "CACHE_INVALID_ARG", "method not allowed: "+want)
		return false
	}
	return true
}

// pathSuffix 取路径后缀（单段；含 "/" 或空 → 非法）。
func pathSuffix(r *http.Request, prefix string) (string, bool) {
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if p == "" || strings.Contains(p, "/") {
		return "", false
	}
	return p, true
}

// backendName 后端形态名（供 /cache/stats）。
func (a *cacheAdminAPI) backendName() string {
	cfg := a.srv.cacheConfig
	if cfg == nil {
		return "unknown"
	}
	switch {
	case cfg.Redis.Enabled:
		return "redis"
	case cfg.Semantic.Enabled:
		return "inproc-semantic"
	default:
		return "inproc-exact"
	}
}

// ===== 端点实现 =====

// handleStats GET /cache/stats：条目数/容量/后端/查询统计（§4.3 #1）。
func (a *cacheAdminAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodGet) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	st := a.srv.cacheEngine.Stats()
	writeCacheOK(w, r, map[string]any{
		"mode":                    st.Mode,
		"backend":                 a.backendName(),
		"entries":                 map[string]int{"exact": st.ExactEntries, "negative": st.NegativeEntries, "vector": st.VectorEntries},
		"evictions":               st.Evictions,
		"fast_check_blocks":       st.FastCheckBlocks,
		"semantic_false_positive": st.SemanticFP,
		"saved_tokens":            st.SavedTokens,
		"lookups":                 st.Lookups,
	})
}

// handleInvalidateKey DELETE /cache/entry/{key_hash}（§4.3 #2）。
func (a *cacheAdminAPI) handleInvalidateKey(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodDelete) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	key, ok := pathSuffix(r, "/cache/entry/")
	if !ok {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "key_hash 必填")
		return
	}
	n, err := a.srv.cacheEngine.Invalidate(cacheengine.InvalidateSelector{KeyHash: key})
	if err != nil {
		writeCacheErr(w, r, http.StatusServiceUnavailable, "CACHE_BACKEND_UNAVAILABLE", err.Error())
		return
	}
	writeCacheOK(w, r, map[string]any{"key_hash": key, "deleted": n})
}

// handleInvalidateTenant DELETE /cache/tenant/{tenant_id}（§4.3 #3）。
func (a *cacheAdminAPI) handleInvalidateTenant(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodDelete) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	tenant, ok := pathSuffix(r, "/cache/tenant/")
	if !ok {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "tenant_id 必填")
		return
	}
	n, err := a.srv.cacheEngine.Invalidate(cacheengine.InvalidateSelector{TenantID: tenant})
	if err != nil {
		writeCacheErr(w, r, http.StatusServiceUnavailable, "CACHE_BACKEND_UNAVAILABLE", err.Error())
		return
	}
	writeCacheOK(w, r, map[string]any{"tenant_id": tenant, "deleted": n})
}

// handleInvalidateModel DELETE /cache/model/{model}（§4.3 #4）。
func (a *cacheAdminAPI) handleInvalidateModel(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodDelete) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	model, ok := pathSuffix(r, "/cache/model/")
	if !ok {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "model 必填")
		return
	}
	n, err := a.srv.cacheEngine.Invalidate(cacheengine.InvalidateSelector{Model: model})
	if err != nil {
		writeCacheErr(w, r, http.StatusServiceUnavailable, "CACHE_BACKEND_UNAVAILABLE", err.Error())
		return
	}
	writeCacheOK(w, r, map[string]any{"model": model, "deleted": n})
}

// handleInvalidateAll DELETE /cache/all?confirm=yes（§4.3 #5）。
func (a *cacheAdminAPI) handleInvalidateAll(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodDelete) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	if r.URL.Query().Get("confirm") != "yes" {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "全量清空需 confirm=yes")
		return
	}
	n, err := a.srv.cacheEngine.Invalidate(cacheengine.InvalidateSelector{All: true})
	if err != nil {
		writeCacheErr(w, r, http.StatusServiceUnavailable, "CACHE_BACKEND_UNAVAILABLE", err.Error())
		return
	}
	writeCacheOK(w, r, map[string]any{"deleted": n})
}

// handleInspect GET /cache/inspect/{key_hash}：返回元数据（不含文本；§4.3 #9 / I-6）。
func (a *cacheAdminAPI) handleInspect(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodGet) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	key, ok := pathSuffix(r, "/cache/inspect/")
	if !ok {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "key_hash 必填")
		return
	}
	entry, found := a.srv.cacheEngine.Inspect(key)
	if !found {
		writeCacheErr(w, r, http.StatusNotFound, "CACHE_NOT_FOUND", "key_hash 不存在")
		return
	}
	// Entry.Text/Segments 标 json:"-"：序列化天然不含明文。
	writeCacheOK(w, r, entry)
}

// cacheFeedbackRequest POST /cache/feedback 请求体（§4.3 #8 / §6.6.1）。
type cacheFeedbackRequest struct {
	RequestID string `json:"request_id"`
	Verdict   string `json:"verdict"` // good | bad | irrelevant
	Note      string `json:"note"`    // 自由文本，仅内存态、截断至 256 字节、不落审计/日志/库
}

// handleFeedback POST /cache/feedback（§4.3 #8）。
// 本轮：校验 + 幂等（B-6.6-2）；归因到 scene/驱动检测器需 request_id→scene 索引（会话层），归后续（偏差登记）。
func (a *cacheAdminAPI) handleFeedback(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodPost) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req cacheFeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "请求体非法 JSON")
		return
	}
	if strings.TrimSpace(req.RequestID) == "" {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "request_id 必填")
		return
	}
	switch req.Verdict {
	case "good", "bad", "irrelevant":
	default:
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "verdict 必须为 good|bad|irrelevant")
		return
	}
	if len(req.Note) > 256 {
		req.Note = req.Note[:256] // N4-P2-8：超长截断，且不持久化
	}

	// B-6.6-2：同一 request_id 覆盖（幂等、不重复计数）；B-6.6-1：未知 request_id 不报错。
	a.feedbackMu.Lock()
	_, dup := a.seen[req.RequestID]
	if !dup && len(a.seen) >= cacheFeedbackMaxSeen {
		a.seen = make(map[string]string) // 基数保护：满则重置（幂等窗口回绕）
		dup = false
	}
	a.seen[req.RequestID] = req.Verdict
	a.feedbackMu.Unlock()

	writeCacheOK(w, r, map[string]any{"request_id": req.RequestID, "verdict": req.Verdict, "duplicate": dup})
}

// handleConfigSnapshot GET /config/cache：缓存配置只读快照（§4.3 #10；mode=off 时亦可读）。
func (a *cacheAdminAPI) handleConfigSnapshot(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodGet) || !a.authorize(w, r) {
		return
	}
	if a.srv.cacheConfig == nil {
		writeCacheOK(w, r, map[string]any{"configured": false})
		return
	}
	writeCacheOK(w, r, map[string]any{"configured": true, "config": a.srv.cacheConfig})
}

// ===== 预热端点（E4-B；§4.3 #6/#7） =====

// warmupInfer 预热推理回调（§6.7.3）：与真实请求同源构造 ctx → 推理 → 输出侧审查 → 写前门禁结论。
// 口径（E4-B 决策）：按 §6.7.3 字面（推理 + 输出侧审查 + 写前门禁）；**不计配额、不做输入侧 Guardrail/PII**
// （预热清单为可信离线内容，§6.7.1）——偏差登记；配额（B-6.7-3）归后续。
func (s *teeServer) warmupInfer(ctx context.Context, it cacheengine.WarmItem) (cacheengine.StoreContext, cacheengine.InferResult, error) {
	engType, eng, err := s.resolveEngineWithFailover(it.Tenant, it.Model, protocol.EngineTypeTEEGPU)
	if err != nil {
		return cacheengine.StoreContext{}, cacheengine.InferResult{}, err
	}
	tx := sha256hex([]byte(it.Prompt))
	lctx := buildCacheLookupContext(it.Tenant, engType, it.Model, tx, it.Prompt, it.MaxNewTokens, false, s.policyVersion())

	maxTok := it.MaxNewTokens
	if maxTok < 0 {
		maxTok = 0 // 0 = 引擎缺省
	}
	genReq := model.GenerateRequest{
		Model:     it.Model,
		Messages:  []model.ChatMessage{{Role: "user", Content: it.Prompt}},
		MaxTokens: uint32(maxTok),
	}
	if _, isCMAAS := eng.(*model.CmaasEngine); isCMAAS {
		genReq.Model = "" // 与主链一致：cmaas 上游模型名由引擎缺省回退
	}
	var agg strings.Builder
	if err := eng.Generate(genReq, func(d string) error { agg.WriteString(d); return nil }); err != nil {
		return cacheengine.StoreContext{}, cacheengine.InferResult{}, err
	}

	// 输出侧审查（写前门禁依据）；mode=off 时 og=nil → writable=true（零行为变化）
	writable := true
	og, ogErr := s.newRequestOutputGuard(it.Tenant, "warmup")
	if ogErr != nil {
		return cacheengine.StoreContext{}, cacheengine.InferResult{}, ogErr
	}
	if og != nil {
		noop := func(delta, finish string) error { return nil }
		if err := og.Process(agg.String(), noop); err != nil {
			writable = false
		}
		if err := og.Finish(noop); err != nil {
			writable = false
		}
		if blocked, _ := og.BlockInfo(); blocked {
			writable = false
		}
		og.Close()
	}
	sc := cacheengine.StoreContext{LookupContext: lctx, Writable: writable}
	res := cacheengine.InferResult{Text: agg.String(), TokensOut: s.countTokens(agg.String()), Finish: "stop"}
	return sc, res, nil
}

// handleWarmupTrigger POST /cache/warmup（§4.3 #6；体 {reset:bool} 可空）。
func (a *cacheAdminAPI) handleWarmupTrigger(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodPost) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	cfg := a.srv.cacheConfig
	if a.srv.warmer == nil || cfg == nil || !cfg.Warmup.Enabled {
		writeCacheErr(w, r, http.StatusConflict, "CACHE_DISABLED", "预热未启用（warmup.enabled=false 或未装配）")
		return
	}
	var body struct {
		Reset bool `json:"reset"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body) // 体可空

	f, err := os.Open(cfg.Warmup.File)
	if err != nil {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "预热文件不可读: "+err.Error())
		return
	}
	defer f.Close()
	items, err := cacheengine.LoadWarmItems(f)
	if err != nil {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", err.Error()) // 含行号（B-6.7-4）
		return
	}

	id, err := a.srv.warmer.Run(items, body.Reset)
	switch {
	case errors.Is(err, cacheengine.ErrWarmupBusy):
		writeCacheErr(w, r, http.StatusConflict, "CACHE_WARMUP_BUSY", "已有活跃预热任务")
		return
	case errors.Is(err, cacheengine.ErrWarmupDisabled):
		writeCacheErr(w, r, http.StatusConflict, "CACHE_DISABLED", "预热未启用")
		return
	case err != nil:
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", err.Error())
		return
	}
	writeCacheOK(w, r, map[string]any{"task_id": id, "total": len(items)})
}

// handleWarmupStatus GET /cache/warmup/{task_id}（§4.3 #7）。
func (a *cacheAdminAPI) handleWarmupStatus(w http.ResponseWriter, r *http.Request) {
	if !requireCacheMethod(w, r, http.MethodGet) || !a.authorize(w, r) || !a.enabled(w, r) {
		return
	}
	if a.srv.warmer == nil {
		writeCacheErr(w, r, http.StatusConflict, "CACHE_DISABLED", "预热未装配")
		return
	}
	id, ok := pathSuffix(r, "/cache/warmup/")
	if !ok {
		writeCacheErr(w, r, http.StatusBadRequest, "CACHE_INVALID_ARG", "task_id 必填")
		return
	}
	st := a.srv.warmer.Status()
	if st.ID != id {
		writeCacheErr(w, r, http.StatusNotFound, "CACHE_NOT_FOUND", "task_id 不存在或已过期")
		return
	}
	writeCacheOK(w, r, st)
}
