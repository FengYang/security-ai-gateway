package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
)

// ===== E4：/cache/* 管理 API 端点测试（§4.3） =====

const cacheTestAdminToken = "test-admin-token"

func cacheAPITestCfg(mode cacheengine.CacheMode) cacheengine.CacheConfig {
	cfg := cacheengine.DefaultConfig()
	cfg.Mode = mode
	cfg.Exact.Enabled = true
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.WriteLimit.Enabled = false // 聚焦管理 API，不做写入限流
	return cfg
}

func newCacheAPITest(mode cacheengine.CacheMode) (*http.ServeMux, *teeServer, cacheengine.CacheEngine) {
	cfg := cacheAPITestCfg(mode)
	eng := cacheengine.NewCacheEngine(cfg)
	srv := &teeServer{cacheEngine: eng, cacheConfig: &cfg, adminToken: cacheTestAdminToken}
	mux := http.NewServeMux()
	srv.registerCacheAPIRoutes(mux)
	return mux, srv, eng
}

func cacheAPIReq(mux *http.ServeMux, method, path, body string, withToken bool) *httptest.ResponseRecorder {
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if withToken {
		req.Header.Set(adminHeader, cacheTestAdminToken)
	}
	req.Header.Set("X-Request-Id", "req-1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

type cacheAPIEnvelope struct {
	OK        bool           `json:"ok"`
	Data      map[string]any `json:"data"`
	Error     *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

func decodeEnvelope(t *testing.T, w *httptest.ResponseRecorder) cacheAPIEnvelope {
	t.Helper()
	var env cacheAPIEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("响应非合法 JSON：%v（body=%s）", err, w.Body.String())
	}
	return env
}

// seedCacheEntry 写入一条精确缓存条目并返回其 key_hash。
func seedCacheEntry(t *testing.T, eng cacheengine.CacheEngine) (cacheengine.LookupContext, string) {
	t.Helper()
	ctx := cacheengine.LookupContext{
		TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
		TransformedHash: "h1", PromptText: "long enough prompt text", PolicyVer: "1", GuardVer: "v1",
	}
	out := eng.Store(cacheengine.StoreContext{LookupContext: ctx, Writable: true},
		cacheengine.InferResult{Text: "SECRET-ANSWER-TEXT", TokensOut: 5, Finish: "stop"})
	if !out.Stored {
		t.Fatalf("预置写入失败：%+v", out)
	}
	r := eng.Lookup(ctx)
	if !r.Hit || r.Entry == nil || r.Entry.KeyHash == "" {
		t.Fatalf("预置条目应可命中且带 key_hash，实际 %+v", r)
	}
	return ctx, r.Entry.KeyHash
}

// TestCacheAPI_AuthForbidden 未带管理令牌 → 403 CACHE_FORBIDDEN（§4.3）。
func TestCacheAPI_AuthForbidden(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeExact)
	w := cacheAPIReq(mux, http.MethodGet, "/cache/stats", "", false)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", w.Code)
	}
	if env := decodeEnvelope(t, w); env.OK || env.Error == nil || env.Error.Code != "CACHE_FORBIDDEN" {
		t.Fatalf("错误码应为 CACHE_FORBIDDEN：%+v", env)
	}
}

// TestCacheAPI_Disabled mode=off → 409 CACHE_DISABLED（§4.3）。
func TestCacheAPI_Disabled(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeOff)
	w := cacheAPIReq(mux, http.MethodGet, "/cache/stats", "", true)
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409", w.Code)
	}
	if env := decodeEnvelope(t, w); env.Error == nil || env.Error.Code != "CACHE_DISABLED" {
		t.Fatalf("错误码应为 CACHE_DISABLED：%+v", env)
	}
}

// TestCacheAPI_Stats GET /cache/stats。
func TestCacheAPI_Stats(t *testing.T) {
	mux, _, eng := newCacheAPITest(cacheengine.ModeExact)
	seedCacheEntry(t, eng)

	w := cacheAPIReq(mux, http.MethodGet, "/cache/stats", "", true)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	env := decodeEnvelope(t, w)
	if !env.OK || env.Data["mode"] != "exact" || env.RequestID != "req-1" {
		t.Fatalf("stats 响应异常：%+v", env)
	}
}

// TestCacheAPI_InvalidateKey DELETE /cache/entry/{hash}（幂等）。
func TestCacheAPI_InvalidateKey(t *testing.T) {
	mux, _, eng := newCacheAPITest(cacheengine.ModeExact)
	ctx, hash := seedCacheEntry(t, eng)

	w := cacheAPIReq(mux, http.MethodDelete, "/cache/entry/"+hash, "", true)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// 删除后查询应为 miss
	if r := eng.Lookup(ctx); r.Hit {
		t.Fatal("删除后不应命中")
	}
	// 再删一次仍 200（幂等）
	if w2 := cacheAPIReq(mux, http.MethodDelete, "/cache/entry/"+hash, "", true); w2.Code != http.StatusOK {
		t.Fatalf("幂等删除应 200，实际 %d", w2.Code)
	}
}

// TestCacheAPI_InvalidateTenantModel 按租户/模型失效返回 200。
func TestCacheAPI_InvalidateTenantModel(t *testing.T) {
	mux, _, eng := newCacheAPITest(cacheengine.ModeExact)
	seedCacheEntry(t, eng)

	if w := cacheAPIReq(mux, http.MethodDelete, "/cache/tenant/t1", "", true); w.Code != http.StatusOK {
		t.Fatalf("tenant 失效 status=%d", w.Code)
	}
	if w := cacheAPIReq(mux, http.MethodDelete, "/cache/model/m1", "", true); w.Code != http.StatusOK {
		t.Fatalf("model 失效 status=%d", w.Code)
	}
}

// TestCacheAPI_InvalidateAllConfirmation 缺 confirm → 400；带 confirm=yes → 200（§4.3 #5）。
func TestCacheAPI_InvalidateAllConfirmation(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeExact)

	w := cacheAPIReq(mux, http.MethodDelete, "/cache/all", "", true)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺 confirm 应 400，实际 %d", w.Code)
	}
	if env := decodeEnvelope(t, w); env.Error == nil || env.Error.Code != "CACHE_INVALID_ARG" {
		t.Fatalf("错误码应为 CACHE_INVALID_ARG：%+v", env)
	}
	if w2 := cacheAPIReq(mux, http.MethodDelete, "/cache/all?confirm=yes", "", true); w2.Code != http.StatusOK {
		t.Fatalf("confirm=yes 应 200，实际 %d", w2.Code)
	}
}

// TestCacheAPI_InspectMetadataOnly GET /cache/inspect/{hash}：元数据可得且不含文本（S-3/I-6）。
func TestCacheAPI_InspectMetadataOnly(t *testing.T) {
	mux, _, eng := newCacheAPITest(cacheengine.ModeExact)
	_, hash := seedCacheEntry(t, eng)

	w := cacheAPIReq(mux, http.MethodGet, "/cache/inspect/"+hash, "", true)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "SECRET-ANSWER-TEXT") {
		t.Fatal("inspect 响应不得包含缓存文本（I-6）")
	}
	env := decodeEnvelope(t, w)
	if !env.OK || env.Data["key_hash"] != hash {
		t.Fatalf("inspect 元数据异常：%+v", env)
	}

	// 不存在的 key → 404 CACHE_NOT_FOUND
	if w2 := cacheAPIReq(mux, http.MethodGet, "/cache/inspect/deadbeef", "", true); w2.Code != http.StatusNotFound {
		t.Fatalf("未知 key 应 404，实际 %d", w2.Code)
	}
}

// TestCacheAPI_Feedback POST /cache/feedback：校验 + 幂等（B-6.6-1/2）。
func TestCacheAPI_Feedback(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeExact)

	body := `{"request_id":"r1","verdict":"bad","note":"wrong"}`
	w := cacheAPIReq(mux, http.MethodPost, "/cache/feedback", body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	env := decodeEnvelope(t, w)
	if env.Data["duplicate"] != false {
		t.Fatalf("首次反馈 duplicate 应为 false：%+v", env)
	}
	// 同 request_id 重复 → duplicate=true（覆盖、不重复计数）
	env2 := decodeEnvelope(t, cacheAPIReq(mux, http.MethodPost, "/cache/feedback", body, true))
	if env2.Data["duplicate"] != true {
		t.Fatalf("重复反馈 duplicate 应为 true：%+v", env2)
	}
	// 非法 verdict → 400
	if w3 := cacheAPIReq(mux, http.MethodPost, "/cache/feedback", `{"request_id":"r2","verdict":"maybe"}`, true); w3.Code != http.StatusBadRequest {
		t.Fatalf("非法 verdict 应 400，实际 %d", w3.Code)
	}
	// 缺 request_id → 400
	if w4 := cacheAPIReq(mux, http.MethodPost, "/cache/feedback", `{"verdict":"good"}`, true); w4.Code != http.StatusBadRequest {
		t.Fatalf("缺 request_id 应 400，实际 %d", w4.Code)
	}
}

// TestCacheAPI_ConfigSnapshot GET /config/cache。
func TestCacheAPI_ConfigSnapshot(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeExact)
	w := cacheAPIReq(mux, http.MethodGet, "/config/cache", "", true)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	env := decodeEnvelope(t, w)
	if !env.OK || env.Data["configured"] != true {
		t.Fatalf("config 快照异常：%+v", env)
	}
}

// TestCacheAPI_MethodGuard 方法不符 → 405。
func TestCacheAPI_MethodGuard(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeExact)
	if w := cacheAPIReq(mux, http.MethodGet, "/cache/all", "", true); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /cache/all 应 405，实际 %d", w.Code)
	}
	if w := cacheAPIReq(mux, http.MethodGet, "/cache/feedback", "", true); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /cache/feedback 应 405，实际 %d", w.Code)
	}
}

// TestCacheAPI_FeedbackNoteTruncated note 超 256 字节截断且不入响应文本。
func TestCacheAPI_FeedbackNoteTruncated(t *testing.T) {
	mux, _, _ := newCacheAPITest(cacheengine.ModeExact)
	long := strings.Repeat("x", 300)
	body := `{"request_id":"r9","verdict":"good","note":"` + long + `"}`
	w := cacheAPIReq(mux, http.MethodPost, "/cache/feedback", body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if strings.Contains(w.Body.String(), long) {
		t.Fatal("note 不应回显（仅内存态、截断）")
	}
}
