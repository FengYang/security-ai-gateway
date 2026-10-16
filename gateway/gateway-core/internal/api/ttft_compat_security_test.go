package api

// ttft_compat_security_test.go — P1-6 M6.6：兼容与安全测试（§9.1「兼容测试」/「安全测试」）。
//
// 逐条对齐 §9.1：
//
//	兼容：
//	  - 旧路由表（无 latency / 无新字段）经 API upsert→get 原样保留、不注入延迟字段；
//	  - strategy 缺省/旧值（failure-rate-aware）保持不变（行为不变，C-8/V-7）；
//	  - 逐字节口径（CanonicalBytes / 验签）由 internal/route 基线单测覆盖
//	    （TestCanonicalBytesOldTableUnchanged / TestV1FormatStillWorks），本文件只补 API 层。
//	安全：
//	  - 上报鉴权（无 token / 错 token → 401）；
//	  - 跨租户隔离（伪造 tenant/model/endpoint 上报被拒 + stats 按 tenant 隔离，TT2-10）；
//	  - 非法统计注入被拒并钳制（值域/长度/时间窗 consolidated，TT2-03/TT2-08）；
//	  - reset 需鉴权（admin 语义由部署侧收敛）且落审计（审计断言见 ttft_reset_test.go）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// doRoute 以给定方法/路径/体（带 token）请求控制面。
func doRoute(s *Server, method, url, body string, authorized bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if authorized {
		req.Header.Set("Authorization", "Bearer tok")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestTTFT_Security_AuthRequired 上报/查询/重置三端点：无 token 与错 token 一律 401；
// 正确 token 非 401（业务码依请求而异）。对齐 §9.1 安全测试「上报鉴权（无 token 拒绝）」。
func TestTTFT_Security_AuthRequired(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	cases := []struct{ method, url, body string }{
		{http.MethodPost, "/routes/ttft/report", ttftBody("auth1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{http.MethodGet, "/routes/ttft/stats?tenant=t-001", ""},
		{http.MethodPost, "/routes/ttft/reset", `{"tenant":"t-001","model":"qwen-max"}`},
	}
	for _, c := range cases {
		// 无 Authorization → 401
		if rec := doRoute(s, c.method, c.url, c.body, false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 无 token 应 401，got %d %s", c.method, c.url, rec.Code, rec.Body.String())
		}
		// 错 token → 401
		req := httptest.NewRequest(c.method, c.url, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 错 token 应 401，got %d", c.method, c.url, rec.Code)
		}
		// 正确 token → 非 401（业务成功或业务拒绝）
		if rec := doRoute(s, c.method, c.url, c.body, true); rec.Code == http.StatusUnauthorized {
			t.Fatalf("%s %s 正确 token 不应 401：%s", c.method, c.url, rec.Body.String())
		}
	}
}

// TestTTFT_Security_CrossTenantIsolation 跨租户隔离（TT2-10）：
//   - 伪造 tenant（路由表无此租户）上报 → 400 拒绝；
//   - 合法 tenant/model 但幽灵端点 → 400 拒绝；
//   - stats 按 tenant 隔离：他租户查询 404，不泄漏本租户画像。
func TestTTFT_Security_CrossTenantIsolation(t *testing.T) {
	s := ttftTestServer(t) // 仅含 t-001/qwen-max
	nowMs := time.Now().Unix() * 1000

	// 1) 伪造 tenant：路由表无 t-999。
	if rec := ttftPost(s, ttftBody("x1", nowMs, "t-999", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)); rec.Code != http.StatusBadRequest {
		t.Fatalf("伪造 tenant 上报应 400，got %d %s", rec.Code, rec.Body.String())
	}
	// 2) 合法 tenant/model 但不在白名单的端点（幽灵端点，TT2-08）。
	if rec := ttftPost(s, ttftBody("x2", nowMs, "t-001", "qwen-max", "ghost-ep", "miss", ttftZeroBuckets)); rec.Code != http.StatusBadRequest {
		t.Fatalf("幽灵端点上报应 400，got %d %s", rec.Code, rec.Body.String())
	}
	// 3) 合法上报落片。
	if rec := ttftPost(s, ttftBody("x3", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("合法上报应 200，got %d %s", rec.Code, rec.Body.String())
	}
	// 4) 本租户可见。
	rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001")
	if rec.Code != http.StatusOK {
		t.Fatalf("t-001 stats 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	if resp := decodeStats(t, rec); len(resp.Stats) == 0 {
		t.Fatal("t-001 上报后应有统计（隔离测试前置）")
	}
	// 5) 他租户查询 → 404，无跨租户泄漏。
	rec = ttftGet(s, "/routes/ttft/stats?tenant=t-002")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("t-002 stats 应 404（跨租户隔离），got %d %s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "not_found" {
		t.Fatalf("t-002 错误码应 not_found，got %q（body=%s）", e.Code, rec.Body.String())
	}
}

// TestTTFT_Security_InjectionClamped 非法统计注入 consolidated 钳制（TT2-03/TT2-08）：
// 单桶值域、单批总量上限、buckets 长度、reported_at 时间窗（超前/过旧）一律 400 拒绝。
func TestTTFT_Security_InjectionClamped(t *testing.T) {
	s := ttftTestServer(t) // 路由 latency.window_sec=300
	nowMs := time.Now().Unix() * 1000

	overBucket := []uint64{1_000_001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	overTotal := make([]uint64, 11)
	for i := range overTotal {
		overTotal[i] = 1_000_000 // 11 × 1e6 = 1.1e7 > 单批上限 1e7（各桶均未超单桶上限）
	}
	cases := []struct{ name, body string }{
		{"单桶超上限", ttftBody("c1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", overBucket)},
		{"单批总量超限", ttftBody("c2", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", overTotal)},
		{"buckets 长度不合法", ttftBody("c3", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})},
		{"reported_at 超前越窗", ttftBody("c4", nowMs+10*60*1000, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{"reported_at 过旧越窗", ttftBody("c5", nowMs-10*60*1000, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
	}
	for _, c := range cases {
		if rec := ttftPost(s, c.body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400 拒绝，got %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	// 对照：合法样本应 200 落片（证明上列拒绝非因其它因素）。
	if rec := ttftPost(s, ttftBody("c-ok", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("合法样本应 200，got %d %s", rec.Code, rec.Body.String())
	}
}

// TestTTFT_Compat_LegacyRouteTableUnchanged 旧路由表（无 latency、旧 strategy）经 API 往返后
// 原样保留：不注入 latency 字段、strategy 不变，且其端点可作为合法上报来源（行为不变）。
func TestTTFT_Compat_LegacyRouteTableUnchanged(t *testing.T) {
	s := testServer()
	legacy := `{"tenant":"t-legacy","model":"qwen-max","default_engine":"cmaas",` +
		`"strategy":"failure-rate-aware","target":"cmaas",` +
		`"endpoints":[{"name":"e1","url":"https://e1.internal/v1","weight":1,"priority":1,"enabled":true}]}`
	if rec := doRoute(s, http.MethodPut, "/routes/t-legacy/qwen-max", legacy, true); rec.Code != http.StatusOK {
		t.Fatalf("旧表 upsert 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	rec := doRoute(s, http.MethodGet, "/routes/t-legacy/qwen-max", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("旧表 get 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	var wrap struct {
		Route map[string]json.RawMessage `json:"route"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
		t.Fatalf("get 响应解析失败：%v（body=%s）", err, rec.Body.String())
	}
	if _, ok := wrap.Route["latency"]; ok {
		t.Fatalf("旧表（无 latency）不应出现 latency 字段：%s", rec.Body.String())
	}
	var gotStrategy string
	if raw, ok := wrap.Route["strategy"]; ok {
		_ = json.Unmarshal(raw, &gotStrategy)
	}
	if gotStrategy != "failure-rate-aware" {
		t.Fatalf("旧表 strategy 应保持 failure-rate-aware，got %q", gotStrategy)
	}
	if _, ok := wrap.Route["endpoints"]; !ok {
		t.Fatalf("旧表端点应保留：%s", rec.Body.String())
	}
}
