package api

// ttft_stats_test.go — P1-6 M3.5：GET /routes/ttft/stats（§6.3；404/400/增量/上限/单调/valid 判定）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/route"
)

// ttftGet 发送 stats 查询。
func ttftGet(s *Server, url string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

type ttftStatsResponse struct {
	GeneratedAt int64      `json:"generated_at"`
	Stats       []ttftStat `json:"stats"`
}

func decodeStats(t *testing.T, rec *httptest.ResponseRecorder) ttftStatsResponse {
	t.Helper()
	var resp ttftStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应 JSON 解析失败：%v（body=%s）", err, rec.Body.String())
	}
	return resp
}

// TestTTFTStats_HappyAndValid：双 cache 条目下发、分位/样本/updated_at、valid=true。
func TestTTFTStats_HappyAndValid(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	body := fmt.Sprintf(
		`{"batch_id":"s1","reported_at":%d,"samples":[`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","buckets":[30,0,0,0,0,0,0,0,0,0,0]},`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"hit","buckets":[30,0,0,0,0,0,0,0,0,0,0]}]}`, nowMs)
	if rec := ttftPost(s, body); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d %s", rec.Code, rec.Body.String())
	}

	rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001")
	if rec.Code != http.StatusOK {
		t.Fatalf("stats 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeStats(t, rec)
	if resp.GeneratedAt <= 0 {
		t.Fatalf("generated_at 应为毫秒时间戳，got %d", resp.GeneratedAt)
	}
	if len(resp.Stats) != 2 {
		t.Fatalf("应下发 2 条（miss/hit），got %d：%s", len(resp.Stats), rec.Body.String())
	}
	byCache := map[string]ttftStat{}
	for _, st := range resp.Stats {
		byCache[st.Cache] = st
	}
	for _, cache := range []string{"miss", "hit"} {
		st, ok := byCache[cache]
		if !ok {
			t.Fatalf("缺 cache=%s 条目：%s", cache, rec.Body.String())
		}
		// 30 样本全在首桶 [0,10]：p50=5、p95=round(9.5)=10
		if st.P50Ms != 5 || st.P95Ms != 10 {
			t.Errorf("cache=%s 分位不符：p50=%d p95=%d", cache, st.P50Ms, st.P95Ms)
		}
		if st.Samples != 30 || !st.Valid {
			t.Errorf("cache=%s 应 samples=30 valid=true，got %d/%v", cache, st.Samples, st.Valid)
		}
		if st.UpdatedAt != nowMs/1000 {
			t.Errorf("cache=%s updated_at 应=%d，got %d", cache, nowMs/1000, st.UpdatedAt)
		}
		if st.Tenant != "t-001" || st.Model != "qwen-max" || st.Endpoint != "tee-gpu-a" {
			t.Errorf("cache=%s 键维度不符：%+v", cache, st)
		}
	}
}

// TestTTFTStats_LowSamplesInvalid：样本 < min_samples（20）→ valid=false 仍下发。
func TestTTFTStats_LowSamplesInvalid(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	if rec := ttftPost(s, ttftBody("s2", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d", rec.Code)
	}
	resp := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t-001"))
	if len(resp.Stats) != 1 {
		t.Fatalf("应 1 条，got %d", len(resp.Stats))
	}
	st := resp.Stats[0]
	if st.Samples != 5 || st.Valid {
		t.Fatalf("低样本应 samples=5 valid=false，got %d/%v", st.Samples, st.Valid)
	}
	if st.P50Ms != 5 {
		t.Fatalf("低样本仍应下发计算值（p50=5），got %d", st.P50Ms)
	}
}

// TestTTFTStats_StaleInvalid：样本充足但 updated_at 超过 stale_sec（75s）→ valid=false。
func TestTTFTStats_StaleInvalid(t *testing.T) {
	s := ttftTestServer(t)
	now := time.Now().Unix()
	reportedAt := (now - 100) * 1000 // 100s 前（在窗口 300 内、超 stale 75）
	if rec := ttftPost(s, ttftBody("s3", reportedAt, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t-001"))
	if len(resp.Stats) != 1 {
		t.Fatalf("应 1 条，got %d", len(resp.Stats))
	}
	st := resp.Stats[0]
	if st.Samples != 30 || st.Valid {
		t.Fatalf("陈旧条目应 samples=30 valid=false，got %d/%v（updated_at=%d now=%d）",
			st.Samples, st.Valid, st.UpdatedAt, now)
	}
	if st.UpdatedAt != now-100 {
		t.Fatalf("updated_at 应=%d，got %d", now-100, st.UpdatedAt)
	}
}

// TestTTFTStats_GeneratedAtMonotonic：generated_at 严格递增（§6.3 控制面保证）。
func TestTTFTStats_GeneratedAtMonotonic(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	if rec := ttftPost(s, ttftBody("s4", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d", rec.Code)
	}
	g1 := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t-001")).GeneratedAt
	g2 := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t-001")).GeneratedAt
	g3 := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t-001")).GeneratedAt
	if !(g1 < g2 && g2 < g3) {
		t.Fatalf("generated_at 应严格递增：%d, %d, %d", g1, g2, g3)
	}
}

// TestTTFTStats_NotFoundAndBadRequest：如实 404 / 400 分支。
func TestTTFTStats_NotFoundAndBadRequest(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	if rec := ttftPost(s, ttftBody("s5", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d", rec.Code)
	}

	// 404：无统计的 tenant / 无统计的 model 过滤
	for _, url := range []string{
		"/routes/ttft/stats?tenant=t-none",
		"/routes/ttft/stats?tenant=t-001&model=other-model",
	} {
		rec := ttftGet(s, url)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s 应 404，got %d %s", url, rec.Code, rec.Body.String())
			continue
		}
		var e struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "not_found" {
			t.Errorf("%s 错误码应 not_found，got %q", url, e.Code)
		}
	}

	// 400：tenant 缺失 / updated_since 非法
	for _, url := range []string{
		"/routes/ttft/stats",
		"/routes/ttft/stats?tenant=t-001&updated_since=-1",
		"/routes/ttft/stats?tenant=t-001&updated_since=abc",
	} {
		rec := ttftGet(s, url)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 应 400，got %d %s", url, rec.Code, rec.Body.String())
		}
	}

	// model 过滤命中 → 200
	if rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001&model=qwen-max"); rec.Code != http.StatusOK {
		t.Errorf("model 过滤命中应 200，got %d", rec.Code)
	}
}

// TestTTFTStats_UpdatedSinceIncrement：增量语义（updated_at > updated_since；过滤后可为空 stats）。
func TestTTFTStats_UpdatedSinceIncrement(t *testing.T) {
	s := ttftTestServer(t)
	now := time.Now().Unix()
	if rec := ttftPost(s, ttftBody("s6", now*1000, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d", rec.Code)
	}
	u := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t-001")).Stats[0].UpdatedAt

	// updated_since = u → 无增量（200 空 stats，不 404）
	resp := decodeStats(t, ttftGet(s, fmt.Sprintf("/routes/ttft/stats?tenant=t-001&updated_since=%d", u)))
	if len(resp.Stats) != 0 {
		t.Fatalf("updated_since=u 应过滤全部，got %d 条", len(resp.Stats))
	}
	// updated_since = u-1 → 全量
	resp = decodeStats(t, ttftGet(s, fmt.Sprintf("/routes/ttft/stats?tenant=t-001&updated_since=%d", u-1)))
	if len(resp.Stats) != 1 {
		t.Fatalf("updated_since=u-1 应保留 1 条，got %d", len(resp.Stats))
	}
}

// TestTTFTStats_MaxEntries：单次下发 ≤1000 条（超出按稳定序截断，§6.3）。
func TestTTFTStats_MaxEntries(t *testing.T) {
	s := ttftTestServer(t)
	s.ttftRing = route.NewTTFTRingWithLimit(nil, 1100)
	nowSec := time.Now().Unix()
	var b [route.TTFTBucketCount]uint64
	b[0] = 1
	for i := 0; i < 1005; i++ {
		k := route.TTFTKey{Tenant: "t", Model: "m", Endpoint: fmt.Sprintf("ep-%04d", i), Cache: "miss"}
		if res := s.ttftRing.Record(k, &b, nowSec, 300); res != route.TTFTIngestOK {
			t.Fatalf("预置第 %d 条失败：%v", i, res)
		}
	}
	resp := decodeStats(t, ttftGet(s, "/routes/ttft/stats?tenant=t"))
	if len(resp.Stats) != 1000 {
		t.Fatalf("单次应截断为 1000 条，got %d", len(resp.Stats))
	}
	if resp.Stats[0].Endpoint != "ep-0000" {
		t.Fatalf("截断应按稳定序（首条 ep-0000），got %s", resp.Stats[0].Endpoint)
	}
}
