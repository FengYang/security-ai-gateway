package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
)

// TestHandleMetrics_CacheGating P0-2 接线回归：
//   - mode=off（默认）→ /metrics 不得追加任何 otpmask_cache_* 指标（与现网输出一致）；
//   - mode=exact      → /metrics 追加缓存指标（entries 等）。
func TestHandleMetrics_CacheGating(t *testing.T) {
	offSrv := &teeServer{
		audit:       newAuditChainWithTSA(nil),
		metrics:     newMetrics(),
		cacheEngine: cacheengine.NewCacheEngine(cacheengine.DefaultConfig()),
	}
	if body := fetchMetrics(t, offSrv); strings.Contains(body, "otpmask_cache_") {
		t.Fatalf("mode=off 不得追加缓存指标（/metrics 应与现网一致）:\n%s", body)
	}

	cfg := cacheengine.DefaultConfig()
	cfg.Mode = cacheengine.ModeExact
	onSrv := &teeServer{
		audit:       newAuditChainWithTSA(nil),
		metrics:     newMetrics(),
		cacheEngine: cacheengine.NewCacheEngine(cfg),
	}
	if body := fetchMetrics(t, onSrv); !strings.Contains(body, "otpmask_cache_entries") {
		t.Fatalf("mode=exact 应追加缓存指标，实际输出:\n%s", body)
	}
}

// fetchMetrics 通过最小 mux 抓取 /metrics 响应体。
func fetchMetrics(t *testing.T, s *teeServer) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	return string(b)
}
