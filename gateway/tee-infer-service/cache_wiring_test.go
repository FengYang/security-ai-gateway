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
	offCfg := cacheengine.DefaultConfig()
	offSrv := &teeServer{
		audit:   newAuditChainWithTSA(nil),
		metrics: newMetrics(),
	}
	offSrv.cacheRT.Store(newCacheState(&offCfg, cacheengine.NewCacheEngine(offCfg)))
	if body := fetchMetrics(t, offSrv); strings.Contains(body, "otpmask_cache_") {
		t.Fatalf("mode=off 不得追加缓存指标（/metrics 应与现网一致）:\n%s", body)
	}

	cfg := cacheengine.DefaultConfig()
	cfg.Mode = cacheengine.ModeExact
	onSrv := &teeServer{
		audit:   newAuditChainWithTSA(nil),
		metrics: newMetrics(),
	}
	onSrv.cacheRT.Store(newCacheState(&cfg, cacheengine.NewCacheEngine(cfg)))
	if body := fetchMetrics(t, onSrv); !strings.Contains(body, "otpmask_cache_entries") {
		t.Fatalf("mode=exact 应追加缓存指标，实际输出:\n%s", body)
	}
}

// TestHandleMetrics_ModeOffByteIdentical S-7：默认关闭（mode=off）时，
// /metrics 输出必须与"未装配缓存引擎"的现网基线**逐字节一致**（不只是"不含 otpmask_cache_"）。
func TestHandleMetrics_ModeOffByteIdentical(t *testing.T) {
	baselineSrv := &teeServer{ // 现网基线：cacheEngine == nil
		audit:   newAuditChainWithTSA(nil),
		metrics: newMetrics(),
	}
	offCfg := cacheengine.DefaultConfig()
	offSrv := &teeServer{
		audit:   newAuditChainWithTSA(nil),
		metrics: newMetrics(),
	}
	offSrv.cacheRT.Store(newCacheState(&offCfg, cacheengine.NewCacheEngine(offCfg))) // mode=off（默认）

	baseline := fetchMetrics(t, baselineSrv)
	off := fetchMetrics(t, offSrv)
	if baseline != off {
		t.Fatalf("mode=off 的 /metrics 必须与现网基线逐字节一致（baseline=%d 字节，off=%d 字节）", len(baseline), len(off))
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
