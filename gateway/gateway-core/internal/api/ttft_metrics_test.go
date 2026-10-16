package api

// ttft_metrics_test.go — P1-6 M3.8：控制面 TTFT 指标渲染（§6.5）。
//
// 覆盖：计数族（report_total{result} / samples_total{...} / reset_total）与
// 抓取时刻盘族（last_update_seconds / p50_ms / p95_ms）；reset 后刻盘族消失。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ttftMetricsBody 拉取 /metrics 文本。
func ttftMetricsBody(t *testing.T, s *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// TestTTFTMetrics_FamiliesAndResetClearsGauges：计数族 + 刻盘族（含 reset 后消失）。
func TestTTFTMetrics_FamiliesAndResetClearsGauges(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	labels := `tenant="t-001",model="qwen-max",endpoint="tee-gpu-a",cache="miss"`

	// 1 批 ok（30 样本全在首桶 [0,10] → p50=5 / p95=10）
	if rec := ttftPost(s, ttftBody("m1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d %s", rec.Code, rec.Body.String())
	}
	// 同批重发 → duplicate
	if rec := ttftPost(s, ttftBody("m1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); decodeResult(t, rec) != "duplicate" {
		t.Fatalf("重发应 duplicate，got %s", rec.Body.String())
	}
	// 非法批次（buckets 长度 0）→ 400 → reject 计数
	if rec := ttftPost(s, ttftBody("m2", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{})); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法批次应 400，got %d %s", rec.Code, rec.Body.String())
	}

	body := ttftMetricsBody(t, s)
	for _, want := range []string{
		`gateway_core_route_ttft_report_total{result="ok"} 1`,
		`gateway_core_route_ttft_report_total{result="duplicate"} 1`,
		`gateway_core_route_ttft_report_total{result="reject"} 1`,
		`gateway_core_route_ttft_samples_total{` + labels + `} 30`,
		`gateway_core_route_ttft_p50_ms{` + labels + `} 5`,
		`gateway_core_route_ttft_p95_ms{` + labels + `} 10`,
		`gateway_core_route_ttft_last_update_seconds{` + labels + `} ` + fmt.Sprintf("%d", nowMs/1000),
		`gateway_core_route_ttft_reset_total 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("缺指标行：%s\n---- body ----\n%s", want, body)
		}
	}
	// 无统计端点（tee-gpu-b）不得出现刻盘样本
	if strings.Contains(body, `endpoint="tee-gpu-b"`) {
		t.Errorf("无统计端点不应出现指标样本：\n%s", body)
	}

	// reset → 键清空：reset_total=1 且刻盘族消失（samples_total 为累计 Counter 保留）
	if rec := ttftResetReq(s, `{"tenant":"t-001","model":"qwen-max"}`, "ops"); rec.Code != http.StatusOK {
		t.Fatalf("reset 应 200，got %d", rec.Code)
	}
	body2 := ttftMetricsBody(t, s)
	if !strings.Contains(body2, `gateway_core_route_ttft_reset_total 1`) {
		t.Errorf("reset 后应 reset_total=1：\n%s", body2)
	}
	for _, absent := range []string{
		"gateway_core_route_ttft_p50_ms{",
		"gateway_core_route_ttft_p95_ms{",
		"gateway_core_route_ttft_last_update_seconds{",
	} {
		if strings.Contains(body2, absent) {
			t.Errorf("reset 后刻盘族不应渲染：%s", absent)
		}
	}
	// 累计 Counter 不因 reset 回退（样本已落片的历史仍计入）
	if !strings.Contains(body2, `gateway_core_route_ttft_samples_total{`+labels+`} 30`) {
		t.Errorf("samples_total 应保留累计值 30：\n%s", body2)
	}
}

// TestTTFTMetrics_NoData：无 TTFT 数据时仅 reset_total=0 可见（其余族不渲染）。
func TestTTFTMetrics_NoData(t *testing.T) {
	s := ttftTestServer(t)
	body := ttftMetricsBody(t, s)
	if !strings.Contains(body, "gateway_core_route_ttft_reset_total 0") {
		t.Errorf("应始终输出 reset_total=0：\n%s", body)
	}
	for _, absent := range []string{
		"gateway_core_route_ttft_report_total{",
		"gateway_core_route_ttft_samples_total{",
		"gateway_core_route_ttft_p50_ms",
		"gateway_core_route_ttft_p95_ms",
		"gateway_core_route_ttft_last_update_seconds",
	} {
		if strings.Contains(body, absent) {
			t.Errorf("无数据时不应渲染：%s\n%s", absent, body)
		}
	}
}
