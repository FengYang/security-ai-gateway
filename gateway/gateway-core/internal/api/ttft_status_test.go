package api

// ttft_status_test.go — P1-6 M3.7：GET /routes/endpoints/status TTFT 扩展（§6.4；TT2-16 兼容性）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ttftStatusEndpoints 拉取端点状态并按 name 索引。
func ttftStatusEndpoints(t *testing.T, s *Server) map[string]map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/routes/endpoints/status", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("endpoints/status 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应 JSON 解析失败：%v", err)
	}
	out := map[string]map[string]any{}
	for _, ep := range resp.Endpoints {
		name, _ := ep["name"].(string)
		out[name] = ep
	}
	return out
}

// TestEndpointStatusTTFT_ExtensionAndCompat：有统计端点为 cache 合并快照；无统计端点字段缺失（TT2-16）。
func TestEndpointStatusTTFT_ExtensionAndCompat(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	body := fmt.Sprintf(
		`{"batch_id":"st1","reported_at":%d,"samples":[`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","buckets":[30,0,0,0,0,0,0,0,0,0,0]},`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"hit","buckets":[30,0,0,0,0,0,0,0,0,0,0]}]}`, nowMs)
	if rec := ttftPost(s, body); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d %s", rec.Code, rec.Body.String())
	}

	eps := ttftStatusEndpoints(t, s)
	// tee-gpu-a：60 样本（cache 合并），p95=10，valid=true
	epA, ok := eps["tee-gpu-a"]
	if !ok {
		t.Fatal("缺 tee-gpu-a 条目")
	}
	if epA["ttft_samples"] != float64(60) || epA["ttft_valid"] != true || epA["ttft_p95_ms"] != float64(10) {
		t.Fatalf("tee-gpu-a TTFT 快照不符：%v", epA)
	}
	// 既有字段不受影响
	if epA["tenant"] != "t-001" || epA["model"] != "qwen-max" || epA["enabled"] != true {
		t.Fatalf("既有字段不符：%v", epA)
	}
	// tee-gpu-b：无统计 → 三个 TTFT 字段整体缺失（兼容性：缺失=无统计）
	epB, ok := eps["tee-gpu-b"]
	if !ok {
		t.Fatal("缺 tee-gpu-b 条目")
	}
	for _, f := range []string{"ttft_p95_ms", "ttft_valid", "ttft_samples"} {
		if _, present := epB[f]; present {
			t.Fatalf("无统计端点不得出现 %s：%v", f, epB)
		}
	}
}

// TestEndpointStatusTTFT_InvalidThenResetAbsent：陈旧 → valid=false 仍可见；reset → 字段复归缺失。
func TestEndpointStatusTTFT_InvalidThenResetAbsent(t *testing.T) {
	s := ttftTestServer(t)
	now := time.Now().Unix()
	// 陈旧上报（100s 前，超 stale 75s）
	if rec := ttftPost(s, ttftBody("st2", (now-100)*1000, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("上报应 200，got %d %s", rec.Code, rec.Body.String())
	}
	eps := ttftStatusEndpoints(t, s)
	epA := eps["tee-gpu-a"]
	if epA["ttft_samples"] != float64(30) || epA["ttft_valid"] != false {
		t.Fatalf("陈旧快照应 samples=30 valid=false：%v", epA)
	}
	if _, present := epA["ttft_p95_ms"]; !present {
		t.Fatalf("有统计（虽无效）应下发 p95 值：%v", epA)
	}

	// reset → 键清空 → 字段复归缺失
	if rec := ttftResetReq(s, `{"tenant":"t-001","model":"qwen-max"}`, "ops"); rec.Code != http.StatusOK {
		t.Fatalf("reset 应 200，got %d", rec.Code)
	}
	eps = ttftStatusEndpoints(t, s)
	epA = eps["tee-gpu-a"]
	for _, f := range []string{"ttft_p95_ms", "ttft_valid", "ttft_samples"} {
		if _, present := epA[f]; present {
			t.Fatalf("reset 后不得出现 %s：%v", f, epA)
		}
	}
}
