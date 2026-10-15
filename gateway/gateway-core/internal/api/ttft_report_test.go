package api

// ttft_report_test.go — P1-6 M3.4：POST /routes/ttft/report（§6.2；400 分支齐备 + 去重 + 条目上限）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/route"
)

// ttftTestServer 构造带一条已签名路由（含端点）的控制面实例。
func ttftTestServer(t *testing.T) *Server {
	t.Helper()
	s := testServer()
	tbl := &route.RouteTable{Version: 2, UpdatedAt: 1725500001, Routes: []route.TableRoute{{
		Tenant: "t-001", Model: "qwen-max", DefaultEngine: "cmaas",
		Strategy: "latency-aware", Latency: &route.RouteLatency{WindowSec: 300},
		Endpoints: []route.TableEndpoint{
			{Name: "tee-gpu-a", URL: "https://a.internal/v1", Weight: 1, Priority: 1, Enabled: true},
			{Name: "tee-gpu-b", URL: "https://b.internal/v1", Weight: 1, Priority: 2, Enabled: true},
		},
	}}}
	if err := s.signer.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	s.store.SaveRouteTable(tbl)
	return s
}

// ttftPost 发送上报请求并返回响应。
func ttftPost(s *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/routes/ttft/report", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// ttftBody 构造单样本上报体（worker = VM 实例 ID 字符串，§6.2/R2-03）。
func ttftBody(batchID string, reportedAtMs int64, tenant, model, endpoint, cache string, buckets []uint64) string {
	bs, _ := json.Marshal(buckets)
	return fmt.Sprintf(
		`{"node":"envoy-0","worker":"vm-2","batch_id":%q,"reported_at":%d,"samples":[{"tenant":%q,"model":%q,"endpoint":%q,"cache":%q,"buckets":%s}]}`,
		batchID, reportedAtMs, tenant, model, endpoint, cache, bs)
}

var ttftZeroBuckets = []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func decodeResult(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应 JSON 解析失败：%v（body=%s）", err, rec.Body.String())
	}
	r, _ := resp["result"].(string)
	return r
}

// TestTTFTReport_HappyPathAndDedup：落片/同 batch_id 重复 ACK 丢弃不双计/窗口内旧时间戳可入。
func TestTTFTReport_HappyPathAndDedup(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	keyA := route.TTFTKey{Tenant: "t-001", Model: "qwen-max", Endpoint: "tee-gpu-a", Cache: "miss"}

	rec := ttftPost(s, ttftBody("envoy-0|2|p1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0}))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "ok" {
		t.Fatalf("合法上报应 200 ok，got %d %s", rec.Code, rec.Body.String())
	}
	w, ok := s.ttftRing.Merge(keyA)
	if !ok || w.Samples != 6 || w.Buckets[1] != 2 {
		t.Fatalf("落片不符：ok=%v %+v", ok, w)
	}

	// 重复 batch_id：内容不同也不双计、返回 duplicate
	rec = ttftPost(s, ttftBody("envoy-0|2|p1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "duplicate" {
		t.Fatalf("重复批次应 200 duplicate，got %d %s", rec.Code, rec.Body.String())
	}
	if w2, _ := s.ttftRing.Merge(keyA); w2.Samples != 6 {
		t.Fatalf("重复批次不应双计，got samples=%d", w2.Samples)
	}

	// 正常重试窗口内旧时间戳（now-40s）可入（落对应旧分片、不同索引）
	rec = ttftPost(s, ttftBody("envoy-0|2|p2", nowMs-40_000, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0}))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "ok" {
		t.Fatalf("正常重试应 200 ok，got %d %s", rec.Code, rec.Body.String())
	}
	if w3, _ := s.ttftRing.Merge(keyA); w3.Samples != 10 {
		t.Fatalf("重试批次应参与合并，got samples=%d", w3.Samples)
	}

	// 边界旧批次（now-299s，分片起点已跨淘汰线且与在窗分片索引冲突）：ACK 但不得破坏在窗数据
	rec = ttftPost(s, ttftBody("envoy-0|2|p3", nowMs-299_000, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "ok" {
		t.Fatalf("边界旧批次应 ACK（200 ok），got %d %s", rec.Code, rec.Body.String())
	}
	if w4, _ := s.ttftRing.Merge(keyA); w4.Samples != 10 {
		t.Fatalf("边界旧批次不得破坏/叠加在窗数据，got samples=%d", w4.Samples)
	}

	// 计数
	if s.metrics.reportResult["ok"] != 3 || s.metrics.reportResult["duplicate"] != 1 {
		t.Fatalf("计数不符：%v", s.metrics.reportResult)
	}
}

// TestTTFTReport_RejectBranches：400 invalid_request 分支矩阵（TT2-03/TT2-08）。
func TestTTFTReport_RejectBranches(t *testing.T) {
	s := ttftTestServer(t)
	now := time.Now().Unix()
	nowMs := now * 1000

	tooMany := strings.Repeat(`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","buckets":[0,0,0,0,0,0,0,0,0,0,0]},`, 1001)
	overBucket := []uint64{1_000_001, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	overTotal := []uint64{1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000}

	cases := []struct {
		name string
		body string
	}{
		{"JSON 非法", `{`},
		{"batch_id 为空", ttftBody("", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{"reported_at 为 0", ttftBody("b1", 0, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{"samples 为空", fmt.Sprintf(`{"batch_id":"b2","reported_at":%d,"samples":[]}`, nowMs)},
		{"samples 超上限", fmt.Sprintf(`{"batch_id":"b3","reported_at":%d,"samples":[%s]}`,
			nowMs, strings.TrimSuffix(tooMany, ","))},
		{"tenant 为空", ttftBody("b4", nowMs, "", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{"cache 非法", ttftBody("b5", nowMs, "t-001", "qwen-max", "tee-gpu-a", "l1", ttftZeroBuckets)},
		{"buckets 长度≠11", ttftBody("b6", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", []uint64{1, 2, 3})},
		{"单桶越上限", ttftBody("b7", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", overBucket)},
		{"单批总样本越上限", ttftBody("b8", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", overTotal)},
		{"reported_at 越窗（过旧）", ttftBody("b9", (now-400)*1000, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{"reported_at 越窗（超前）", ttftBody("b10", (now+120)*1000, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
		{"幽灵端点", ttftBody("b11", nowMs, "t-001", "qwen-max", "ghost", "miss", ttftZeroBuckets)},
		{"未知路由", ttftBody("b12", nowMs, "t-x", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)},
	}
	for _, c := range cases {
		rec := ttftPost(s, c.body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s：应 400，got %d %s", c.name, rec.Code, rec.Body.String())
			continue
		}
		var e struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "invalid_request" {
			t.Errorf("%s：错误码应 invalid_request，got %q（%s）", c.name, e.Code, rec.Body.String())
		}
	}
	// 全部被拒 → 无落片
	if _, ok := s.ttftRing.Merge(route.TTFTKey{Tenant: "t-001", Model: "qwen-max", Endpoint: "tee-gpu-a", Cache: "miss"}); ok {
		t.Fatal("被拒批次不应落片")
	}
	if s.metrics.reportResult["reject"] != int64(len(cases)) {
		t.Fatalf("reject 计数应=%d，got %d", len(cases), s.metrics.reportResult["reject"])
	}
	// 400 拒绝不消耗 batch_id：同 batch_id 修正后重发应 ok
	rec := ttftPost(s, ttftBody("b11", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "ok" {
		t.Fatalf("被拒 batch_id 重发（合法）应 200 ok，got %d %s", rec.Code, rec.Body.String())
	}
}

// TestTTFTReport_EntryLimit503：聚合条目上限 → 503 source_unavailable；既有键不受影响。
func TestTTFTReport_EntryLimit503(t *testing.T) {
	s := ttftTestServer(t)
	s.ttftRing = route.NewTTFTRingWithLimit(nil, 1)
	nowMs := time.Now().Unix() * 1000

	// 占满唯一容量（tee-gpu-a）
	if rec := ttftPost(s, ttftBody("e1", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)); rec.Code != http.StatusOK {
		t.Fatalf("首条应 200，got %d %s", rec.Code, rec.Body.String())
	}
	// 新键（tee-gpu-b）→ 503
	rec := ttftPost(s, ttftBody("e2", nowMs, "t-001", "qwen-max", "tee-gpu-b", "miss", ttftZeroBuckets))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("条目超限应 503，got %d %s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Code != "source_unavailable" {
		t.Fatalf("错误码应 source_unavailable，got %q", e.Code)
	}
	// 既有键照常
	if rec := ttftPost(s, ttftBody("e3", nowMs, "t-001", "qwen-max", "tee-gpu-a", "miss", ttftZeroBuckets)); rec.Code != http.StatusOK {
		t.Fatalf("既有键应不受上限影响，got %d %s", rec.Code, rec.Body.String())
	}
}
