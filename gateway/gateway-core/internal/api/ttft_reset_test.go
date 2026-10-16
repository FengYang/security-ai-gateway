package api

// ttft_reset_test.go — P1-6 M3.6：POST /routes/ttft/reset（§6.2；清空 + reset 水位 + 审计 + 幂等）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
)

// ttftResetReq 发送重置请求（actor 非空时带 X-Actor）。
func ttftResetReq(s *Server, body, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/routes/ttft/reset", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

type ttftResetResp struct {
	Result  string `json:"result"`
	Tenant  string `json:"tenant"`
	Model   string `json:"model"`
	Cleared int    `json:"cleared"`
	ResetAt int64  `json:"reset_at"`
}

func decodeReset(t *testing.T, rec *httptest.ResponseRecorder) ttftResetResp {
	t.Helper()
	var resp ttftResetResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应 JSON 解析失败：%v（body=%s）", err, rec.Body.String())
	}
	return resp
}

// TestTTFTReset_ClearsWatermarkAndIdempotent：清空全部键、stats 404、幂等、旧世代丢弃/新世代可入。
func TestTTFTReset_ClearsWatermarkAndIdempotent(t *testing.T) {
	s := ttftTestServer(t)
	nowMs := time.Now().Unix() * 1000
	body := fmt.Sprintf(
		`{"batch_id":"bb1","reported_at":%d,"samples":[`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","buckets":[30,0,0,0,0,0,0,0,0,0,0]},`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"hit","buckets":[30,0,0,0,0,0,0,0,0,0,0]}]}`, nowMs)
	if rec := ttftPost(s, body); rec.Code != http.StatusOK {
		t.Fatalf("预置上报应 200，got %d %s", rec.Code, rec.Body.String())
	}
	if rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001"); rec.Code != http.StatusOK {
		t.Fatalf("预置后 stats 应 200，got %d", rec.Code)
	}

	// 重置：清空 2 键
	rec := ttftResetReq(s, `{"tenant":"t-001","model":"qwen-max"}`, "ops-bot")
	if rec.Code != http.StatusOK {
		t.Fatalf("reset 应 200，got %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeReset(t, rec)
	if resp.Result != "ok" || resp.Cleared != 2 || resp.ResetAt <= 0 {
		t.Fatalf("reset 响应不符：%+v", resp)
	}
	// 清空后 stats 如实 404
	if rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001"); rec.Code != http.StatusNotFound {
		t.Fatalf("reset 后 stats 应 404，got %d %s", rec.Code, rec.Body.String())
	}
	// 幂等：再重置 cleared=0
	resp2 := decodeReset(t, ttftResetReq(s, `{"tenant":"t-001","model":"qwen-max"}`, ""))
	if resp2.Result != "ok" || resp2.Cleared != 0 {
		t.Fatalf("二次 reset 应幂等 cleared=0，got %+v", resp2)
	}

	// 旧世代批次（周期起始 = resetAt-5 < 水位）→ 200 dropped 且不落片
	oldMs := (resp.ResetAt - 5) * 1000
	rec = ttftPost(s, ttftBody("bb-old", oldMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "dropped" {
		t.Fatalf("旧世代批次应 200 dropped，got %d %s", rec.Code, rec.Body.String())
	}
	if rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001"); rec.Code != http.StatusNotFound {
		t.Fatalf("旧世代批次不得复现统计（应仍 404），got %d %s", rec.Code, rec.Body.String())
	}

	// 新世代批次（周期起始 = resetAt == 水位）→ 200 ok 且落片
	newMs := resp.ResetAt * 1000
	rec = ttftPost(s, ttftBody("bb-new", newMs, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
	if rec.Code != http.StatusOK || decodeResult(t, rec) != "ok" {
		t.Fatalf("新世代批次应 200 ok，got %d %s", rec.Code, rec.Body.String())
	}
	statsRec := ttftGet(s, "/routes/ttft/stats?tenant=t-001")
	if statsRec.Code != http.StatusOK {
		t.Fatalf("新世代落片后 stats 应 200，got %d %s", statsRec.Code, statsRec.Body.String())
	}
	if got := decodeStats(t, statsRec); len(got.Stats) != 1 || got.Stats[0].UpdatedAt != resp.ResetAt {
		t.Fatalf("新世代统计不符：%s", statsRec.Body.String())
	}
}

// TestTTFTReset_MixedBatchPartialDrop：批次跨模型——命中水位的样本丢弃、未 reset 模型正常落片。
func TestTTFTReset_MixedBatchPartialDrop(t *testing.T) {
	s := ttftTestServer(t)
	// 追加第二条路由（qwen-turbo / tee-gpu-b）
	cur := s.store.GetRouteTable()
	tbl := &route.RouteTable{Version: cur.Version + 1, UpdatedAt: time.Now().Unix(),
		Routes: append(cur.Clone().Routes, route.TableRoute{
			Tenant: "t-001", Model: "qwen-turbo", DefaultEngine: "cmaas",
			Endpoints: []route.TableEndpoint{
				{Name: "tee-gpu-b", URL: "https://b.internal/v1", Weight: 1, Priority: 1, Enabled: true},
			},
		})}
	if err := s.signer.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	s.store.SaveRouteTable(tbl)

	// 给 qwen-max 预置并 reset（建立水位）
	now := time.Now().Unix()
	if rec := ttftPost(s, ttftBody("mx0", now*1000, "t-001", "qwen-max", "tee-gpu-a", "miss",
		[]uint64{30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})); rec.Code != http.StatusOK {
		t.Fatalf("预置应 200，got %d", rec.Code)
	}
	resp := decodeReset(t, ttftResetReq(s, `{"tenant":"t-001","model":"qwen-max"}`, "ops"))

	// 混合批次：同一 reported_at（resetAt-5）；qwen-max 丢弃、qwen-turbo 落片
	mixMs := (resp.ResetAt - 5) * 1000
	mix := fmt.Sprintf(
		`{"batch_id":"mx1","reported_at":%d,"samples":[`+
			`{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","buckets":[9,0,0,0,0,0,0,0,0,0,0]},`+
			`{"tenant":"t-001","model":"qwen-turbo","endpoint":"tee-gpu-b","cache":"miss","buckets":[5,0,0,0,0,0,0,0,0,0,0]}]}`, mixMs)
	rec := ttftPost(s, mix)
	if rec.Code != http.StatusOK {
		t.Fatalf("混合批次应 200，got %d %s", rec.Code, rec.Body.String())
	}
	var r map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r["result"] != "ok" || r["dropped"] != float64(1) {
		t.Fatalf("混合批次应 ok+dropped=1，got %s", rec.Body.String())
	}
	// qwen-max 无统计；qwen-turbo 有 5 样本
	if rec := ttftGet(s, "/routes/ttft/stats?tenant=t-001&model=qwen-max"); rec.Code != http.StatusNotFound {
		t.Fatalf("qwen-max 应 404，got %d", rec.Code)
	}
	statsRec := ttftGet(s, "/routes/ttft/stats?tenant=t-001&model=qwen-turbo")
	if statsRec.Code != http.StatusOK {
		t.Fatalf("qwen-turbo stats 应 200，got %d %s", statsRec.Code, statsRec.Body.String())
	}
	if got := decodeStats(t, statsRec); len(got.Stats) != 1 || got.Stats[0].Samples != 5 {
		t.Fatalf("qwen-turbo 统计不符：%s", statsRec.Body.String())
	}
}

// TestTTFTReset_AuditAndMetrics：落 policyaudit（action=route_ttft_reset；actor/rule_id）与 reset 计数。
func TestTTFTReset_AuditAndMetrics(t *testing.T) {
	s := ttftTestServer(t)
	before := s.audit.Len()
	rec := ttftResetReq(s, `{"tenant":"t-001","model":"qwen-max"}`, "ops-bot")
	if rec.Code != http.StatusOK {
		t.Fatalf("reset 应 200，got %d", rec.Code)
	}
	if s.audit.Len() != before+1 {
		t.Fatalf("审计链应 +1 条，got %d→%d", before, s.audit.Len())
	}
	found := false
	for _, ev := range s.audit.List(10) {
		if ev.Action == policyaudit.ActionTTFTReset {
			found = true
			if ev.Actor != "ops-bot" || ev.RuleID != "t-001/qwen-max" || ev.Change != "reset" || ev.Result != policyaudit.ResultOK {
				t.Errorf("审计事件字段不符：%+v", ev)
			}
		}
	}
	if !found {
		t.Fatal("审计链缺 route_ttft_reset 事件")
	}
	if s.metrics.ttftResets != 1 {
		t.Fatalf("reset 计数应=1，got %d", s.metrics.ttftResets)
	}
}

// TestTTFTReset_BadRequests：400 分支。
func TestTTFTReset_BadRequests(t *testing.T) {
	s := ttftTestServer(t)
	for _, c := range []struct{ name, body string }{
		{"JSON 非法", `{`},
		{"tenant 缺失", `{"model":"qwen-max"}`},
		{"model 缺失", `{"tenant":"t-001"}`},
	} {
		rec := ttftResetReq(s, c.body, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 应 400，got %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	if s.metrics.ttftResets != 0 {
		t.Fatalf("400 不应计数 reset，got %d", s.metrics.ttftResets)
	}
}
