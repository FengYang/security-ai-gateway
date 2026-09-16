package main

// A 项（判据 4 扩展）：数据面明文路由影子的**窗口级汇总上报**测试。
//   - 端点契约（200 + accepted/deduped/chain_events）
//   - 每条 report 落**一条**审计事件（action=shadow / result=would_reject / shadow_rule / payload_hash=sha256(report_id)）
//   - report_id 幂等（TTL 内重复 → 不重复落链）
//   - 校验（整批 400，不做部分接受）、方法与认证
//   - 幂等状态 TTL/容量淘汰
//   - 指标 otpmask_shadow_reports_total{result}

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// postShadowReports 向上报端点发一批 report（返回状态码与响应体）。
func postShadowReports(t *testing.T, ts *httptest.Server, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(ts.URL+"/audit/shadow", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// shadowReportsMetrics 渲染当前指标文本（直接调 render，避免依赖 HTTP 与认证）。
func shadowReportsMetrics(s *teeServer) string {
	var buf bytes.Buffer
	s.metrics.render(&buf, s.audit.len())
	return buf.String()
}

// validShadowBody 两条合法上报：tenant 维度 + api_key 维度（消费者名＝X-Mse-Consumer 值）。
const validShadowBody = `{"reports":[
  {"report_id":"rp-tenant","rule_id":"t-a-rate-shadow","scope":"tenant","target":"t-a",
   "window":"minute","window_start":1789272000,"threshold":600,"observed":617,"would_reject":17,"source":"data-plane"},
  {"report_id":"rp-apikey","rule_id":"c1-rate-shadow","scope":"api_key","target":"a-probe-consumer","tenant":"t-a",
   "window":"minute","window_start":1789272000,"threshold":60,"observed":80,"would_reject":20,"sample_request_ids":["r1","r2"]}
]}`

// TestShadowReportEndpoint_acceptAndChain 汇总上报落链：字段契约 + 链完整 + 指标。
func TestShadowReportEndpoint_acceptAndChain(t *testing.T) {
	srv, ts := newM9Server(t)
	code, out := postShadowReports(t, ts, validShadowBody)
	if code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d（%+v）", code, out)
	}
	if out["accepted"] != float64(2) || out["deduped"] != float64(0) || out["chain_events"] != float64(2) {
		t.Fatalf("响应不符: %+v", out)
	}
	events := srv.audit.query("")
	if len(events) != 2 {
		t.Fatalf("应落 2 条链事件，实际 %d", len(events))
	}
	byID := map[string]AuditEvent{}
	for _, e := range events {
		byID[e.RequestID] = e
	}
	e1, ok := byID["rp-tenant"]
	if !ok {
		t.Fatal("缺 tenant 维度事件（request_id=report_id）")
	}
	if e1.Action != "shadow" || e1.Result != "would_reject" || e1.ShadowRule != "t-a-rate-shadow@minute" {
		t.Fatalf("事件字段不符: %+v", e1)
	}
	if e1.TenantID != "t-a" {
		t.Fatalf("tenant 维度事件应归属 t-a（target 即租户）: %+v", e1)
	}
	sum := sha256.Sum256([]byte("rp-tenant"))
	if e1.PayloadSHA != hex.EncodeToString(sum[:]) {
		t.Fatalf("payload_hash 应为 sha256(report_id)，实际 %s", e1.PayloadSHA)
	}
	if e1.TokensIn != 0 || e1.TokensOut != 0 {
		t.Fatalf("明文影子不计量 token（tokens_in/out 应为 0）: %+v", e1)
	}
	e2, ok := byID["rp-apikey"]
	if !ok {
		t.Fatal("缺 api_key 维度事件")
	}
	if e2.ShadowRule != "c1-rate-shadow@minute" || e2.TenantID != "t-a" {
		t.Fatalf("api_key 维度事件不符（target=消费者名、tenant 取请求侧租户）: %+v", e2)
	}
	if ok, at := srv.audit.verify(); !ok {
		t.Fatalf("落链后审计链应完整，断点在 %d", at)
	}
	m := shadowReportsMetrics(srv)
	if !strings.Contains(m, `otpmask_shadow_reports_total{result="accepted"} 2`) {
		t.Fatalf("指标应记录 accepted=2: %s", m)
	}
}

// TestShadowReportEndpoint_idempotent 同 report_id 重复上报：deduped 计数、不重复落链。
func TestShadowReportEndpoint_idempotent(t *testing.T) {
	srv, ts := newM9Server(t)
	if code, _ := postShadowReports(t, ts, validShadowBody); code != http.StatusOK {
		t.Fatalf("首次上报应 200，实际 %d", code)
	}
	code, out := postShadowReports(t, ts, validShadowBody)
	if code != http.StatusOK {
		t.Fatalf("重复上报应 200（幂等非错误），实际 %d", code)
	}
	if out["accepted"] != float64(0) || out["deduped"] != float64(2) || out["chain_events"] != float64(0) {
		t.Fatalf("重复上报应全部 deduped: %+v", out)
	}
	if n := len(srv.audit.query("")); n != 2 {
		t.Fatalf("重复上报不得追加链事件，实际 %d 条", n)
	}
	m := shadowReportsMetrics(srv)
	if !strings.Contains(m, `otpmask_shadow_reports_total{result="deduped"} 2`) {
		t.Fatalf("指标应记录 deduped=2: %s", m)
	}
}

// TestShadowReportEndpoint_validation 非法上报一律 400（整批拒绝），并计 rejected 指标。
func TestShadowReportEndpoint_validation(t *testing.T) {
	srv, ts := newM9Server(t)
	cases := []struct {
		name string
		body string
	}{
		{"空 reports", `{"reports":[]}`},
		{"缺 report_id", `{"reports":[{"rule_id":"r","scope":"tenant","target":"t-a","window":"minute","window_start":1,"threshold":1,"observed":1,"would_reject":0}]}`},
		{"scope 非法", `{"reports":[{"report_id":"r1","rule_id":"r","scope":"model","target":"m","window":"minute","window_start":1,"threshold":1,"observed":1,"would_reject":0}]}`},
		{"缺 target", `{"reports":[{"report_id":"r1","rule_id":"r","scope":"api_key","window":"minute","window_start":1,"threshold":1,"observed":1,"would_reject":0}]}`},
		{"window 非 minute", `{"reports":[{"report_id":"r1","rule_id":"r","scope":"tenant","target":"t-a","window":"day","window_start":1,"threshold":1,"observed":1,"would_reject":0}]}`},
		{"threshold 非正", `{"reports":[{"report_id":"r1","rule_id":"r","scope":"tenant","target":"t-a","window":"minute","window_start":1,"threshold":0,"observed":1,"would_reject":0}]}`},
		{"would_reject > observed", `{"reports":[{"report_id":"r1","rule_id":"r","scope":"tenant","target":"t-a","window":"minute","window_start":1,"threshold":1,"observed":1,"would_reject":2}]}`},
		{"样本超 5 条", `{"reports":[{"report_id":"r1","rule_id":"r","scope":"tenant","target":"t-a","window":"minute","window_start":1,"threshold":1,"observed":9,"would_reject":1,"sample_request_ids":["1","2","3","4","5","6"]}]}`},
	}
	for _, c := range cases {
		if code, _ := postShadowReports(t, ts, c.body); code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d", c.name, code)
		}
	}
	if n := len(srv.audit.query("")); n != 0 {
		t.Fatalf("非法上报不得落链，实际 %d 条", n)
	}
	m := shadowReportsMetrics(srv)
	if !strings.Contains(m, `otpmask_shadow_reports_total{result="rejected"} 8`) {
		t.Fatalf("指标应记录 rejected=8: %s", m)
	}
	// 方法：非 POST → 405
	resp, err := http.Get(ts.URL + "/audit/shadow")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应 405，实际 %d", resp.StatusCode)
	}
}

// TestShadowReportEndpoint_adminAuth 配置管理令牌后须带 X-Admin-Token。
func TestShadowReportEndpoint_adminAuth(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.adminToken = "admin-tok"
	if code, _ := postShadowReports(t, ts, validShadowBody); code != http.StatusUnauthorized {
		t.Fatalf("缺管理令牌应 401，实际 %d", code)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/audit/shadow", bytes.NewReader([]byte(validShadowBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "admin-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带管理令牌应 200，实际 %d", resp.StatusCode)
	}
}

// TestShadowReportState_ttlAndCap 幂等状态：TTL 过期后可重新接受；超容量按最早淘汰。
func TestShadowReportState_ttlAndCap(t *testing.T) {
	now := time.Now()
	st := newShadowReportState(50*time.Millisecond, 3)
	if !st.admit("a", now) {
		t.Fatal("首次应接受")
	}
	if st.admit("a", now) {
		t.Fatal("TTL 内重复应拒绝")
	}
	if !st.admit("a", now.Add(100*time.Millisecond)) {
		t.Fatal("TTL 过期后应重新接受")
	}

	// 容量上限：max=2 → 第 3 条进入时淘汰最早者（a），故 a 可再次被接受。
	// 三条共用同一时间戳（对齐生产同请求共用 time.Now）：相等时间按插入序 FIFO
	// 淘汰，结果必须确定性（R8 回归，禁止退回 map 随机遍历序）。
	st2 := newShadowReportState(time.Minute, 2)
	st2.admit("a", now)
	st2.admit("b", now)
	st2.admit("c", now)
	if len(st2.seen) != 2 {
		t.Fatalf("应保持 max=2，实际 %d", len(st2.seen))
	}
	if !st2.admit("a", now) {
		t.Fatal("被淘汰的 report_id 应可重新接受（避免误判重）")
	}
}

// TestShadowReportEndpoint_apiKeyScopeWithoutTenant api_key 维度未带租户时不伪造归属。
func TestShadowReportEndpoint_apiKeyScopeWithoutTenant(t *testing.T) {
	srv, ts := newM9Server(t)
	body := fmt.Sprintf(`{"reports":[{"report_id":"rp-no-tenant-%d","rule_id":"c9-rate-shadow","scope":"api_key","target":"consumer-x","window":"minute","window_start":1789272000,"threshold":10,"observed":20,"would_reject":10}]}`, time.Now().UnixNano())
	if code, _ := postShadowReports(t, ts, body); code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", code)
	}
	events := srv.audit.query("")
	if len(events) != 1 {
		t.Fatalf("应落 1 条事件，实际 %d", len(events))
	}
	if events[0].TenantID != "" {
		t.Fatalf("api_key 维度且未带租户时不得伪造归属，实际 tenant=%q", events[0].TenantID)
	}
	if events[0].ShadowRule != "c9-rate-shadow@minute" {
		t.Fatalf("shadow_rule 不符: %q", events[0].ShadowRule)
	}
}
