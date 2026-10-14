package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signReport 计算请求体 HMAC-SHA256 签名（D-13）。
func signReport(t *testing.T, token string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// newReportServer 构造带内存审计链的上报端点测试 server（plugin 模式，绑定 t-001/t-002）。
func newReportServer(token string, tenants map[string]bool) *teeServer {
	s := &teeServer{
		auditReportToken:  token,
		auditReportTenants: tenants,
		auditReports:      newShadowReportState(shadowReportTTL, shadowReportMax),
		audit:             newAuditChain(),
	}
	return s
}

func buildReportBody(t *testing.T, items []auditReportItem) ([]byte, *auditReport) {
	t.Helper()
	req := &auditReport{Reports: items}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw, req
}

func doReport(t *testing.T, s *teeServer, raw []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/audit/report", bytes.NewReader(raw))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.handleAuditReport(w, r)
	return w
}

const testReportToken = "report-tok-0001"

func pluginServer(t *testing.T) *teeServer {
	return newReportServer(testReportToken, map[string]bool{"t-001": true, "t-002": true})
}

// TestT2aValidBatchAccepted 合法批量 → 200，事件落链 action=request/origin=data-plane/payload_hash=sha256(request_id)。
func TestT2aValidBatchAccepted(t *testing.T) {
	s := pluginServer(t)
	now := time.Now().UnixNano()
	items := []auditReportItem{
		{RequestID: "req-a", TenantID: "t-001", Path: "/v1/infer", PathMode: "encrypted", HTTPStatus: 200, Result: "cache_hit_dataplane", TimestampNS: now, DurMS: 3, Model: "qwen-max"},
		{RequestID: "req-b", TenantID: "t-002", Result: "non_infer", TimestampNS: now},
	}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         testReportToken,
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Accepted != 2 || resp.Duplicates != 0 {
		t.Fatalf("期望 accepted=2 duplicates=0，实际 %+v", resp)
	}
	evs := s.audit.events
	if len(evs) != 2 {
		t.Fatalf("期望落链 2 条，实际 %d", len(evs))
	}
	for _, e := range evs {
		if e.Action != "request" || e.Origin != "data-plane" {
			t.Fatalf("落链事件字段错误：action=%q origin=%q", e.Action, e.Origin)
		}
		sum := sha256.Sum256([]byte(e.RequestID))
		if e.PayloadSHA != hex.EncodeToString(sum[:]) {
			t.Fatalf("payload_hash 不符：%q", e.PayloadSHA)
		}
		if e.ReporterID != "tok-"+reporterHash8(testReportToken) {
			t.Fatalf("reporter_id 未由服务端写入：%q", e.ReporterID)
		}
		// timestamp_ns 有效 → 落链时间戳保留原始上报时刻
		if e.Timestamp != now {
			t.Fatalf("期望 Timestamp=%d，实际 %d", now, e.Timestamp)
		}
	}
}

// TestT2aIdempotent 同 request_id 重复上报 → duplicates+1，不重复落链。
func TestT2aIdempotent(t *testing.T) {
	s := pluginServer(t)
	now := time.Now().UnixNano()
	items := []auditReportItem{{RequestID: "req-dup", TenantID: "t-001", Result: "cache_hit_dataplane", TimestampNS: now}}
	raw, _ := buildReportBody(t, items)
	hdr := map[string]string{adminHeader: testReportToken, "X-Audit-Report-Sig": signReport(t, testReportToken, raw)}

	w1 := doReport(t, s, raw, hdr)
	if w1.Code != http.StatusOK {
		t.Fatalf("首次上报期望 200，实际 %d", w1.Code)
	}
	w2 := doReport(t, s, raw, hdr) // 同 body 重放（仍在 10 分钟 TTL 内）
	if w2.Code != http.StatusOK {
		t.Fatalf("二次上报期望 200，实际 %d", w2.Code)
	}
	var r2 struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &r2)
	if r2.Accepted != 0 || r2.Duplicates != 1 {
		t.Fatalf("期望二次 accepted=0 duplicates=1，实际 %+v", r2)
	}
	if len(s.audit.events) != 1 {
		t.Fatalf("期望仅落链 1 条，实际 %d", len(s.audit.events))
	}
}

// TestT2aConsumerUnauthorizedAccepted 【T-4 · v1.13】403 路由授权拒绝子类
// `result=consumer_unauthorized` 须被白名单接受并落链。
//
// 依据《P1-7-T2c-X-Mse-Consumer注入行为实测报告》（2026-10-14 K3s 实测）：403 存在两个
// 语义与归属均不同的子类（Unauthorized_consumer 可归真实租户 / ip_not_allowed 落哨兵），
// 若该值不在白名单 ⇒ 整批校验判 400 ⇒ V-13 不可达。
func TestT2aConsumerUnauthorizedAccepted(t *testing.T) {
	s := pluginServer(t)
	now := time.Now().UnixNano()
	items := []auditReportItem{{
		RequestID: "req-authz-deny", TenantID: "t-001", Path: "/infer", PathMode: "plain",
		HTTPStatus: 403, Result: "consumer_unauthorized", TimestampNS: now,
	}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:          testReportToken,
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200（consumer_unauthorized 为白名单值），实际 %d: %s", w.Code, w.Body.String())
	}
	if len(s.audit.events) != 1 {
		t.Fatalf("期望落链 1 条，实际 %d", len(s.audit.events))
	}
	if got := s.audit.events[0].Result; got != "consumer_unauthorized" {
		t.Fatalf("落链 result 不符：期望 consumer_unauthorized，实际 %q", got)
	}
}

// TestT2aWhitelistComplete 白名单全集防回归：7 项齐备且无多余项（§6.5 v1.13）。
func TestT2aWhitelistComplete(t *testing.T) {
	want := []string{
		"rate_limited", "auth_failed", "ip_blocked", "consumer_unauthorized",
		"cache_hit_dataplane", "non_infer", "ok",
	}
	if len(auditReportResultWhitelist) != len(want) {
		t.Fatalf("白名单项数不符：期望 %d，实际 %d", len(want), len(auditReportResultWhitelist))
	}
	for _, r := range want {
		if !auditReportResultWhitelist[r] {
			t.Fatalf("白名单缺项：%q", r)
		}
	}
}

// TestT2aInvalidResult400 白名单外 result → 整批 400。
func TestT2aInvalidResult400(t *testing.T) {
	s := pluginServer(t)
	items := []auditReportItem{{RequestID: "req-x", TenantID: "t-001", Result: "evil_result", TimestampNS: time.Now().UnixNano()}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         testReportToken,
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d: %s", w.Code, w.Body.String())
	}
	// T3b（A 类）：拒绝出口落 deny 事件；但被拒上报内容**不得**入链（无 action=request）。
	if n := countAction(s, "request"); n != 0 {
		t.Fatalf("非法批次不应入链（action=request），实际 %d 条", n)
	}
	if n := countAction(s, "deny"); n != 1 {
		t.Fatalf("非法批次应落 1 条 deny，实际 %d 条", n)
	}
}

// TestT2aMissingRequestID400 缺 request_id → 整批 400。
func TestT2aMissingRequestID400(t *testing.T) {
	s := pluginServer(t)
	items := []auditReportItem{{TenantID: "t-001", Result: "non_infer", TimestampNS: time.Now().UnixNano()}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         testReportToken,
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d", w.Code)
	}
}

// TestT2aWrongSig401 签名错误 → 401（D-13 完整性保护）。
func TestT2aWrongSig401(t *testing.T) {
	s := pluginServer(t)
	items := []auditReportItem{{RequestID: "req-y", TenantID: "t-001", Result: "cache_hit_dataplane", TimestampNS: time.Now().UnixNano()}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         testReportToken,
		"X-Audit-Report-Sig": signReport(t, "wrong-token", raw),
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", w.Code)
	}
	if n := countAction(s, "request"); n != 0 {
		t.Fatalf("签名错误不应入链（action=request），实际 %d 条", n)
	}
	if n := countAction(s, "deny"); n != 1 {
		t.Fatalf("签名错误应落 1 条 deny，实际 %d 条", n)
	}
}

// TestT2aMissingToken401 缺令牌 → 401。
func TestT2aMissingToken401(t *testing.T) {
	s := pluginServer(t)
	items := []auditReportItem{{RequestID: "req-z", TenantID: "t-001", Result: "cache_hit_dataplane", TimestampNS: time.Now().UnixNano()}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", w.Code)
	}
}

// TestT2aTenantNotInSet400 插件侧租户越界 → 整批 400（A3-10）。
func TestT2aTenantNotInSet400(t *testing.T) {
	s := pluginServer(t)
	items := []auditReportItem{{RequestID: "req-t", TenantID: "t-999", Result: "cache_hit_dataplane", TimestampNS: time.Now().UnixNano()}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         testReportToken,
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d: %s", w.Code, w.Body.String())
	}
	if n := countAction(s, "request"); n != 0 {
		t.Fatalf("越界租户不应入链（action=request），实际 %d 条", n)
	}
	if n := countAction(s, "deny"); n != 1 {
		t.Fatalf("越界租户应落 1 条 deny，实际 %d 条", n)
	}
}

// countAction 统计链上指定 action 的事件数（T3b：区分"拒绝落 deny"与"内容入链 request"）。
func countAction(s *teeServer, action string) int {
	n := 0
	for _, ev := range s.audit.events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

// TestT2aGatewayModeResolvesTenant 网关级（无 tenants 绑定）：忽略自报 tenant，
// 落哨兵租户 + TenantIDResolution 标记（D-18 分型②）。
func TestT2aGatewayModeResolvesTenant(t *testing.T) {
	s := newReportServer(testReportToken, nil) // 网关级模式
	now := time.Now().UnixNano()
	items := []auditReportItem{{RequestID: "req-g", TenantID: "t-attacker-self-report", Result: "rate_limited", TimestampNS: now}}
	raw, _ := buildReportBody(t, items)
	// 带 X-Mse-Consumer 头（D-18 解析线索）
	w := doReport(t, s, raw, map[string]string{
		adminHeader:          testReportToken,
		"X-Audit-Report-Sig":  signReport(t, testReportToken, raw),
		"X-Mse-Consumer":      "consumer-abc",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", w.Code, w.Body.String())
	}
	evs := s.audit.events
	if len(evs) != 1 {
		t.Fatalf("期望落链 1 条，实际 %d", len(evs))
	}
	if evs[0].TenantID != auditReportSentinelTenant {
		t.Fatalf("网关模式应落哨兵租户，实际 %q", evs[0].TenantID)
	}
	if evs[0].TenantIDResolution != "consumer_map" {
		t.Fatalf("带 X-Mse-Consumer 应标记 consumer_map，实际 %q", evs[0].TenantIDResolution)
	}
}

// TestT2aReplayWindowExceeded400 timestamp_ns 超 ±5 分钟窗 → 整批 400（D-13 重放防护）。
func TestT2aReplayWindowExceeded400(t *testing.T) {
	s := pluginServer(t)
	old := time.Now().Add(-10 * time.Minute).UnixNano()
	items := []auditReportItem{{RequestID: "req-old", TenantID: "t-001", Result: "non_infer", TimestampNS: old}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         testReportToken,
		"X-Audit-Report-Sig": signReport(t, testReportToken, raw),
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400（超窗），实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestT2aAdminTokenRejected 管理令牌不可用于上报端点（A3-11 不回落）。
func TestT2aAdminTokenRejected(t *testing.T) {
	s := pluginServer(t)
	s.adminToken = "admin-tok" // 另设管理令牌
	items := []auditReportItem{{RequestID: "req-adm", TenantID: "t-001", Result: "cache_hit_dataplane", TimestampNS: time.Now().UnixNano()}}
	raw, _ := buildReportBody(t, items)
	w := doReport(t, s, raw, map[string]string{
		adminHeader:         "admin-tok", // 用管理令牌访问上报端点
		"X-Audit-Report-Sig": signReport(t, "admin-tok", raw),
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401（管理令牌不得用于上报端点），实际 %d", w.Code)
	}
}

// TestT2aParseTenantSet 集合解析边界。
func TestT2aParseTenantSet(t *testing.T) {
	if parseTenantSet("") != nil {
		t.Fatal("空串应为 nil（网关级）")
	}
	if parseTenantSet("  ") != nil {
		t.Fatal("纯空白应为 nil")
	}
	set := parseTenantSet(" t-1 , t-2 ,,")
	if !set["t-1"] || !set["t-2"] || len(set) != 2 {
		t.Fatalf("解析结果错误：%v", set)
	}
}
