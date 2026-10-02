// billing_test.go — GA-计费接口设计（P0-4 增量查询 / P1-1 Webhook 推送 / P1-2 计量令牌）
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- parseBillingTime ----------

func TestParseBillingTime(t *testing.T) {
	// Unix 秒 → 纳秒
	got, ok := parseBillingTime("1700000000", 0)
	if !ok || got != int64(1700000000)*int64(time.Second) {
		t.Fatalf("Unix 秒解析失败: got=%d ok=%v", got, ok)
	}
	// RFC 3339（UTC）
	rfc, err := time.Parse(time.RFC3339, "2026-08-30T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	got, ok = parseBillingTime("2026-08-30T12:00:00Z", 0)
	if !ok || got != rfc.UnixNano() {
		t.Fatalf("RFC3339 解析失败: got=%d want=%d", got, rfc.UnixNano())
	}
	// 空 → 缺省值
	def := int64(123)
	got, ok = parseBillingTime("", def)
	if !ok || got != def {
		t.Fatalf("空值应返回缺省: got=%d ok=%v", got, ok)
	}
	// 非法 → ok=false
	if _, ok := parseBillingTime("not-a-time", 0); ok {
		t.Fatal("非法时间应返回 ok=false")
	}
}

// ---------- modelDimensionKey ----------

func TestModelDimensionKey(t *testing.T) {
	cases := []struct{ name, engine, model, want string }{
		{"双维度", "tee_gpu", "qwen2.5-72b", "tee_gpu/qwen2.5-72b"},
		{"仅引擎", "cmaas", "", "cmaas"},
		{"仅模型", "", "mock", "mock"},
		{"双空", "", "", ""},
	}
	for _, c := range cases {
		if got := modelDimensionKey(c.engine, c.model); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// ---------- aggregateUsage ----------

// billingEvent 构造审计事件（直接给定时间戳，绕过 append 的 now 覆盖）。
func billingEvent(ts int64, tenant, action, result string, tin, tout int, eng, model string) AuditEvent {
	return AuditEvent{
		Timestamp: ts, TenantID: tenant, Action: action, Result: result,
		TokensIn: tin, TokensOut: tout, EngineType: eng, Model: model,
	}
}

func TestAggregateUsage(t *testing.T) {
	base := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC).UnixNano()
	events := []AuditEvent{
		billingEvent(base, "acme", "infer", "ok", 10, 20, "tee_gpu", "qwen"),
		billingEvent(base+int64(time.Minute), "acme", "infer", "ok", 5, 7, "cmaas", "glm"),
		billingEvent(base+2*int64(time.Minute), "acme", "deny", "deny", 0, 0, "", ""), // 不计费
		billingEvent(base+3*int64(time.Minute), "beta", "infer", "ok", 1, 1, "tee_gpu", "qwen"),
		billingEvent(base+10*int64(time.Minute), "acme", "infer", "ok", 99, 99, "tee_gpu", "qwen"), // 窗口外
	}
	from, to := base, base+5*int64(time.Minute)
	got := aggregateUsage(events, from, to)

	acme := got["acme"]
	if acme == nil {
		t.Fatal("acme 缺失")
	}
	if acme.TokensIn != 15 || acme.TokensOut != 27 || acme.Requests != 2 {
		t.Fatalf("acme 聚合错误: in=%d out=%d req=%d（deny 与窗口外不应计入）", acme.TokensIn, acme.TokensOut, acme.Requests)
	}
	// 模型维度
	if m := acme.ByModel["tee_gpu/qwen"]; m == nil || m.Requests != 1 || m.TokensOut != 20 {
		t.Fatalf("tee_gpu/qwen 维度聚合错误: %+v", m)
	}
	if m := acme.ByModel["cmaas/glm"]; m == nil || m.TokensIn != 5 {
		t.Fatalf("cmaas/glm 维度聚合错误: %+v", m)
	}
	// 边界：timestamp == from 计入（已在上面验证）；== to 不计入
	got2 := aggregateUsage(events, base, base+int64(time.Minute))
	if got2["acme"] == nil || got2["acme"].Requests != 1 {
		t.Fatalf("左闭右开边界错误: %+v", got2["acme"])
	}
	// 多租户分离
	beta := got["beta"]
	if beta == nil || beta.Requests != 1 || beta.TokensIn != 1 {
		t.Fatalf("beta 租户聚合错误: %+v", beta)
	}
}

// ---------- billingWebhook.notify ----------

func TestBillingWebhookNilSafe(t *testing.T) {
	var b *billingWebhook
	b.notify(billingEvent(time.Now().UnixNano(), "acme", "infer", "ok", 1, 1, "", "")) // 不应 panic
}

func TestBillingWebhookSkipsNonInfer(t *testing.T) {
	hit := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := newBillingWebhook(srv.URL, "")
	b.notify(billingEvent(time.Now().UnixNano(), "acme", "key_issue", "ok", 0, 0, "", ""))
	time.Sleep(50 * time.Millisecond)
	if hit.Load() != 0 {
		t.Fatalf("非 infer 动作不应推送: hits=%d", hit.Load())
	}
}

func TestBillingWebhookDeliveryAndSignature(t *testing.T) {
	const secret = "s3cret"
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := newBillingWebhook(srv.URL, secret)
	ev := AuditEvent{
		Timestamp: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC).UnixNano(),
		EventID:   "evt-123", TenantID: "acme", RequestID: "req-1",
		Action: "infer", Result: "ok", TokensIn: 3, TokensOut: 4,
		EngineType: "tee_gpu", Model: "qwen",
		IsRetry: true, // ★ §4.1.5：重试证据随载荷下行
	}
	b.notify(ev)

	var payload billingEventPayload
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("推送体解析失败: %v", err)
	}
	if payload.EventID != "evt-123" || payload.TenantID != "acme" || payload.RequestID != "req-1" {
		t.Fatalf("推送体字段错误: %+v", payload)
	}
	if payload.TokensIn != 3 || payload.TokensOut != 4 || payload.Result != "ok" {
		t.Fatalf("推送体计量字段错误: %+v", payload)
	}
	if payload.EngineType != "tee_gpu" || payload.Model != "qwen" {
		t.Fatalf("推送体模型维度缺失: %+v", payload)
	}
	if !payload.IsRetry {
		t.Fatalf("is_retry 未随载荷推送（§4.1.5）: %+v", payload)
	}
	// HMAC-SHA256 签名校验
	want := "sha256=" + hmacHex(gotBody, secret)
	if gotSig != want {
		t.Fatalf("X-Signature 不匹配: got=%q want=%q", gotSig, want)
	}
}

func TestBillingWebhookIdempotent(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := newBillingWebhook(srv.URL, "")
	ev := billingEvent(time.Now().UnixNano(), "acme", "infer", "ok", 1, 1, "", "")
	ev.EventID = "evt-dup"
	b.notify(ev)
	b.notify(ev) // 同 event_id 重复 → 幂等忽略
	if hits.Load() != 1 {
		t.Fatalf("event_id 幂等失败: hits=%d", hits.Load())
	}
}

func TestBillingWebhookRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError) // 首次 500 → 触发重试
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := newBillingWebhook(srv.URL, "")
	b.retryWait = time.Millisecond // 测试加速退避
	ev := billingEvent(time.Now().UnixNano(), "acme", "infer", "ok", 1, 1, "", "")
	ev.EventID = "evt-retry"
	b.notify(ev)
	if hits.Load() != 2 {
		t.Fatalf("指数退避重试失败: hits=%d（应为 2：首败+重试成功）", hits.Load())
	}
}

func TestBillingWebhookFailNoBlock(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError) // 一直失败
	}))
	defer srv.Close()

	b := newBillingWebhook(srv.URL, "")
	b.retryWait = time.Millisecond
	ev := billingEvent(time.Now().UnixNano(), "acme", "infer", "ok", 1, 1, "", "")
	ev.EventID = "evt-fail"
	b.notify(ev) // 不 panic，最多 webhookMaxAttempts 次
	if hits.Load() != webhookMaxAttempts {
		t.Fatalf("重试次数错误: hits=%d want=%d", hits.Load(), webhookMaxAttempts)
	}
}

// ---------- handleUsageIncremental（HTTP 集成） ----------

func TestHandleUsageIncremental(t *testing.T) {
	chain := &auditChain{}
	base := time.Now().UnixNano() - int64(time.Hour) // 稳定在测试窗口内
	chain.append(billingEvent(base, "acme", "infer", "ok", 10, 20, "tee_gpu", "qwen"))
	chain.append(billingEvent(base+int64(time.Minute), "acme", "deny", "deny", 0, 0, "", ""))
	chain.append(billingEvent(base+2*int64(time.Minute), "beta", "infer", "ok", 1, 1, "cmaas", "glm"))

	// adminToken 非空（避免开发模式不拦截），meterToken 为独立只读计量令牌
	s := &teeServer{audit: chain, adminToken: "admin-tok", meterToken: "meter-tok"}
	mux := http.NewServeMux()
	mux.HandleFunc("/usage", s.handleUsage)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 无令牌 → 401
	resp, err := http.Get(ts.URL + "/usage?from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401: got %d", resp.StatusCode)
	}

	// 带计量令牌 → 200，聚合正确（deny 不计费）
	req, _ := http.NewRequest(http.MethodGet,
		ts.URL+"/usage?from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z", nil)
	req.Header.Set(adminHeader, "meter-tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("合法请求应 200: got %d", resp.StatusCode)
	}
	var body struct {
		From            string                       `json:"from"`
		To              string                       `json:"to"`
		WindowSemantics string                       `json:"window_semantics"`
		Tenants         map[string]*billingIncrement `json:"tenants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if !strings.Contains(body.WindowSemantics, "[from, to)") {
		t.Fatalf("window_semantics 缺失: %q", body.WindowSemantics)
	}
	acme := body.Tenants["acme"]
	if acme == nil || acme.TokensIn != 10 || acme.TokensOut != 20 || acme.Requests != 1 {
		t.Fatalf("acme 增量聚合错误: %+v", acme)
	}
	if m := acme.ByModel["tee_gpu/qwen"]; m == nil || m.Requests != 1 {
		t.Fatalf("模型维度缺失: %+v", acme.ByModel)
	}
	// deny 不计费：acme 只有 1 条 infer（deny 未计入）

	// 非法 from → 400（带令牌）
	badReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/usage?from=bogus&to=2027-01-01T00:00:00Z", nil)
	badReq.Header.Set(adminHeader, "meter-tok")
	resp, _ = http.DefaultClient.Do(badReq)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法 from 应 400: got %d", resp.StatusCode)
	}

	// from >= to → 400（带令牌）
	badReq, _ = http.NewRequest(http.MethodGet, ts.URL+"/usage?from=2027-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil)
	badReq.Header.Set(adminHeader, "meter-tok")
	resp, _ = http.DefaultClient.Do(badReq)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("from>=to 应 400: got %d", resp.StatusCode)
	}
}

// ---------- S-3 金额域隔离扫描（§10.6 / M10 / INV-4，CI 强制） ----------

// usageForbiddenAmountKeys 金额字段禁用词（小写；命中即视为金额域泄漏）。
// 依据：§10.6 S-3「/usage 域响应不得含 amount/total/price 等金额字段」（M10/INV-4）。
var usageForbiddenAmountKeys = map[string]bool{
	"amount": true, "total": true, "price": true, "cost": true, "fee": true,
	"currency": true, "subtotal": true, "unit_price": true, "price_version": true,
}

// collectJSONKeys 递归收集 JSON 中全部对象 key（小写）。
func collectJSONKeys(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			out[strings.ToLower(k)] = true
			collectJSONKeys(child, out)
		}
	case []any:
		for _, child := range t {
			collectJSONKeys(child, out)
		}
	}
}

// TestUsageDomainNoAmountFields S-3：`/usage` 域响应**不得含金额字段**（含增量/配额视图全分支）。
// 金额一律走 `/billing` 域；本用例为 M10/INV-4 的直接证据（CI 强制、离线可跑）。
func TestUsageDomainNoAmountFields(t *testing.T) {
	_, ts := newM9Server(t)

	// 造用量 + 配额，使 toks/by_model/quota_limits/shadow 等分支均有数据（扫描面最大化）
	sessionID, ksig, kenc := setupTestSession(t, ts)
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusOK {
		t.Fatalf("seed infer failed: %d", code)
	}
	setQuota(t, ts, "default", 100)

	now := time.Now().Unix()
	paths := []string{
		"/usage",                // 全租户累计视图
		"/usage?tenant=default", // 单租户累计视图（含配额视图）
		fmt.Sprintf("/usage?from=%d&to=%d", now-3600, now+1), // 增量聚合视图（出账权威口径）
	}
	for _, p := range paths {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", p, resp.StatusCode, string(raw))
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s decode: %v", p, err)
		}
		keys := map[string]bool{}
		collectJSONKeys(v, keys)
		for k := range keys {
			if usageForbiddenAmountKeys[k] {
				t.Errorf("S-3 违规：%s 响应含金额字段 %q（M10/INV-4）", p, k)
			}
		}
	}
}

// ---------- helpers ----------

func hmacHex(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
