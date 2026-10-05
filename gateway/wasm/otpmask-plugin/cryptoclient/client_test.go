package cryptoclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// ---- 测试夹具 ----

// mockTransport 同步 mock：记录请求并立即回调预置响应。
type mockTransport struct {
	status  int
	resp    string
	err     error

	calls   []mockCall
	failWith error // 非 nil 时 Post 直接返回该错误（模拟不可达）
}

type mockCall struct {
	path string
	hdr  [][2]string
	body []byte
}

func (m *mockTransport) Post(path string, hdr [][2]string, body []byte, cb ResponseCallback, _ uint32) error {
	m.calls = append(m.calls, mockCall{path: path, hdr: hdr, body: body})
	if m.failWith != nil {
		return m.failWith
	}
	st := m.status
	if st == 0 {
		st = 200
	}
	cb(st, http.Header{}, []byte(m.resp))
	return nil
}

func (m *mockTransport) Get(path string, hdr [][2]string, cb ResponseCallback, _ uint32) error {
	return m.Post(path, hdr, nil, cb, 0)
}

// recMetrics 记录 #13/#14/#5。
type recMetrics struct {
	calls      []string
	failclosed []string
	circuit    []bool
}

func (r *recMetrics) Call(op string)        { r.calls = append(r.calls, op) }
func (r *recMetrics) FailClosed(op string)  { r.failclosed = append(r.failclosed, op) }
func (r *recMetrics) CircuitOpen(open bool) { r.circuit = append(r.circuit, open) }

func newClient(m *mockTransport, cfg Config) (*Client, *recMetrics) {
	rm := &recMetrics{}
	c := New(m, NewBreaker(3, time.Second), rm, cfg)
	return c, rm
}

func lastCall(t *testing.T, m *mockTransport) mockCall {
	t.Helper()
	if len(m.calls) == 0 {
		t.Fatal("无出站调用")
	}
	return m.calls[len(m.calls)-1]
}

func bodyField(t *testing.T, c mockCall, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(c.body, &m); err != nil {
		t.Fatalf("解析请求体: %v", err)
	}
	s, _ := m[key].(string)
	return s
}

// ---- Breaker ----

func TestBreakerOpensAfterThreshold(t *testing.T) {
	b := NewBreaker(3, 30*time.Second)
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("第 %d 次应放行", i)
		}
		b.OnResult(false)
	}
	if b.Allow() {
		t.Fatal("达阈值后应熔断")
	}
	// cooldown 未到 → 仍熔断
	now = now.Add(29 * time.Second)
	if b.Allow() {
		t.Fatal("cooldown 未到不应放行")
	}
	// cooldown 到 → half-open 放行一次
	now = now.Add(2 * time.Second)
	if !b.Allow() {
		t.Fatal("cooldown 到期应 half-open 放行")
	}
	// 探测成功 → closed
	b.OnResult(true)
	if !b.Allow() {
		t.Fatal("探测成功后应恢复放行")
	}
}

func TestBreakerHalfOpenFailureReopens(t *testing.T) {
	b := NewBreaker(2, 10*time.Second)
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now }
	b.OnResult(false)
	b.OnResult(false)
	now = now.Add(11 * time.Second)
	if !b.Allow() { // → half-open
		t.Fatal("应放行探测")
	}
	b.OnResult(false) // 探测失败 → 重新 open
	if b.Allow() {
		t.Fatal("探测失败应重新熔断")
	}
}

func TestBreakerOnStateChange(t *testing.T) {
	b := NewBreaker(2, 10*time.Second)
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now }
	var got []bool
	b.OnStateChange(func(open bool) { got = append(got, open) })

	b.OnResult(false)
	b.OnResult(false) // → open
	now = now.Add(11 * time.Second)
	b.Allow() // → half-open（open=false）
	b.OnResult(true) // → closed

	want := []bool{true, false}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("状态回调序列 = %v，期望 %v", got, want)
	}
}

// ---- 调用路径 ----

func TestSealDecodesMockResponse(t *testing.T) {
	m := &mockTransport{resp: `{"nonce":"AAAA","ciphertext":"QkJC"}`}
	c, rm := newClient(m, Config{})
	var gotNonce, gotCT []byte
	var gotErr error
	c.Seal("static/aead", []byte("aad"), nil, []byte("pt"), func(nonce, ct []byte, err error) {
		gotNonce, gotCT, gotErr = nonce, ct, err
	})
	if gotErr != nil {
		t.Fatalf("Seal: %v", gotErr)
	}
	if string(gotNonce) != "\x00\x00\x00" || len(gotNonce) != 3 {
		t.Fatalf("nonce 解码错: %x", gotNonce)
	}
	if string(gotCT) != "BBB" {
		t.Fatalf("ciphertext 解码错: %x", gotCT)
	}
	call := lastCall(t, m)
	if call.path != pathSeal {
		t.Fatalf("path=%s", call.path)
	}
	if bodyField(t, call, "key_ref") != "static/aead" {
		t.Fatalf("key_ref 字段错")
	}
	// nonce 为空 → 请求体**不含** nonce 字段（由 sidecar 生成，§4.3.4）。
	var body map[string]any
	_ = json.Unmarshal(call.body, &body)
	if _, present := body["nonce"]; present {
		t.Fatalf("空 nonce 不应出现在请求体: %v", body)
	}
	if len(rm.calls) != 1 || rm.calls[0] != OpSeal {
		t.Fatalf("#13 应记 seal: %v", rm.calls)
	}
	if len(rm.failclosed) != 0 {
		t.Fatalf("成功不应计 #14: %v", rm.failclosed)
	}
}

// TestSealSendsExplicitNonce 校验信封路径的确定性 nonce 透传（§5.4.6 / R8-P1-1）：
// 非空 nonce 必须出现在请求体，使 sidecar 用 `EnvelopeNonce(counter)` 封装（与 tee-infer 互通）。
func TestSealSendsExplicitNonce(t *testing.T) {
	m := &mockTransport{resp: `{"nonce":"QkJCQkJCQkJCQkJCQkJC","ciphertext":"Q0M="}`}
	c, _ := newClient(m, Config{})
	nonce := []byte("OTPE\x00\x00\x00\x00\x00\x00\x00\x01")
	c.Seal("session/ab/enc/c2s", []byte("aad"), nonce, []byte("pt"), func(_, _ []byte, err error) {
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
	})
	call := lastCall(t, m)
	var body map[string]any
	_ = json.Unmarshal(call.body, &body)
	if body["nonce"] != b64(nonce) {
		t.Fatalf("nonce 未透传: got %v want %s", body["nonce"], b64(nonce))
	}
}

func TestCallFailClosedOnHTTPError(t *testing.T) {
	m := &mockTransport{status: 404, resp: `{"error":{"code":"unknown_key_ref","message":"no"}}`}
	c, rm := newClient(m, Config{})
	var gotErr error
	c.Open("missing", nil, []byte("n"), []byte("c"), func(_ []byte, err error) { gotErr = err })
	var e *Error
	if !errors.As(gotErr, &e) || e.Code != CodeUnknownKeyRef || e.Status != 404 {
		t.Fatalf("应得 *Error{unknown_key_ref,404}，得 %v", gotErr)
	}
	if len(rm.failclosed) != 1 || rm.failclosed[0] != OpOpen {
		t.Fatalf("#14 应记 open: %v", rm.failclosed)
	}
}

func TestTransportErrorFailsClosed(t *testing.T) {
	m := &mockTransport{failWith: errors.New("dial timeout")}
	c, rm := newClient(m, Config{})
	var gotErr error
	c.Rand(16, func(_ []byte, err error) { gotErr = err })
	if !errors.Is(gotErr, ErrTransport) {
		t.Fatalf("应得 ErrTransport，得 %v", gotErr)
	}
	if len(rm.failclosed) != 1 {
		t.Fatalf("#14 应计一次: %v", rm.failclosed)
	}
}

func TestCircuitOpenSkipsTransport(t *testing.T) {
	m := &mockTransport{status: 500, resp: `{"error":{"code":"internal"}}`}
	c, rm := newClient(m, Config{}) // threshold=3
	for i := 0; i < 3; i++ {
		c.Hash([]byte("x"), func(_ []byte, _ error) {})
	}
	before := len(m.calls)
	var gotErr error
	c.Hash([]byte("x"), func(_ []byte, err error) { gotErr = err })
	if !errors.Is(gotErr, ErrCircuitOpen) {
		t.Fatalf("熔断期应得 ErrCircuitOpen，得 %v", gotErr)
	}
	if len(m.calls) != before {
		t.Fatalf("熔断期不应打 sidecar（calls %d→%d）", before, len(m.calls))
	}
	// #5 应记录一次 open=true
	found := false
	for _, v := range rm.circuit {
		if v {
			found = true
		}
	}
	if !found {
		t.Fatalf("#5 应记录熔断开启: %v", rm.circuit)
	}
}

func TestVerifyFailedIsNotError(t *testing.T) {
	m := &mockTransport{resp: `{"ok":false}`}
	c, _ := newClient(m, Config{})
	var ok bool
	var gotErr error
	c.Verify(nil, []byte("pub"), []byte("d"), []byte("s"), "p256", func(v bool, err error) { ok, gotErr = v, err })
	if gotErr != nil {
		t.Fatalf("verify_failed 不应为错误: %v", gotErr)
	}
	if ok {
		t.Fatal("应 ok=false")
	}
}

func TestMaskStreamSendsVersionHeader(t *testing.T) {
	m := &mockTransport{resp: `{"values":[1,2,3]}`}
	c, _ := newClient(m, Config{MaskVersion: MaskPRGSM4})
	var vals []uint64
	c.MaskStream("session/x/enc", []byte("otpmask/guardrail-text/v1"), 3, 1<<32, func(v []uint64, err error) {
		vals, _ = v, err
	})
	if len(vals) != 3 || vals[2] != 3 {
		t.Fatalf("掩码值解码错: %v", vals)
	}
	call := lastCall(t, m)
	var foundHdr bool
	for _, h := range call.hdr {
		if h[0] == HeaderMaskVersion && h[1] == MaskPRGSM4 {
			foundHdr = true
		}
	}
	if !foundHdr {
		t.Fatalf("应带 %s=%s 头: %v", HeaderMaskVersion, MaskPRGSM4, call.hdr)
	}
	var body map[string]any
	_ = json.Unmarshal(call.body, &body)
	if body["domain"] != "otpmask/guardrail-text/v1" { // domain 为纯文本（非 base64）
		t.Fatalf("domain 字段错: %v", body["domain"])
	}
}

// TestKDFReturnsChildKeyRef 校验 /v1/kdf 映射（R8-P1-1：信封方向子密钥派生）。
// 出参仅子 KeyRef（C-5：不返回密钥字节）。
func TestKDFReturnsChildKeyRef(t *testing.T) {
	m := &mockTransport{resp: `{"key_ref":"session/ab/enc/c2s"}`}
	c, rm := newClient(m, Config{})
	var child KeyRef
	var gotErr error
	c.KDF("session/ab/enc", nil, []byte("otpmask/kdf/enc/c2s/v1"), 32, "otpmask/kdf/enc/c2s/v1",
		func(kr KeyRef, err error) { child, gotErr = kr, err })
	if gotErr != nil {
		t.Fatalf("KDF: %v", gotErr)
	}
	if child != "session/ab/enc/c2s" {
		t.Fatalf("子 KeyRef 错: %q", child)
	}
	call := lastCall(t, m)
	if call.path != pathKDF {
		t.Fatalf("path=%s", call.path)
	}
	if bodyField(t, call, "key_ref") != "session/ab/enc" {
		t.Fatalf("父 key_ref 字段错")
	}
	if bodyField(t, call, "alias") != "otpmask/kdf/enc/c2s/v1" {
		t.Fatalf("alias 字段错")
	}
	var body map[string]any
	_ = json.Unmarshal(call.body, &body)
	if body["out_len"] != float64(32) {
		t.Fatalf("out_len 字段错: %v", body["out_len"])
	}
	if len(rm.calls) != 1 || rm.calls[0] != OpKDF {
		t.Fatalf("#13 应记 kdf: %v", rm.calls)
	}
}

// TestKDFEmptyChildIsFailClosed 校验空 key_ref（sidecar 未注册/异常）→ fail-closed（C-4）。
func TestKDFEmptyChildIsFailClosed(t *testing.T) {
	m := &mockTransport{resp: `{}`}
	c, rm := newClient(m, Config{})
	var gotErr error
	c.KDF("x", nil, nil, 32, "alias", func(_ KeyRef, err error) { gotErr = err })
	if !errors.Is(gotErr, ErrMalformed) {
		t.Fatalf("空子 ref 应 fail-closed，得 %v", gotErr)
	}
	if len(rm.failclosed) != 1 || rm.failclosed[0] != OpKDF {
		t.Fatalf("#14 应记 kdf: %v", rm.failclosed)
	}
}

func TestSessionBeginEnd(t *testing.T) {
	m := &mockTransport{resp: `{"key_ref_sig":"session/ab/sig","key_ref_enc":"session/ab/enc","client_pub":"Q0M="}`}
	c, _ := newClient(m, Config{TimeoutMS: 50})
	var ksig, kenc KeyRef
	var pub []byte
	c.SessionBegin([]byte("server"), []byte("nonce"), "x25519", func(sig, enc KeyRef, cp []byte, err error) {
		ksig, kenc, pub, _ = sig, enc, cp, err
	})
	if ksig != "session/ab/sig" || kenc != "session/ab/enc" || string(pub) != "CC" {
		t.Fatalf("SessionBegin 结果错: %q %q %x", ksig, kenc, pub)
	}
	m.resp = `{"ok":true}`
	var endErr error
	c.SessionEnd(ksig, kenc, func(err error) { endErr = err })
	if endErr != nil {
		t.Fatalf("SessionEnd: %v", endErr)
	}
	call := lastCall(t, m)
	if call.path != pathSessionEnd {
		t.Fatalf("path=%s", call.path)
	}
	if bodyField(t, call, "key_ref_sig") != "session/ab/sig" {
		t.Fatalf("key_ref_sig 字段错")
	}
}

func TestBatchPerOpIsolation(t *testing.T) {
	m := &mockTransport{resp: `{"results":[
		{"id":"a","digest":"QQ=="},
		{"id":"b","error":{"code":"unknown_key_ref","message":"no"}}
	]}`}
	c, _ := newClient(m, Config{})
	var results []OpResult
	var gotErr error
	c.Batch([]Op{
		{ID: "a", Op: OpHash, Payload: map[string]any{"data": "eA=="}},
		{ID: "b", Op: OpHMAC, Payload: map[string]any{"key_ref": "missing", "data": "eA=="}},
	}, func(r []OpResult, err error) { results, gotErr = r, err })
	if gotErr != nil {
		t.Fatalf("批失败: %v", gotErr)
	}
	if len(results) != 2 {
		t.Fatalf("应有 2 条结果: %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("op a 不应有错: %+v", results[0].Error)
	}
	if results[1].Error == nil || results[1].Error.Code != CodeUnknownKeyRef {
		t.Fatalf("op b 应得 unknown_key_ref: %+v", results[1].Error)
	}
}

func TestLoadCapabilities(t *testing.T) {
	m := &mockTransport{resp: `{"profile":"sm-software","suite":2,"mask_prg":"sm4","compliance_note":"SM2/SM3/SM4"}`}
	c, _ := newClient(m, Config{})
	var caps Capabilities
	c.LoadCapabilities(func(cc Capabilities, err error) { caps, _ = cc, err })
	if caps.Profile != "sm-software" || caps.Suite != 2 || caps.MaskPRG != MaskPRGSM4 {
		t.Fatalf("capabilities 解析错: %+v", caps)
	}
	if c.Capabilities().ComplianceNote != "SM2/SM3/SM4" {
		t.Fatalf("Capabilities() 未缓存: %+v", c.Capabilities())
	}
	if m.calls[0].path != pathCapabilities {
		t.Fatalf("path=%s", m.calls[0].path)
	}
}

// TestMetricsNilSafe 确保 m/br 为 nil 时不 panic（插件未配置时的降级）。
func TestMetricsNilSafe(t *testing.T) {
	m := &mockTransport{resp: `{"digest":"QQ=="}`}
	c := New(m, nil, nil, Config{})
	c.Hash([]byte("x"), func(_ []byte, err error) {
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
	})
}
