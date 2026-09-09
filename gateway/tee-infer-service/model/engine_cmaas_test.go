package model

// GF.4.2：CmaasEngine 多账号密钥池接线测试。
// 验证轮询顺序、空池 fail-closed、失败 Release 标记，均经 httptest 模拟 openai-proxy。

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestCmaasEngineKeyPoolRoundRobin 多账号轮询：连续请求的 Authorization 按池顺序轮换。
func TestCmaasEngineKeyPoolRoundRobin(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"choices":[{"delta":{"content":"x"}}]}` + "\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "sk-single", "cmaas-glm-5.2")
	eng.SetKeyPool(NewRoundRobinKeyPool("sk-a", "sk-b"))

	for i := 0; i < 3; i++ {
		if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}},
			func(string) error { return nil }); err != nil {
			t.Fatalf("Generate 失败: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"Bearer sk-a", "Bearer sk-b", "Bearer sk-a"}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("第 %d 次 Authorization 应为 %q, got %q（全序 %v）", i, want[i], seen[i], seen)
		}
	}
}

// TestCmaasEngineKeyPoolEmptyFailClosed 空池 → Acquire 空 → fail-closed（不发请求）。
func TestCmaasEngineKeyPoolEmptyFailClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("空池不应发起请求")
	}))
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "", "cmaas-glm-5.2")
	eng.SetKeyPool(NewRoundRobinKeyPool()) // 空池
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("空池应 fail-closed")
	}
}

// TestCmaasEngineKeyPoolReleaseOnFail 引擎失败 → Release(failed=true) 记录连续失败计数。
func TestCmaasEngineKeyPoolReleaseOnFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	pool := NewRoundRobinKeyPool("sk-a")
	eng := NewCmaasEngine(ts.URL, "", "cmaas-glm-5.2")
	eng.SetKeyPool(pool)

	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("503 应失败")
	}
	if pool.failed["sk-a"] != 1 {
		t.Fatalf("失败应记录 1 次, got %d", pool.failed["sk-a"])
	}
}

// TestCmaasEngineKeyFingerprint GF.4.2：每次请求记录所用 key 指纹（计量归属）。
func TestCmaasEngineKeyFingerprint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "", "cmaas-glm-5.2")
	eng.SetKeyPool(NewRoundRobinKeyPool("sk-a", "sk-b"))

	// 请求前无指纹
	if fp := eng.LastKeyFingerprint(); fp != "" {
		t.Fatalf("请求前指纹应为空, got %q", fp)
	}
	// 第一次请求用 sk-a → 指纹 = KeyFingerprint("sk-a")
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	if got, want := eng.LastKeyFingerprint(), KeyFingerprint("sk-a"); got != want {
		t.Fatalf("第 1 次指纹应指向 sk-a: got %q want %q", got, want)
	}
	// 第二次请求用 sk-b → 指纹切换
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	if got, want := eng.LastKeyFingerprint(), KeyFingerprint("sk-b"); got != want {
		t.Fatalf("第 2 次指纹应指向 sk-b: got %q want %q", got, want)
	}
	// 指纹不可反推明文 key：长度 8 hex（sha256 前 4 字节）
	if len(eng.LastKeyFingerprint()) != 8 {
		t.Fatalf("指纹应为 8 hex 字符, got %q", eng.LastKeyFingerprint())
	}
}

// TestCmaasEngineAttestationByKey GF.4.2：证明引用按 key 指纹关联（多账号可追溯）。
func TestCmaasEngineAttestationByKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "", "cmaas-glm-5.2")
	eng.SetKeyPool(NewRoundRobinKeyPool("sk-a", "sk-b"))

	// 第 1 次请求（sk-a）后记录证明 ref-a → 应关联到 sk-a 指纹
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	eng.RecordAttestation("rekor://ref-a")

	// 第 2 次请求（sk-b）后记录证明 ref-b → 应关联到 sk-b 指纹
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	eng.RecordAttestation("rekor://ref-b")

	byKey := eng.AttestationByKey()
	if got := byKey[KeyFingerprint("sk-a")]; got != "rekor://ref-a" {
		t.Fatalf("sk-a 指纹应关联 ref-a, got %q", got)
	}
	if got := byKey[KeyFingerprint("sk-b")]; got != "rekor://ref-b" {
		t.Fatalf("sk-b 指纹应关联 ref-b, got %q", got)
	}
	// 最近值（全局）应为最后一次记录
	if got := eng.LastAttestation(); got != "rekor://ref-b" {
		t.Fatalf("LastAttestation 应为 ref-b, got %q", got)
	}
}

// TestKeyFingerprintStable 指纹确定性 + 不同 key 指纹不同。
func TestKeyFingerprintStable(t *testing.T) {
	if KeyFingerprint("sk-a") != KeyFingerprint("sk-a") {
		t.Fatal("同一 key 指纹应稳定")
	}
	if KeyFingerprint("sk-a") == KeyFingerprint("sk-b") {
		t.Fatal("不同 key 指纹应不同")
	}
}

// ---------- Phala 密态网关兼容（证明回执采集与流后验证） ----------

// newPhalaMockServer 模拟 Phala：POST /v1/chat/completions 带 X-Receipt-Id 响应头，
// GET /v1/aci/receipts/<id> 返回指定 result 的 upstream.verified 事件。
// receiptResult 为空串时不设回执头（模拟百炼 openai-proxy 形态）。
func newPhalaMockServer(t *testing.T, receiptID, receiptResult string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
			if receiptID != "" {
				w.Header().Set("X-Receipt-Id", receiptID)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/aci/receipts/"+receiptID:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"event_log":[{"type":"upstream.verified","provider":"phala","result":"` +
				receiptResult + `","required":true}]}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// TestCmaasPhalaReceiptVerified 回执验证通过 → RecordAttestation 记 verified=true。
func TestCmaasPhalaReceiptVerified(t *testing.T) {
	ts := newPhalaMockServer(t, "rid-123", "verified")
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "sk-phala", "phala/qwen3.5-27b")
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	want := "phala-receipt:rid-123:verified=true"
	if got := eng.LastAttestation(); got != want {
		t.Fatalf("LastAttestation 应为 %q, got %q", want, got)
	}
	// 证明按 key 指纹关联（GF.4.2 口径不变）
	if got := eng.AttestationByKey()[KeyFingerprint("sk-phala")]; got != want {
		t.Fatalf("按 key 关联应为 %q, got %q", want, got)
	}
}

// TestCmaasPhalaReceiptNotVerified 回执无 verified 条目 → verified=false（不中断业务）。
func TestCmaasPhalaReceiptNotVerified(t *testing.T) {
	ts := newPhalaMockServer(t, "rid-456", "pending")
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "sk-phala", "phala/qwen3.5-27b")
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 不应因回执未验证而失败: %v", err)
	}
	if got := eng.LastAttestation(); got != "phala-receipt:rid-456:verified=false" {
		t.Fatalf("应为 verified=false, got %q", got)
	}
}

// TestCmaasPhalaReceiptFetchError 回执端点 404 → fetch-error（不中断业务）。
func TestCmaasPhalaReceiptFetchError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
			w.Header().Set("X-Receipt-Id", "rid-789")
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
		default:
			http.Error(w, "not found", http.StatusNotFound) // 回执端点缺失
		}
	}))
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "sk-phala", "phala/qwen3.5-27b")
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 不应因回执拉取失败而失败: %v", err)
	}
	if got := eng.LastAttestation(); got != "phala-receipt:rid-789:fetch-error" {
		t.Fatalf("应为 fetch-error, got %q", got)
	}
}

// TestCmaasNoReceiptHeaderBailianCompatible 无回执头（百炼 openai-proxy 形态）→
// 不触发回执验证，LastAttestation 保持空，原路径零回归。
func TestCmaasNoReceiptHeaderBailianCompatible(t *testing.T) {
	ts := newPhalaMockServer(t, "", "") // 不设回执头
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "sk-bailian", "cmaas-glm-5.2")
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}},
		func(string) error { return nil }); err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	if got := eng.LastAttestation(); got != "" {
		t.Fatalf("无回执头时不应记录证明, got %q", got)
	}
}
