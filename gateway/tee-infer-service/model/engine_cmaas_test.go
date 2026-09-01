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
