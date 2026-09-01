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
