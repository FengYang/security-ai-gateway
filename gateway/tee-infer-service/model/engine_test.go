package model

// V-4 引擎对接验证：RemoteEngine 经 vLLM 适配器接口推理，与本地引擎结果一致
// （适配器 mock 引擎复用本包 Model，协议正确性由此单测保障）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteEngineMatchesLocal(t *testing.T) {
	local := New()

	// 模拟 vllm-adapter 的 /generate（与 gateway/vllm-adapter mock 引擎同逻辑）
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Vectors [][]float64 `json:"vectors"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		tokens := make([]uint64, len(req.Vectors))
		for i, v := range req.Vectors {
			tokens[i] = uint64(local.Predict(v))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]uint64{"tokens": tokens})
	}))
	defer ts.Close()

	remote := NewRemoteEngine(ts.URL)

	inputs := [][]float64{
		{1, 2, 3, 4, 5, 6, 7, 8},
		{0.5, -1.2, 3.3, 2.2, 0.1, -0.9, 1.7, 0.0},
		{1000, 2000, 3000, 4, 5, 6, 7, 8},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{-100, 50, -25, 12, -6, 3, -1, 0.5},
	}
	for i, vec := range inputs {
		got := remote.Predict(vec)
		want := local.Predict(vec)
		if got != want {
			t.Fatalf("输入 %d：远程引擎 %d != 本地引擎 %d", i, got, want)
		}
	}
}

// TestRemoteEngineUnavailable 适配器不可用 → 返回 -1（上层 fail-closed 拒绝，不产生明文）。
func TestRemoteEngineUnavailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	remote := NewRemoteEngine(ts.URL)
	if got := remote.Predict([]float64{1, 2, 3}); got != -1 {
		t.Fatalf("适配器 503 应返回 -1，got %d", got)
	}
	ts.Close()
	// 连接失败同样 -1
	dead := NewRemoteEngine("http://127.0.0.1:1")
	if got := dead.Predict([]float64{1, 2, 3}); got != -1 {
		t.Fatalf("连接失败应返回 -1，got %d", got)
	}
}
