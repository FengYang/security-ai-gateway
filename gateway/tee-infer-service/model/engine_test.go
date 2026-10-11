package model

// V-4 引擎对接验证：RemoteEngine 经 vLLM 适配器接口推理，与本地引擎结果一致
// （适配器 mock 引擎复用本包 Model，协议正确性由此单测保障）。
// P2：RemoteEngine 流式 Generate（vLLM OpenAI 兼容 SSE）+ 失败路径；
// P5：CmaasEngine 经 openai-proxy httptest 模拟。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// ---------- P2：RemoteEngine 流式 Generate（vLLM OpenAI 兼容） ----------

// sseServer 构造 OpenAI 兼容 SSE 流式服务（vLLM 模拟）。
func sseServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}

// TestRemoteEngineGenerateStream vLLM 流式生成：增量按序回调 + [DONE] 正常终止。
func TestRemoteEngineGenerateStream(t *testing.T) {
	ts := sseServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		var req struct {
			Model    string        `json:"model"`
			Messages []ChatMessage `json:"messages"`
			Stream   bool          `json:"stream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if !req.Stream || req.Model != "qwen2.5-1.5b" || len(req.Messages) != 1 || req.Messages[0].Content != "你好" {
			http.Error(w, "request mismatch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, delta := range []string{"你", "好", "！"} {
			chunk := fmt.Sprintf(`data: {"choices":[{"delta":{"content":%q},"finish_reason":null}]}`+"\n\n", delta)
			_, _ = w.Write([]byte(chunk))
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	defer ts.Close()

	remote := NewRemoteEngine(ts.URL)
	var got []string
	err := remote.Generate(GenerateRequest{Model: "qwen2.5-1.5b", Messages: []ChatMessage{{Role: "user", Content: "你好"}}},
		func(delta string) error { got = append(got, delta); return nil })
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	if strings.Join(got, "") != "你好！" {
		t.Fatalf("流式增量不符: %v", got)
	}
}

// TestRemoteEngineGenerateFailClosed 流式失败路径 fail-closed：
// 非 200 / 缺 [DONE] / 流中断 → error（不产出半截明文视为成功）。
func TestRemoteEngineGenerateFailClosed(t *testing.T) {
	// 非 200
	ts1 := sseServer(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model overloaded", http.StatusServiceUnavailable)
	})
	remote1 := NewRemoteEngine(ts1.URL)
	if err := remote1.Generate(GenerateRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("非 200 应失败")
	}
	ts1.Close()

	// 缺 [DONE]（截断攻击）→ 失败
	ts2 := sseServer(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`data: {"choices":[{"delta":{"content":"半截"}}]}` + "\n\n"))
	})
	remote2 := NewRemoteEngine(ts2.URL)
	if err := remote2.Generate(GenerateRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("缺 [DONE] 应失败（fail-closed）")
	}
	ts2.Close()

	// 连接失败
	dead := NewRemoteEngine("http://127.0.0.1:1")
	if err := dead.Generate(GenerateRequest{Model: "m", Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("连接失败应报错")
	}
}

// TestCmaasEngineViaProxy C-MaaS 经 openai-proxy（httptest 模拟）：
// Bearer 透传 + 流式增量 + 模型 code 缺省回退。
func TestCmaasEngineViaProxy(t *testing.T) {
	ts := sseServer(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			http.Error(w, "auth mismatch: "+got, http.StatusUnauthorized)
			return
		}
		var req struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "cmaas-glm-5.2" {
			http.Error(w, "model mismatch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"choices":[{"delta":{"content":"机密"}}]}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"choices":[{"delta":{"content":"推理"}}]}` + "\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	defer ts.Close()

	eng := NewCmaasEngine(ts.URL, "sk-test", "cmaas-glm-5.2")
	var got []string
	err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}},
		func(delta string) error { got = append(got, delta); return nil })
	if err != nil {
		t.Fatalf("CmaasEngine.Generate 失败: %v", err)
	}
	if strings.Join(got, "") != "机密推理" {
		t.Fatalf("增量不符: %v", got)
	}
}

// TestCmaasEngineFailClosed C-MaaS fail-closed：未配置代理 / 未指定模型 → error。
func TestCmaasEngineFailClosed(t *testing.T) {
	eng := NewCmaasEngine("", "", "")
	if err := eng.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("未配置代理应失败（fail-closed）")
	}
	eng2 := NewCmaasEngine("http://127.0.0.1:1", "", "")
	if err := eng2.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "x"}}},
		func(string) error { return nil }); err == nil {
		t.Fatal("未指定模型应失败（fail-closed）")
	}
	// Predict（vectors）不支持 → -1
	if got := eng.Predict([]float64{1, 2, 3}); got != -1 {
		t.Fatalf("C-MaaS Predict 应 -1，got %d", got)
	}
}

// TestLocalEngineGenerate 本地演示引擎流式回显（确定性）。
func TestLocalEngineGenerate(t *testing.T) {
	m := New()
	var got []string
	err := m.Generate(GenerateRequest{Messages: []ChatMessage{{Role: "user", Content: "abc"}}},
		func(delta string) error { got = append(got, delta); return nil })
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	if strings.Join(got, "") != "abc" {
		t.Fatalf("回显不符: %v", got)
	}
}

// ---------- P1-1 G-8 / M8-1：统一 text 载荷 tool_calls 扩展（向后兼容） ----------

// TestChatMessageToolCallsRoundTrip tool_calls / tool_call_id 序列化往返保真。
func TestChatMessageToolCallsRoundTrip(t *testing.T) {
	in := []ChatMessage{
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: "call_1", Type: "function",
			Function: ToolCallFunc{Name: "query", Arguments: `{"q":"x"}`},
		}}},
		{Role: "tool", Content: "ok", ToolCallID: "call_1"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []ChatMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || len(out[0].ToolCalls) != 1 {
		t.Fatalf("tool_calls 往返失败: %+v", out)
	}
	if out[0].ToolCalls[0].Function.Name != "query" || out[0].ToolCalls[0].Function.Arguments != `{"q":"x"}` {
		t.Fatalf("ToolCall 字段不符: %+v", out[0].ToolCalls[0])
	}
	if out[1].Role != "tool" || out[1].ToolCallID != "call_1" {
		t.Fatalf("tool 角色往返失败: %+v", out[1])
	}
}

// TestBackwardCompatNoToolCalls 缺省无 tool_calls/tool_call_id → 序列化逐字节不变（向后兼容）。
func TestBackwardCompatNoToolCalls(t *testing.T) {
	raw, err := json.Marshal([]ChatMessage{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `[{"role":"user","content":"hi"}]` {
		t.Fatalf("旧载荷序列化被改变: %s", raw)
	}
}
