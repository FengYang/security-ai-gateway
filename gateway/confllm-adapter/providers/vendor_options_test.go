package providers

import (
	"encoding/json"
	"testing"

	"security-ai-gateway/gateway/confllm-adapter"
)

// TestBuildBodyVendorWhitelist 覆盖 base.go:119-120 的 L2 白名单裁剪路径：
// 配置级 + 请求级 vendor 参数合并后，仅白名单命中的 key 透传，其余丢弃（防污染统一契约）。
func TestBuildBodyVendorWhitelist(t *testing.T) {
	cfg := confllm.ProviderConfig{
		ID:            "p",
		Capabilities:  confllm.Capabilities{AllowedVendorKeys: []string{"enable_thinking", "thinking"}},
		VendorOptions: map[string]any{"enable_thinking": true, "cfg_leak": "x"},
	}
	p := buildBaseHTTPProvider(cfg)

	req := &confllm.ChatRequest{
		Model:        "m",
		Messages:     []confllm.Message{{Role: "user", Content: "hi"}},
		VendorOptions: map[string]any{"thinking": 1, "req_leak": "y"},
	}
	body := p.buildBody(req)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("buildBody 产出非法 JSON：%v", err)
	}
	if _, ok := m["enable_thinking"]; !ok {
		t.Fatal("配置级白名单 key enable_thinking 应透传")
	}
	if _, ok := m["thinking"]; !ok {
		t.Fatal("请求级白名单 key thinking 应透传")
	}
	if _, ok := m["cfg_leak"]; ok {
		t.Fatal("非白名单配置级 key 不应透传")
	}
	if _, ok := m["req_leak"]; ok {
		t.Fatal("非白名单请求级 key 不应透传")
	}
	if m["model"] != "m" {
		t.Fatal("base model 应保留")
	}
	if _, ok := m["messages"]; !ok {
		t.Fatal("base messages 应保留")
	}
}

// TestBuildBodyVendorWhitelistEmpty 白名单为空（未声明 AllowedVendorKeys）→ 全部 vendor 字段 fail-closed 丢弃。
func TestBuildBodyVendorWhitelistEmpty(t *testing.T) {
	cfg := confllm.ProviderConfig{
		ID:           "p",
		Capabilities: confllm.Capabilities{}, // AllowedVendorKeys 为空
		VendorOptions: map[string]any{"x": 1},
	}
	p := buildBaseHTTPProvider(cfg)

	req := &confllm.ChatRequest{
		Model:        "m",
		Messages:     []confllm.Message{{Role: "user", Content: "hi"}},
		VendorOptions: map[string]any{"y": 2},
	}
	body := p.buildBody(req)

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("buildBody 产出非法 JSON：%v", err)
	}
	if _, ok := m["x"]; ok {
		t.Fatal("白名单为空时配置级 vendor 字段不应透传")
	}
	if _, ok := m["y"]; ok {
		t.Fatal("白名单为空时请求级 vendor 字段不应透传")
	}
	if m["model"] != "m" {
		t.Fatal("base model 应保留")
	}
}
