package cacheengine

import "testing"

// TestCacheable_ToolCallAlwaysRejected 工具调用强制不可缓存。
func TestCacheable_ToolCallAlwaysRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Cacheability.MultiTurn = true

	ce := newCacheabilityEngine(&cfg, NewRuleSceneClassifier())

	ctx := &LookupContext{
		TenantID:     "t1",
		PromptText:   "你好，请列出所有订单",
		HasToolCall:  true,
		PolicyVer:    "1",
		GuardVer:     "v1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
	}
	ctx.Scene = SceneGeneral

	d := ce.Cacheable(ctx)
	if d.Cacheable {
		t.Fatal("tool call should not be cacheable")
	}
	if d.Reason != "tool_call" {
		t.Fatalf("expected reason tool_call, got %s", d.Reason)
	}
}

// TestCacheable_MultiTurn 多轮默认不可缓存。
func TestCacheable_MultiTurn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact

	ce := newCacheabilityEngine(&cfg, NewRuleSceneClassifier())

	ctx := &LookupContext{
		TenantID:    "t1",
		PromptText:  "你好",
		TurnCount:   2,
		PolicyVer:   "1",
		GuardVer:    "v1",
		EngineType:  "cmaas",
		Model:       "gpt-4",
		MaxNewTokens: 100,
	}
	ctx.Scene = SceneGeneral

	d := ce.Cacheable(ctx)
	if d.Cacheable {
		t.Fatal("multi-turn should not be cacheable by default")
	}
	if d.Reason != "multi_turn" {
		t.Fatalf("expected reason multi_turn, got %s", d.Reason)
	}
}

// TestCacheable_BypassHeader 旁路头。
func TestCacheable_BypassHeader(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact

	ce := newCacheabilityEngine(&cfg, NewRuleSceneClassifier())

	ctx := &LookupContext{
		TenantID:     "t1",
		PromptText:   "你好，请列出所有订单",
		NoCache:      true,
		PolicyVer:    "1",
		GuardVer:     "v1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
	}
	ctx.Scene = SceneGeneral

	d := ce.Cacheable(ctx)
	if d.Cacheable {
		t.Fatal("no-cache should bypass")
	}
	if d.Reason != "bypass" {
		t.Fatalf("expected reason bypass, got %s", d.Reason)
	}
}

// TestCacheable_ShortPrompt 输入过短。
func TestCacheable_ShortPrompt(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 8

	ce := newCacheabilityEngine(&cfg, NewRuleSceneClassifier())

	ctx := &LookupContext{
		TenantID:     "t1",
		PromptText:   "hi", // 很短
		PolicyVer:    "1",
		GuardVer:     "v1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
	}
	ctx.Scene = SceneGeneral

	d := ce.Cacheable(ctx)
	if d.Cacheable {
		t.Fatal("short prompt should not be cacheable")
	}
	if d.Reason != "too_short" {
		t.Fatalf("expected reason too_short, got %s", d.Reason)
	}
}

// TestCacheable_Allowed 正常可缓存。
func TestCacheable_Allowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact

	ce := newCacheabilityEngine(&cfg, NewRuleSceneClassifier())

	ctx := &LookupContext{
		TenantID:     "t1",
		PromptText:   "什么是 Go 语言？请详细说明",
		PolicyVer:    "1",
		GuardVer:     "v1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
	}
	ctx.Scene = SceneFactual

	d := ce.Cacheable(ctx)
	if !d.Cacheable {
		t.Fatalf("should be cacheable, reason: %s", d.Reason)
	}
}

// TestTTLFor_SpecificFirst TTL 维度优先级。
func TestTTLFor_SpecificFirst(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.TTLPolicy.ByTenant = map[string]string{"t1": "300s"}
	cfg.TTLPolicy.ByModel = map[string]string{"m1": "7200s"}
	cfg.TTLPolicy.ByScene = map[string]string{"factual": "86400s"}

	resolver := NewTTLResolver(&cfg)
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID: "t1",
			Model:    "m1",
			Scene:    SceneFactual,
		},
	}

	ttl := resolver.TTLFor(ctx)
	// specific_first: 租户最高，应为 300s
	if ttl != 300*1e9 { // 300s in nanoseconds
		t.Fatalf("expected 300s TTL, got %v", ttl)
	}
}

// TestTTLFor_MinMode min 模式。
func TestTTLFor_MinMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.TTLPolicy.Resolution = "min"
	cfg.TTLPolicy.ByTenant = map[string]string{"t1": "300s"}
	cfg.TTLPolicy.ByModel = map[string]string{"m1": "7200s"}
	cfg.TTLPolicy.ByScene = map[string]string{"factual": "86400s"}

	resolver := NewTTLResolver(&cfg)
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID: "t1",
			Model:    "m1",
			Scene:    SceneFactual,
		},
	}

	ttl := resolver.TTLFor(ctx)
	// min: 取最小值，300s
	if ttl != 300*1e9 {
		t.Fatalf("expected 300s TTL (min), got %v", ttl)
	}
}

// TestTTLFor_Default 无命中回退默认。
func TestTTLFor_Default(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact

	resolver := NewTTLResolver(&cfg)
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID: "unknown",
			Model:    "unknown",
			Scene:    SceneGeneral,
		},
	}

	ttl := resolver.TTLFor(ctx)
	if ttl != cfg.Exact.TTL.D() {
		t.Fatalf("expected default TTL %v, got %v", cfg.Exact.TTL.D(), ttl)
	}
}

// TestSceneClassifier_Basic 场景分类基础测试。
func TestSceneClassifier_Basic(t *testing.T) {
	c := NewRuleSceneClassifier()

	tests := []struct {
		prompt   string
		expected SceneClass
	}{
		{"这段代码有什么问题？func main() {}", SceneCode},
		{"计算 1 + 1 等于多少", SceneMath},
		{"什么是 HTTP 协议？请列表说明", SceneFactual},
		{"你好啊", SceneGeneral},
	}

	for _, tt := range tests {
		got := c.Classify(tt.prompt)
		if got != tt.expected {
			t.Errorf("Classify(%q) = %v, want %v", tt.prompt, got, tt.expected)
		}
	}
}

// TestDefaultConfig_Validate 默认配置应通过校验。
func TestDefaultConfig_Validate(t *testing.T) {
	cfg := DefaultConfig()
	errs := cfg.Validate()
	if len(errs) > 0 {
		t.Fatalf("default config should validate, got errors: %v", errs)
	}
}

// TestConfig_ValidateThreshold 阈值校验。
func TestConfig_ValidateThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeSemantic
	cfg.Semantic.Enabled = true
	cfg.Semantic.Threshold.Factual = 0.3 // 低于 0.5

	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected validation error for low threshold")
	}
}

// TestGenParams_Canonical 生成参数规范化。
func TestGenParams_Canonical(t *testing.T) {
	g1 := GenParams{Temperature: 0.7, TopP: 0.9}
	g2 := GenParams{Temperature: 0.7, TopP: 0.9}

	if g1.Canonical() != g2.Canonical() {
		t.Fatal("same params should have same canonical")
	}

	g3 := GenParams{Temperature: 0.8, TopP: 0.9}
	if g1.Canonical() == g3.Canonical() {
		t.Fatal("different temp should have different canonical")
	}
}

// testConfig 返回测试用默认配置（降低阈值，方便测试）。
func testConfig() CacheConfig {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.WriteLimit.Enabled = false // 单测聚焦各自特性；写入限流的专项用例在 throttle_test.go 显式开启
	return cfg
}
