package cacheengine

import (
	"fmt"
	"testing"
)

// TestCanary_Disabled 灰度关闭 → 全部放行。
func TestCanary_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = false
	c := NewConfigCanaryController(&cfg)

	if c.Enabled() {
		t.Fatal("should not be enabled")
	}
	if c.WriteOnly() {
		t.Fatal("should not be write-only")
	}

	ctx := LookupContext{TenantID: "any-tenant"}
	if !c.Allowed(ctx) {
		t.Fatal("disabled canary should allow all")
	}
}

// TestCanary_TenantWhitelist 租户白名单。
func TestCanary_TenantWhitelist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"t1", "t2"}

	c := NewConfigCanaryController(&cfg)

	if !c.Allowed(LookupContext{TenantID: "t1"}) {
		t.Fatal("t1 should be allowed")
	}
	if !c.Allowed(LookupContext{TenantID: "t2"}) {
		t.Fatal("t2 should be allowed")
	}
	if c.Allowed(LookupContext{TenantID: "t3"}) {
		t.Fatal("t3 should not be allowed (not in whitelist, no traffic)")
	}
}

// TestCanary_SceneWhitelist 场景白名单。
func TestCanary_SceneWhitelist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryScenes = []string{"factual", "code"}

	c := NewConfigCanaryController(&cfg)

	if !c.Allowed(LookupContext{TenantID: "x", Scene: SceneFactual}) {
		t.Fatal("factual scene should be allowed")
	}
	if !c.Allowed(LookupContext{TenantID: "x", Scene: SceneCode}) {
		t.Fatal("code scene should be allowed")
	}
	if c.Allowed(LookupContext{TenantID: "x", Scene: SceneGeneral}) {
		t.Fatal("general scene should not be allowed")
	}
}

// TestCanary_ModelWhitelist 模型白名单。
func TestCanary_ModelWhitelist(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryModels = []string{"gpt-4", "claude-3"}

	c := NewConfigCanaryController(&cfg)

	if !c.Allowed(LookupContext{TenantID: "x", Model: "gpt-4"}) {
		t.Fatal("gpt-4 should be allowed")
	}
	if c.Allowed(LookupContext{TenantID: "x", Model: "llama-3"}) {
		t.Fatal("llama-3 should not be allowed")
	}
}

// TestCanary_TrafficPercent 流量比例（基于 tenant hash 稳定）。
func TestCanary_TrafficPercent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 50

	c := NewConfigCanaryController(&cfg)

	// 同一租户结果应一致（稳定性）
	ctx := LookupContext{TenantID: "stable-tenant-id"}
	result1 := c.Allowed(ctx)
	for i := 0; i < 100; i++ {
		if c.Allowed(ctx) != result1 {
			t.Fatal("canary decision should be stable for same tenant")
		}
	}

	// 100 个不同租户，应大致符合比例（允许一定偏差）
	var allowed int
	for i := 0; i < 100; i++ {
		if c.Allowed(LookupContext{TenantID: fmt.Sprintf("tenant-%d", i)}) {
			allowed++
		}
	}
	// 50% 比例，100 个样本，正常在 35-65 之间
	if allowed < 30 || allowed > 70 {
		t.Fatalf("traffic percent out of range: %d/100", allowed)
	}
}

// TestCanary_100Percent 100% 流量 → 全部放行。
func TestCanary_100Percent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 100

	c := NewConfigCanaryController(&cfg)

	for i := 0; i < 50; i++ {
		if !c.Allowed(LookupContext{TenantID: fmt.Sprintf("t-%d", i)}) {
			t.Fatalf("100%% traffic should allow all, but t-%d was rejected", i)
		}
	}
}

// TestCanary_0Percent 0% 流量 + 无白名单 → 全部拒绝。
func TestCanary_0Percent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 0

	c := NewConfigCanaryController(&cfg)

	for i := 0; i < 20; i++ {
		if c.Allowed(LookupContext{TenantID: fmt.Sprintf("t-%d", i)}) {
			t.Fatalf("0%% traffic should reject all, but t-%d was allowed", i)
		}
	}
}

// TestCanary_WriteOnly 只写模式。
func TestCanary_WriteOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.WriteOnly = true
	cfg.Gray.CanaryTenants = []string{"t1"}

	c := NewConfigCanaryController(&cfg)

	if !c.WriteOnly() {
		t.Fatal("should be write-only")
	}
	if !c.Enabled() {
		t.Fatal("should be enabled")
	}
}

// ===== Engine 集成灰度测试 =====

// TestEngineCanary_SkipsNonCanary 非灰度租户 → canary_skip。
func TestEngineCanary_SkipsNonCanary(t *testing.T) {
	cfg := testConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 0
	// 无白名单，0% 流量 → 全拒

	eng := NewCacheEngine(cfg)

	r := eng.Lookup(LookupContext{
		TenantID:        "unknown-tenant",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h1",
		PromptText:      "long enough prompt text for cache",
		PolicyVer:       "v1",
		GuardVer:        "v1",
	})

	if r.Hit {
		t.Fatal("canary skip should result in miss")
	}
	if r.RejectReason != "canary_skip" {
		t.Fatalf("expected canary_skip, got %s", r.RejectReason)
	}
}

// TestEngineCanary_AllowsWhitelist 白名单租户正常访问。
func TestEngineCanary_AllowsWhitelist(t *testing.T) {
	cfg := testConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 0
	cfg.Gray.CanaryTenants = []string{"t-canary"}

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t-canary",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h1",
		PromptText:      "long enough prompt text for cache",
		PolicyVer:       "v1",
		GuardVer:        "v1",
	}

	// 写入
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Text:      "canary response",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 命中
	r := eng.Lookup(ctx)
	if !r.Hit {
		t.Fatalf("expected hit for canary tenant, reason=%s", r.RejectReason)
	}
}

// TestEngineCanary_WriteOnlyMode 只写模式 → 查询不命中但可以写入。
func TestEngineCanary_WriteOnlyMode(t *testing.T) {
	cfg := testConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.WriteOnly = true
	cfg.Gray.CanaryTenants = []string{"t1"}

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h1",
		PromptText:      "long enough prompt text for cache",
		PolicyVer:       "v1",
		GuardVer:        "v1",
	}

	// 写入
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Text:      "write-only response",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 查询 → 不命中（write_only）
	r := eng.Lookup(ctx)
	if r.Hit {
		t.Fatal("write-only mode should not return hits")
	}
	if r.RejectReason != "canary_write_only" {
		t.Fatalf("expected canary_write_only, got %s", r.RejectReason)
	}
}

// TestEngineCanary_CustomController 注入自定义灰度控制器。
func TestEngineCanary_CustomController(t *testing.T) {
	cfg := testConfig()
	cfg.Gray.Enabled = true // 默认配置开，但自定义控制器会覆盖

	// 自定义：始终拒绝
	custom := &alwaysDenyCanary{}
	eng := NewCacheEngine(cfg, WithCanaryController(custom))

	ctx := LookupContext{
		TenantID:        "anyone",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h1",
		PromptText:      "long enough prompt text",
		PolicyVer:       "v1",
		GuardVer:        "v1",
	}

	r := eng.Lookup(ctx)
	if r.Hit {
		t.Fatal("custom deny controller should skip all")
	}
	// 因为自定义的是 alwaysDeny，enabled=true 但 allowed=false → canary_skip
	if r.RejectReason != "canary_skip" {
		t.Fatalf("expected canary_skip, got %s", r.RejectReason)
	}
}

// alwaysDenyCanary 测试用自定义灰度控制器（始终拒绝）。
type alwaysDenyCanary struct{}

func (c *alwaysDenyCanary) Enabled() bool                { return true }
func (c *alwaysDenyCanary) WriteOnly() bool              { return false }
func (c *alwaysDenyCanary) Allowed(ctx LookupContext) bool { return false }
