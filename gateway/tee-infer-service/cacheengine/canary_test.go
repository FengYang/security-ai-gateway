package cacheengine

import (
	"testing"
)

// ===== 灰度控制器专项用例（§12 四件套 T-12-1..5） =====

func canaryCfg() CacheConfig {
	cfg := testConfig()
	cfg.Mode = ModeExact
	return cfg
}

func canaryCtx(tenant string) LookupContext {
	return LookupContext{
		TenantID: tenant, EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
		TransformedHash: "h-" + tenant, PromptText: "long enough prompt for canary test",
		PolicyVer: "1", GuardVer: "1",
	}
}

func canaryStore(tenant string) StoreContext {
	return StoreContext{LookupContext: canaryCtx(tenant), Writable: true}
}

func canaryRes() InferResult {
	return InferResult{Text: "answer", TokensOut: 5, Finish: "stop"}
}

// denyCanary 测试用自定义控制器（始终拒绝）。
type denyCanary struct{}

func (denyCanary) Allow(string, SceneClass, string) (bool, bool) { return false, false }
func (denyCanary) Stage() string                                 { return "G-0" }
func (denyCanary) Enabled() bool                                 { return true }

// TestCanary_Disabled 灰度关闭 → 全量放行（B-12-1）。
func TestCanary_Disabled(t *testing.T) {
	cfg := canaryCfg()
	c := NewConfigCanaryController(&cfg)
	if c.Enabled() {
		t.Fatal("默认应关闭灰度")
	}
	if allow, wo := c.Allow("t1", SceneFactual, "m1"); !allow || wo {
		t.Fatalf("关闭时应全量放行，实际 allow=%v writeOnly=%v", allow, wo)
	}
	if c.Stage() != "G-0" {
		t.Fatalf("缺省 stage 应为 G-0，实际 %s", c.Stage())
	}
}

// TestCanary_NilConfigSafe 空配置不 panic。
func TestCanary_NilConfigSafe(t *testing.T) {
	c := NewConfigCanaryController(nil)
	if c.Enabled() {
		t.Fatal("nil 配置应为未启用")
	}
	if allow, _ := c.Allow("t1", SceneGeneral, "m"); !allow {
		t.Fatal("nil 配置应全量放行")
	}
	if c.Stage() != "G-0" {
		t.Fatalf("stage=%s", c.Stage())
	}
}

// TestCanary_TenantWhitelist 租户白名单（无场景过滤）。
func TestCanary_TenantWhitelist(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"t1", "t2"}
	c := NewConfigCanaryController(&cfg)

	if allow, _ := c.Allow("t1", SceneGeneral, "m"); !allow {
		t.Fatal("白名单租户应放行")
	}
	if allow, _ := c.Allow("t9", SceneGeneral, "m"); allow {
		t.Fatal("非白名单租户不应放行")
	}
}

// TestCanary_TenantSceneAND §12.4：租户白名单 ×（场景空或匹配）为 AND。
func TestCanary_TenantSceneAND(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"t1"}
	cfg.Gray.CanaryScenes = []string{"factual"}
	c := NewConfigCanaryController(&cfg)

	if allow, _ := c.Allow("t1", SceneFactual, "m"); !allow {
		t.Fatal("租户✓且场景✓应放行")
	}
	if allow, _ := c.Allow("t1", SceneCode, "m"); allow {
		t.Fatal("租户✓但场景✗不应放行（AND 语义）")
	}
}

// TestCanary_SceneWithoutTenantNotAllowed §12.4：仅配场景（无租户白名单）不单独放行。
func TestCanary_SceneWithoutTenantNotAllowed(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryScenes = []string{"factual"}
	c := NewConfigCanaryController(&cfg)

	if allow, _ := c.Allow("t1", SceneFactual, "m"); allow {
		t.Fatal("无租户白名单时场景维度不应独立放行")
	}
}

// TestCanary_ModelWhitelist 模型白名单独立放行。
func TestCanary_ModelWhitelist(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryModels = []string{"m1"}
	c := NewConfigCanaryController(&cfg)

	if allow, _ := c.Allow("t9", SceneGeneral, "m1"); !allow {
		t.Fatal("模型白名单应放行")
	}
	if allow, _ := c.Allow("t9", SceneGeneral, "other"); allow {
		t.Fatal("非白名单模型不应放行")
	}
}

// TestCanary_TenantBucketStable T-12-2：同一租户结论恒定（稳定分桶）。
func TestCanary_TenantBucketStable(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 50
	c := NewConfigCanaryController(&cfg)

	first, _ := c.Allow("stable-tenant", SceneGeneral, "m")
	for i := 0; i < 20; i++ {
		if got, _ := c.Allow("stable-tenant", SceneGeneral, "m"); got != first {
			t.Fatal("同一租户在同一配置版本内结论应恒定")
		}
	}
}

// TestCanary_TrafficBounds 流量比例边界：100% 全放行、0% 全拒绝。
func TestCanary_TrafficBounds(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true

	cfg.Gray.TrafficPercent = 100
	c100 := NewConfigCanaryController(&cfg)
	if allow, _ := c100.Allow("any-tenant", SceneGeneral, "m"); !allow {
		t.Fatal("100% 应全放行")
	}

	cfg.Gray.TrafficPercent = 0
	c0 := NewConfigCanaryController(&cfg)
	if allow, _ := c0.Allow("any-tenant", SceneGeneral, "m"); allow {
		t.Fatal("0% 且无白名单应全拒绝")
	}
}

// TestCanary_WriteOnly T-12-1：G-0 影子 → 全部写、一律不读。
func TestCanary_WriteOnly(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.WriteOnly = true
	cfg.Gray.CanaryTenants = []string{"t1"}
	c := NewConfigCanaryController(&cfg)

	for _, tenant := range []string{"t1", "other"} {
		allow, wo := c.Allow(tenant, SceneGeneral, "m")
		if !allow || !wo {
			t.Fatalf("G-0 影子应 allow=true writeOnly=true，实际 %v/%v", allow, wo)
		}
	}
}

// TestCanary_StageExplicit 显式阶段透传。
func TestCanary_StageExplicit(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Stage = "G-3"
	if got := NewConfigCanaryController(&cfg).Stage(); got != "G-3" {
		t.Fatalf("stage=%s want G-3", got)
	}
}

// TestCanary_HotReloadTakesEffect T-12-5：配置变更即时生效（引擎层验证）。
func TestCanary_HotReloadTakesEffect(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 0
	c := NewConfigCanaryController(&cfg)

	if allow, _ := c.Allow("t1", SceneGeneral, "m"); allow {
		t.Fatal("初始应拒绝")
	}
	cfg.Gray.TrafficPercent = 100 // 模拟热更新（同一配置对象）
	if allow, _ := c.Allow("t1", SceneGeneral, "m"); !allow {
		t.Fatal("热更新应即时生效")
	}
}

// TestEngineCanary_SkipsNonCanary 非灰度租户读路径 miss。
func TestEngineCanary_SkipsNonCanary(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"allowed"}
	eng := NewCacheEngine(cfg)

	r := eng.Lookup(canaryCtx("other"))
	if r.Hit || r.RejectReason != "canary_skip" {
		t.Fatalf("非灰度租户应 canary_skip，实际 %+v", r)
	}
}

// TestEngineCanary_WriteSideGate §12.4：写入侧同源判定（范围外不写）。
func TestEngineCanary_WriteSideGate(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"allowed"}
	eng := NewCacheEngine(cfg)

	out := eng.Store(canaryStore("other"), canaryRes())
	if out.Stored || out.Skipped != "canary_skip" {
		t.Fatalf("非灰度租户写入应 canary_skip，实际 %+v", out)
	}
}

// TestEngineCanary_AllowsWhitelist 白名单租户读写正常。
func TestEngineCanary_AllowsWhitelist(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"allowed"}
	eng := NewCacheEngine(cfg)

	if out := eng.Store(canaryStore("allowed"), canaryRes()); !out.Stored {
		t.Fatalf("白名单租户写入应成功，实际 %+v", out)
	}
	if r := eng.Lookup(canaryCtx("allowed")); !r.Hit {
		t.Fatalf("白名单租户应命中，reason=%s", r.RejectReason)
	}
}

// TestEngineCanary_WriteOnlyMode T-12-1：G-0 查询恒 miss、写入照常。
func TestEngineCanary_WriteOnlyMode(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.WriteOnly = true
	eng := NewCacheEngine(cfg)

	if r := eng.Lookup(canaryCtx("t1")); r.Hit || r.RejectReason != "canary_write_only" {
		t.Fatalf("G-0 查询应 canary_write_only，实际 %+v", r)
	}
	if out := eng.Store(canaryStore("t1"), canaryRes()); !out.Stored {
		t.Fatalf("G-0 写入应照常，实际 %+v", out)
	}
}

// TestEngineCanary_ModeIsUpperBound T-12-4：灰度不能突破 mode 上界（mode=off 优先）。
func TestEngineCanary_ModeIsUpperBound(t *testing.T) {
	cfg := canaryCfg()
	cfg.Mode = ModeOff
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"t1"}
	eng := NewCacheEngine(cfg)

	if r := eng.Lookup(canaryCtx("t1")); r.RejectReason != "disabled" {
		t.Fatalf("mode=off 应优先，实际 %+v", r)
	}
}

// TestEngineCanary_OffTenantPrecedence T-12-3：tenant_policy=off 优先于灰度白名单。
func TestEngineCanary_OffTenantPrecedence(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"t1"}
	cfg.Semantic.Vector.TenantPolicy = map[string]string{"t1": "off"}
	eng := NewCacheEngine(cfg)

	if r := eng.Lookup(canaryCtx("t1")); r.RejectReason != "disabled" {
		t.Fatalf("tenant_policy=off 应优先于白名单，实际 %+v", r)
	}
}

// TestEngineCanary_CustomController 注入自定义控制器。
func TestEngineCanary_CustomController(t *testing.T) {
	cfg := canaryCfg()
	eng := NewCacheEngine(cfg, WithCanaryController(denyCanary{}))

	if r := eng.Lookup(canaryCtx("t1")); r.RejectReason != "canary_skip" {
		t.Fatalf("自定义控制器应拒绝，实际 %+v", r)
	}
}

// TestEngineCanary_Metric §9.1 #36：灰度判定发射 canary_total{stage,result}。
func TestEngineCanary_Metric(t *testing.T) {
	cfg := canaryCfg()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"allowed"}
	eng := NewCacheEngine(cfg).(*engine)

	eng.Lookup(canaryCtx("allowed")) // allow
	eng.Lookup(canaryCtx("other"))   // skip

	snap := eng.stats.canaryC.snapshot()
	if snap["G-0:allow"] != 1 || snap["G-0:skip"] != 1 {
		t.Fatalf("canary_total 计数异常：%+v", snap)
	}
}
