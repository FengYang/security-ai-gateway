// routectl_test.go — M4-1/M4-2 单测（校验失败不换入 / 原子性 / 热加载 / 内容去重 / 防抖）。
package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"security-ai-gateway/protocol/go"
)

// bytesSource 测试用内存配置源。
type bytesSource struct {
	mu   sync.Mutex
	data []byte
}

func (b *bytesSource) Load() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), nil
}

func (b *bytesSource) set(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = data
}

const validRouteJSON = `{
  "tenant": {"acme": {"engine": "cmaas", "attest": "token"}},
  "model": {
    "mock": {"engines": ["tee_gpu", "masked_vector", "cmaas"], "tier": "small",
             "costs": [{"engine": "tee_gpu", "price_per_1k": 3.0, "latency_p50_ms": 80, "quality": 95},
                        {"engine": "masked_vector", "price_per_1k": 1.5, "latency_p50_ms": 120, "quality": 70}]},
    "qwen2.5-0.5b": {"engines": ["tee_gpu", "masked_vector"], "tier": "small"}
  },
  "default_engine": "tee_gpu",
  "require_quote": false,
  "policy": "cost"
}`

// TestValidateRouteConfig 校验器正/负向用例（技术方案 §3.1 判据 4）。
func TestValidateRouteConfig(t *testing.T) {
	cfg, err := ParseRouteConfig([]byte(validRouteJSON))
	if err != nil {
		t.Fatalf("解析合法配置失败: %v", err)
	}
	if err := validateRouteConfig(cfg); err != nil {
		t.Fatalf("合法配置被拒: %v", err)
	}

	cases := []struct {
		name string
		json string
	}{
		{"未知默认引擎", `{"default_engine": "nope", "model": {}}`},
		{"未知策略", `{"policy": "cheapest", "model": {}}`},
		{"模型引擎空", `{"model": {"m": {"engines": []}}}`},
		{"模型引擎未注册", `{"model": {"m": {"engines": ["wasm_x"]}}}`},
		{"costs 引用越界", `{"model": {"m": {"engines": ["tee_gpu"], "costs": [{"engine": "cmaas", "price_per_1k": 1}]}}}`},
		{"costs 负值", `{"model": {"m": {"engines": ["tee_gpu"], "costs": [{"engine": "tee_gpu", "price_per_1k": -1}]}}}`},
		{"租户引擎未注册", `{"tenant": {"t": {"engine": "ghost"}}, "model": {}}`},
		{"租户 attest 非法", `{"tenant": {"t": {"attest": "none"}}, "model": {}}`},
	}
	for _, c := range cases {
		cfg, err := ParseRouteConfig([]byte(c.json))
		if err != nil {
			t.Fatalf("%s: 解析失败（应在校验层拒而非解析层）: %v", c.name, err)
		}
		if err := validateRouteConfig(cfg); err == nil {
			t.Errorf("%s: 非法配置未被拒绝", c.name)
		}
	}
}

// TestRouteConfigManager_ReloadSwapOnValid 热换入成功路径：新请求立即见新配置。
func TestRouteConfigManager_ReloadSwapOnValid(t *testing.T) {
	src := &bytesSource{data: []byte(validRouteJSON)}
	m, err := NewRouteConfigManager(src)
	if err != nil {
		t.Fatalf("首载失败: %v", err)
	}
	if m.Get().Policy != "cost" {
		t.Fatalf("首载配置 policy != cost")
	}
	v1 := m.Version()
	if len(v1) != 12 {
		t.Fatalf("版本号应为 sha256 前 12 hex，got %q", v1)
	}

	// 换入合法新配置：policy 变化即时生效。
	updated := `{"default_engine": "masked_vector", "policy": "latency", "model": {"m": {"engines": ["tee_gpu", "masked_vector"]}}}`
	src.set([]byte(updated))
	if err := m.Reload(); err != nil {
		t.Fatalf("合法配置换入被拒: %v", err)
	}
	if got := m.Get().DefaultEngine; got != "masked_vector" {
		t.Fatalf("热换入未生效: default_engine=%q", got)
	}
	if m.Version() == v1 {
		t.Fatal("内容已变但版本号未变")
	}
}

// TestRouteConfigManager_RejectInvalidKeepsOld 非法配置拒绝换入并保持旧配置（fail-safe，判据 2）。
func TestRouteConfigManager_RejectInvalidKeepsOld(t *testing.T) {
	src := &bytesSource{data: []byte(validRouteJSON)}
	m, err := NewRouteConfigManager(src)
	if err != nil {
		t.Fatalf("首载失败: %v", err)
	}
	v1 := m.Version()

	var rejected atomic.Int32
	m.OnReload = func(version string, err error) {
		if err != nil {
			rejected.Add(1)
		}
	}

	// JSON 语法错误。
	src.set([]byte(`{"policy": `))
	if err := m.Reload(); err == nil {
		t.Fatal("语法错误配置应被拒绝")
	}
	// 语义非法（costs 引用越界）。
	src.set([]byte(`{"model": {"m": {"engines": ["tee_gpu"], "costs": [{"engine": "cmaas"}]}}}`))
	if err := m.Reload(); err == nil {
		t.Fatal("语义非法配置应被拒绝")
	}
	if rejected.Load() != 2 {
		t.Fatalf("拒绝留痕次数 = %d，want 2", rejected.Load())
	}
	if m.Version() != v1 {
		t.Fatalf("拒绝后版本漂移: %s != %s", m.Version(), v1)
	}
	if m.Get().Policy != "cost" {
		t.Fatal("拒绝后旧配置被破坏（fail-safe 违约）")
	}
}

// TestRouteConfigManager_IdempotentReload 内容未变不重换入（mtime 变化但内容一致）。
func TestRouteConfigManager_IdempotentReload(t *testing.T) {
	src := &bytesSource{data: []byte(validRouteJSON)}
	m, err := NewRouteConfigManager(src)
	if err != nil {
		t.Fatalf("首载失败: %v", err)
	}
	var swapped atomic.Int32
	old := m.OnReload
	m.OnReload = func(version string, err error) {
		if err == nil {
			swapped.Add(1)
		}
		if old != nil {
			old(version, err)
		}
	}
	if err := m.Reload(); err != nil {
		t.Fatalf("同内容 Reload 应成功去重: %v", err)
	}
	if swapped.Load() != 0 {
		t.Fatalf("内容未变却触发了换入回调 %d 次", swapped.Load())
	}
}

// TestRouteConfigManager_FileWatchHotReload 文件源 poll 热加载端到端（≤5s 生效红线）。
func TestRouteConfigManager_FileWatchHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route.json")
	if err := os.WriteFile(path, []byte(validRouteJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := NewRouteConfigManager(NewFileRouteConfigSource(path))
	if err != nil {
		t.Fatalf("首载失败: %v", err)
	}
	stop := m.StartWatch("poll", 100*time.Millisecond)
	defer stop()

	// 内容变化触发换入（mtime 粒度依赖文件系统，这里直接改内容）。
	updated := `{"default_engine": "masked_vector", "model": {"m": {"engines": ["tee_gpu", "masked_vector"]}}}`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.Get().DefaultEngine == "masked_vector" {
			return // 生效
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("5s 内热加载未生效（判据 2 违约）")
}

// TestRouteCfgFallback 未启用外置管理器时 routeCfg() 回落启动期 route 字段。
func TestRouteCfgFallback(t *testing.T) {
	s := &teeServer{route: DefaultRouteConfig()}
	if s.routeCfg() != s.route {
		t.Fatal("无 routeMgr 时应回落 route 字段")
	}
	src := &bytesSource{data: []byte(validRouteJSON)}
	mgr, err := NewRouteConfigManager(src)
	if err != nil {
		t.Fatal(err)
	}
	s.routeMgr = mgr
	if s.routeCfg() == nil || s.routeCfg().Policy != "cost" {
		t.Fatal("有 routeMgr 时应取管理器当前配置")
	}
}

// TestDefaultRouteConfigPassesValidation 内置缺省配置必须能通过校验器（回退路径自洽）。
func TestDefaultRouteConfigPassesValidation(t *testing.T) {
	if err := validateRouteConfig(DefaultRouteConfig()); err != nil {
		t.Fatalf("内置缺省配置未通过校验: %v", err)
	}
}

// ---------- M9-1/M4-3：路由配置扩展点（placement，技术实现方案 §7.1） ----------

// TestPlacementHintDerivation hint 派生规则：nil→cloud；edge 目标+租户在范围→raw edge；
// 不在范围且有 cloud 目标→raw auto；均不满足→cloud；edge 引擎未注册时 raw 非 cloud
// 一律回退 cloud（§7.1：未注册回退 + 告警），现有引擎列表语义不变。
func TestPlacementHintDerivation(t *testing.T) {
	cases := []struct {
		name string
		p    *PlacementConfig
		hint string
	}{
		{"未配置", nil, PlacementHintCloud},
		{"仅 cloud", &PlacementConfig{Targets: []string{"cloud"}}, PlacementHintCloud},
		{"edge+范围匹配", &PlacementConfig{Targets: []string{"cloud", "edge"}, EdgeRequiredTenantScopes: []string{"edge-tenant"}}, PlacementHintCloud},  // edge 未注册 → 回退
		{"edge+不限范围", &PlacementConfig{Targets: []string{"edge"}}, PlacementHintCloud},                                                              // raw=edge，未注册 → 回退
		{"edge+范围不匹配含cloud", &PlacementConfig{Targets: []string{"cloud", "edge"}, EdgeRequiredTenantScopes: []string{"other"}}, PlacementHintCloud}, // raw=auto → 回退
		{"edge+范围不匹配仅edge", &PlacementConfig{Targets: []string{"edge"}, EdgeRequiredTenantScopes: []string{"other"}}, PlacementHintCloud},           // fail-safe → cloud
	}
	for _, tc := range cases {
		cfg := DefaultRouteConfig()
		cfg.Placement = tc.p
		if got := cfg.placementHintFor("edge-tenant"); got != tc.hint {
			t.Fatalf("%s: placementHintFor = %q，want %q", tc.name, got, tc.hint)
		}
	}
}

// TestPlacementRawHintBeforeEdgeRegistered 验证 raw hint 派生逻辑本身（绕过未注册回退：
// edge 注册后 hint 即生效——以「直接调派生规则」的等价输入组合断言中间值）。
func TestPlacementRawHintBeforeEdgeRegistered(t *testing.T) {
	cfg := DefaultRouteConfig()
	cfg.Placement = &PlacementConfig{Targets: []string{"cloud", "edge"}, EdgeRequiredTenantScopes: []string{"t1", "t2"}}
	// 在范围内 → raw=edge（当前因未注册回退 cloud；注册 edge 后此处直接生效）。
	if got := cfg.placementHintFor("t1"); got != PlacementHintCloud {
		t.Fatalf("edge 未注册时应回退 cloud，got %q", got)
	}
	// 模拟端侧引擎注册后的行为：临时登记 edge 引擎（仅测试进程内）。
	registeredEngines[placementEngineEdge] = true
	defer delete(registeredEngines, placementEngineEdge)
	if got := cfg.placementHintFor("t1"); got != PlacementHintEdge {
		t.Fatalf("edge 注册后 hint 应为 edge，got %q", got)
	}
	if got := cfg.placementHintFor("t3"); got != PlacementHintAuto {
		t.Fatalf("范围外 hint 应为 auto，got %q", got)
	}
}

// TestValidatePlacementConfig 校验：非法 targets/policy/空白 scope 拒绝换入（fail-safe）。
func TestValidatePlacementConfig(t *testing.T) {
	bads := []PlacementConfig{
		{Targets: nil},
		{Targets: []string{"cloud", "far-edge"}},
		{Targets: []string{"edge"}, Policy: "cheapest"},
		{Targets: []string{"edge"}, EdgeRequiredTenantScopes: []string{"  "}},
	}
	for i, p := range bads {
		if err := validatePlacementConfig(&p); err == nil {
			t.Fatalf("负例 %d 应拒绝: %+v", i, p)
		}
	}
	if err := validatePlacementConfig(nil); err != nil {
		t.Fatalf("nil 应放行（缺省 cloud）: %v", err)
	}
	if err := validatePlacementConfig(&PlacementConfig{Targets: []string{"cloud", "edge"}, Policy: "privacy"}); err != nil {
		t.Fatalf("合法配置应放行: %v", err)
	}
}

// TestResolvePlacementExtensionPoint Resolve 第 4 返回值：未配置 → cloud；
// 配置后因 edge 未注册 → cloud（现有路由行为不受影响）；配置经热加载可插拔换入。
func TestResolvePlacementExtensionPoint(t *testing.T) {
	src := &bytesSource{data: []byte(`{"model": {"m": {"engines": ["tee_gpu"]}}, "placement": {"targets": ["cloud", "edge"], "policy": "privacy", "edge_required_tenant_scopes": ["t1"]}}`)}
	mgr, err := NewRouteConfigManager(src)
	if err != nil {
		t.Fatalf("首载带 placement 配置失败: %v", err)
	}
	cfg := mgr.Get()
	if cfg.Placement == nil {
		t.Fatal("placement 字段应解析成功（扩展点可插拔）")
	}
	engines, attest, placement, err := cfg.Resolve("t1", "m")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(engines) != 1 || engines[0] != protocol.EngineTypeTEEGPU || attest == "" {
		t.Fatalf("引擎列表语义不得因扩展点改变: engines=%v attest=%q", engines, attest)
	}
	if placement != PlacementHintCloud {
		t.Fatalf("edge 未注册时 placement 应回退 cloud，got %q", placement)
	}
	// 未配置 placement 的配置 → cloud（与现状一致）。
	cfg2, err := ParseRouteConfig([]byte(`{"model": {"m": {"engines": ["tee_gpu"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, placement2, err := cfg2.Resolve("any", "m")
	if err != nil || placement2 != PlacementHintCloud {
		t.Fatalf("未配置 placement 应恒 cloud: got %q err=%v", placement2, err)
	}
	// 非法 placement 拒绝换入，保持旧配置。
	src.set([]byte(`{"model": {"m": {"engines": ["tee_gpu"]}}, "placement": {"targets": ["mars"]}}`))
	if err := mgr.Reload(); err == nil {
		t.Fatal("非法 placement 应拒绝换入")
	}
	if mgr.Get().Placement == nil {
		t.Fatal("拒绝换入后应保持旧配置（含 placement）")
	}
}
