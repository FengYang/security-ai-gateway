// routectl_test.go — M4-1/M4-2 单测（校验失败不换入 / 原子性 / 热加载 / 内容去重 / 防抖）。
package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
