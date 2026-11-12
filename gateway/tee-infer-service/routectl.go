// routectl.go — 路由配置外置化 + 热加载（M4-1/M4-2，设计依据《网关侧缺口整改·技术实现方案》§3）。
//
// 职责：
//   - M4-1：把 DefaultRouteConfig() 硬编码外置为 JSON 配置文件（沿用 ParseRouteConfig 现有
//     JSON 契约，字段 tenant/model/default_engine/require_quote/policy/costs 100% 兼容）；
//   - M4-2：运行时热加载——文件变更（poll 轮询 stat）或 SIGHUP 触发重读 → 校验 →
//     原子换入（atomic.Pointer），进行中请求用旧配置；非法配置拒绝换入并保持旧配置（fail-safe）。
//
// 生效语义：换入瞬时生效于**新请求**（Resolve/ValidateRequest/OrderedEngines 每次经 Get() 取当前配置）。
//
// 实现选型偏差登记（技术方案 §3.4 允许的零依赖备选）：
//
//	热加载通知采用「poll 轮询（默认 2s，远小于 5s 生效红线）+ SIGHUP 兜底」而非 fsnotify——
//	① K8s ConfigMap 以符号链接换目录挂载，fsnotify 监听在该场景失效（技术方案 §3.5 风险表自记），
//	poll 同时覆盖常规文件与 ConfigMap 两场景；② 零新增第三方依赖（fsnotify 为 BSD-3 但需引新模块）。
//
// 安装期参数（参数名·默认值·覆写点·未填行为）：
//   - ROUTE_CONFIG_PATH·空·env·未填=内置 DefaultRouteConfig（现状行为，不启用外置）；
//   - ROUTE_CONFIG_RELOAD·poll·env·off|sighup|poll|poll+sighup·未填=poll（含 SIGHUP）；
//   - ROUTE_CONFIG_POLL_INTERVAL·2s·env·未填=默认值（go duration 格式，≤0 取默认）；
//   - ROUTE_CONFIG_SIG_REF·空·env·未填=不做签名校验（仅校验和审计；二期接入）。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"security-ai-gateway/protocol/go"
)

// ---------- M4-1：配置源抽象 ----------

// RouteConfigSource 路由配置字节源抽象（技术方案 §3.2 接口冻结基线）。
type RouteConfigSource interface {
	// Load 读配置字节。
	Load() ([]byte, error)
}

// fileRouteConfigSource 本地文件配置源。
type fileRouteConfigSource struct{ path string }

// NewFileRouteConfigSource 构造文件配置源。
func NewFileRouteConfigSource(path string) RouteConfigSource {
	return &fileRouteConfigSource{path: path}
}

func (s *fileRouteConfigSource) Load() ([]byte, error) {
	return os.ReadFile(s.path)
}

func (s *fileRouteConfigSource) String() string { return s.path }

// ---------- M4-1：配置校验（技术方案 §3.1 判据 4：配置完整性校验） ----------

// registeredEngines 已注册引擎集合（与 protocol 常量对齐；新增引擎须同步登记）。
var registeredEngines = map[string]bool{
	protocol.EngineTypeTEEGPU:       true,
	protocol.EngineTypeMaskedVector: true,
	protocol.EngineTypeCMAAS:        true,
}

// validateRouteConfig 配置完整性校验：
//   - default_engine ∈ 已注册引擎集合（空 = 由 defaultRoute() 回落 tee_gpu，允许）；
//   - policy ∈ {"" , cost, latency, quality}（未知策略旧代码保守不重排，但外置配置应当显式拒绝，
//     防止拼写错误造成「看似生效实则静默忽略」）；
//   - 每模型 engines 非空且全部 ∈ 已注册引擎集合；
//   - costs 引用引擎 ∈ 该模型 engines；costs 数值非负；
//   - 租户 engine（若填）∈ 已注册引擎集合；attest（若填）∈ {quote, token}。
//
// 校验失败不换入（fail-safe，保持旧配置运行）。
func validateRouteConfig(c *RouteConfig) error {
	if c == nil {
		return fmt.Errorf("routectl: 配置为空")
	}
	if c.DefaultEngine != "" && !registeredEngines[c.DefaultEngine] {
		return fmt.Errorf("routectl: default_engine %q 不在已注册引擎集合中", c.DefaultEngine)
	}
	switch c.Policy {
	case "", "cost", "latency", "quality":
	default:
		return fmt.Errorf("routectl: 未知 policy %q（允许：cost/latency/quality）", c.Policy)
	}
	for name, mr := range c.Model {
		if len(mr.Engines) == 0 {
			return fmt.Errorf("routectl: 模型 %q engines 为空", name)
		}
		inModel := map[string]bool{}
		for _, e := range mr.Engines {
			if !registeredEngines[e] {
				return fmt.Errorf("routectl: 模型 %q 引擎 %q 不在已注册引擎集合中", name, e)
			}
			inModel[e] = true
		}
		for i, ec := range mr.Costs {
			if !inModel[ec.Engine] {
				return fmt.Errorf("routectl: 模型 %q costs[%d] 引擎 %q 不在 engines %v 中", name, i, ec.Engine, mr.Engines)
			}
			if ec.PricePer1K < 0 || ec.LatencyP50 < 0 || ec.Quality < 0 {
				return fmt.Errorf("routectl: 模型 %q costs[%d] 存在负值", name, i)
			}
		}
	}
	for t, tr := range c.Tenant {
		if tr.Engine != "" && !registeredEngines[tr.Engine] {
			return fmt.Errorf("routectl: 租户 %q 引擎 %q 不在已注册引擎集合中", t, tr.Engine)
		}
		if tr.Attest != "" && tr.Attest != protocol.AttestTypeQuote && tr.Attest != protocol.AttestTypeToken {
			return fmt.Errorf("routectl: 租户 %q attest %q 非法", t, tr.Attest)
		}
	}
	return nil
}

// routeConfigVersion 计算配置版本（内容 sha256 前 12 hex）。
func routeConfigVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// ---------- M4-2：RouteConfigManager（热加载 + 原子换入） ----------

// RouteConfigManager 路由配置管理器（技术方案 §3.2 接口冻结基线）。
type RouteConfigManager struct {
	src RouteConfigSource

	cur atomic.Pointer[RouteConfig]
	ver atomic.Value // string

	reloadMu sync.Mutex // Reload 串行化（poll 与 SIGHUP 并发触发防抖后仍可能并发）
	lastData []byte     // 上次成功换入的原始字节（内容级去重：文件 mtime 变化但内容未变时不重换入）

	// OnReload 换入/拒绝回调（可选；技术方案 §3.1 判据 5：每次换入（含拒绝）落审计事件）。
	// 参数：version（成功时为新版本；失败时为旧版本）、err（nil=换入成功）。
	// 由装配方注入；nil 安全跳过。
	OnReload func(version string, err error)
}

// NewRouteConfigManager 构造并首载配置（技术方案 §3.2：首载失败 fail-closed 拒启动）。
func NewRouteConfigManager(src RouteConfigSource) (*RouteConfigManager, error) {
	m := &RouteConfigManager{src: src}
	data, err := src.Load()
	if err != nil {
		return nil, fmt.Errorf("routectl: 读取路由配置失败: %w", err)
	}
	if err := m.swap(data); err != nil {
		return nil, fmt.Errorf("routectl: 首载路由配置被拒（fail-closed）: %w", err)
	}
	return m, nil
}

// swap 解析 → 校验 → 原子换入。调用方须持 reloadMu（NewRouteConfigManager 首载除外）。
func (m *RouteConfigManager) swap(data []byte) error {
	cfg, err := ParseRouteConfig(data)
	if err != nil {
		return fmt.Errorf("routectl: 解析失败: %w", err)
	}
	if err := validateRouteConfig(cfg); err != nil {
		return err
	}
	m.cur.Store(cfg)
	m.ver.Store(routeConfigVersion(data))
	m.lastData = append([]byte(nil), data...)
	return nil
}

// Get 返回当前配置（无锁读；热换入对新请求瞬时生效）。
func (m *RouteConfigManager) Get() *RouteConfig { return m.cur.Load() }

// Version 返回当前配置版本（内容 sha256 前 12 hex）。
func (m *RouteConfigManager) Version() string {
	if v, ok := m.ver.Load().(string); ok {
		return v
	}
	return ""
}

// Reload 重读 → 校验 → 原子换入；失败保持旧配置并返回 err（fail-safe）。
func (m *RouteConfigManager) Reload() error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	data, err := m.src.Load()
	if err != nil {
		log.Printf("[routectl] 配置重读失败（保持旧配置 version=%s）: %v", m.Version(), err)
		m.notify(m.Version(), err)
		return err
	}
	// 内容级去重：内容未变不重换入（mtime/事件触发但内容一致的幂等场景）。
	if m.lastData != nil && string(data) == string(m.lastData) {
		return nil
	}
	if err := m.swap(data); err != nil {
		log.Printf("[routectl] 配置换入被拒（保持旧配置 version=%s）: %v", m.Version(), err)
		m.notify(m.Version(), err)
		return err
	}
	log.Printf("[routectl] 路由配置已热换入 version=%s", m.Version())
	m.notify(m.Version(), nil)
	return nil
}

func (m *RouteConfigManager) notify(version string, err error) {
	if m.OnReload != nil {
		m.OnReload(version, err)
	}
}

// StartWatch 启动热加载监听（poll 轮询 + SIGHUP，按 ROUTE_CONFIG_RELOAD 装配）。
// 返回 stop 函数（幂等）；watcher 事件防抖 300ms。
func (m *RouteConfigManager) StartWatch(mode string, interval time.Duration) (stop func()) {
	if mode == "off" || m.src == nil {
		return func() {}
	}
	path := ""
	if fs, ok := m.src.(*fileRouteConfigSource); ok {
		path = fs.path
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	stopped := make(chan struct{})
	var closeOnce sync.Once
	stopFn := func() { closeOnce.Do(func() { close(stopped) }) }

	var lastSize int64
	var lastMod int64
	if fi, err := os.Stat(path); err == nil {
		lastSize = fi.Size()
		lastMod = fi.ModTime().UnixNano()
	}

	sigCh := make(chan os.Signal, 1)
	if mode == "sighup" || mode == "poll+sighup" || mode == "" {
		signal.Notify(sigCh, syscall.SIGHUP)
	}

	go func() {
		defer func() {
			if mode == "sighup" || mode == "poll+sighup" || mode == "" {
				signal.Stop(sigCh)
			}
		}()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		// 防抖（单 goroutine 状态机，无跨 goroutine 共享字段——300ms 内多次事件合并为一次 Reload）：
		// pending=事件待处理；debounceC=防抖到期信号（nil=无计时中）。
		var pending bool
		var debounceC <-chan time.Time
		fire := func() {
			if debounceC == nil {
				debounceC = time.After(300 * time.Millisecond)
			}
		}
		for {
			select {
			case <-stopped:
				return
			case <-sigCh:
				pending = true
			case <-debounceC:
				debounceC = nil
				_ = m.Reload()
			case <-tick.C:
				if path != "" {
					if fi, err := os.Stat(path); err == nil {
						if fi.Size() != lastSize || fi.ModTime().UnixNano() != lastMod {
							lastSize = fi.Size()
							lastMod = fi.ModTime().UnixNano()
							pending = true
						}
					}
				}
			}
			if pending {
				pending = false
				fire()
			}
		}
	}()
	return stopFn
}

// routeReloadModeFromEnv 解析 ROUTE_CONFIG_RELOAD（off|sighup|poll|poll+sighup；默认 poll+sighup 口径）。
func routeReloadModeFromEnv() string {
	switch os.Getenv("ROUTE_CONFIG_RELOAD") {
	case "off", "sighup", "poll":
		return os.Getenv("ROUTE_CONFIG_RELOAD")
	default:
		return "poll+sighup"
	}
}

// routePollIntervalFromEnv 解析 ROUTE_CONFIG_POLL_INTERVAL（≤0/非法取默认 2s）。
func routePollIntervalFromEnv() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ROUTE_CONFIG_POLL_INTERVAL")); err == nil && d > 0 {
		return d
	}
	return 2 * time.Second
}

// ---------- teeServer 接线（技术方案 §3.3：调用点经 Manager 获取） ----------

// routeCfg 返回当前生效的路由配置：外置管理器优先（热换入对新请求瞬时生效），
// 未启用外置时回落启动期 route 字段（DefaultRouteConfig 或首载文件）。
func (s *teeServer) routeCfg() *RouteConfig {
	if s.routeMgr != nil {
		if c := s.routeMgr.Get(); c != nil {
			return c
		}
	}
	return s.route
}
