package cacheengine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ===== 写入限流专项用例（§7.4.2 / B-7.4-1 / §9.1 #6 / 配置校验规则 26） =====

// throttleTestCfg 构造启用写入限流的测试配置（其余沿用 testConfig 的低阈值）。
func throttleTestCfg(maxQPS int, headroom float64, window time.Duration) CacheConfig {
	cfg := testConfig() // testConfig 已关闭 WriteLimit，这里显式开启
	cfg.Mode = ModeExact
	cfg.WriteLimit = WriteLimitConfig{
		Enabled:         true,
		MaxQPS:          maxQPS,
		InboundHeadroom: headroom,
		Window:          Duration(window),
	}
	return cfg
}

func throttleStoreCtx(tenant, hash string) StoreContext {
	return StoreContext{
		LookupContext: LookupContext{
			TenantID: tenant, EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
			TransformedHash: hash, PromptText: "long enough prompt for throttle test",
			PolicyVer: "1", GuardVer: "v1",
		},
		Writable: true,
	}
}

func throttleLookupCtx(tenant, hash string) LookupContext {
	return throttleStoreCtx(tenant, hash).LookupContext
}

func throttleRes() InferResult {
	return InferResult{Text: "answer", TokensOut: 10, Finish: "stop"}
}

// freezeNow 注入可控时钟（Unix 毫秒），返回推进函数。
func freezeNow(eng CacheEngine, startMs int64) func(d time.Duration) {
	nowMs := startMs
	SetNow(eng, func() int64 { return nowMs })
	return func(d time.Duration) { nowMs += int64(d / time.Millisecond) }
}

// TestWriteThrottle_LimitAndDrop §7.4.2：上限 = min(入向×headroom, max_qps)；超限丢弃且不影响响应。
func TestWriteThrottle_LimitAndDrop(t *testing.T) {
	eng := NewCacheEngine(throttleTestCfg(100, 1.2, time.Second)).(*engine)
	freezeNow(eng, 1_700_000_000_000)

	// 入向 = 5 → 上限 = min(5×1.2, 100) = 6
	const inbound = 5
	for i := 0; i < inbound; i++ {
		eng.Lookup(throttleLookupCtx("t1", fmt.Sprintf("lk-%d", i)))
	}
	for i := 0; i < 6; i++ {
		if out := eng.Store(throttleStoreCtx("t1", fmt.Sprintf("k-%d", i)), throttleRes()); !out.Stored {
			t.Fatalf("write %d 应放行，实际 %+v", i, out)
		}
	}
	out := eng.Store(throttleStoreCtx("t1", "k-over"), throttleRes())
	if out.Stored || out.Skipped != "throttled" {
		t.Fatalf("第 7 次写入应被限流丢弃，实际 %+v", out)
	}
	if got := eng.stats.writeThrottledSnapshot()["t1"]; got != 1 {
		t.Fatalf("write_throttled{t1} = %d, want 1", got)
	}
	// 限流不影响读路径：已写条目仍可正常命中
	if r := eng.Lookup(throttleLookupCtx("t1", "k-0")); !r.Hit {
		t.Fatalf("限流不应影响读路径：已写条目 k-0 应命中，实际 %+v", r)
	}
}

// TestWriteThrottle_NoInboundHardCap §7.4.2 偏差：无入向（预热/预置写）时退化为绝对硬顶。
func TestWriteThrottle_NoInboundHardCap(t *testing.T) {
	eng := NewCacheEngine(throttleTestCfg(3, 1.2, time.Second)).(*engine)
	freezeNow(eng, 1_700_000_000_000)

	for i := 0; i < 3; i++ {
		if out := eng.Store(throttleStoreCtx("t1", fmt.Sprintf("k-%d", i)), throttleRes()); !out.Stored {
			t.Fatalf("无入向时前 3 次应放行（硬顶），实际 %+v", out)
		}
	}
	out := eng.Store(throttleStoreCtx("t1", "k-over"), throttleRes())
	if out.Stored || out.Skipped != "throttled" {
		t.Fatalf("超过硬顶应被限流，实际 %+v", out)
	}
}

// TestWriteThrottle_TenantIsolation §7.4.2：单租户超限不影响其他租户。
func TestWriteThrottle_TenantIsolation(t *testing.T) {
	eng := NewCacheEngine(throttleTestCfg(2, 1.2, time.Second)).(*engine)
	freezeNow(eng, 1_700_000_000_000)

	for i := 0; i < 2; i++ {
		eng.Store(throttleStoreCtx("t1", fmt.Sprintf("k-%d", i)), throttleRes())
	}
	if out := eng.Store(throttleStoreCtx("t1", "k-over"), throttleRes()); out.Skipped != "throttled" {
		t.Fatalf("t1 超限应被限流，实际 %+v", out)
	}
	if out := eng.Store(throttleStoreCtx("t2", "k-0"), throttleRes()); !out.Stored {
		t.Fatalf("t2 不应受 t1 超限影响，实际 %+v", out)
	}
}

// TestWriteThrottle_WindowRollover §7.4.2：窗口滑动后计数复位、恢复写入。
func TestWriteThrottle_WindowRollover(t *testing.T) {
	eng := NewCacheEngine(throttleTestCfg(2, 1.2, time.Second)).(*engine)
	advance := freezeNow(eng, 1_700_000_000_000)

	for i := 0; i < 2; i++ {
		eng.Store(throttleStoreCtx("t1", fmt.Sprintf("k-%d", i)), throttleRes())
	}
	if out := eng.Store(throttleStoreCtx("t1", "k-over"), throttleRes()); out.Skipped != "throttled" {
		t.Fatalf("本窗口超限应被限流，实际 %+v", out)
	}
	advance(time.Second) // 跨窗口
	if out := eng.Store(throttleStoreCtx("t1", "k-next"), throttleRes()); !out.Stored {
		t.Fatalf("新窗口应恢复写入，实际 %+v", out)
	}
}

// TestWriteThrottle_ModeOffDisabled §9.3：mode=off 时不创建限流器（零行为变化）。
func TestWriteThrottle_ModeOffDisabled(t *testing.T) {
	cfg := throttleTestCfg(2, 1.2, time.Second)
	cfg.Mode = ModeOff
	eng := NewCacheEngine(cfg).(*engine)
	if eng.limiter != nil {
		t.Fatal("mode=off 不应创建限流器")
	}
	out := eng.Store(throttleStoreCtx("t1", "k-0"), throttleRes())
	if out.Skipped != "disabled" { // off 路径的既有语义，而非 throttled
		t.Fatalf("mode=off 应走 disabled 路径，实际 %+v", out)
	}
	var buf bytes.Buffer
	eng.RenderPrometheus(&buf)
	if strings.Contains(buf.String(), "otpmask_cache_write_throttled_total") {
		t.Fatal("mode=off 且无事件时不应渲染 #6")
	}
}

// TestWriteThrottle_MetricRendered §9.1 #6：限流事件渲染为 write_throttled_total{tenant}。
func TestWriteThrottle_MetricRendered(t *testing.T) {
	eng := NewCacheEngine(throttleTestCfg(1, 1.2, time.Second)).(*engine)
	freezeNow(eng, 1_700_000_000_000)

	eng.Store(throttleStoreCtx("t1", "k-0"), throttleRes()) // 放行
	eng.Store(throttleStoreCtx("t1", "k-1"), throttleRes()) // 限流

	var buf bytes.Buffer
	eng.RenderPrometheus(&buf)
	want := `otpmask_cache_write_throttled_total{tenant="t1"} 1`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("缺少指标 %s\n%s", want, buf.String())
	}
}

// TestWriteThrottle_CardinalityCap §9.1 基数控制：租户数超上限后并入 __other__。
func TestWriteThrottle_CardinalityCap(t *testing.T) {
	sc := newStatsCollector()
	const overflow = 5
	for i := 0; i < writeThrottledMaxTenants+overflow; i++ {
		sc.observeWriteThrottled(fmt.Sprintf("t%d", i))
	}
	snap := sc.writeThrottledSnapshot()
	if snap["__other__"] != overflow {
		t.Fatalf("__other__ = %d, want %d", snap["__other__"], overflow)
	}
	if len(snap) != writeThrottledMaxTenants+1 {
		t.Fatalf("租户基数 = %d, want %d", len(snap), writeThrottledMaxTenants+1)
	}
}

// TestWriteThrottle_IdleTenantSweep 惰性回收：空闲超过 10×window 的租户被清理（防基数膨胀）。
func TestWriteThrottle_IdleTenantSweep(t *testing.T) {
	l := newWriteLimiter(WriteLimitConfig{Enabled: true, MaxQPS: 10, InboundHeadroom: 1.2, Window: Duration(time.Second)})
	now := time.UnixMilli(1_700_000_000_000)

	l.recordInbound("idle", now) // 建一个随后变空闲的租户

	later := now.Add(20 * time.Second) // > idleTTL(10×1s)
	for i := 0; i < writeLimiterSweepInterval; i++ {
		l.recordInbound("active", later) // 触发一次扫描
	}
	if _, ok := l.tenants["idle"]; ok {
		t.Fatal("空闲租户应被回收")
	}
	if _, ok := l.tenants["active"]; !ok {
		t.Fatal("活跃租户不应被回收")
	}
}

// TestWriteThrottle_WindowDurFallback 未校验配置（window<=0）时窗口兜底为 1s。
func TestWriteThrottle_WindowDurFallback(t *testing.T) {
	l := newWriteLimiter(WriteLimitConfig{Enabled: true, MaxQPS: 10, InboundHeadroom: 1.2})
	if got := l.windowDur(); got != time.Second {
		t.Fatalf("windowDur = %v, want 1s", got)
	}
}

// TestWriteLimit_ConfigValidationRule26 §4.2.1 规则 26：写入限流配置区间校验。
func TestWriteLimit_ConfigValidationRule26(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*CacheConfig)
		wantErr bool
	}{
		{"max_qps 越界", func(c *CacheConfig) { c.WriteLimit.MaxQPS = 0 }, true},
		{"headroom 过小", func(c *CacheConfig) { c.WriteLimit.InboundHeadroom = 0.5 }, true},
		{"headroom 过大", func(c *CacheConfig) { c.WriteLimit.InboundHeadroom = 11 }, true},
		{"window 过小", func(c *CacheConfig) { c.WriteLimit.Window = Duration(10 * time.Millisecond) }, true},
		{"window 过大", func(c *CacheConfig) { c.WriteLimit.Window = Duration(2 * time.Minute) }, true},
		{"默认值合法", func(c *CacheConfig) {}, false},
		{"禁用时忽略非法值", func(c *CacheConfig) {
			c.WriteLimit.Enabled = false
			c.WriteLimit.MaxQPS = 0
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.WriteLimit.Enabled = true
			tc.mutate(&cfg)
			var got bool
			for _, err := range cfg.Validate() {
				if strings.Contains(err.Error(), "rule 26") {
					got = true
				}
			}
			if got != tc.wantErr {
				t.Fatalf("rule 26 命中 = %v, want %v（errs=%v）", got, tc.wantErr, cfg.Validate())
			}
		})
	}
}
