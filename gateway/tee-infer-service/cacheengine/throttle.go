package cacheengine

import (
	"sync"
	"time"
)

// writeLimiterSweepInterval 惰性回收的触发间隔：每 N 次操作扫描一次空闲租户。
const writeLimiterSweepInterval = 4096

// writeLimiter 单租户写入限流（§7.4.2 写入滥用约束 / B-7.4-1）。
//
// 口径（实现约定）：
//   - 入向请求数以 **Lookup 次数**为代理（每个推理请求先查缓存）；
//   - 按**固定窗口**（cfg.Window，默认 1s）分别统计每租户的 inbound 与已放行 writes；
//   - 单窗口写入上限 = min(inbound × InboundHeadroom, MaxQPS)；
//   - 超限的写入被丢弃（仅跳过写入，不影响响应下发），由调用方记 #6 指标。
//
// 并发：Lookup 与 Store 可能来自不同 goroutine，用互斥锁保护。
// 基数：租户集合可能有界，仍惰性回收空闲租户，防伪造租户 ID 导致 map 膨胀。
type writeLimiter struct {
	cfg WriteLimitConfig

	mu      sync.Mutex
	tenants map[string]*writeWindow
	ops     int
}

// writeWindow 单租户的固定窗口计数。
type writeWindow struct {
	start    time.Time
	inbound  int
	writes   int
	lastSeen time.Time
}

func newWriteLimiter(cfg WriteLimitConfig) *writeLimiter {
	return &writeLimiter{cfg: cfg, tenants: make(map[string]*writeWindow)}
}

// recordInbound 记录一次入向请求（由 engine.Lookup 调用）。
func (l *writeLimiter) recordInbound(tenant string, now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.window(tenant, now)
	w.inbound++
	w.lastSeen = now
	l.maybeSweep(now)
}

// allowWrite 判定本次写入是否放行（由 engine.Store 调用）。
// 放行则累计一次 writes；不放行则调用方跳过写入并记 #6。
func (l *writeLimiter) allowWrite(tenant string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.window(tenant, now)
	w.lastSeen = now
	if w.writes >= l.limit(w.inbound) {
		return false
	}
	w.writes++
	l.maybeSweep(now)
	return true
}

// window 取（必要时滚动）当前窗口。
func (l *writeLimiter) window(tenant string, now time.Time) *writeWindow {
	w := l.tenants[tenant]
	if w == nil {
		w = &writeWindow{start: now}
		l.tenants[tenant] = w
		return w
	}
	if now.Sub(w.start) >= l.windowDur() {
		w.start = now
		w.inbound = 0
		w.writes = 0
	}
	return w
}

// limit 计算当前窗口的写入上限（§7.4.2：min(入向 × headroom, max_qps)）。
//
// 偏差登记：当窗口内入向=0（如预热/预置的"无 Lookup 直接 Store"）时，
// 字面公式得 0 会误伤合法写入，故此处退化为**绝对硬顶 max_qps**；
// 相对约束（×headroom）仅在存在入向时生效。
func (l *writeLimiter) limit(inbound int) int {
	if inbound <= 0 {
		return l.cfg.MaxQPS
	}
	lim := int(float64(inbound) * l.cfg.InboundHeadroom)
	if lim > l.cfg.MaxQPS {
		lim = l.cfg.MaxQPS
	}
	if lim < 0 {
		lim = 0
	}
	return lim
}

// windowDur 返回统计窗口（含防御性下限，防未校验配置）。
func (l *writeLimiter) windowDur() time.Duration {
	if d := l.cfg.Window.D(); d > 0 {
		return d
	}
	return time.Second
}

// maybeSweep 惰性回收长时间空闲的租户窗口。
func (l *writeLimiter) maybeSweep(now time.Time) {
	l.ops++
	if l.ops < writeLimiterSweepInterval {
		return
	}
	l.ops = 0
	idleTTL := l.windowDur() * 10
	for k, w := range l.tenants {
		if now.Sub(w.lastSeen) > idleTTL {
			delete(l.tenants, k)
		}
	}
}
