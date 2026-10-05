// Package cryptoclient —— 插件侧 cryptop sidecar 客户端（P0-4 §4.5/§4.7）。
//
// 位置说明（对齐 §5.4.5）：本包是**传输无关**的客户端核心，**不 import** proxy-wasm
// hostcall，故可原生单测（§4.7 line-577 "或经接口抽象以便单测 mock"）。插件侧（package
// main）提供 `Transport` 的 wrapper 实现，把 `proxywasm.DispatchHttpCall` 接进来。
//
// 语义契约（与设计逐条对齐）：
//   - C-4：sidecar 不可达/超时/返回错误 ⇒ **fail-closed**，绝不回退插件内运算；
//   - R-3：单次调用超时 50ms；超时 = fail-closed；
//   - R-4：连续 5 次失败 → 熔断 30s；熔断期直接 fail-closed，不打 sidecar（`Breaker`）；
//   - R-10：**不重试**（密码运算非幂等）；
//   - §4.4：错误码映射；`verify_failed` = HTTP 200 `{ok:false}`（**非**错误）。
package cryptoclient

import (
	"sync"
	"time"
)

// 熔断器状态（closed→open(cooldown)→half-open→closed）。
const (
	stateClosed int8 = iota
	stateOpen
	stateHalfOpen
)

// R-4 默认参数：连续 5 次失败 → 熔断 30s。
const (
	DefaultThreshold = 5
	DefaultCooldown  = 30 * time.Second
)

// Breaker 插件侧线路熔断（§4.5-⑨ / R-4）。
//
// 复用既有 route_fetch 熔断模式；状态机 closed→open(cooldown)→half-open→closed。
// `OnStateChange` 是**指标 #5 `cryptop_circuit_open` 的唯一生产者**（gauge 0/1）。
type Breaker struct {
	threshold int
	cooldown  time.Duration
	now       func() time.Time // 注入时钟（单测确定性）

	mu       sync.Mutex
	fails    int
	state    int8
	openedAt time.Time
	onChange func(open bool)
}

// NewBreaker 构造熔断器；threshold ≤ 0 取默认 5，cooldown ≤ 0 取默认 30s。
func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	if cooldown <= 0 {
		cooldown = DefaultCooldown
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

// OnStateChange 注册状态变更回调（指标 #5 生产点）；回调在锁内触发，参数 open=true 表示熔断开启。
// 回调须为轻量、非重入（仅 set gauge 0/1），不得回调本 Breaker。
func (b *Breaker) OnStateChange(fn func(open bool)) {
	b.mu.Lock()
	b.onChange = fn
	b.mu.Unlock()
}

// Allow 是否放行本次调用。open 期返回 false ⇒ 直接 fail-closed，不打 sidecar；
// open 期满 cooldown 后转 half-open 放行一次探测。
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case stateOpen:
		if b.now().Sub(b.openedAt) >= b.cooldown {
			b.setStateLocked(stateHalfOpen)
			return true
		}
		return false
	case stateHalfOpen:
		return true // 单线程事件循环下一个探测
	default: // closed
		return true
	}
}

// OnResult 上报调用结果：成功复位；连续失败达阈值 → open；half-open 失败 → 重新 open。
func (b *Breaker) OnResult(ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.fails = 0
		if b.state != stateClosed {
			b.setStateLocked(stateClosed)
		}
		return
	}
	b.fails++
	switch b.state {
	case stateHalfOpen:
		b.openedAt = b.now()
		b.setStateLocked(stateOpen) // 探测失败 → 重新熔断
	default:
		if b.fails >= b.threshold {
			b.openedAt = b.now()
			b.setStateLocked(stateOpen)
		}
	}
}

// setStateLocked 变更状态并在 `open` 布尔位翻转时触发回调（调用方持锁）。
func (b *Breaker) setStateLocked(next int8) {
	if b.state == next {
		return
	}
	wasOpen := b.state == stateOpen
	b.state = next
	isOpen := next == stateOpen
	if wasOpen != isOpen && b.onChange != nil {
		b.onChange(isOpen)
	}
}

// IsOpen 当前是否处于熔断（供指标/日志观测）。
func (b *Breaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state == stateOpen
}
