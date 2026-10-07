package cacheengine

import (
	"errors"
	"sync"
	"time"
)

// ErrSingleFlightTimeout 跟随者等待超过 max_wait 时返回（§6.13 B-6.13-3）：
// 调用方应据此 fail-open（自行查询/推理），绝不因等待拖死请求。
var ErrSingleFlightTimeout = errors.New("cache: singleflight wait timeout")

// SingleFlight 请求合并接口（防缓存击穿）。
type SingleFlight interface {
	// Do 执行 key 的操作，同 key 的并发请求会合并为一次。
	// shared=true 表示本调用为**跟随者**（复用 leader 结果）；leader（shared=false）执行 fn。
	// 等待超 max_wait 返回 ErrSingleFlightTimeout（shared=false）。
	Do(key string, fn func() (LookupResult, error)) (LookupResult, bool, error)

	// Len 当前活跃的分组数。
	Len() int
}

// singleflightGroup 基于 sync.WaitGroup 的请求合并实现。
type singleflightGroup struct {
	mu    sync.Mutex
	m     map[string]*sfCall
	cfg   SingleFlightConfig
}

type sfCall struct {
	done chan struct{} // leader 完成后关闭；跟随者据此读取 val/err（channel 关闭提供 happens-before）
	val  LookupResult
	err  error
}

// NewSingleFlight 构造请求合并器。
func NewSingleFlight(cfg SingleFlightConfig) SingleFlight {
	if cfg.MaxWait.D() <= 0 {
		cfg.MaxWait = Duration(3 * time.Second)
	}
	if cfg.FailurePolicy == "" {
		cfg.FailurePolicy = "independent"
	}
	return &singleflightGroup{
		m:   make(map[string]*sfCall),
		cfg: cfg,
	}
}

func (g *singleflightGroup) Do(key string, fn func() (LookupResult, error)) (LookupResult, bool, error) {
	g.mu.Lock()
	if call, ok := g.m[key]; ok {
		// 跟随者：等待 leader 完成；若超过 max_wait 则放弃等待（fail-open，§6.13 B-6.13-3）。
		g.mu.Unlock()
		timer := time.NewTimer(g.cfg.MaxWait.D())
		defer timer.Stop()
		select {
		case <-call.done:
			return call.val, true, call.err
		case <-timer.C:
			return LookupResult{}, false, ErrSingleFlightTimeout
		}
	}

	// leader：创建分组并执行
	call := &sfCall{done: make(chan struct{})}
	g.m[key] = call
	g.mu.Unlock()

	// 执行函数（val/err 写完后 close(done) 对跟随者可见）
	val, err := fn()
	call.val = val
	call.err = err
	close(call.done)

	// 清理分组
	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return val, false, err
}

func (g *singleflightGroup) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.m)
}
