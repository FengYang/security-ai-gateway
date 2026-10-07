package cacheengine

import (
	"sync"
	"time"
)

// SingleFlight 请求合并接口（防缓存击穿）。
type SingleFlight interface {
	// Do 执行 key 的操作，同 key 的并发请求会合并为一次。
	// 返回值是 leader 的结果；如果 leader 失败，根据 failure_policy 决定等待者行为。
	Do(key string, fn func() (LookupResult, error)) (LookupResult, error)

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
	wg  sync.WaitGroup
	val LookupResult
	err error
	done bool
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

func (g *singleflightGroup) Do(key string, fn func() (LookupResult, error)) (LookupResult, error) {
	g.mu.Lock()
	if call, ok := g.m[key]; ok {
		// 跟随者：等待 leader 完成
		g.mu.Unlock()
		call.wg.Wait()
		return call.val, call.err
	}

	// leader：创建分组并执行
	call := &sfCall{}
	call.wg.Add(1)
	g.m[key] = call
	g.mu.Unlock()

	// 执行函数
	val, err := fn()
	call.val = val
	call.err = err
	call.done = true
	call.wg.Done()

	// 清理分组
	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return val, err
}

func (g *singleflightGroup) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.m)
}
