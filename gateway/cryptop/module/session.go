package cryptopmodule

// session.go —— 会话池（B-6.1-7 / GM2-05）。
//
// 语义（§6.4 配置项）：
//   - 池大小 = module_max_sessions；池满时新请求按 module_session_queue_size
//     排队等待，超排队上限失败（计入 cryptop_call_timeout_total）；
//   - 多 Pod 场景采用静态配额分配（由部署侧按 Pod 数划分 module_max_sessions），
//     避免分布式资源竞争；
//   - Close 关闭池并销毁空闲会话；在途会话经 Release 路径关闭（fail-closed）。

import (
	"sync"
)

// SessionPool 会话池（线程安全；factory/closer 由后端注入）。
type SessionPool struct {
	mu      sync.Mutex
	cond    *sync.Cond
	max     int
	queue   int
	idle    []Session
	inUse   int
	waiters int
	closed  bool
	seq     uintptr

	factory func() (Session, error)
	closer  func(Session) error
}

// NewSessionPool 构造会话池（max=池大小，queue=排队深度；factory/closer 必填）。
func NewSessionPool(max, queue int, factory func() (Session, error), closer func(Session) error) (*SessionPool, error) {
	if max <= 0 {
		return nil, ErrModuleUnavailable // 复用稳定错误语义：配置非法由调用方前置校验
	}
	if queue < 0 {
		return nil, ErrModuleUnavailable
	}
	if factory == nil || closer == nil {
		return nil, ErrModuleUnavailable
	}
	p := &SessionPool{max: max, queue: queue, factory: factory, closer: closer}
	p.cond = sync.NewCond(&p.mu)
	return p, nil
}

// Acquire 获取会话：优先复用空闲会话；未满则新建；已满则排队（超 queue 失败）。
func (p *SessionPool) Acquire() (Session, error) {
	p.mu.Lock()
	for {
		if p.closed {
			p.mu.Unlock()
			return 0, ErrModuleUnavailable
		}
		if n := len(p.idle); n > 0 {
			s := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.inUse++
			p.mu.Unlock()
			return s, nil
		}
		if p.inUse < p.max {
			p.inUse++ // 先占位，锁外创建（避免持锁执行可能阻塞的厂商调用）
			p.mu.Unlock()
			s, err := p.factory()
			if err != nil {
				p.mu.Lock()
				p.inUse--
				p.cond.Signal() // 让位给排队者重试
				p.mu.Unlock()
				return 0, err
			}
			return s, nil
		}
		if p.waiters >= p.queue {
			p.mu.Unlock()
			return 0, ErrSessionExhausted
		}
		p.waiters++
		p.cond.Wait()
		p.waiters--
	}
}

// Release 归还会话到池（池已关则直接关闭该会话）。
func (p *SessionPool) Release(s Session) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return p.closer(s)
	}
	p.inUse--
	p.idle = append(p.idle, s)
	p.cond.Signal()
	p.mu.Unlock()
	return nil
}

// Stats 池状态（测试与指标用）。
type PoolStats struct {
	Max     int
	Queue   int
	Idle    int
	InUse   int
	Waiters int
	Closed  bool
}

// Stats 返回当前池状态快照。
func (p *SessionPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStats{Max: p.max, Queue: p.queue, Idle: len(p.idle), InUse: p.inUse, Waiters: p.waiters, Closed: p.closed}
}

// Close 关闭池：广播唤醒所有排队者（后续 Acquire 失败），销毁空闲会话。
// 在途会话不强制销毁，由各自 Release 路径关闭。
func (p *SessionPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.cond.Broadcast()
	p.mu.Unlock()
	var firstErr error
	for _, s := range idle {
		if err := p.closer(s); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
