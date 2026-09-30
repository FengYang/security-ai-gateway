package cacheengine

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// NegativeStore 负向缓存接口。
// 键为输入侧哈希，值与响应内容无关。
type NegativeStore interface {
	Get(key string) (*NegativePayload, bool)
	Put(key string, p *NegativePayload, ttl time.Duration)
	Delete(key string) bool
	DeleteByTenant(tenant string) int
	Len() int
	Enabled() bool
}

// lruNegativeStore LRU 负向缓存实现。
type lruNegativeStore struct {
	mu        sync.Mutex
	cap       int
	lru       *list.List
	items     map[string]*negItem
	evictions uint64
	nowFn     nowFunc
}

type negItem struct {
	payload  *NegativePayload
	tenantID string // 用于按租户删除
	expireAt int64
	elem     *list.Element
}

// NewLRUNegativeStore 构造 LRU 负向缓存。
func NewLRUNegativeStore(maxEntries int) NegativeStore {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &lruNegativeStore{
		cap:   maxEntries,
		lru:   list.New(),
		items: make(map[string]*negItem, maxEntries),
		nowFn: defaultNow,
	}
}

// Enabled 负向缓存是否启用。
func (s *lruNegativeStore) Enabled() bool {
	return s != nil && s.cap > 0
}

// Get 获取负向缓存条目。
func (s *lruNegativeStore) Get(key string) (*NegativePayload, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[key]
	if !ok {
		return nil, false
	}

	// TTL 检查
	if s.nowFn().UnixMilli() >= item.expireAt {
		s.removeLocked(key, item.elem)
		return nil, false
	}

	s.lru.MoveToFront(item.elem)
	return item.payload, true
}

// Put 写入负向缓存。
func (s *lruNegativeStore) Put(key string, p *NegativePayload, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expireAt := s.nowFn().UnixMilli() + ttl.Milliseconds()

	if item, ok := s.items[key]; ok {
		item.payload = p
		item.expireAt = expireAt
		s.lru.MoveToFront(item.elem)
		return
	}

	item := &negItem{
		payload:  p,
		expireAt: expireAt,
	}
	item.elem = s.lru.PushFront(key)
	s.items[key] = item

	// 淘汰
	for len(s.items) > s.cap {
		oldest := s.lru.Back()
		if oldest == nil {
			break
		}
		s.removeLocked(oldest.Value.(string), oldest)
		atomic.AddUint64(&s.evictions, 1)
	}
}

// Delete 删除指定 key。
func (s *lruNegativeStore) Delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[key]
	if !ok {
		return false
	}
	s.removeLocked(key, item.elem)
	return true
}

// DeleteByTenant 按租户删除。
// 注意：负向缓存的 key 是 hash，无法直接从 key 提取 tenant。
// 一期实现：由于 NegativePayload 不含 tenant，且 key 是 hash，
// 我们无法高效按租户删除。返回 0。
// 二期接 Redis 后用 SCAN + meta 实现。
func (s *lruNegativeStore) DeleteByTenant(tenant string) int {
	return 0
}

// Len 当前条目数。
func (s *lruNegativeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// removeLocked 必须在持锁状态下调用。
func (s *lruNegativeStore) removeLocked(key string, elem *list.Element) {
	s.lru.Remove(elem)
	delete(s.items, key)
}
