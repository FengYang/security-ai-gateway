package cacheengine

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// ExactStore 精确键值存储接口（升级自 model.ExactCache）。
type ExactStore interface {
	Get(key string) (*Entry, bool)
	Put(key string, e *Entry)
	Delete(key string) bool
	DeleteByTenant(tenant string) int
	DeleteByModel(model string) int
	Clear() int
	Len() int
	Evictions() uint64
}

// lruExactStore 基于 LRU + TTL 的精确缓存实现。
type lruExactStore struct {
	mu        sync.Mutex
	cap       int
	maxBytes  int
	lru       *list.List                // 前=最近使用，后=最久未用
	items     map[string]*lruExactItem // key -> item
	evictions uint64
	nowFn     nowFunc
}

type lruExactItem struct {
	entry *Entry
	elem  *list.Element
}

// NewLRUExactStore 构造 LRU 精确缓存。
func NewLRUExactStore(maxEntries, maxEntryBytes int) ExactStore {
	if maxEntries <= 0 {
		maxEntries = 8192
	}
	if maxEntryBytes <= 0 {
		maxEntryBytes = 65536
	}
	return &lruExactStore{
		cap:      maxEntries,
		maxBytes: maxEntryBytes,
		lru:      list.New(),
		items:    make(map[string]*lruExactItem, maxEntries),
		nowFn:    defaultNow,
	}
}

// Get 命中返回条目；未命中返回 (nil, false)。
func (s *lruExactStore) Get(key string) (*Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[key]
	if !ok {
		return nil, false
	}

	// TTL 检查
	if s.nowFn().UnixMilli() >= item.entry.ExpireAt {
		s.removeLocked(key, item.elem)
		return nil, false
	}

	s.lru.MoveToFront(item.elem)
	return item.entry, true
}

// Put 写入/更新条目；容量满时淘汰最久未使用。
func (s *lruExactStore) Put(key string, e *Entry) {
	if len(e.Text) > s.maxBytes {
		return // 超限不写（B-6.3-3）
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if item, ok := s.items[key]; ok {
		item.entry = e
		s.lru.MoveToFront(item.elem)
		return
	}

	item := &lruExactItem{entry: e}
	item.elem = s.lru.PushFront(key)
	s.items[key] = item

	// 淘汰最久未使用
	for len(s.items) > s.cap {
		oldest := s.lru.Back()
		if oldest == nil {
			break
		}
		s.removeLocked(oldest.Value.(string), oldest)
		atomic.AddUint64(&s.evictions, 1)
	}
}

// Delete 删除指定 key 的条目。
func (s *lruExactStore) Delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[key]
	if !ok {
		return false
	}
	s.removeLocked(key, item.elem)
	return true
}

// DeleteByTenant 按租户删除，返回受影响条目数。
func (s *lruExactStore) DeleteByTenant(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for key, item := range s.items {
		if item.entry.TenantID == tenant {
			s.lru.Remove(item.elem)
			delete(s.items, key)
			count++
		}
	}
	return count
}

// DeleteByModel 按模型删除，返回受影响条目数（§6.8.1 按模型失效）。
func (s *lruExactStore) DeleteByModel(model string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for key, item := range s.items {
		if item.entry.Model == model {
			s.lru.Remove(item.elem)
			delete(s.items, key)
			count++
		}
	}
	return count
}

// Clear 清空全部条目，返回清空前条目数（§6.8.1 全量清空）。
// 原地清空（不重建对象）：避免并发读侧对 e.exact 字段的无锁读取产生数据竞争；
// 淘汰计数归零，保持与既有"重建 store"一致的对外语义。
func (s *lruExactStore) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.items)
	s.lru.Init()
	s.items = make(map[string]*lruExactItem, s.cap)
	atomic.StoreUint64(&s.evictions, 0)
	return n
}

// Len 当前条目数。
func (s *lruExactStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Evictions 累计淘汰次数。
func (s *lruExactStore) Evictions() uint64 {
	return atomic.LoadUint64(&s.evictions)
}

// removeLocked 必须在持锁状态下调用。
func (s *lruExactStore) removeLocked(key string, elem *list.Element) {
	s.lru.Remove(elem)
	delete(s.items, key)
}

// ===== Entry 辅助函数 =====

// ComputeChecksum 计算条目的完整性校验和（sha256 of 规范化文本）。
func ComputeChecksum(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}

// ComputeEntryID 从 tenantID + keyHash 计算条目 ID。
func ComputeEntryID(tenantID, keyHash string) string {
	h := sha256.Sum256([]byte(tenantID + "\x1f" + keyHash))
	return hex.EncodeToString(h[:])[:16]
}

// EntryUsable 校验条目是否可用（TTL / PolicyVer / GuardVer）。
func EntryUsable(e *Entry, guardVer, policyVer string, now time.Time) bool {
	if now.UnixMilli() >= e.ExpireAt {
		return false
	}
	if e.PolicyVer != policyVer {
		return false
	}
	if e.GuardVer != guardVer {
		return false
	}
	return true
}
