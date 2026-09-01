// Package model — 精确命中缓存（GF.4.1 演示实现，非语义缓存）。
//
// 定位：真机语义缓存到位前的"接线占位"——用 LRU + 精确键匹配验证缓存控制流
// （查询→命中回放 / 未命中回填→容量淘汰），不声称具备语义相似命中能力。
// 真机到位后替换为基于 embedding 相似度的 SemanticCache 实现（接口不变）。
//
// 键由调用方（tee-infer 主链）以"租户+引擎+模型+参数+transformed_hash"的哈希构造，
// 保证租户隔离与参数隔离；缓存值仅为明文域内的生成文本，随进程内存存活、不落盘。
package model

import (
	"container/list"
	"sync"
)

// ExactCache 精确命中缓存（LRU，线程安全）。
type ExactCache struct {
	mu    sync.Mutex
	cap   int
	lru   *list.List // 前 = 最近使用，后 = 最久未使用
	items map[string]*exactEntry
}

type exactEntry struct {
	text string
	elem *list.Element
}

// ensure *ExactCache implements SemanticCache。
var _ SemanticCache = (*ExactCache)(nil)

// NewExactCache 构造容量为 capacity 的精确缓存；capacity<=0 时取默认 1024。
func NewExactCache(capacity int) *ExactCache {
	if capacity <= 0 {
		capacity = 1024
	}
	return &ExactCache{
		cap:   capacity,
		lru:   list.New(),
		items: make(map[string]*exactEntry),
	}
}

// Get 命中返回缓存文本；未命中返回 ( "", false )。
func (c *ExactCache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return "", false
	}
	c.lru.MoveToFront(e.elem)
	return e.text, true
}

// Put 写入/更新条目；容量满时淘汰最久未使用条目。
func (c *ExactCache) Put(key, text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		e.text = text
		c.lru.MoveToFront(e.elem)
		return
	}
	e := &exactEntry{text: text}
	e.elem = c.lru.PushFront(key)
	c.items[key] = e
	for len(c.items) > c.cap {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.lru.Remove(oldest)
		delete(c.items, oldest.Value.(string))
	}
}

// Len 返回当前条目数（测试/可观测性用）。
func (c *ExactCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
