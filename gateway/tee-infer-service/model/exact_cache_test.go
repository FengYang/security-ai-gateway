package model

import "testing"

// TestExactCacheHitMiss 精确缓存命中/未命中。
func TestExactCacheHitMiss(t *testing.T) {
	c := NewExactCache(8)
	if _, ok := c.Get("k"); ok {
		t.Fatal("空缓存应未命中")
	}
	c.Put("k", "v")
	got, ok := c.Get("k")
	if !ok || got != "v" {
		t.Fatalf("应命中 k=v, got %q ok=%v", got, ok)
	}
	// 键精确匹配：不同键不命中
	if _, ok := c.Get("k2"); ok {
		t.Fatal("不同键不应命中")
	}
}

// TestExactCacheUpdate 覆盖更新：同键 Put 更新值，不增加条目数。
func TestExactCacheUpdate(t *testing.T) {
	c := NewExactCache(8)
	c.Put("k", "v1")
	c.Put("k", "v2")
	if c.Len() != 1 {
		t.Fatalf("更新不应增加条目，got %d", c.Len())
	}
	got, _ := c.Get("k")
	if got != "v2" {
		t.Fatalf("应取最新值 v2, got %q", got)
	}
}

// TestExactCacheEviction LRU 淘汰：容量满时淘汰最久未使用条目。
func TestExactCacheEviction(t *testing.T) {
	c := NewExactCache(2)
	c.Put("a", "1")
	c.Put("b", "2")
	// 访问 a，使 a 变为最近使用；再写 c 应淘汰 b
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a 应命中")
	}
	c.Put("c", "3")
	if _, ok := c.Get("b"); ok {
		t.Fatal("b 应已被 LRU 淘汰")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a 应仍在缓存")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("c 应已在缓存")
	}
}

// TestExactCacheImplementsSemanticCache 接口装配点：ExactCache 满足 SemanticCache。
func TestExactCacheImplementsSemanticCache(t *testing.T) {
	var sc SemanticCache = NewExactCache(4)
	sc.Put("x", "y")
	if got, ok := sc.Get("x"); !ok || got != "y" {
		t.Fatalf("SemanticCache 装配失败: %q %v", got, ok)
	}
}
