package cacheengine

import (
	"testing"
	"time"
)

// TestExactStore_Basic 测试精确缓存的基本 Get/Put/Delete。
func TestExactStore_Basic(t *testing.T) {
	s := NewLRUExactStore(10, 1024)
	entry := &Entry{
		Text:     "hello world",
		ExpireAt: time.Now().Add(time.Hour).UnixMilli(),
		TenantID: "t1",
	}

	// 未命中
	if _, ok := s.Get("k1"); ok {
		t.Fatal("expected miss")
	}

	// 写入后命中
	s.Put("k1", entry)
	if e, ok := s.Get("k1"); !ok {
		t.Fatal("expected hit")
	} else if e.Text != "hello world" {
		t.Fatalf("unexpected text: %s", e.Text)
	}

	// 删除
	if !s.Delete("k1") {
		t.Fatal("expected delete success")
	}
	if _, ok := s.Get("k1"); ok {
		t.Fatal("expected miss after delete")
	}
}

// TestExactStore_Eviction 测试 LRU 淘汰。
func TestExactStore_Eviction(t *testing.T) {
	cap := 3
	s := NewLRUExactStore(cap, 1024)

	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		s.Put(key, &Entry{
			Text:     key,
			ExpireAt: time.Now().Add(time.Hour).UnixMilli(),
		})
	}

	if s.Len() != cap {
		t.Fatalf("expected len=%d, got %d", cap, s.Len())
	}
	if s.Evictions() != 2 {
		t.Fatalf("expected 2 evictions, got %d", s.Evictions())
	}

	// a 和 b 应该被淘汰了
	if _, ok := s.Get("a"); ok {
		t.Fatal("'a' should have been evicted")
	}
	if _, ok := s.Get("b"); ok {
		t.Fatal("'b' should have been evicted")
	}
	// c, d, e 应该还在
	for _, k := range []string{"c", "d", "e"} {
		if _, ok := s.Get(k); !ok {
			t.Fatalf("'%s' should exist", k)
		}
	}
}

// TestExactStore_MaxBytes 测试单条大小限制。
func TestExactStore_MaxBytes(t *testing.T) {
	s := NewLRUExactStore(10, 5) // 最大 5 字节

	s.Put("k1", &Entry{
		Text:     "123456", // 6 字节 > 5
		ExpireAt: time.Now().Add(time.Hour).UnixMilli(),
	})

	if _, ok := s.Get("k1"); ok {
		t.Fatal("entry exceeding max_bytes should not be stored")
	}
}

// TestExactStore_DeleteByTenant 测试按租户删除。
func TestExactStore_DeleteByTenant(t *testing.T) {
	s := NewLRUExactStore(10, 1024)
	expireAt := time.Now().Add(time.Hour).UnixMilli()

	s.Put("k1", &Entry{Text: "v1", TenantID: "t1", ExpireAt: expireAt})
	s.Put("k2", &Entry{Text: "v2", TenantID: "t1", ExpireAt: expireAt})
	s.Put("k3", &Entry{Text: "v3", TenantID: "t2", ExpireAt: expireAt})

	count := s.DeleteByTenant("t1")
	if count != 2 {
		t.Fatalf("expected 2 deleted, got %d", count)
	}
	if s.Len() != 1 {
		t.Fatalf("expected len=1, got %d", s.Len())
	}
	if _, ok := s.Get("k3"); !ok {
		t.Fatal("t2 entry should still exist")
	}
}

// TestExactStore_DeleteByModel 按模型删除（§6.8.1）。
func TestExactStore_DeleteByModel(t *testing.T) {
	s := NewLRUExactStore(10, 1024)
	expireAt := time.Now().Add(time.Hour).UnixMilli()

	s.Put("k1", &Entry{Text: "v1", Model: "m1", ExpireAt: expireAt})
	s.Put("k2", &Entry{Text: "v2", Model: "m1", ExpireAt: expireAt})
	s.Put("k3", &Entry{Text: "v3", Model: "m2", ExpireAt: expireAt})

	count := s.DeleteByModel("m1")
	if count != 2 {
		t.Fatalf("expected 2 deleted, got %d", count)
	}
	if s.Len() != 1 {
		t.Fatalf("expected len=1, got %d", s.Len())
	}
	if _, ok := s.Get("k3"); !ok {
		t.Fatal("m2 entry should still exist")
	}
}

// TestExactStore_Clear 全量清空（§6.8.1）：返回清空前条目数，清空后可继续写入。
func TestExactStore_Clear(t *testing.T) {
	s := NewLRUExactStore(10, 1024)
	expireAt := time.Now().Add(time.Hour).UnixMilli()
	s.Put("k1", &Entry{Text: "v1", ExpireAt: expireAt})
	s.Put("k2", &Entry{Text: "v2", ExpireAt: expireAt})

	if n := s.Clear(); n != 2 {
		t.Fatalf("Clear() = %d, want 2", n)
	}
	if s.Len() != 0 {
		t.Fatalf("expected len=0 after clear, got %d", s.Len())
	}
	if _, ok := s.Get("k1"); ok {
		t.Fatal("k1 should be cleared")
	}
	// 原地清空：对象复用，清空后仍可写入
	s.Put("k3", &Entry{Text: "v3", ExpireAt: expireAt})
	if _, ok := s.Get("k3"); !ok {
		t.Fatal("should accept writes after clear")
	}
}

// TestComputeChecksum 测试校验和计算。
func TestComputeChecksum(t *testing.T) {
	c1 := ComputeChecksum("hello")
	c2 := ComputeChecksum("hello")
	c3 := ComputeChecksum("world")

	if c1 != c2 {
		t.Fatal("same text should have same checksum")
	}
	if c1 == c3 {
		t.Fatal("different text should have different checksums")
	}
	if len(c1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(c1))
	}
}

// TestEntryUsable 测试条目可用性校验。
func TestEntryUsable(t *testing.T) {
	now := time.Now()
	e := &Entry{
		ExpireAt:  now.Add(time.Hour).UnixMilli(),
		PolicyVer: "1",
		GuardVer:  "v1",
	}

	if !EntryUsable(e, "v1", "1", now) {
		t.Fatal("entry should be usable")
	}
	if EntryUsable(e, "v2", "1", now) {
		t.Fatal("guard version mismatch should be unusable")
	}
	if EntryUsable(e, "v1", "2", now) {
		t.Fatal("policy version mismatch should be unusable")
	}
	if EntryUsable(e, "v1", "1", now.Add(2*time.Hour)) {
		t.Fatal("expired entry should be unusable")
	}
}
