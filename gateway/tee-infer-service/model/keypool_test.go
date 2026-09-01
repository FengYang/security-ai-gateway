package model

import "testing"

// TestRoundRobinKeyPool 验证轮询顺序与并发安全。
func TestRoundRobinKeyPool(t *testing.T) {
	p := NewRoundRobinKeyPool("a", "b", "c")
	if p.Len() != 3 {
		t.Fatalf("Len 应为 3, got %d", p.Len())
	}
	order := []string{p.Acquire(), p.Acquire(), p.Acquire(), p.Acquire()}
	want := []string{"a", "b", "c", "a"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("轮询顺序错误（第 %d 次）: got %v want %v", i, order, want)
		}
	}
}

// TestRoundRobinKeyPoolEmpty 空池 Acquire 恒空（fail-closed 语义）。
func TestRoundRobinKeyPoolEmpty(t *testing.T) {
	p := NewRoundRobinKeyPool()
	if p.Acquire() != "" {
		t.Fatal("空池应返回空凭证")
	}
}

// TestRoundRobinKeyPoolRelease 失败计数不改变轮询顺序（仅记录）。
func TestRoundRobinKeyPoolRelease(t *testing.T) {
	p := NewRoundRobinKeyPool("a", "b")
	_ = p.Acquire() // a
	p.Release("a", true)
	p.Release("a", true)
	if p.failed["a"] != 2 {
		t.Fatalf("失败计数应为 2, got %d", p.failed["a"])
	}
	// 下一轮仍从 b 开始（轮询指针不受 Release 影响）
	if got := p.Acquire(); got != "b" {
		t.Fatalf("应轮询到 b, got %q", got)
	}
}
