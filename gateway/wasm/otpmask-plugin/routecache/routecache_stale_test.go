package routecache

import (
	"testing"
	"time"
)

// TestDecideSourceAndDegraded（§6 阶梯）：L1 不降级；L2 属降级（需可观测）；都未命中 → SourceNone。
func TestDecideSourceAndDegraded(t *testing.T) {
	c := New(testKey())
	tbl := validTable(1)
	sign(testKey(), tbl)
	c.Update(tbl)

	if d := c.Decide("tenant-a", "qwen-plus", "yrproxy"); d.Source != SourcePrescription || d.Degraded {
		t.Errorf("L1 应标记为处方来源且不降级，got %+v", d)
	}
	if d := c.Decide("tenant-a", "qwen-plus", ""); d.Source != SourceCache || !d.Degraded {
		t.Errorf("L2 应标记为缓存来源且 Degraded=true，got %+v", d)
	}
	if d := c.Decide("tenant-a", "missing", ""); d.Source != SourceNone || d.Degraded || d.Stale {
		t.Errorf("未命中应为 SourceNone 且无降级/过期标记，got %+v", d)
	}
}

// TestMaxStaleExpiry 超过 MaxStale 的缓存按未命中处理（Stale=true）→ 调用方走密态 fail-closed，
// 而不是静默使用陈旧路由（这是"加可配过期阈值"的目的）。
func TestMaxStaleExpiry(t *testing.T) {
	base := time.Unix(1725500000, 0) // validTable 的 UpdatedAt
	key := testKey()
	tbl := validTable(1)
	sign(key, tbl)

	// 阈值 60s：+59s 仍命中
	c := NewWithOptions(key, Options{
		MaxStale: 60 * time.Second,
		Now:      func() time.Time { return base.Add(59 * time.Second) },
	})
	if !c.Update(tbl) {
		t.Fatal("合法表应接受")
	}
	if d := c.Decide("tenant-a", "qwen-plus", ""); d.Source != SourceCache || d.Stale {
		t.Fatalf("阈值内应命中缓存，got %+v", d)
	}

	// +61s 视为失效 → SourceNone 且 Stale=true，不给出引擎（避免调用方误用陈旧路由）
	c2 := NewWithOptions(key, Options{
		MaxStale: 60 * time.Second,
		Now:      func() time.Time { return base.Add(61 * time.Second) },
	})
	if !c2.Update(tbl) {
		t.Fatal("合法表应接受")
	}
	if d := c2.Decide("tenant-a", "qwen-plus", ""); d.Source != SourceNone || !d.Stale || d.Engine != "" {
		t.Fatalf("超阈值应按未命中（Stale=true、不给引擎）返回，got %+v", d)
	}
}

// TestMaxStaleZeroNeverExpires MaxStale<=0 时保持设计 §6 原文语义：接受旧版本（可用性优先）。
func TestMaxStaleZeroNeverExpires(t *testing.T) {
	c := NewWithOptions(testKey(), Options{
		Now: func() time.Time { return time.Unix(1725500000+86400, 0) }, // 缓存已"一天前"
	})
	tbl := validTable(1)
	sign(testKey(), tbl)
	c.Update(tbl)
	if d := c.Decide("tenant-a", "qwen-plus", ""); d.Source != SourceCache || d.Stale {
		t.Fatalf("MaxStale=0 应永不过期（接受旧版本），got %+v", d)
	}
}
