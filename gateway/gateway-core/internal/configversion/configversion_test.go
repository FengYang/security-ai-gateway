package configversion

import (
	"strings"
	"sync"
	"testing"
)

// TestNormalizeRejectsIllegal 非法版本头一律拒绝（空/超长/含空白/含控制字符/非 ASCII）。
func TestNormalizeRejectsIllegal(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"空串", ""},
		{"纯空白", "   "},
		{"超长", strings.Repeat("a", MaxVersionLength+1)},
		{"含空格", "1 2"},
		{"含换行", "1\n2"},
		{"含制表", "1\t2"},
		{"非ASCII", "版本1"},
	}
	for _, c := range cases {
		if _, ok := Normalize(c.raw); ok {
			t.Fatalf("%s 应被判非法: %q", c.name, c.raw)
		}
	}
}

// TestNormalizeAcceptsLegal 合法版本头原样通过（数字/哈希型均可）。
func TestNormalizeAcceptsLegal(t *testing.T) {
	for _, raw := range []string{"0", "7", "42", "sha256-abc123"} {
		v, ok := Normalize(raw)
		if !ok {
			t.Fatalf("合法版本头被拒: %q", raw)
		}
		if v != raw {
			t.Fatalf("合法版本头被改写: %q → %q", raw, v)
		}
	}
}

// TestReportRecordsAndReadsBack 上报后可读回（版本 + 时间）。
func TestReportRecordsAndReadsBack(t *testing.T) {
	c := New()
	rec, ok := c.Report(SourceRoutes, "7", timeZero())
	if !ok {
		t.Fatalf("首次上报应被采纳")
	}
	if rec.Version != "7" {
		t.Fatalf("采纳版本错误: got %q", rec.Version)
	}
	got, ok := c.Get(SourceRoutes)
	if !ok {
		t.Fatalf("读回失败：应存在记录")
	}
	if got.Version != "7" || got.ReportedAt.IsZero() {
		t.Fatalf("读回内容错误: %+v", got)
	}
}

// TestReportEmptyHeaderDoesNotOverwrite 无版本头（空）不覆盖既有记录 ⇒ 仍为 unknown/旧值。
func TestReportEmptyHeaderDoesNotOverwrite(t *testing.T) {
	c := New()
	// 先上报一次有效版本
	c.Report(SourceRoutes, "5", timeZero())
	// 空头：视为未上报，不得覆盖
	c.Report(SourceRoutes, "", timeZero())
	got, ok := c.Get(SourceRoutes)
	if !ok || got.Version != "5" {
		t.Fatalf("空头不应覆盖既有版本: %+v", got)
	}
	// 从未上报过的通道：Get 返回 ok=false（unknown）
	c2 := New()
	if _, ok := c2.Get(SourceRoutes); ok {
		t.Fatalf("未上报通道应返回 unknown")
	}
}

// TestReportInvalidIgnoredNotFail 非法版本头被忽略（不采纳），但不影响其它记录。
func TestReportInvalidIgnoredNotFail(t *testing.T) {
	c := New()
	c.Report(SourceRoutes, "9", timeZero())
	rec, ok := c.Report(SourceRoutes, "bad version", timeZero())
	if ok {
		t.Fatalf("非法版本头不应被采纳")
	}
	if rec.RejectedInvalid != 1 {
		t.Fatalf("非法计数错误: %+v", rec)
	}
	got, _ := c.Get(SourceRoutes)
	if got.Version != "9" {
		t.Fatalf("非法上报污染了生效版本: %+v", got)
	}
}

// TestReportStaleDoesNotRegress 陈旧/回退的上报不得把生效版本冲回旧值（单调不回退）。
func TestReportStaleDoesNotRegress(t *testing.T) {
	c := New()
	c.Report(SourceRoutes, "10", timeZero())
	rec, ok := c.Report(SourceRoutes, "3", timeZero())
	if ok {
		t.Fatalf("陈旧上报不应被采纳")
	}
	if rec.RejectedStale != 1 {
		t.Fatalf("陈旧计数错误: %+v", rec)
	}
	if rec.LastReportedVersion != "3" {
		t.Fatalf("陈旧上报应如实保留原始取值: %+v", rec)
	}
	got, _ := c.Get(SourceRoutes)
	if got.Version != "10" {
		t.Fatalf("生效版本被回退: got %q", got.Version)
	}
}

// TestReportConcurrentMonotonic 并发上报下生效版本单调不回退，且计数无丢失。
func TestReportConcurrentMonotonic(t *testing.T) {
	c := New()
	const n = 64
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			c.Report(SourceRoutes, itoa(v), timeZero())
		}(i)
	}
	wg.Wait()
	rec, ok := c.Get(SourceRoutes)
	if !ok {
		t.Fatalf("并发上报后应存在记录")
	}
	if rec.Version != itoa(n) {
		t.Fatalf("并发上报后生效版本应为最大值 %d: got %q", n, rec.Version)
	}
	if rec.Seq != n {
		t.Fatalf("上报计数应等于 %d（无丢失更新）: got %d", n, rec.Seq)
	}
}

// TestSnapshotIncludesAllSources 多通道快照互不串扰（独立版本命名空间）。
func TestSnapshotIncludesAllSources(t *testing.T) {
	c := New()
	c.Report(SourceRoutes, "3", timeZero())
	c.Report("ratelimits", "11", timeZero())
	snap := c.Snapshot()
	if snap[SourceRoutes].Version != "3" {
		t.Fatalf("routes 槽位错误: %+v", snap[SourceRoutes])
	}
	if snap["ratelimits"].Version != "11" {
		t.Fatalf("ratelimits 槽位错误: %+v", snap["ratelimits"])
	}
}
