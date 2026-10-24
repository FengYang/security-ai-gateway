package cryptopmodule

// failover_snapshot_test.go —— FailoverSnapshot / HealthLevel.Float64 测试
// （P1-5 M5：cryptop_module_health / cryptop_module_failover_total 数据源）。
//
// 策略同 failover_test.go：MockBackend + FailHealth + 手动 Probe 保证确定性。

import (
	"testing"
)

func TestHealthLevelFloat64(t *testing.T) {
	cases := []struct {
		h    HealthLevel
		want float64
	}{
		{HealthOK, 1},
		{HealthDegraded, 0.5},
		{HealthDown, 0},
		{HealthLevel(99), 0}, // 未知级别按 down（宁可误报不可用，C-3 同构）
	}
	for _, c := range cases {
		if got := c.h.Float64(); got != c.want {
			t.Errorf("HealthLevel(%d).Float64()=%v, want %v", int(c.h), got, c.want)
		}
	}
}

func TestFailoverSnapshotNormal(t *testing.T) {
	m, _, _ := newFailoverPair(t, FailoverFailover)
	m.Probe() // 主备均健康
	s := m.Snapshot()
	if s.State != StateNormal || s.ActivePeer != PeerPrimary {
		t.Fatalf("正常态快照异常: state=%s active=%s", s.State, s.ActivePeer)
	}
	if s.PrimaryLevel != HealthOK || s.BackupLevel != HealthOK {
		t.Fatalf("主备级别应均为 ok: primary=%s backup=%s", s.PrimaryLevel, s.BackupLevel)
	}
	if !s.HasBackup || s.BreakerPrimary || s.BreakerBackup {
		t.Fatalf("HasBackup/熔断标志异常: %+v", s)
	}
	if len(s.FailoverCounts) != 0 {
		t.Fatalf("无切换时计数应为空: %v", s.FailoverCounts)
	}
	if s.Degraded() {
		t.Fatal("normal 态不应 Degraded")
	}
}

func TestFailoverSnapshotOnSwitch(t *testing.T) {
	m, primary, _ := newFailoverPair(t, FailoverFailover)
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateSwitched {
		t.Fatalf("应已切换: %s", m.State())
	}
	s := m.Snapshot()
	if s.State != StateSwitched || s.ActivePeer != PeerBackup {
		t.Fatalf("快照状态异常: state=%s active=%s", s.State, s.ActivePeer)
	}
	if s.PrimaryLevel != HealthDown || s.BackupLevel != HealthOK {
		t.Fatalf("级别异常: primary=%s backup=%s", s.PrimaryLevel, s.BackupLevel)
	}
	// 槽位标签：mock 后端恒 "mock"。
	if s.PrimarySlot != "mock" || s.BackupSlot != "mock" {
		t.Fatalf("槽位标签异常: primary=%q backup=%q", s.PrimarySlot, s.BackupSlot)
	}
	// 切换计数：key = from|to|reason（与 MetricsSink.RecordFailover 同契约）。
	if got := s.FailoverCounts["primary|backup|primary_down"]; got != 1 {
		t.Fatalf(`FailoverCounts["primary|backup|primary_down"]=%d, want 1（全部=%v）`, got, s.FailoverCounts)
	}
	// 快照 map 为拷贝：改快照不影响管理器（指标层可安全消费）。
	s.FailoverCounts["primary|backup|primary_down"] = 99
	if again := m.Snapshot(); again.FailoverCounts["primary|backup|primary_down"] != 1 {
		t.Fatal("快照 map 未拷贝，外部修改泄漏进管理器")
	}
}

func TestFailoverSnapshotFailClosedNoBackup(t *testing.T) {
	m, primary, _ := newFailoverPair(t, FailoverFailClosed)
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if m.State() != StateClosed {
		t.Fatalf("应 fail-closed: %s", m.State())
	}
	s := m.Snapshot()
	if s.HasBackup {
		t.Fatal("fail_closed 模式无备，HasBackup 应为 false")
	}
	if s.ActivePeer != "" {
		t.Fatalf("fail-closed 无 active peer, got %q", s.ActivePeer)
	}
	if s.BackupSlot != "unknown" {
		t.Fatalf(`无备时 BackupSlot 应为 "unknown", got %q`, s.BackupSlot)
	}
	if len(s.FailoverCounts) != 0 {
		t.Fatalf("无备无切换，计数应为空: %v", s.FailoverCounts)
	}
}

func TestFailoverSnapshotDegraded(t *testing.T) {
	m, primary, _ := newFailoverPair(t, FailoverDegrade)
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	s := m.Snapshot()
	if s.State != StateDegraded || !s.Degraded() {
		t.Fatalf("degrade 模式主 Down 应 StateDegraded: %s", s.State)
	}
}

func TestFailoverBackendSlotLabelDelegates(t *testing.T) {
	m, primary, _ := newFailoverPair(t, FailoverFailover)
	fb := NewFailoverBackend(m)
	// normal：active=primary（mock → "mock"）。
	if got := fb.SlotLabel(); got != "mock" {
		t.Fatalf("normal SlotLabel=%q, want mock", got)
	}
	primary.FailHealth = true
	probeN(m, m.cfg.HealthFailCount)
	if got := fb.SlotLabel(); got != "mock" {
		t.Fatalf("switched SlotLabel=%q, want mock（备也是 mock）", got)
	}
	// fail-closed：Active() 报错 → "unknown"。
	m2, p2, _ := newFailoverPair(t, FailoverFailClosed)
	p2.FailHealth = true
	probeN(m2, m2.cfg.HealthFailCount)
	fb2 := NewFailoverBackend(m2)
	if got := fb2.SlotLabel(); got != "unknown" {
		t.Fatalf("fail-closed SlotLabel=%q, want unknown", got)
	}
}
