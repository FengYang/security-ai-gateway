package billing

import (
	"bytes"
	"strings"
	"testing"
)

// ---------- 冻结状态指标 #24（gateway_admin_billing_frozen） ----------

func renderDefaultMetrics() string {
	var buf bytes.Buffer
	DefaultMetrics.Render(&buf)
	return buf.String()
}

// 冻结/解冻状态变更即置 gauge（1/0）
func TestSetFrozen_GaugeOnFreezeUnfreeze(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })

	if err := fc.Freeze("gf-t1", "manual", string(SeverityCritical), "admin"); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if !strings.Contains(renderDefaultMetrics(), `gateway_admin_billing_frozen{tenant="gf-t1"} 1`) {
		t.Error("frozen gauge should be 1 after Freeze")
	}

	if err := fc.Unfreeze("gf-t1", "admin"); err != nil {
		t.Fatalf("unfreeze: %v", err)
	}
	if !strings.Contains(renderDefaultMetrics(), `gateway_admin_billing_frozen{tenant="gf-t1"} 0`) {
		t.Error("frozen gauge should be 0 after Unfreeze")
	}
}

// 重启恢复：存储中已有冻结但 gauge 归零 → SyncFrozenGauge 回填为 1
func TestSyncFrozenGauge_RestoresAfterRestart(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	// 模拟"重启前已冻结"：直接写存储（不经 Freeze，故 gauge 未置）
	if err := s.Freezes().Put(FreezeRecord{
		TenantID: "gf-t2", Reason: "manual", Severity: "critical", FrozenAt: 1,
	}); err != nil {
		t.Fatalf("put freeze: %v", err)
	}
	det := NewAnomalyDetectorForStore(s, nil, nil, AnomalyConfig{}, nil)
	det.SetFreezeLinker(NewFreezeController(s.Freezes(), nil, func() int64 { return 2 }))

	det.SyncFrozenGauge()
	if !strings.Contains(renderDefaultMetrics(), `gateway_admin_billing_frozen{tenant="gf-t2"} 1`) {
		t.Error("SyncFrozenGauge should restore frozen gauge from store")
	}
}

// 已到期冻结不置 1（ListFrozen 过滤）
func TestSyncFrozenGauge_SkipsExpired(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := s.Freezes().Put(FreezeRecord{
		TenantID: "gf-t3", Reason: "manual", Severity: "critical", FrozenAt: 1, Until: 5, // 已过期
	}); err != nil {
		t.Fatalf("put freeze: %v", err)
	}
	det := NewAnomalyDetectorForStore(s, nil, nil, AnomalyConfig{}, nil)
	det.SetFreezeLinker(NewFreezeController(s.Freezes(), nil, func() int64 { return 10 }))

	det.SyncFrozenGauge()
	if strings.Contains(renderDefaultMetrics(), `gateway_admin_billing_frozen{tenant="gf-t3"} 1`) {
		t.Error("expired freeze should not set gauge to 1")
	}
}
