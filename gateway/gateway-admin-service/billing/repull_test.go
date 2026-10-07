package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- 对账回补重拉（§6.12.3 软分支） ----------

func TestMarkRepulledOnce(t *testing.T) {
	svc := &BillingService{}
	if !svc.markRepulledOnce("t1", "2026-10-01") {
		t.Error("first mark should be true")
	}
	if svc.markRepulledOnce("t1", "2026-10-01") {
		t.Error("second mark same key should be false")
	}
	if !svc.markRepulledOnce("t1", "2026-10-02") {
		t.Error("different day should be true")
	}
}

// 回补重拉：从未入账尾段重拉并入账（★ BUG-001：不再用加宽窗口，避免覆盖已入账区间）
func TestPullRange_Ingests(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(&fakePullSource{win: pullWindow("pull-repull")}, time.Hour, SyncModePull)

	if err := svc.pullRange(context.Background(), 0, int64(time.Hour)); err != nil {
		t.Fatalf("pullRange err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1 (range ingested)", len(entries))
	}
	// 游标与水位推进到区间末端
	if svc.lastPollNs != int64(time.Hour) {
		t.Errorf("cursor = %d, want %d", svc.lastPollNs, int64(time.Hour))
	}
	if ns, _ := s.Ledger().PollWatermark(); ns != int64(time.Hour) {
		t.Errorf("watermark = %d, want %d", ns, int64(time.Hour))
	}
}

// 软分支（0<ratio≤0.1%）：不出账 + 排一次回补
func TestGateL2_SoftBranchSchedulesRepull(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100000, StdIn: 100000, Requests: 1, EventKey: "e1",
	})
	// 差 50 → ratio ≈ 0.05% ≤ 0.1% → 软分支
	reader := &stubReader{net: NetTotals{TokensIn: 99950, Requests: 1}}
	svc := newTestBillingService(s, reader)
	svc.SetMeteringSource(&fakePullSource{}, time.Hour, SyncModePull) // 空窗口：回补 no-op（避免后台写库）

	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err == nil {
		t.Fatal("expected reconcile block (diff>0)")
	}
	// 回补已排（同步置标记）→ 再次尝试应返回 false
	if svc.markRepulledOnce("t1", "2026-10-01") {
		t.Error("soft branch should have scheduled a repull for (t1, 2026-10-01)")
	}
}

// 硬分支（ratio>0.1%）：不出账，但**不**排回补（交由 S-5 判冻结）
func TestGateL2_HardBranchNoRepull(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100000, StdIn: 100000, Requests: 1, EventKey: "e1",
	})
	// 差 10000 → ratio ≈ 11% > 0.1% → 硬分支
	reader := &stubReader{net: NetTotals{TokensIn: 90000, Requests: 1}}
	svc := newTestBillingService(s, reader)
	svc.SetMeteringSource(&fakePullSource{}, time.Hour, SyncModePull)

	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err == nil {
		t.Fatal("expected reconcile block (diff>0)")
	}
	if !svc.markRepulledOnce("t1", "2026-10-01") {
		t.Error("hard branch should NOT schedule a repull")
	}
}

// 未注入拉取源 → no-op（不置标记）
func TestOnReconcileWarning_NoSource(t *testing.T) {
	svc := &BillingService{}
	svc.onReconcileWarning("t1", "2026-10-01")
	if !svc.markRepulledOnce("t1", "2026-10-01") {
		t.Error("no source should not mark repull")
	}
}
