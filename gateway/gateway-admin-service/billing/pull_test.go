package billing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---------- S-1 增量拉取（§6.1.1） ----------

type fakePullSource struct {
	win   *UsageWindow
	err   error
	calls int
}

func (f *fakePullSource) Pull(ctx context.Context, fromNs, toNs int64) (*UsageWindow, error) {
	f.calls++
	return f.win, f.err
}

func pullWindow(eventKey string) *UsageWindow {
	return &UsageWindow{
		FromNs: 1, ToNs: 2, Source: "pull", EventKey: eventKey,
		Tenants: map[string]*TenantAgg{
			"t1": {TokensIn: 1000, ByModel: map[string]*ModelAgg{"cheap-model": {TokensIn: 1000}}},
		},
	}
}

// 正常拉取 → 入账
func TestPullOnce_WritesLedger(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	src := &fakePullSource{win: pullWindow("pull-1-2")}
	svc.SetMeteringSource(src, time.Hour, SyncModePull)

	svc.pullOnce(context.Background())
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
	if src.calls != 1 {
		t.Errorf("pull calls = %d, want 1", src.calls)
	}
}

// 拉取失败 → 不写账（B-6.1-1：不推进游标，下轮重拉）
func TestPullOnce_PullErrorNoWrite(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(&fakePullSource{err: errors.New("unreachable")}, time.Hour, SyncModePull)

	svc.pullOnce(context.Background())
	entries, _ := s.Ledger().Range(LedgerQuery{})
	if len(entries) != 0 {
		t.Errorf("expected no ledger write on pull error, got %d entries", len(entries))
	}
}

// sync_mode=push → 拉取不写账（A-12 单写者）
func TestPullOnce_NonWriterModeNoLedger(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(&fakePullSource{win: pullWindow("pull-1-2")}, time.Hour, SyncModePush)

	svc.pullOnce(context.Background())
	entries, _ := s.Ledger().Range(LedgerQuery{})
	if len(entries) != 0 {
		t.Errorf("push mode pull wrote %d entries, want 0 (R-30)", len(entries))
	}
}

// 时钟回拨 → 跳过本轮（B-6.1-3）
func TestPullOnce_ClockSkewSkips(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	src := &fakePullSource{win: pullWindow("pull-1-2")}
	svc.SetMeteringSource(src, time.Hour, SyncModePull)
	svc.now = func() int64 { return 100 }
	svc.lastPollNs = 200 // 上次更晚 → 回拨

	svc.pullOnce(context.Background())
	if src.calls != 0 {
		t.Errorf("clock skew should skip pull, calls = %d", src.calls)
	}
}

// 未注入拉取源 → no-op（不 panic）
func TestPullOnce_NoSource(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	newTestBillingService(s, nil).pullOnce(context.Background())
}

// 任务可运行
func TestPullTask_Runs(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(&fakePullSource{win: pullWindow("pull-1-2")}, time.Hour, SyncModePull)
	PullTask(svc)(context.Background())
}
