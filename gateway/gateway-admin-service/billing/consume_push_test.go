package billing

import (
	"testing"
	"time"
)

// ---------- 推送消费（§6.3.1/§6.3.2；T-6.3-1/3/5/7、B-6.3-2/4/6） ----------

func pushTS() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// push 模式：推送事件入账（事件级单条 + std 锁定）
func TestConsumePush_WritesLedgerInPushMode(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePush)

	if err := svc.ConsumePush(PushEvent{
		EventID: "e1", TenantID: "t1", Model: "cheap-model",
		TokensIn: 1000, TokensOut: 500, Result: "ok", TS: pushTS(),
	}); err != nil {
		t.Fatalf("ConsumePush err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Source != "push" || e.ModelKey != "cheap-model" || e.TokensIn != 1000 || e.Requests != 1 {
		t.Errorf("entry = %+v", e)
	}
	if e.StdIn == 0 || e.PriceVer == "" {
		t.Errorf("std/price_ver not locked (A-32): %+v", e)
	}
}

// B-6.3-2 / T-6.3-1：同 event_id 重投 → 仅 1 条（UNIQUE event_key 幂等）
func TestConsumePush_DuplicateEventIdempotent(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePush)

	ev := PushEvent{EventID: "dup", TenantID: "t1", Model: "cheap-model", TokensIn: 100, TS: pushTS()}
	for i := 0; i < 3; i++ {
		if err := svc.ConsumePush(ev); err != nil {
			t.Fatalf("ConsumePush#%d err: %v", i, err)
		}
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Errorf("entries = %d, want 1 (idempotent by event_id)", len(entries))
	}
}

// T-6.3-3：is_retry=true → retry_toks>0，tokens_* = 0（M9）
func TestConsumePush_RetryAttribution(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePush)

	if err := svc.ConsumePush(PushEvent{
		EventID: "r1", TenantID: "t1", Model: "cheap-model",
		TokensIn: 100, TokensOut: 50, IsRetry: true, TS: pushTS(),
	}); err != nil {
		t.Fatalf("ConsumePush err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].RetryToks != 150 || entries[0].TokensIn != 0 || entries[0].TokensOut != 0 {
		t.Errorf("entry = %+v, want retry=150 in/out=0 (M9)", entries[0])
	}
}

// T-6.3-7 / A-12：sync_mode=pull → 推送不写账
func TestConsumePush_PullModeNoLedger(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePull)

	if err := svc.ConsumePush(PushEvent{
		EventID: "e1", TenantID: "t1", Model: "cheap-model", TokensIn: 100, TS: pushTS(),
	}); err != nil {
		t.Fatalf("ConsumePush err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{})
	if len(entries) != 0 {
		t.Errorf("pull mode push wrote %d entries, want 0 (A-12)", len(entries))
	}
}

// B-6.3-6：冻结租户仍入账（供人工核账）
func TestConsumePush_FrozenStillIngests(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePush)

	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })
	if err := fc.Freeze("t1", "manual", "critical", "admin"); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if err := svc.ConsumePush(PushEvent{
		EventID: "e1", TenantID: "t1", Model: "cheap-model", TokensIn: 100, TS: pushTS(),
	}); err != nil {
		t.Fatalf("ConsumePush err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Errorf("frozen tenant push should still ingest, entries = %d", len(entries))
	}
}

// B-6.3-4：负 token → 忽略（不落账、不计负）
func TestConsumePush_NegativeTokensNoLedger(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePush)

	if err := svc.ConsumePush(PushEvent{
		EventID: "e1", TenantID: "t1", Model: "cheap-model",
		TokensIn: -1, TokensOut: -1, TS: pushTS(),
	}); err != nil {
		t.Fatalf("ConsumePush err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{})
	if len(entries) != 0 {
		t.Errorf("negative tokens wrote %d entries, want 0", len(entries))
	}
}

// B-6.3-3：未知 result 值 → 仍落账（按 ok 兜底）
func TestConsumePush_UnknownResultStillIngests(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(nil, time.Hour, SyncModePush)

	if err := svc.ConsumePush(PushEvent{
		EventID: "e1", TenantID: "t1", Model: "cheap-model",
		TokensIn: 100, Result: "weird", TS: pushTS(),
	}); err != nil {
		t.Fatalf("ConsumePush err: %v", err)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Errorf("unknown result should still ingest, entries = %d", len(entries))
	}
}
