package billing

import (
	"errors"
	"testing"
	"time"
)

// ---------- L2 对账器接线（§6.12.2 / §6.16 S-4） ----------

// 计量侧读取器：映射净量三元组；缺租户 → 零值
func TestPullNetReader_NetAggregate(t *testing.T) {
	src := &fakePullSource{win: &UsageWindow{Tenants: map[string]*TenantAgg{
		"t1": {TokensIn: 100, TokensOut: 50, RetryToks: 5, Requests: 2},
	}}}
	r := NewPullNetReader(src)

	got, err := r.NetAggregate("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("NetAggregate err: %v", err)
	}
	if got.TokensIn != 100 || got.TokensOut != 50 || got.RetryToks != 5 || got.Requests != 2 {
		t.Errorf("got %+v, want {100 50 5 2}", got)
	}

	zero, err := r.NetAggregate("t2", "2026-10-01", "2026-10-01") // 缺失租户
	if err != nil || zero.TokensIn != 0 {
		t.Errorf("missing tenant = %+v, err=%v, want zero", zero, err)
	}
}

func TestPullNetReader_ErrorPropagates(t *testing.T) {
	r := NewPullNetReader(&fakePullSource{err: errors.New("boom")})
	if _, err := r.NetAggregate("t1", "2026-10-01", "2026-10-01"); err == nil {
		t.Error("expected error from source")
	}
}

// 窗口换算：闭区间 [D1,D1] → 左闭右开 24h，起点为 UTC+8 当日 00:00
func TestDayRangeNs(t *testing.T) {
	from, to, err := dayRangeNs("2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("dayRangeNs err: %v", err)
	}
	if to-from != int64(24*time.Hour) {
		t.Errorf("span = %v, want 24h", time.Duration(to-from))
	}
	loc := time.FixedZone("UTC+8", utc8Offset)
	want, _ := time.ParseInLocation(dayLayout, "2026-10-01", loc)
	if from != want.UnixNano() {
		t.Errorf("from = %d, want %d", from, want.UnixNano())
	}
}

// L2 接线：账本 == 计量侧 → 零差异通过
func TestReconcilerForStore_Pass(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1000, Requests: 1, EventKey: "e1",
	})
	src := &fakePullSource{win: &UsageWindow{Tenants: map[string]*TenantAgg{
		"t1": {TokensIn: 1000, Requests: 1},
	}}}
	r := NewReconcilerForStore(s, NewPullNetReader(src), 0.001)

	res, err := r.L2("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("L2 err: %v", err)
	}
	if !res.Pass || res.Diff != 0 {
		t.Errorf("res = %+v, want pass diff=0", res)
	}
}

// nil 账本 → 降级通过（不 panic）
func TestReconcilerForStore_NilLedgerDegrades(t *testing.T) {
	r := NewReconcilerForStore(nil, NewPullNetReader(&fakePullSource{}), 0.001)
	res, err := r.L2("t1", "2026-10-01", "2026-10-01")
	if err != nil || !res.Pass {
		t.Errorf("res=%+v err=%v, want degraded pass", res, err)
	}
}
