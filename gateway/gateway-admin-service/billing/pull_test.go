package billing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------- S-1 增量拉取（§6.1.1） ----------

// TestTEEPullSource_AuthHeader 回归：拉取源须用 tee-infer 计量鉴权头 `X-Admin-Token`
// （此前误用 `Authorization: Bearer` → 受保护 tee-infer 下恒 401；由 §10.3 E2E-1 暴露）。
func TestTEEPullSource_AuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Admin-Token") != "tok" {
			http.Error(w, "计量查询认证失败", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenants":{"t1":{"tokens_in_net":1,"tokens_out_net":1,"requests":1}}}`))
	}))
	defer srv.Close()

	src := NewTEEPullSource(srv.URL, "tok", time.Second)
	win, err := src.Pull(context.Background(), 0, int64(time.Hour))
	if err != nil {
		t.Fatalf("Pull err（认证头不符即 401）: %v", err)
	}
	if win == nil || win.Tenants["t1"] == nil {
		t.Fatalf("聚合异常: %+v", win)
	}
}

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
	svc.now = fixedMidday // 固定正午：区间不跨自然日 → 单段（★ BUG-007 切分下确定性）

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

// ---------- ★ BUG-001 / BUG-007 修复回归 ----------

// fixedMidday 固定“2026-09-15 12:00（UTC+8）”——用于消除自然日切分带来的测试不确定性。
func fixedMidday() int64 {
	return time.Date(2026, 9, 15, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*3600)).UnixNano()
}

// timedPullSource 模拟真实 tee-infer 语义：仅当事件时间戳落在 [from,to) 内才返回该事件
// （旧“滑动窗口”实现会因窗口重叠而重复入账；游标式非重叠窗口则恰好一次）。
type timedPullSource struct {
	eventTs int64
	tokens  int64
	froms   []int64
}

func (s *timedPullSource) Pull(ctx context.Context, fromNs, toNs int64) (*UsageWindow, error) {
	s.froms = append(s.froms, fromNs)
	win := &UsageWindow{FromNs: fromNs, ToNs: toNs, Source: "pull",
		EventKey: fmt.Sprintf("pull-%d-%d", fromNs/int64(time.Second), toNs/int64(time.Second))}
	if s.eventTs >= fromNs && s.eventTs < toNs {
		win.Tenants = map[string]*TenantAgg{
			"t1": {TokensIn: s.tokens, Requests: 1, ByModel: map[string]*ModelAgg{
				"cheap-model": {TokensIn: s.tokens, Requests: 1},
			}},
		}
	}
	return win, nil
}

// BUG-001 回归锚：游标式非重叠窗口 → 同一事件只入账一次（旧滑动窗口实现会重复入账 → 本用例失败）。
func TestPullOnce_NonOverlapNoDuplicate(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	base := fixedMidday()
	src := &timedPullSource{eventTs: base - int64(30*time.Minute), tokens: 1000}
	svc.SetMeteringSource(src, time.Hour, SyncModePull)

	svc.now = func() int64 { return base }
	svc.pullOnce(context.Background()) // 窗口 [base-1h, base) 覆盖事件 → 入账 1 条
	svc.now = func() int64 { return base + int64(60*time.Second) }
	svc.pullOnce(context.Background()) // 窗口 [base, base+60s) 不含事件 → 0 条

	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("BUG-001 回归：ledger entries = %d, want 1（重叠窗口不得重复入账）", len(entries))
	}
}

// BUG-001：拉取失败**不推进游标**（下轮覆盖同区间，无丢账无重复）。
func TestPullOnce_FailureKeepsCursor(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(&fakePullSource{err: errors.New("unreachable")}, time.Hour, SyncModePull)
	svc.now = fixedMidday

	svc.pullOnce(context.Background())
	if svc.lastPollNs != 0 {
		t.Errorf("failure must not advance cursor, lastPollNs=%d", svc.lastPollNs)
	}
	if ns, _ := s.Ledger().PollWatermark(); ns != 0 {
		t.Errorf("failure must not advance watermark, got %d", ns)
	}
}

// BUG-001：进程重启后从**持久化水位**续拉（不回溯 lookback → 不重复）。
func TestPullOnce_RestartResumesWatermark(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	base := fixedMidday()
	if err := s.Ledger().SetPollWatermark(base); err != nil {
		t.Fatalf("set watermark: %v", err)
	}
	svc := newTestBillingService(s, nil) // 模拟重启：lastPollNs=0，仅水位持久
	src := &timedPullSource{eventTs: base - int64(30*time.Minute), tokens: 1000}
	svc.SetMeteringSource(src, time.Hour, SyncModePull)
	svc.now = func() int64 { return base + int64(30*time.Second) }

	svc.pullOnce(context.Background())
	// 事件时间戳 < 水位 → 不在 [水位, now) 内 → 不重复入账
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 0 {
		t.Fatalf("restart must resume from watermark (no replay), got %d entries", len(entries))
	}
	if len(src.froms) == 0 || src.froms[0] != base {
		t.Errorf("first pull from = %v, want %d (watermark)", src.froms, base)
	}
}

// dayEchoSource 对任意窗口都返回同一租户用量（EventKey 随窗口变化，模拟逐段独立入账）。
type dayEchoSource struct{ calls int }

func (s *dayEchoSource) Pull(ctx context.Context, fromNs, toNs int64) (*UsageWindow, error) {
	s.calls++
	return &UsageWindow{FromNs: fromNs, ToNs: toNs, Source: "pull",
		EventKey: fmt.Sprintf("pull-%d-%d", fromNs/int64(time.Second), toNs/int64(time.Second)),
		Tenants: map[string]*TenantAgg{
			"t1": {TokensIn: 10, Requests: 1, ByModel: map[string]*ModelAgg{
				"cheap-model": {TokensIn: 10, Requests: 1},
			}},
		}}, nil
}

// BUG-007：跨 UTC+8 零点时按自然日切分，账本归日与 tee-infer /usage 同口径。
func TestPullOnce_DaySplitAcrossMidnight(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	loc := time.FixedZone("UTC+8", 8*3600)
	now := time.Date(2026, 9, 15, 0, 5, 0, 0, loc).UnixNano() // 00:05，from=now-1h → 跨零点
	src := &dayEchoSource{}
	svc.SetMeteringSource(src, time.Hour, SyncModePull)
	svc.now = func() int64 { return now }

	svc.pullOnce(context.Background())
	if src.calls != 2 {
		t.Fatalf("跨零点应切为 2 段，got %d", src.calls)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	days := map[string]bool{}
	for _, e := range entries {
		days[e.Day] = true
	}
	if !days["2026-09-14"] || !days["2026-09-15"] {
		t.Fatalf("BUG-007 回归：归日错误，got days=%v entries=%+v", days, entries)
	}
}

// ★ A6 回归：同一秒内重复触发**不得重复请求**同一秒窗口。
// 否则两次拉取的 event_key 相同（pull-{fromSec}-{toSec}），UNIQUE 去重会吞掉该秒内
// 迟到的迟到事件 → 漏账；秒对齐后每个"秒桶"仅被请求一次。
func TestPullOnce_SameSecondNoDuplicateRequest(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	base := fixedMidday()
	src := &timedPullSource{eventTs: base - int64(time.Minute), tokens: 1000}
	svc.SetMeteringSource(src, time.Hour, SyncModePull)

	svc.now = func() int64 { return base + int64(200*time.Millisecond) }
	svc.pullOnce(context.Background()) // 端点对齐到 base → 覆盖事件，入账 1 条
	svc.now = func() int64 { return base + int64(800*time.Millisecond) }
	svc.pullOnce(context.Background()) // 与上轮同一秒 → 无新增区间，不请求

	if len(src.froms) != 1 {
		t.Fatalf("同一秒内重复触发应只请求一次，got %d 次（froms=%v）", len(src.froms), src.froms)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
}
