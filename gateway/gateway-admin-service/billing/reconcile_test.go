package billing

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- T13 对账回归（零容差，M1/M2 直接证据） ----------

func TestREC1_ZeroTolerance(t *testing.T) {
	// REC-1：账本净量与计量侧一致 → diff=0，Pass=true
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1000, TokensOut: 500, Requests: 2, EventKey: "e1",
	})
	r := NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 1000, TokensOut: 500, Requests: 2},
	}, 0.001)

	res, err := r.L2("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("L2 err: %v", err)
	}
	if res.Diff != 0 {
		t.Errorf("diff = %d, want 0 (zero tolerance)", res.Diff)
	}
	if !res.Pass {
		t.Error("Pass should be true when diff = 0")
	}
}

func TestREC2a_SmallDiffNoFreeze(t *testing.T) {
	// REC-2a：ratio ≈ 0.05% → 不出账（Pass=false）+ 不冻结（ShouldFrz=false）
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 200000, StdIn: 200000, Requests: 1, EventKey: "e1",
	})
	// 差 100 → ratio = 100/200000 = 0.05%
	r := NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 199900, Requests: 1},
	}, 0.001)

	res, _ := r.L2("t1", "2026-10-01", "2026-10-01")
	if res.Pass {
		t.Error("Pass should be false (diff > 0)")
	}
	if res.ShouldFrz {
		t.Errorf("ratio %.6f ≤ 0.1%% should NOT freeze (A-22)", res.Ratio)
	}
}

func TestREC2b_LargeDiffFreeze(t *testing.T) {
	// REC-2b：ratio ≈ 5% → 不出账 + 冻结候选
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 100000, StdIn: 100000, Requests: 1, EventKey: "e1",
	})
	// 差 5000 → ratio = 5000/100000 = 5%
	r := NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 95000, Requests: 1},
	}, 0.001)

	res, _ := r.L2("t1", "2026-10-01", "2026-10-01")
	if res.Pass {
		t.Error("Pass should be false (diff > 0)")
	}
	if !res.ShouldFrz {
		t.Errorf("ratio %.6f > 0.1%% should freeze", res.Ratio)
	}
}

func TestREC3_RatioBoundary(t *testing.T) {
	// 阈值边界（§6.12.2 第三轴=请求数）：ratio 恰为 0.1% → 不冻结（严格 > 才冻结）
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1000999, StdIn: 1000999, Requests: 1, EventKey: "e1",
	})
	// 入量差 1000，计量侧三元组量 = 999999+1 = 1000000 → ratio = 1000/1000000 = 0.001（恰 0.1%）
	r := NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 999999, Requests: 1},
	}, 0.001)

	res, _ := r.L2("t1", "2026-10-01", "2026-10-01")
	if res.Ratio != 0.001 {
		t.Fatalf("ratio = %.6f, want exactly 0.001", res.Ratio)
	}
	if res.ShouldFrz {
		t.Errorf("ratio = 0.1%% exactly should NOT freeze (boundary), got ratio=%.6f", res.Ratio)
	}
}

func TestREC4_RequestsCountedRetryExcluded(t *testing.T) {
	// REC-4（§6.12.2）：第三轴 = 请求数（计入）；retry 差异**不**计入（另列 RetryToks，M9 单独校验）
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, Requests: 3, RetryToks: 50, EventKey: "e1",
	})
	r := NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 1000, Requests: 1, RetryToks: 0}, // 请求数差 2；retry 差 50（应被忽略）
	}, 0.001)

	res, _ := r.L2("t1", "2026-10-01", "2026-10-01")
	if res.Diff != 2 {
		t.Errorf("diff = %d, want 2 (requests delta only; retry excluded)", res.Diff)
	}
}

func TestS1_LedgerChainTamperDetected(t *testing.T) {
	// S-1/INV-2：**账本**哈希链篡改可检出（直插伪造行破坏 prev_hash 链接）。
	// 注：本用例原误名 `TestREC6_ChainBrokenDetected`——REC-6 语义为「tee-infer **审计链**
	// 断裂 → 全局停出账」（见 audit_chain_test.go），与账本链是两条不同的链（§10.4/§10.6）。
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, Requests: 1, EventKey: "e1",
	})
	// 完好
	if broken, _ := s.Ledger().Verify(); broken != -1 {
		t.Fatalf("chain should be intact, broken at %d", broken)
	}
	// 直插伪造条目（绕过 Append，伪造 prev_hash）→ 破坏链接
	ls := concreteLedger(s)
	_, err := ls.db.Exec(`INSERT INTO billing_ledger
		(tenant_id, model_key, day, tokens_in, tokens_out, requests, retry_toks,
		 std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, created_at)
		VALUES ('t1','m1','2026-10-01',1,0,1,0,1,0,'pull','v1','forged','deadbeef','cafe',1)`)
	if err != nil {
		t.Fatalf("forged insert err: %v", err)
	}
	broken, err := s.Ledger().Verify()
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if broken == -1 {
		t.Error("Verify should detect the forged (broken) entry")
	}
}

// TestREC5_L2PollsUsageIndependentOfPush REC-5（B-6.12-2）：L1 已 blocked（推送停）时，
// L2 仍可从 `/usage` **拉取**对账——拉取通道不依赖推送。
//
// 证据：L2 的计量侧数据源是 PullSource（`/usage?from&to`），与 push webhook 无关；
// 本用例以真实 HTTP 拉取源（TEEPullSource）喂入与账本等值的净量 → diff=0。
func TestREC5_L2PollsUsageIndependentOfPush(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"from":"x","to":"y","tenants":{"t1":{
			"tokens_in":1000,"tokens_out":500,"requests":2,
			"tokens_in_net":1000,"tokens_out_net":500,"retry_tokens":0}}}`))
	}))
	defer srv.Close()

	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1000, TokensOut: 500, Requests: 2, StdIn: 1000, StdOut: 500, EventKey: "e1",
	})

	// 计量侧 reader = 拉取源（**不经推送**；推送停不影响本路径）。
	reader := NewPullNetReader(NewTEEPullSource(srv.URL, "", time.Second))
	r := NewReconciler(concreteLedger(s), reader, 0.001)

	res, err := r.L2("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("L2 err: %v", err)
	}
	if atomic.LoadInt64(&hits) == 0 {
		t.Fatal("L2 未从 /usage 拉取（REC-5 判据须以拉取构造）")
	}
	if res.Diff != 0 || !res.Pass {
		t.Errorf("diff=%d pass=%v, want 0/true（账本与 /usage 净量同口径）", res.Diff, res.Pass)
	}
}
