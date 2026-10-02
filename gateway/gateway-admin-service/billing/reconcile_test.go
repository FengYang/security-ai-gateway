package billing

import (
	"testing"
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

func TestREC6_ChainBrokenDetected(t *testing.T) {
	// REC-6/7：链断裂可检出（直插伪造行破坏 prev_hash 链接）
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
