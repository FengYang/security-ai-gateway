package billing

import (
	"context"
	"testing"
)

// ---------- S-6 链校验（§7.1.2 / §6.16） ----------

func TestVerifyLedgerChain_Intact(t *testing.T) {
	defer SetChainBroken(false) // 重置进程级标志，避免用例间污染
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100, StdIn: 100, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)

	brokenAt, err := svc.VerifyLedgerChain()
	if err != nil {
		t.Fatalf("VerifyLedgerChain err: %v", err)
	}
	if brokenAt != -1 {
		t.Errorf("brokenAt = %d, want -1 (intact)", brokenAt)
	}
	if ChainBroken() {
		t.Error("ChainBroken() = true, want false")
	}
}

func TestVerifyLedgerChain_BrokenStopsBilling(t *testing.T) {
	defer SetChainBroken(false)
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100, StdIn: 100, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)

	// 直接插入一条 prev_hash 悬空的伪造条目（绕过 Append，模拟就地篡改；
	// 账本 UPDATE/DELETE 受触发器禁止，故用 INSERT 制造断链）。
	db := s.(*sqliteStore).db
	if _, err := db.Exec(`INSERT INTO billing_ledger
		(tenant_id, model_key, day, tokens_in, tokens_out, requests, retry_toks,
		 std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, created_at)
		VALUES ('t1','cheap-model','2026-10-01',0,0,0,0,0,0,'pull','v1','forged','deadbeef','deadbeef',1)`); err != nil {
		t.Fatalf("insert forged entry: %v", err)
	}

	brokenAt, err := svc.VerifyLedgerChain()
	if err != nil {
		t.Fatalf("VerifyLedgerChain err: %v", err)
	}
	if brokenAt < 0 {
		t.Fatalf("brokenAt = %d, want >= 0 (broken)", brokenAt)
	}
	if !ChainBroken() {
		t.Error("ChainBroken() = false after broken chain, want true")
	}
	// 断裂门禁：停出账（fail-closed，§6.15/§7.1）
	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err != ErrChainBroken {
		t.Errorf("CloseDaily err = %v, want ErrChainBroken", err)
	}
}

// 链断裂标志可由下一次完好校验清除（verify 成功 → broken < 0 → 标志复位）。
func TestVerifyLedgerChain_RecoversOnIntact(t *testing.T) {
	defer SetChainBroken(false)
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100, StdIn: 100, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)
	SetChainBroken(true) // 模拟上次断裂

	if _, err := svc.VerifyLedgerChain(); err != nil {
		t.Fatalf("VerifyLedgerChain err: %v", err)
	}
	if ChainBroken() {
		t.Error("ChainBroken() = true after intact verify, want false")
	}
}

// ---------- S-10 关联校验（§7.3 / §6.16） ----------

// 多租户回归：ledger_head 锚定"本租户本周期链尾"后，关联校验必须通过；
// 若沿用全局链尾则本用例失败（修正前的缺陷，见 verify.go periodTailHash 注释）。
func TestCloseDaily_MultiTenantAnchorReproducible(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	seedLedger(t, s, LedgerEntry{
		TenantID: "t2", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e2",
	})
	svc := newTestBillingService(s, nil)

	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	if bill.Status != BillStatusIssued {
		t.Errorf("bill.Status = %q, want issued（S-10 不应误标）", bill.Status)
	}
	if !s.Ledger().ReproduceHead("t1", "2026-10-01", bill.LedgerHead) {
		t.Error("ledger_head 不可由本租户本周期重放复现（§7.3）")
	}
	if err := svc.VerifyBillingChain(bill); err != nil {
		t.Errorf("VerifyBillingChain err (multi-tenant): %v", err)
	}
}

func TestVerifyAssocRecent_Pass(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)
	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}

	checked, failed, err := svc.VerifyAssocRecent("")
	if err != nil {
		t.Fatalf("VerifyAssocRecent err: %v", err)
	}
	if checked != 1 || failed != 0 {
		t.Errorf("checked=%d failed=%d, want 1/0", checked, failed)
	}
}

func TestVerifyAssocRecent_MarksMismatch(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)
	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}

	// 篡改账单锚定的链尾（模拟锚定不符，§7.1.3「改链尾摘要」）
	db := s.(*sqliteStore).db
	if _, err := db.Exec(`UPDATE bills SET ledger_head = 'tampered' WHERE id = ?`, bill.ID); err != nil {
		t.Fatalf("tamper bill: %v", err)
	}

	checked, failed, err := svc.VerifyAssocRecent("")
	if err != nil {
		t.Fatalf("VerifyAssocRecent err: %v", err)
	}
	if checked != 1 || failed != 1 {
		t.Fatalf("checked=%d failed=%d, want 1/1", checked, failed)
	}
	got, err := s.Bills().Get(bill.ID)
	if err != nil || got == nil {
		t.Fatalf("Get bill err: %v", err)
	}
	if got.Status != BillStatusAssocMismatch {
		t.Errorf("status = %q, want %q", got.Status, BillStatusAssocMismatch)
	}
	// 不阻断：已出账账单金额不变（仅状态机迁移）
	if got.Total != bill.Total {
		t.Errorf("total = %d, want %d（S-10 不得改动金额）", got.Total, bill.Total)
	}
}
