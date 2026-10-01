package billing

import (
	"context"
	"testing"
)

// ---------- T-7.2 账单签名测试 ----------

func testBill() *Bill {
	return &Bill{
		ID: "daily-t1-2026-10-01", TenantID: "t1", Kind: BillKindDaily,
		Period: "2026-10-01", Total: 20000, Currency: "CNY",
		PriceVersion: "v1", Status: BillStatusIssued,
		LedgerHead: "abc123", AuditHead: "def456", GeneratedAt: 100,
		Items: []BillItem{
			{ModelKey: "m2", StandardTokens: 100, TokensIn: 50, Amount: 500},
			{ModelKey: "m1", StandardTokens: 200, TokensIn: 100, Amount: 1000},
		},
	}
}

func TestSignAndVerify(t *testing.T) {
	// T-7.2-1 正常签名 → 验证通过
	sig := NewBillSigner([]byte("secret-key-1"))
	b := testBill()
	b.Sig = sig.Sign(b)
	if !sig.Verify(b) {
		t.Error("Verify failed for correctly signed bill")
	}
	if b.Sig == "" {
		t.Error("Sig is empty")
	}
}

func TestVerify_TamperedTotal(t *testing.T) {
	// T-7.2-2 改 Total 1 分 → 验签失败（B-7.2-3）
	sig := NewBillSigner([]byte("secret-key-1"))
	b := testBill()
	b.Sig = sig.Sign(b)

	b.Total = 20001 // 篡改 1 分
	if sig.Verify(b) {
		t.Error("Verify passed for tampered Total (B-7.2-3 violated)")
	}
}

func TestVerify_TamperedItem(t *testing.T) {
	// T-7.2-3 改明细一行 → 验签失败
	sig := NewBillSigner([]byte("secret-key-1"))
	b := testBill()
	b.Sig = sig.Sign(b)

	b.Items[0].Amount = 999999
	if sig.Verify(b) {
		t.Error("Verify passed for tampered item (B-7.2-3 violated)")
	}
}

func TestVerify_ItemOrderIndependent(t *testing.T) {
	// B-7.2-2 明细顺序不同 → 规范序列化强制排序 → 签名相同
	sig := NewBillSigner([]byte("secret-key-1"))
	b1 := testBill()
	b1.Sig = sig.Sign(b1)

	b2 := testBill()
	// 反转明细顺序
	b2.Items[0], b2.Items[1] = b2.Items[1], b2.Items[0]
	b2.Sig = b1.Sig // 复用同一签名
	if !sig.Verify(b2) {
		t.Error("Verify failed for reordered items (B-7.2-2: canonical must sort)")
	}
}

func TestVerify_KeyRotation(t *testing.T) {
	// T-7.2-4 / B-7.2-1 密钥轮换后旧账单仍可验（双密钥并存）
	oldKey := []byte("old-key")
	newKey := []byte("new-key")

	oldSigner := NewBillSigner(oldKey)
	b := testBill()
	b.Sig = oldSigner.Sign(b) // 用旧密钥签

	// 新签名器持当前密钥 + 旧密钥（轮换期）
	rotated := NewBillSigner(newKey, oldKey)
	if !rotated.Verify(b) {
		t.Error("rotated signer should verify bill signed with old key (B-7.2-1)")
	}

	// 只用新密钥的签名器应验签失败
	onlyNew := NewBillSigner(newKey)
	if onlyNew.Verify(b) {
		t.Error("new-only signer should NOT verify old-key bill")
	}
}

func TestVerify_EmptySig(t *testing.T) {
	sig := NewBillSigner([]byte("k"))
	b := testBill()
	if sig.Verify(b) {
		t.Error("Verify should fail for empty Sig")
	}
}

// ---------- T-7.3 关联校验测试 ----------

type stubAuditAnchor struct {
	heads map[string]bool
	cur   string
}

func (s *stubAuditAnchor) AuditAnchorExists(head string) bool { return s.heads[head] }
func (s *stubAuditAnchor) AuditHead() (string, error)          { return s.cur, nil }

func TestVerifyBillingChain_Pass(t *testing.T) {
	// T-7.3-1 账单→链→审计 全链绿
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})

	svc := newTestBillingService(s, nil)
	anchor := &stubAuditAnchor{heads: map[string]bool{"audit-head-1": true}, cur: "audit-head-1"}
	svc.SetAuditAnchor(anchor)

	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	if bill.AuditHead != "audit-head-1" {
		t.Errorf("bill.AuditHead = %q, want audit-head-1", bill.AuditHead)
	}
	if err := svc.VerifyBillingChain(bill); err != nil {
		t.Errorf("VerifyBillingChain err: %v", err)
	}
}

func TestVerifyBillingChain_LedgerAnchorMismatch(t *testing.T) {
	// T-7.3-2 篡改账本链尾 → 关联断
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
	// 篡改账单锚定的链尾
	bill.LedgerHead = "tampered-head"
	if err := svc.VerifyBillingChain(bill); err != ErrLedgerAnchorMismatch {
		t.Errorf("expected ErrLedgerAnchorMismatch, got %v", err)
	}
}

func TestVerifyBillingChain_AuditAnchorMissing(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)
	// 审计链中不存在该 head
	anchor := &stubAuditAnchor{heads: map[string]bool{}, cur: "unknown-head"}
	svc.SetAuditAnchor(anchor)

	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	if err := svc.VerifyBillingChain(bill); err != ErrAuditAnchorMissing {
		t.Errorf("expected ErrAuditAnchorMissing, got %v", err)
	}
}
