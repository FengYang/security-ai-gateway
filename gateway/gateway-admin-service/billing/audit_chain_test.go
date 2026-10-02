package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------- REC-6 审计链断裂 → 全局停出账（B-6.12-4） ----------

// fakeAuditVerifier 审计链校验替身。
type fakeAuditVerifier struct {
	ok   bool
	err  error
	hits int
}

func (f *fakeAuditVerifier) VerifyAuditChain(context.Context) (bool, error) {
	f.hits++
	return f.ok, f.err
}

// TestREC6_AuditChainBrokenGlobalFreeze 断裂 → 全部租户停出账（全局，fail-closed）。
func TestREC6_AuditChainBrokenGlobalFreeze(t *testing.T) {
	defer SetAuditChainBroken(false) // 进程级标志复位，避免污染其它用例
	s := openTestStore(t)
	defer s.Close()
	for _, tn := range []string{"t1", "t2"} {
		seedLedger(t, s, LedgerEntry{
			TenantID: tn, ModelKey: "cheap-model", Day: "2026-10-01",
			TokensIn: 1000, StdIn: 1000, EventKey: "e-" + tn,
		})
	}
	svc := newTestBillingService(s, nil)
	svc.SetAuditChainVerifier(&fakeAuditVerifier{ok: false})

	if err := svc.VerifyAuditChain(context.Background()); err != nil {
		t.Fatalf("VerifyAuditChain err: %v", err)
	}
	if !AuditChainBroken() {
		t.Fatal("审计链断裂应置标志（ok=false）")
	}
	// 全局：每个租户的日结/月结均被停（fail-closed）
	for _, tn := range []string{"t1", "t2"} {
		if _, err := svc.CloseDaily(context.Background(), tn, "2026-10-01"); !errors.Is(err, ErrAuditChainBroken) {
			t.Errorf("CloseDaily(%s) err = %v, want ErrAuditChainBroken", tn, err)
		}
		if _, err := svc.CloseMonthly(context.Background(), tn, "2026-10"); !errors.Is(err, ErrAuditChainBroken) {
			t.Errorf("CloseMonthly(%s) err = %v, want ErrAuditChainBroken", tn, err)
		}
	}
}

// TestREC6_AuditChainIntactAllowsClose 完好 → 复位标志，出账不受阻。
func TestREC6_AuditChainIntactAllowsClose(t *testing.T) {
	defer SetAuditChainBroken(false)
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)
	svc.SetAuditChainVerifier(&fakeAuditVerifier{ok: true})
	SetAuditChainBroken(true) // 模拟上次断裂

	if err := svc.VerifyAuditChain(context.Background()); err != nil {
		t.Fatalf("VerifyAuditChain err: %v", err)
	}
	if AuditChainBroken() {
		t.Fatal("完好校验应复位标志")
	}
	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	if bill == nil || bill.Status != BillStatusIssued {
		t.Fatalf("账单异常：%+v", bill)
	}
}

// TestREC6_VerifierNilNoop 未注入校验器 → no-op（标志不变）。
func TestREC6_VerifierNilNoop(t *testing.T) {
	defer SetAuditChainBroken(false)
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	SetAuditChainBroken(true)
	if err := svc.VerifyAuditChain(context.Background()); err != nil {
		t.Fatalf("VerifyAuditChain err: %v", err)
	}
	if !AuditChainBroken() {
		t.Error("未注入校验器不应改变标志")
	}
}

// TestTEEAuditVerifier_HTTP 校验器 HTTP 契约：解析 {ok}、非 2xx 报错。
func TestTEEAuditVerifier_HTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "events": 3})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewTEEAuditVerifier(srv.URL, "", 0)
	ok, err := v.VerifyAuditChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyAuditChain err: %v", err)
	}
	if ok {
		t.Error("ok = true, want false（响应 ok=false）")
	}

	// 非 2xx → 错误
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer bad.Close()
	if _, err := NewTEEAuditVerifier(bad.URL, "", 0).VerifyAuditChain(context.Background()); err == nil {
		t.Error("非 2xx 应返回错误")
	}
}
