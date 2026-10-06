package billing

// hashalg_test.go — P0-4 §5.4.3 组⑬ 计数链"算法标识 + 双读"回归：
//   · 账单签名按**自身前缀**分派（`hmac-sha256:`/`hmac-sm3:`），历史账单跨档可验；
//   · 账本条目 `hash_alg` 自述落库（ALTER 迁移列），跨档可复算；
//   · 未知算法 fail-closed（不复算、不静默回退）。

import (
	"encoding/hex"
	"strings"
	"testing"
)

// T-5.4-⑬-1：账单签名按候选签名自身前缀分派（intl 档也能验 sm 档签发的历史账单）。
func TestT54_BillSignPrefixDispatch(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	s := NewBillSigner(key)

	b := testBill()
	sig := s.Sign(b)
	if !strings.HasPrefix(sig, "hmac-sha256:") {
		t.Fatalf("intl 档签名前缀应为 hmac-sha256:，got %q", sig)
	}
	b.Sig = sig
	if !s.Verify(b) {
		t.Fatal("本档签名应自验通过")
	}

	// 模拟"sm 档签发的历史账单"：前缀 hmac-sm3 → 前缀分派应可验（双读）
	b.Sig = "hmac-sm3:" + hex.EncodeToString(macByAlg("hmac-sm3", key, canonicalBill(b)))
	if !s.Verify(b) {
		t.Fatal("hmac-sm3: 前缀签名应可验（前缀分派双读）")
	}

	// 篡改内容后同签名必须失效
	b.Total = 999999
	if s.Verify(b) {
		t.Fatal("篡改账单内容后签名应失效")
	}
}

// T-5.4-⑬-2：账本条目按自述 `hash_alg` 分派复算；sm3 标记条目落库后可验（持久化 + 分派）。
func TestT54_LedgerHashAlgDualRead(t *testing.T) {
	e := LedgerEntry{
		Seq: 1, TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 100, TokensOut: 50, Requests: 1, StdIn: 100, StdOut: 50,
		Source: "pull", PriceVer: "v1", EventKey: "e1",
	}
	sha, err := ComputeEntryHash(e)
	if err != nil {
		t.Fatal(err)
	}
	sm := e
	sm.HashAlg = "sm3"
	sm3, err := ComputeEntryHash(sm)
	if err != nil {
		t.Fatal(err)
	}
	if sha == sm3 {
		t.Fatal("同一内容在缺省与 sm3 下哈希应不同（分派未生效）")
	}

	s := openTestStore(t)
	defer s.Close()
	sm.EventKey = "e2" // 幂等键唯一
	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Ledger().Append(tx, []LedgerEntry{e, sm}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// 两条（缺省 SHA-256 / sm3）混合链均须通过 → 证明显式标记落库且按条目分派复算
	broken, err := s.Ledger().Verify()
	if err != nil {
		t.Fatalf("Verify() err: %v", err)
	}
	if broken != -1 {
		t.Fatalf("混合算法链应完好，断链于 seq=%d", broken)
	}
}

// T-5.4-⑬-3：未知 `hash_alg` → 复算 fail-closed（不静默回退 SHA-256）；恶意行使 Verify 报错。
func TestT54_LedgerUnknownHashAlgFails(t *testing.T) {
	e := LedgerEntry{TenantID: "t1", ModelKey: "m1", Day: "2026-10-01", Source: "pull", PriceVer: "v1", EventKey: "e1"}
	e.HashAlg = "md5"
	if _, err := ComputeEntryHash(e); err == nil {
		t.Fatal("未知 hash_alg 应报错（B-5.4-1）")
	}

	s := openTestStore(t)
	defer s.Close()
	st := s.(*sqliteStore)
	// prev_hash 置空以通过链式检查（prevHash 初值为 ""），使校验推进到"按 hash_alg 复算"一步
	if _, err := st.db.Exec(`INSERT INTO billing_ledger
		(tenant_id, model_key, day, tokens_in, tokens_out, requests, retry_toks, std_in, std_out,
		 source, price_ver, event_key, prev_hash, entry_hash, hash_alg, created_at)
		VALUES ('t1','m1','2026-10-01',0,0,0,0,0,0,'pull','v1','forged','','deadbeef','md5',1)`); err != nil {
		t.Fatalf("forged insert: %v", err)
	}
	if _, err := s.Ledger().Verify(); err == nil {
		t.Fatal("含未知 hash_alg 的账本应校验失败（B-5.4-1）")
	}
}
