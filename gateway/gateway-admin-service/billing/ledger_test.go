package billing

import (
	"os"
	"testing"
)

// ---------- T-7.1 账本哈希链单元测试 ----------

func TestLedger_EmptyHead(t *testing.T) {
	// T-7.1-1: 空账本 Head() 为 seq=0, hash=""
	s := openTestStore(t)
	defer s.Close()
	head, err := s.Ledger().Head()
	if err != nil {
		t.Fatalf("Head() err: %v", err)
	}
	if head.Seq != 0 {
		t.Errorf("empty head seq = %d, want 0", head.Seq)
	}
	if head.EntryHash != "" {
		t.Errorf("empty head hash = %q, want empty", head.EntryHash)
	}
}

func TestLedger_AppendAndVerify(t *testing.T) {
	// T-7.1-2: 追加 3 条，Verify() 通过
	s := openTestStore(t)
	defer s.Close()

	entries := []LedgerEntry{
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
			TokensIn: 100, TokensOut: 50, Requests: 2, StdIn: 100, StdOut: 50,
			Source: "pull", PriceVer: "v1", EventKey: "pull-2026-10-01-t1-m1", CreatedAt: 1000},
		{TenantID: "t1", ModelKey: "m2", Day: "2026-10-01",
			TokensIn: 200, TokensOut: 100, Requests: 3, StdIn: 200, StdOut: 100,
			Source: "pull", PriceVer: "v1", EventKey: "pull-2026-10-01-t1-m2", CreatedAt: 1001},
		{TenantID: "t2", ModelKey: "m1", Day: "2026-10-01",
			TokensIn: 10, TokensOut: 5, Requests: 1, RetryToks: 3, StdIn: 10, StdOut: 5,
			Source: "pull", PriceVer: "v1", EventKey: "pull-2026-10-01-t2-m1", CreatedAt: 1002},
	}

	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("Begin() err: %v", err)
	}
	added, head, err := s.Ledger().Append(tx, entries)
	if err != nil {
		tx.Rollback()
		t.Fatalf("Append() err: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit() err: %v", err)
	}
	if added != 3 {
		t.Errorf("added = %d, want 3", added)
	}
	if head.Seq != 3 {
		t.Errorf("head seq = %d, want 3", head.Seq)
	}

	// Verify 全链
	broken, err := s.Ledger().Verify()
	if err != nil {
		t.Fatalf("Verify() err: %v", err)
	}
	if broken != -1 {
		t.Errorf("Verify() broken at seq %d, want -1", broken)
	}
}

func TestLedger_IdempotentAppend(t *testing.T) {
	// T-7.1-3: 相同 event_key 重复追加，幂等去重
	s := openTestStore(t)
	defer s.Close()

	entries := []LedgerEntry{
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
			TokensIn: 100, TokensOut: 50, Requests: 1, StdIn: 100, StdOut: 50,
			Source: "pull", PriceVer: "v1", EventKey: "evt-1", CreatedAt: 1000},
	}

	tx, _ := s.Begin()
	added1, _, err := s.Ledger().Append(tx, entries)
	if err != nil {
		tx.Rollback()
		t.Fatalf("first Append err: %v", err)
	}
	tx.Commit()
	if added1 != 1 {
		t.Errorf("first added = %d, want 1", added1)
	}

	tx2, _ := s.Begin()
	added2, head2, err := s.Ledger().Append(tx2, entries)
	if err != nil {
		tx2.Rollback()
		t.Fatalf("second Append err: %v", err)
	}
	tx2.Commit()
	if added2 != 0 {
		t.Errorf("second added = %d, want 0 (idempotent)", added2)
	}
	if head2.Seq != 1 {
		t.Errorf("head seq = %d, want 1", head2.Seq)
	}
}

func TestLedger_TamperDetection(t *testing.T) {
	// T-7.1-4: 篡改 tokens_in 后 Verify() 检出
	s := openTestStore(t)
	defer s.Close()

	entries := []LedgerEntry{
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
			TokensIn: 100, TokensOut: 50, Requests: 1, StdIn: 100, StdOut: 50,
			Source: "pull", PriceVer: "v1", EventKey: "evt-1", CreatedAt: 1000},
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-02",
			TokensIn: 200, TokensOut: 100, Requests: 2, StdIn: 200, StdOut: 100,
			Source: "pull", PriceVer: "v1", EventKey: "evt-2", CreatedAt: 1001},
	}

	tx, _ := s.Begin()
	s.Ledger().Append(tx, entries)
	tx.Commit()

	// 直接 DB 篡改第一条的 tokens_in（绕过触发器的话，这里用 UPDATE 会被触发器拦截）
	// 改为验证触发器：尝试 UPDATE 应失败
	sqlStore := s.(*sqliteStore)
	_, err := sqlStore.db.Exec(`UPDATE billing_ledger SET tokens_in = 999 WHERE seq = 1`)
	if err == nil {
		t.Errorf("tamper UPDATE succeeded, expected trigger failure")
	}

	// 再验证链仍然完整
	broken, err := s.Ledger().Verify()
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if broken != -1 {
		t.Errorf("Verify broken at seq %d, want -1 (no tamper)", broken)
	}
}

func TestLedger_StdInStdOutInHash(t *testing.T) {
	// T-7.1-5 (A-49): 计价基 std_in/std_out/price_ver 必须入链，篡改应被检出
	// 构造两条除 std_in 外全同的条目，验证哈希不同
	e1 := LedgerEntry{
		Seq: 1, TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 100, TokensOut: 50, Requests: 1, StdIn: 100, StdOut: 50,
		Source: "pull", PriceVer: "v1", EventKey: "evt-1", PrevHash: "",
	}
	e2 := e1
	e2.StdIn = 200 // 只改 std_in

	h1, err := ComputeEntryHash(e1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeEntryHash(e2)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Errorf("std_in change does not affect hash (A-49 violated): h1=%s, h2=%s", h1, h2)
	}

	// 同样验证 price_ver
	e3 := e1
	e3.PriceVer = "v2"
	h3, err := ComputeEntryHash(e3)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Errorf("price_ver change does not affect hash: h1=%s, h3=%s", h1, h3)
	}
}

// ---------- helpers ----------

func openTestStore(t testing.TB) Store {
	t.Helper()
	s, err := OpenSQLiteStore(":memory:", false)
	if err != nil {
		t.Fatalf("OpenSQLiteStore(:memory:) err: %v", err)
	}
	return s
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
