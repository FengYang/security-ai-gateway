package billing

// bench_persist_test.go —— P0-3 性能基准（**持久化路径**：file + WAL）。
//
// 与 bench_test.go（`:memory:`）对照：本组复跑同一操作于**文件库**，
// 覆盖真实磁盘写路径（WAL 提交），用于 §8.4 生产形态的数量级判定。
//
// 运行：go test ./gateway/gateway-admin-service/billing -run '^$' -bench 'BenchmarkPp' -benchmem

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// newFileStore 新建临时文件 SQLite（WAL），模拟生产持久化存储路径。
func newFileStore(tb testing.TB) Store {
	tb.Helper()
	s, err := OpenSQLiteStore(filepath.Join(tb.TempDir(), "billing.db"), true)
	if err != nil {
		tb.Fatalf("OpenSQLiteStore(file, wal): %v", err)
	}
	return s
}

// Pp1 持久化：单轮 10k 条目入账（file+WAL）。
func BenchmarkPp1_IngestWindow_10k(b *testing.B) {
	SetChainBroken(false)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := newFileStore(b)
		svc := benchService(s)
		win := benchWindow(fmt.Sprintf("bench-pp1-%d", i), 5000)
		ctx := context.Background()
		b.StartTimer()

		if _, err := svc.IngestWindow(ctx, win, SyncModePull); err != nil {
			b.Fatalf("IngestWindow: %v", err)
		}
		b.StopTimer()
		_ = s.Close()
		b.StartTimer()
	}
}

// Pp2 持久化：2 万行按 (tenant, day 区间) 查询。
func BenchmarkPp2_LedgerRangeQuery(b *testing.B) {
	s := newFileStore(b)
	defer s.Close()
	seedBenchEntries(b, s, 20000)
	q := LedgerQuery{TenantID: "tenant-00000", DayFrom: "2026-09-01", DayTo: "2026-09-28", Limit: 1000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Ledger().Range(q); err != nil {
			b.Fatalf("Range: %v", err)
		}
	}
}

// Pp3 持久化：单租户 30 天 × 20 模型日结。
func BenchmarkPp3_CloseDaily(b *testing.B) {
	SetChainBroken(false)
	SetAuditChainBroken(false)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := newFileStore(b)
		seedClose(b, s, "tenant-00000", 30, 20)
		svc := benchService(s)
		ctx := context.Background()
		b.StartTimer()

		if _, err := svc.CloseDaily(ctx, "tenant-00000", "2026-09-30"); err != nil {
			b.Fatalf("CloseDaily: %v", err)
		}
		b.StopTimer()
		_ = s.Close()
		b.StartTimer()
	}
}

// Pp4 持久化：2 万行全量哈希链校验。
func BenchmarkPp4_LedgerVerify(b *testing.B) {
	s := newFileStore(b)
	defer s.Close()
	seedBenchEntries(b, s, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Ledger().Verify(); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// Pp5 持久化：单事务批量 Append 1000 条。
func BenchmarkPp5_AppendBatch1000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := newFileStore(b)
		entries := make([]LedgerEntry, 1000)
		for j := range entries {
			entries[j] = LedgerEntry{TenantID: "t", ModelKey: "cheap-model", Day: "2026-09-15",
				TokensIn: 10, StdIn: 10, Source: "pull", EventKey: fmt.Sprintf("pp5-%d-%d", i, j),
				PriceVer: "v1", CreatedAt: int64(j + 1)}
		}
		tx, err := s.Begin()
		if err != nil {
			b.Fatalf("Begin: %v", err)
		}
		b.StartTimer()

		if _, _, err := s.Ledger().Append(tx, entries); err != nil {
			b.Fatalf("Append: %v", err)
		}
		if err := tx.Commit(); err != nil {
			b.Fatalf("Commit: %v", err)
		}
		b.StopTimer()
		_ = s.Close()
		b.StartTimer()
	}
}
