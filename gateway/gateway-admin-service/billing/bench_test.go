package billing

// bench_test.go —— P0-3 性能基准（详设 §8.4 P-1..P-5）。
//
// 定位：把 §8.4 的性能矩阵落到可复跑的 Go benchmark，产出 M3/M4/M5 相关的可判定证据。
// 运行：`go test ./gateway/gateway-admin-service/billing -run '^$' -bench . -benchmem`
//
// 说明（规模与门槛口径）：单机内存 SQLite（`:memory:`），规模较 §8.4 的生产估算
// （1000 租户 / 1.8M 行）小 1~2 个数量级，用于**回归对比与数量级判定**；
// 生产容量验收仍需在带持久化存储的目标环境复测（见《…-性能基准报告.md》）。

import (
	"context"
	"fmt"
	"testing"
)

// benchStore 新建独立内存账本（每次迭代独立库，避免数据累积干扰计时）。
func benchStore(b *testing.B) Store {
	b.Helper()
	s, err := OpenSQLiteStore(":memory:", false)
	if err != nil {
		b.Fatalf("OpenSQLiteStore(:memory:): %v", err)
	}
	return s
}

// benchService 构造基准用账单服务（无 L2 对账器；月累计缓存启用 A-37）。
func benchService(s Store) *BillingService {
	eng, cache := NewRatingEngineWithCache("half_up", concreteLedger(s))
	svc := NewBillingService(s, eng, NewStaticPriceTable(testPriceTable()), nil, s.Freezes())
	svc.SetMonthStdCache(cache)
	return svc
}

// benchWindow 构造 nTenants × 2 模型（cheap-model/gpt-4o）的用量窗口 → 条目数 = nTenants×2。
func benchWindow(eventKey string, nTenants int) *UsageWindow {
	tenants := make(map[string]*TenantAgg, nTenants)
	for t := 0; t < nTenants; t++ {
		tenants[fmt.Sprintf("tenant-%05d", t)] = &TenantAgg{
			TokensIn: 1000, TokensOut: 500, Requests: 1,
			ByModel: map[string]*ModelAgg{
				"cheap-model": {TokensIn: 1000, TokensOut: 500, Requests: 1},
				"gpt-4o":      {TokensIn: 10, TokensOut: 5, Requests: 1},
			},
		}
	}
	return &UsageWindow{FromNs: 1, ToNs: 2, Day: "2026-09-15", Source: "pull",
		EventKey: eventKey, Tenants: tenants}
}

// seedBenchEntries 一次性写入 n 条账本条目（跨 100 租户 × 28 天）。
func seedBenchEntries(b *testing.B, s Store, n int) {
	b.Helper()
	entries := make([]LedgerEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, LedgerEntry{
			TenantID: fmt.Sprintf("tenant-%05d", i%100),
			ModelKey: "cheap-model",
			Day:      fmt.Sprintf("2026-09-%02d", 1+i%28),
			TokensIn: 1000, TokensOut: 500, Requests: 1, StdIn: 1000, StdOut: 500,
			Source: "pull", EventKey: fmt.Sprintf("bench-%d", i), PriceVer: "v1", CreatedAt: int64(i + 1),
		})
	}
	appendBench(b, s, entries)
}

// seedClose 为单租户写入 days × models 条条目（供日结基准）。
func seedClose(b *testing.B, s Store, tenant string, days, models int) {
	b.Helper()
	var entries []LedgerEntry
	k := 0
	for d := 1; d <= days; d++ {
		day := fmt.Sprintf("2026-09-%02d", d)
		for m := 0; m < models; m++ {
			mk := "cheap-model"
			if m%2 == 1 {
				mk = "gpt-4o"
			}
			k++
			entries = append(entries, LedgerEntry{TenantID: tenant, ModelKey: mk, Day: day,
				TokensIn: 100, TokensOut: 50, Requests: 1, StdIn: 100, StdOut: 50,
				Source: "pull", EventKey: fmt.Sprintf("bench-close-%d", k), PriceVer: "v1", CreatedAt: int64(k)})
		}
	}
	appendBench(b, s, entries)
}

func appendBench(b *testing.B, s Store, entries []LedgerEntry) {
	b.Helper()
	tx, err := s.Begin()
	if err != nil {
		b.Fatalf("Begin: %v", err)
	}
	if _, _, err := s.Ledger().Append(tx, entries); err != nil {
		_ = tx.Rollback()
		b.Fatalf("Append: %v", err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatalf("Commit: %v", err)
	}
}

// P-1 拉取吞吐：单轮 10k 条目入账（std 锁定 + 批量事务 Append）。门槛：单轮 < 5s。
func BenchmarkP1_IngestWindow_10k(b *testing.B) {
	SetChainBroken(false)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := benchStore(b)
		svc := benchService(s)
		win := benchWindow(fmt.Sprintf("bench-p1-%d", i), 5000)
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

// P-2 查询延迟：1 万行库上按 (tenant, day 区间) 查询（M5：p95 < 200ms）。
func BenchmarkP2_LedgerRangeQuery(b *testing.B) {
	s := benchStore(b)
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

// P-3 日结：单租户 30 天 × 20 模型（≈600 条）→ CloseDaily。门槛：单租户 < 500ms。
func BenchmarkP3_CloseDaily(b *testing.B) {
	SetChainBroken(false)
	SetAuditChainBroken(false)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := benchStore(b)
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

// P-4 链校验：2 万行全量哈希链校验（门槛：全量 1.8M 行 < 30s → 本规模应按比例远小于）。
func BenchmarkP4_LedgerVerify(b *testing.B) {
	s := benchStore(b)
	defer s.Close()
	seedBenchEntries(b, s, 20000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Ledger().Verify(); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// P-5 写争用路径：单事务批量 Append 1000 条（单写者串行化的写路径成本）。
func BenchmarkP5_AppendBatch1000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := benchStore(b)
		entries := make([]LedgerEntry, 1000)
		for j := range entries {
			entries[j] = LedgerEntry{TenantID: "t", ModelKey: "cheap-model", Day: "2026-09-15",
				TokensIn: 10, StdIn: 10, Source: "pull", EventKey: fmt.Sprintf("p5-%d-%d", i, j),
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
