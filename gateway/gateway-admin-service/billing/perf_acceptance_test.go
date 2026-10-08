//go:build perf

package billing

// perf_acceptance_test.go —— P0-3 性能验收测量（分层验收 · 持久化层）。
//
// 定位：把详设 §8.4 的 P-1..P-5 与成功指标 M3/M5/M6 落为**本机可证**的实测，
// 产出可直接写入《PERF-BILLING 性能基准报告》的数据。
//
// 形态：**持久化层**（file + WAL，模拟生产磁盘写路径）。受本机无 TEE/kind 限制，
// TEE 相关（M6 真实 tee-infer 回读、P-3 大规模批处理）标注为“目标环境复测待办”。
//
// 运行：
//   go test -tags perf ./gateway/gateway-admin-service/billing -run TestPerfAcceptance -v -count=1
//
// 规模可用环境变量覆盖：PERF_QUERY_ROWS（默认 100000）。

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

func perfRows() int {
	if v := os.Getenv("PERF_QUERY_ROWS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 100000
}

// percentile 返回升序分位（p 取 0..1）。
func percentile(durs []time.Duration, p float64) time.Duration {
	if len(durs) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), durs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(float64(len(s)-1) * p)
	return s[idx]
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// measureQueryLatency 对同一查询执行 n 次并返回耗时分布（P-2 / M5）。
func measureQueryLatency(s Store, q LedgerQuery, n int) []time.Duration {
	durs := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := s.Ledger().Range(q); err != nil {
			panic(err)
		}
		durs = append(durs, time.Since(start))
	}
	return durs
}

// measureWriteContention 并发写（Pull 写路径）测单写锁争用下的写延迟分布（P-5）。
func measureWriteContention(t *testing.T, s Store, writers, perWriter, batch int) []time.Duration {
	var mu sync.Mutex
	var durs []time.Duration
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for k := 0; k < perWriter; k++ {
				entries := make([]LedgerEntry, batch)
				for j := range entries {
					entries[j] = LedgerEntry{TenantID: fmt.Sprintf("tenant-%05d", w), ModelKey: "cheap-model",
						Day: "2026-09-15", TokensIn: 10, StdIn: 10, Source: "pull",
						EventKey: fmt.Sprintf("ct-%d-%d-%d", w, k, j), PriceVer: "v1", CreatedAt: int64(j + 1)}
				}
				start := time.Now()
				tx, err := s.Begin() // 单写锁（writeMu）→ 此处排队等待
				if err != nil {
					t.Errorf("Begin: %v", err)
					return
				}
				if _, _, err := s.Ledger().Append(tx, entries); err != nil {
					_ = tx.Rollback()
					t.Errorf("Append: %v", err)
					return
				}
				if err := tx.Commit(); err != nil {
					t.Errorf("Commit: %v", err)
					return
				}
				mu.Lock()
				durs = append(durs, time.Since(start))
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return durs
}

// perfQuotaReader 回读替身（perf 专用，避免与 quota_confirm_test.go 的 fakeQuotaReader 重名）：
// 第 readyAfter 次回读起返回已生效限额（M6 判据路径）。
type perfQuotaReader struct {
	mu         sync.Mutex
	calls      int
	readyAfter int
}

func (r *perfQuotaReader) GetQuota(_ context.Context, _ string) ([]QuotaLimit, error) {
	r.mu.Lock()
	r.calls++
	c := r.calls
	r.mu.Unlock()
	if c >= r.readyAfter {
		return []QuotaLimit{{Window: "month", MaxTokens: 1000}}, nil
	}
	return []QuotaLimit{}, nil
}

// TestPerfAcceptance 产出 P-1..P-5 / M3 / M5 / M6 的持久化层实测，并按门槛断言。
func TestPerfAcceptance(t *testing.T) {
	SetChainBroken(false)
	SetAuditChainBroken(false)
	rows := perfRows()
	t.Logf("== P0-3 性能验收（持久化层 file+WAL）rows=%d ==", rows)

	// ---------- P-1 拉取入账（10k 条目/轮） ----------
	t.Run("P-1_ingest_10k", func(t *testing.T) {
		s := newFileStore(t)
		defer s.Close()
		svc := benchService(s)
		win := benchWindow("perf-p1", 5000)
		start := time.Now()
		if _, err := svc.IngestWindow(context.Background(), win, SyncModePull); err != nil {
			t.Fatalf("IngestWindow: %v", err)
		}
		d := time.Since(start)
		t.Logf("P-1 拉取入账 10k 条目/轮: %.1f ms（门槛 <5000ms）", ms(d))
		if d > 5*time.Second {
			t.Fatalf("P-1 超门槛: %.1f ms", ms(d))
		}
	})

	// ---------- P-2 / M5 查询延迟 ----------
	t.Run("P-2_M5_query", func(t *testing.T) {
		s := newFileStore(t)
		defer s.Close()
		seedBenchEntries(t, s, rows)
		query := LedgerQuery{TenantID: "tenant-00000", DayFrom: "2026-09-01", DayTo: "2026-09-28", Limit: 1000}
		measureQueryLatency(s, query, 20) // 预热
		durs := measureQueryLatency(s, query, 300)
		p50, p95, p99 := percentile(durs, 0.50), percentile(durs, 0.95), percentile(durs, 0.99)
		t.Logf("P-2/M5 查询(rows=%d) p50=%.2fms p95=%.2fms p99=%.2fms（M5 门槛 p95<200ms）", rows, ms(p50), ms(p95), ms(p99))
		if p95 > 200*time.Millisecond {
			t.Fatalf("M5 超门槛: p95=%.2fms", ms(p95))
		}
	})

	// ---------- P-3 / M3 日结耗时（单租户） ----------
	t.Run("P-3_M3_close_daily", func(t *testing.T) {
		s := newFileStore(t)
		defer s.Close()
		seedClose(t, s, "tenant-00000", 30, 20)
		svc := benchService(s)
		start := time.Now()
		if _, err := svc.CloseDaily(context.Background(), "tenant-00000", "2026-09-30"); err != nil {
			t.Fatalf("CloseDaily: %v", err)
		}
		d := time.Since(start)
		batchEst := time.Duration(1000) * d
		t.Logf("P-3/M3 单租户日结(30天×20模型): %.1f ms（门槛 <500ms）；1000 租户串行估计 %.1fs（M3 <10min）", ms(d), batchEst.Seconds())
		if d > 500*time.Millisecond {
			t.Fatalf("P-3/M3 单租户超门槛: %.1f ms", ms(d))
		}
	})

	// ---------- P-4 链校验 ----------
	t.Run("P-4_verify", func(t *testing.T) {
		s := newFileStore(t)
		defer s.Close()
		seedBenchEntries(t, s, rows)
		start := time.Now()
		if _, err := s.Ledger().Verify(); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		d := time.Since(start)
		// 线性外推至 §8.4 的 1.8M 行
		est18 := time.Duration(float64(d) * (1800000.0 / float64(rows)))
		t.Logf("P-4 链校验(rows=%d): %.0f ms；外推 1.8M 行 ≈ %.1fs（门槛 <30s）", rows, ms(d), est18.Seconds())
		if est18 > 30*time.Second {
			t.Fatalf("P-4 外推超门槛: %.1fs", est18.Seconds())
		}
	})

	// ---------- P-5 写争用 ----------
	t.Run("P-5_write_contention", func(t *testing.T) {
		s := newFileStore(t)
		defer s.Close()
		durs := measureWriteContention(t, s, 8, 200, 50)
		p50, p95, p99 := percentile(durs, 0.50), percentile(durs, 0.95), percentile(durs, 0.99)
		t.Logf("P-5 写争用(8 并发×200 批×50 条, n=%d) p50=%.2fms p95=%.2fms p99=%.2fms（门槛 写锁等待 p99<100ms）",
			len(durs), ms(p50), ms(p95), ms(p99))
		if p99 > 100*time.Millisecond {
			t.Fatalf("P-5 超门槛: p99=%.2fms", ms(p99))
		}
	})

	// ---------- M6 配额热生效时延（回读确认路径；替身 reader） ----------
	t.Run("M6_quota_confirm", func(t *testing.T) {
		rd := &perfQuotaReader{readyAfter: 2}
		want := []QuotaUpdate{{Tenant: "t1", Limits: []QuotaLimit{{Window: "month", MaxTokens: 1000}}}}
		start := time.Now()
		if err := ConfirmQuotaApplied(context.Background(), rd, "t1", want, 60*time.Second, 200*time.Millisecond); err != nil {
			t.Fatalf("ConfirmQuotaApplied: %v", err)
		}
		d := time.Since(start)
		t.Logf("M6 回读确认路径(轮询 200ms，替身): %.1f ms（门槛 ≤60s）；真实 tee-infer RTT 待目标环境复测", ms(d))
		if d > 60*time.Second {
			t.Fatalf("M6 超门槛: %.1f ms", ms(d))
		}
	})
}
