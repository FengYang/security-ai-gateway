package main

// P1-7 T11（本体 §7.10）：审计写入性能基线（V-10 过程留证）。
//
// 目的：量化审计留痕对写入路径的影响，支撑 V-10（p99 增量 <3%）与 A4-13
// 内存规格回填。三档对比（D-17）：
//   - noworm    ：内存模式（-audit-file 未配置；留痕仅驻内存，不落盘）
//   - worm/batch：D-17 默认档（每 1000 条或每 1 秒 fsync，先到者触发）
//   - worm/per_event：D-17 合规档（每条 Append 后立即 fsync）
//
// 运行：
//   go test -bench BenchmarkAudit -benchmem -benchtime=2s ./gateway/tee-infer-service/
//   AUDIT_PERF=1 go test -run TestAuditWriteLatencyP99 -v ./gateway/tee-infer-service/
//
// ⚠️ 口径边界：本文件测的是**进程内写入路径**（hash 计算 + WORM 落盘）。
// V-10 的 p99 增量是**端到端**判据，须以 e2e 两轮压测（-audit-file 开/关，
// 固定并发/时长，scripts/audit-baseline.sh 模式 B）为准；本文件提供写入侧的
// 可复算分位与吞吐，是 e2e 归因（劣化来自落盘还是哈希）的分解依据。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// perfEvent 构造一条与真实推理留痕字段规模一致的事件（证据字段齐备，
// 进 hash() 的字段同量级），避免因事件过小导致哈希/序列化成本被低估。
func perfEvent(i int) AuditEvent {
	return AuditEvent{
		EventID:      fmt.Sprintf("bench-%010d", i),
		Timestamp:    time.Now().UnixNano(),
		TenantID:     "bench-tenant",
		RequestID:    fmt.Sprintf("req-%010d", i),
		Action:       "infer",
		TokensIn:     512,
		TokensOut:    256,
		Result:       "ok",
		PayloadSHA:   fmt.Sprintf("%064d", i),
		HashAlg:      hashAlgTag(), // 与生产路径一致：intl 档为空串（=SHA-256），GM 档为 sm3；"sha256" 等字面值违反 R-12 会被拒落链
		EngineType:   "tee_gpu",
		Model:        "bench-model",
		MeteringMode: "estimate",
	}
}

// newPerfChain 按档位构造审计链（noworm / batch / per_event）。
func newPerfChain(tb testing.TB, mode string) *auditChain {
	tb.Helper()
	switch mode {
	case "noworm":
		return newAuditChain()
	case "batch", "per_event":
		dir := tb.TempDir()
		cfg := defaultWormFsyncConfig()
		if mode == "per_event" {
			cfg = WormFsyncConfig{Mode: FsyncPerEvent}
		}
		c, err := newAuditChainWORMWithConfig(filepath.Join(dir, "audit.jsonl"), "", cfg)
		if err != nil {
			tb.Fatalf("构造 %s 链失败: %v", mode, err)
		}
		return c
	}
	tb.Fatalf("未知模式 %q（noworm|batch|per_event）", mode)
	return nil
}

func BenchmarkAuditAppendNoWorm(b *testing.B)      { benchAppend(b, "noworm") }
func BenchmarkAuditAppendWormBatch(b *testing.B)   { benchAppend(b, "batch") }
func BenchmarkAuditAppendWormPerEvent(b *testing.B) { benchAppend(b, "per_event") }

func benchAppend(b *testing.B, mode string) {
	c := newPerfChain(b, mode)
	b.Cleanup(func() { _ = c.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.append(perfEvent(i))
	}
}

// BenchmarkAuditArchiveSinkWrite 归档迁移写入吞吐（T11「归档迁移耗时」的
// 可复算来源之一：本地文件系统归档 sink 的写入速率；对象存储 sink 需部署态实测）。
func BenchmarkAuditArchiveSinkWrite(b *testing.B) {
	dir := b.TempDir()
	sink := newLocalFSArchiveSink(dir)
	const batch = 500
	evs := make([]AuditEvent, batch)
	for i := range evs {
		evs[i] = perfEvent(i)
	}
	ctx := context.Background()
	b.SetBytes(int64(batch * 400)) // 约 400 B/条
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		part := fmt.Sprintf("%012d", i)
		if _, err := sink.WriteArchive(ctx, "warm", "bench-tenant", "2026-10-14", part, evs); err != nil {
			b.Fatalf("WriteArchive: %v", err)
		}
	}
}

// ---- V-10：p50/p99 分位测量（默认跳过；AUDIT_PERF=1 显式启用）----

type latencyStat struct {
	mean, p50, p99, max time.Duration
}

// TestAuditWriteLatencyP99 输出三档分位表（markdown），供基准报告引用。
// 注意：进程内分位 ≠ e2e p99；V-10 正式判定见 scripts/audit-baseline.sh 模式 B。
func TestAuditWriteLatencyP99(t *testing.T) {
	if os.Getenv("AUDIT_PERF") != "1" {
		t.Skip("设置 AUDIT_PERF=1 运行（T11 性能基线分位测量）")
	}
	const n = 10000
	measure := func(mode string) latencyStat {
		c := newPerfChain(t, mode)
		defer func() { _ = c.Close() }()
		lat := make([]time.Duration, 0, n)
		var total time.Duration
		for i := 0; i < n; i++ {
			st := time.Now()
			c.append(perfEvent(i))
			d := time.Since(st)
			lat = append(lat, d)
			total += d
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		return latencyStat{
			mean: total / time.Duration(n),
			p50:  lat[n/2],
			p99:  lat[(n*99)/100],
			max:  lat[n-1],
		}
	}
	base := measure("noworm")
	batch := measure("batch")
	pe := measure("per_event")

	inc := func(s latencyStat) string {
		return fmt.Sprintf("%+.1f%%", float64(s.p99-base.p99)/float64(base.p99)*100)
	}
	t.Logf("\n## T11 审计写入分位（进程内，n=%d，K3s 实测）\n", n)
	t.Logf("| 档位 | mean | p50 | p99 | max | p99 增量 vs noworm |")
	t.Logf("|---|---|---|---|---|---|")
	t.Logf("| noworm（内存） | %v | %v | %v | %v | — |", base.mean, base.p50, base.p99, base.max)
	t.Logf("| worm/batch（D-17 默认） | %v | %v | %v | %v | %s |", batch.mean, batch.p50, batch.p99, batch.max, inc(batch))
	t.Logf("| worm/per_event（合规档） | %v | %v | %v | %v | %s |", pe.mean, pe.p50, pe.p99, pe.max, inc(pe))

	// 设计预期断言：批量档必须显著快于逐事件档——这是 D-17「默认批量、合规逐事件」
	// 取舍的可观测证据；若反转说明档位装配错误（如 per_event 未真正逐条 fsync）。
	if batch.p99 >= pe.p99 {
		t.Fatalf("异常：batch 档 p99(%v) 未快于 per_event 档(%v)，与 D-17 设计取舍矛盾", batch.p99, pe.p99)
	}
	t.Logf("注：V-10（p99 增量 <3%%）的正式判定须以 e2e 两轮压测为准（scripts/audit-baseline.sh 模式 B）；本表为进程内写入路径分位。")
}
