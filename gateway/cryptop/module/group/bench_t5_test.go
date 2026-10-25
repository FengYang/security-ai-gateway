package group

import (
	"sort"
	"testing"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// T-5 组模式性能标定基准（§7.2 T-5：基准脚本可复跑；报告含基线 / 并发 / P99）。
//
// **口径与边界**：
//   - 本基准对着 **mock 成员 + 内存控制存储** 运行，度量的是**组抽象自身的开销**
//     （路由、信封解析、组主校验、目录 CAS），**不代表真实 HSM 性能**；
//   - 真实性能标定（含硬件 P99）须在借测硬件到货后以实测替换标称（P1-5 R-3 口径），
//     属 Wave B；本基准**不宣称 V-5/性能达标**。
//   - 并发由 `go test -bench -cpu=N` 或外部压测脚本控制；P99 由 reportLatency 输出。
//
// 运行：`go test -bench=. -benchmem ./gateway/cryptop/module/group/`

func newBenchGroup(b *testing.B, self string) (*ModuleGroup, *module.MockBackend, *module.MockBackend, *testkit.MemoryControlStore) {
	b.Helper()
	cfg := testGroupConfig()
	m1 := newMockMember()
	m2 := newMockMember()
	members := map[string]module.ModuleBackend{"dc1-hsm-a": m1, "dc2-hsm-a": m2}
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	g, err := NewGroupProvider(cfg, members, self, store, "boot-"+self, nil)
	if err != nil {
		b.Fatalf("NewGroupProvider: %v", err)
	}
	return g, m1, m2, store
}

// reportLatency 输出 P50/P99/P99.9（T-5 要求报告含 P99）。
func reportLatency(b *testing.B, lat []time.Duration) {
	b.Helper()
	if len(lat) == 0 {
		return
	}
	sorted := make([]time.Duration, len(lat))
	copy(sorted, lat)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	pick := func(p float64) time.Duration {
		idx := int(float64(len(sorted)-1) * p)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx]
	}
	b.ReportMetric(float64(pick(0.50).Nanoseconds()), "p50_ns")
	b.ReportMetric(float64(pick(0.99).Nanoseconds()), "p99_ns")
	b.ReportMetric(float64(pick(0.999).Nanoseconds()), "p999_ns")
}

// benchEnvelope 构造一个可用的 GroupKeyRef 信封（数据面基准的输入）。
func benchEnvelope(b *testing.B, m *module.MockBackend) module.KeyRef {
	b.Helper()
	inner, err := m.GenerateKey("sm4-128", "")
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	env, err := testkit.EncodeGroupKeyRef(newKeyID(), "dc1-hsm-a", "tenant-a", inner)
	if err != nil {
		b.Fatalf("EncodeGroupKeyRef: %v", err)
	}
	return env
}

// BenchmarkGroupSeal 数据面 Seal：含信封解析 + 成员路由 + 模块运算。
func BenchmarkGroupSeal(b *testing.B) {
	g, m1, _, _ := newBenchGroup(b, "dc1-hsm-a")
	defer g.Close()
	g.Init(nil)

	env := benchEnvelope(b, m1)
	nonce := []byte("0123456789ab")
	pt := []byte("plaintext-bench-payload")

	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := g.Seal(env, nonce, pt, nil); err != nil {
			b.Fatalf("Seal: %v", err)
		}
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	reportLatency(b, lat)
}

// BenchmarkGroupOpen 数据面 Open（解密路径）。
func BenchmarkGroupOpen(b *testing.B) {
	g, m1, _, _ := newBenchGroup(b, "dc1-hsm-a")
	defer g.Close()
	g.Init(nil)

	env := benchEnvelope(b, m1)
	nonce := []byte("0123456789ab")
	ct, err := g.Seal(env, nonce, []byte("plaintext-bench-payload"), nil)
	if err != nil {
		b.Fatalf("预置 Seal: %v", err)
	}

	lat := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := g.Open(env, nonce, ct, nil); err != nil {
			b.Fatalf("Open: %v", err)
		}
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	reportLatency(b, lat)
}

// BenchmarkGroupRouteKey 路由开销：GroupKeyRef 解码 + 成员/分区定位（数据面热路径）。
func BenchmarkGroupRouteKey(b *testing.B) {
	g, m1, _, _ := newBenchGroup(b, "dc1-hsm-a")
	defer g.Close()
	g.Init(nil)
	env := benchEnvelope(b, m1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := g.routeKey(env); err != nil {
			b.Fatalf("routeKey: %v", err)
		}
	}
}

// BenchmarkGroupLeaderCheck 生命周期写的组主校验开销（控制面热路径）。
func BenchmarkGroupLeaderCheck(b *testing.B) {
	g, _, _, _ := newBenchGroup(b, "dc1-hsm-a")
	defer g.Close()
	g.Init(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := g.requireLeader(); err != nil {
			b.Fatalf("requireLeader: %v", err)
		}
	}
}
