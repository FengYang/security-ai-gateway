package cacheengine

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"
)

// ===== §8.3 性能基准（BM-1..BM-8）本地可测部分 =====
//
// 本地可测：BM-1（精确命中 p95）、BM-4（抖动 KS）、BM-5（内存预算）、BM-7（精确就绪）、
//           BM-8（sidecar 不可达 → fail-open 延迟）、BM-2（本地参考：flat 检索，不含 embedder）。
// 待外部环境：BM-2 端到端（真实 sidecar）、BM-3（真实上游 TTFT）、BM-6（sidecar 吞吐）、
//           BM-7 语义段（含权重加载）、BM-8 已就绪后真实断连。
//
// 运行：go test ./gateway/tee-infer-service/cacheengine/ -run TestBM -v

func bmSkipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("基准用例在 -short 下跳过")
	}
}

// bm2EnvInt reads a positive-int BM-2 scale override from env, or returns def.
// Defaults keep the production-representative full scale (50000x512) so the
// p95<15ms judgement keeps its discriminating power; CI / local smoke runs
// lower it via CACHE_BM2_*. Invalid values fail closed (Fatalf), never silently
// fall back to a smaller scale -- that would be a hidden weakening of the
// performance baseline.
func bm2EnvInt(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		t.Fatalf("BM-2 规模参数 %s=%q 非法（须为正整数）", key, v)
	}
	return n
}

// percentile 返回升序 samples 的 p 分位（p∈[0,1]）。
func percentile(samples []float64, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ksTwoSampleP 两样本 KS 检验：返回统计量 D 与渐近 p 值。
func ksTwoSampleP(a, b []float64) (float64, float64) {
	as := append([]float64(nil), a...)
	bs := append([]float64(nil), b...)
	sort.Float64s(as)
	sort.Float64s(bs)
	n1, n2 := len(as), len(bs)
	if n1 == 0 || n2 == 0 {
		return 0, 1
	}
	var d float64
	i, j := 0, 0
	for i < n1 || j < n2 {
		var x float64
		switch {
		case i == n1:
			x = bs[j]
		case j == n2:
			x = as[i]
		case as[i] <= bs[j]:
			x = as[i]
		default:
			x = bs[j]
		}
		for i < n1 && as[i] <= x {
			i++
		}
		for j < n2 && bs[j] <= x {
			j++
		}
		c1 := float64(i) / float64(n1)
		c2 := float64(j) / float64(n2)
		if diff := math.Abs(c1 - c2); diff > d {
			d = diff
		}
	}
	en := math.Sqrt(float64(n1*n2) / float64(n1+n2))
	lambda := (en + 0.12 + 0.11/en) * d
	sum := 0.0
	for k := 1; k <= 100; k++ {
		sum += 2 * math.Pow(-1, float64(k-1)) * math.Exp(-2*float64(k*k)*lambda*lambda)
	}
	p := sum
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	return d, p
}

// bmLookupCtx 构造基准用查询上下文。
func bmLookupCtx(hash string) LookupContext {
	return LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: hash,
		PromptText:      "benchmark prompt with enough tokens to be cacheable",
		PolicyVer:       "v1",
		GuardVer:        "v1",
	}
}

// TestBM1_ExactHitLatency BM-1：预填 8192 条目，测 Lookup p50/p95/p99，判据 p95 < 1ms。
func TestBM1_ExactHitLatency(t *testing.T) {
	bmSkipShort(t)
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Exact.MaxEntries = 20000   // 保证 8192 预填不被淘汰
	cfg.WriteLimit.Enabled = false // 基准预填非请求驱动写入，关闭 §7.4.2 写入限流
	cfg.Guard.ReadFastCheck = false
	eng := NewCacheEngine(cfg)

	const prefill = 8192
	for i := 0; i < prefill; i++ {
		eng.Store(StoreContext{
			LookupContext: bmLookupCtx(fmt.Sprintf("h-%d", i)),
			Writable:      true,
		}, InferResult{Text: "benchmark response content", TokensOut: 20, Finish: "stop"})
	}

	// 采样方式：每样本连续 batch 次取均值（规避 Windows 时钟粒度导致的单次 0 读数）
	const batch = 100
	const samples = 2000
	durs := make([]float64, 0, samples)
	overallStart := time.Now()
	for s := 0; s < samples; s++ {
		start := time.Now()
		for k := 0; k < batch; k++ {
			i := (s*batch + k) % prefill
			r := eng.Lookup(bmLookupCtx(fmt.Sprintf("h-%d", i)))
			if !r.Hit {
				t.Fatalf("expected hit at i=%d, reason=%s", i, r.RejectReason)
			}
		}
		durs = append(durs, float64(time.Since(start).Nanoseconds())/float64(batch)/1e6) // ms/op
	}
	avgUs := float64(time.Since(overallStart).Nanoseconds()) / float64(samples*batch) / 1000.0
	p50 := percentile(durs, 0.50)
	p95 := percentile(durs, 0.95)
	p99 := percentile(durs, 0.99)
	t.Logf("BM-1 精确命中延迟（n=%d，预填=%d）：均值=%.2fµs；分位（每样本 %d 次取均）=p50 %.2fµs / p95 %.2fµs / p99 %.2fµs",
		samples*batch, prefill, avgUs, batch, p50*1000, p95*1000, p99*1000)
	if p95 >= 1.0 {
		t.Fatalf("BM-1 未达标：p95=%.3fms ≥ 1ms", p95)
	}
}

// TestBM4_JitterKS BM-4：hit/miss 各 1e4 采样，KS 检验，判据 p > 0.05（分布同源）。
func TestBM4_JitterKS(t *testing.T) {
	bmSkipShort(t)
	cfg := DefaultConfig()
	cfg.Semantic.Jitter.Enabled = true
	cfg.Semantic.Jitter.MaxMs = 20
	// 固定种子（BM-4 回归确定性）：hit/miss 同分布的 KS 检验在 H0 成立时，
	// 单次 p≤0.05 的固有误拒率约 5%，时间种子会让 CI 偶发红灯（KI flaky）。
	// 生产注入器仍用时间种子；判据 p>0.05 不变，实现若有真实偏差任何种子都会失败。
	j := newJitterInjectorWithSeed(&cfg, 1)

	const n = 10000
	hit := make([]float64, 0, n)
	miss := make([]float64, 0, n)
	ctx := bmLookupCtx("h")
	for i := 0; i < n; i++ {
		hit = append(hit, float64(j.Sample(ctx).Microseconds())/1000.0)
		miss = append(miss, float64(j.Sample(ctx).Microseconds())/1000.0)
	}
	d, p := ksTwoSampleP(hit, miss)
	t.Logf("BM-4 抖动 KS：D=%.4f p=%.4f（n=%d×2，max_ms=%d）", d, p, n, cfg.Semantic.Jitter.MaxMs)
	if p <= 0.05 {
		t.Fatalf("BM-4 未达标：p=%.4f ≤ 0.05（hit/miss 分布可区分）", p)
	}
}

// TestBM5_MemoryBudget BM-5：满载（8192 精确 + 5 万向量）后 ReadMemStats，判据 ≤ cache_memory_budget。
func TestBM5_MemoryBudget(t *testing.T) {
	bmSkipShort(t)
	cfg := DefaultConfig()
	cfg.Mode = ModeSemantic
	cfg.CacheMemoryBudget = ByteSize(256 * 1024 * 1024) // 基准预算 256MB
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Exact.MaxEntries = 20000   // 保证 8192 预填不被淘汰
	cfg.WriteLimit.Enabled = false // 基准预填非请求驱动写入，关闭 §7.4.2 写入限流
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)
	const prefill = 8192
	for i := 0; i < prefill; i++ {
		eng.Store(StoreContext{
			LookupContext: bmLookupCtx(fmt.Sprintf("h-%d", i)),
			Writable:      true,
		}, InferResult{Text: "benchmark response content", TokensOut: 20, Finish: "stop"})
	}

	const vecN = 50000
	idx := NewFlatVectorIndex(512, vecN)
	rng := rand.New(rand.NewSource(1))
	vec := make([]float32, 512)
	for i := 0; i < vecN; i++ {
		for k := range vec {
			vec[k] = rng.Float32()
		}
		if err := idx.Upsert(fmt.Sprintf("v-%d", i), vec, VectorMeta{
			TenantID: "t1", EngineType: "cmaas", Model: "m1", PolicyVer: "v1", GuardVer: "v1",
		}); err != nil {
			t.Fatalf("向量插入失败 i=%d: %v", i, err)
		}
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	runtime.KeepAlive(idx) // 防止索引在 ReadMemStats 前被判为死对象回收，导致测量失真
	used := int64(ms.HeapAlloc)
	t.Logf("BM-5 满载内存：HeapAlloc=%.1fMB Sys=%.1fMB 预算=%.0fMB（精确=%d，向量=%d×512）",
		float64(used)/1048576, float64(ms.Sys)/1048576, float64(cfg.CacheMemoryBudget)/1048576, prefill, vecN)
	if used > cfg.CacheMemoryBudget.Bytes() {
		t.Fatalf("BM-5 未达标：HeapAlloc=%d 字节 > 预算 %d 字节", used, cfg.CacheMemoryBudget.Bytes())
	}
}

// TestBM7_ColdStartExactReady BM-7（精确段）：进程启动到精确就绪 < 100ms（语义段含权重加载待真机）。
func TestBM7_ColdStartExactReady(t *testing.T) {
	bmSkipShort(t)
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	// 多次取均，规避 Windows 时钟粒度
	const iters = 200
	var eng CacheEngine
	start := time.Now()
	for i := 0; i < iters; i++ {
		eng = NewCacheEngine(cfg)
	}
	d := time.Since(start) / iters
	if eng == nil {
		t.Fatal("engine 构造失败")
	}
	t.Logf("BM-7 精确就绪（NewCacheEngine，mode=exact，%d 次均值）=%.2fµs（判据 <100ms；语义段含权重加载待真机）",
		iters, float64(d.Nanoseconds())/1000.0)
	if d > 100*time.Millisecond {
		t.Fatalf("BM-7 未达标：精确就绪耗时 %v ≥ 100ms", d)
	}
}

// TestBM8_FaultInjectionLatency BM-8：sidecar 不可达时命中路径快速失败，判据 ≤ embedder.timeout。
func TestBM8_FaultInjectionLatency(t *testing.T) {
	bmSkipShort(t)
	cfg := DefaultConfig()
	cfg.Mode = ModeSemantic
	cfg.Semantic.Enabled = true
	cfg.Semantic.Embedder.Kind = "sidecar"
	cfg.Semantic.Embedder.Endpoint = "http://127.0.0.1:1/embed" // 不可达端口
	cfg.Semantic.Embedder.HealthEndpoint = "http://127.0.0.1:1/health"
	cfg.Semantic.Embedder.Timeout = Duration(200 * time.Millisecond)
	cfg.Semantic.Embedder.FailOpen = true

	eng := NewCacheEngine(cfg)
	// 批量均值，规避 Windows 时钟粒度（单次查询为亚微秒级）
	const iters = 1000
	var r LookupResult
	start := time.Now()
	for i := 0; i < iters; i++ {
		r = eng.Lookup(bmLookupCtx("h-1"))
	}
	d := time.Since(start) / iters
	t.Logf("BM-8 sidecar 不可达 Lookup（%d 次均值）：%.2fµs（hit=%v reason=%s；timeout=%s）",
		iters, float64(d.Nanoseconds())/1000.0, r.Hit, r.RejectReason, cfg.Semantic.Embedder.Timeout.D())
	if d > cfg.Semantic.Embedder.Timeout.D() {
		t.Fatalf("BM-8 未达标：Lookup 耗时 %v > timeout %v", d, cfg.Semantic.Embedder.Timeout.D())
	}
}

// TestBM2_LocalReference_Backends BM-2 本地参考：flat 与 HNSW 后端检索延迟对照
// （**不含** embedder；端到端待真实 sidecar）。判据（p95 < 15ms）在本地对 HNSW 生效。
func TestBM2_LocalReference_Backends(t *testing.T) {
	bmSkipShort(t)
	// 规模可配（KI#5）：默认保持生产代表性全量档，CI / 本地冒烟用
	// CACHE_BM2_VECN / CACHE_BM2_DIM / CACHE_BM2_SAMPLES / CACHE_BM2_BATCH 降档。
	// p95<15ms 判据与产品代码均不变；全量档须由 make test-bm2-full 单独举证。
	vecN := bm2EnvInt(t, "CACHE_BM2_VECN", 50000)
	dim := bm2EnvInt(t, "CACHE_BM2_DIM", 512)
	samples := bm2EnvInt(t, "CACHE_BM2_SAMPLES", 200)
	hnswBatch := bm2EnvInt(t, "CACHE_BM2_BATCH", 50)
	t.Logf("BM-2 规模档：vecN=%d dim=%d samples=%d flatBatch=1 hnswBatch=%d（默认全量档 50000x512；CACHE_BM2_* 可覆写）",
		vecN, dim, samples, hnswBatch)
	rng := rand.New(rand.NewSource(2))
	vecs := make([][]float32, vecN)
	for i := range vecs {
		vecs[i] = randVec(rng, dim)
	}
	build := func(idx VectorIndex) time.Duration {
		start := time.Now()
		for i, v := range vecs {
			if err := idx.Upsert(fmt.Sprintf("v-%d", i), v, hnswTestMeta(i, "t1")); err != nil {
				t.Fatalf("插入失败 i=%d: %v", i, err)
			}
		}
		return time.Since(start)
	}

	flat := NewFlatVectorIndex(dim, vecN)
	flatBuild := build(flat)
	hn := NewHNSWVectorIndex(dim, vecN, 16, 200, 64)
	hnBuild := build(hn)

	// 采样：flat 昂贵（每样本 1 次），HNSW 快（每样本 50 次取均）
	measure := func(idx VectorIndex, samples, batch int) (p50, p95, p99 float64) {
		durs := make([]float64, 0, samples)
		for s := 0; s < samples; s++ {
			start := time.Now()
			for k := 0; k < batch; k++ {
				if _, err := idx.Search(randVec(rng, dim), 5, VectorFilter{TenantID: "t1"}); err != nil {
					t.Fatalf("检索失败: %v", err)
				}
			}
			durs = append(durs, float64(time.Since(start).Nanoseconds())/float64(batch)/1e6)
		}
		return percentile(durs, 0.50), percentile(durs, 0.95), percentile(durs, 0.99)
	}
	f50, f95, f99 := measure(flat, samples, 1)
	h50, h95, h99 := measure(hn, samples, hnswBatch)

	t.Logf("BM-2 本地参考（不含 embedder；向量=%d×%d）：flat 建索引=%.2fs 检索 p50/p95/p99 = %.2f/%.2f/%.2f ms",
		vecN, dim, flatBuild.Seconds(), f50, f95, f99)
	t.Logf("BM-2 本地参考（不含 embedder）：hnsw 建索引=%.2fs 检索 p50/p95/p99 = %.2f/%.2f/%.2f ms",
		hnBuild.Seconds(), h50, h95, h99)

	if h95 >= 15.0 {
		t.Fatalf("BM-2 本地参考（hnsw）未达标：p95=%.2fms ≥ 15ms", h95)
	}
	// 端到端判据（含 sidecar）待环境，本用例仅本地对照。
}
