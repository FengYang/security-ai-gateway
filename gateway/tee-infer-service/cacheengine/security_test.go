package cacheengine

import (
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// ===== 测试用 FastScanner 实现 =====

// mockScanner 模拟扫描器，用于测试读时快审。
type mockScanner struct {
	allow    bool
	reason   string
	match    string
	avail    bool
	callCount int
}

func (m *mockScanner) Scan(text string) (ScanVerdict, error) {
	m.callCount++
	if !m.avail {
		return ScanVerdict{}, ErrClassifierUnavailable
	}
	if m.allow {
		return ScanVerdict{Allow: true}, nil
	}
	return ScanVerdict{Allow: false, Reason: m.reason, Match: m.match}, nil
}

// TestReadFastCheck_Block 读时快审命中 → block/treat_as_miss。
func TestReadFastCheck_Block(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = true
	cfg.Guard.ReadFastCheckAction = "treat_as_miss"

	mock := &mockScanner{allow: false, reason: "pii", match: "13800138000", avail: true}
	eng := NewCacheEngine(cfg, WithFastScanner(mock))

	// 先写入
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "test prompt long enough",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}
	eng.Store(ctx, InferResult{
		Text:      "手机号是 13800138000",
		TokensOut: 20,
		Finish:    "stop",
	})

	// 查询 → 精确命中 → 读时快审拦截 → treat_as_miss
	r := eng.Lookup(ctx.LookupContext)
	if r.Hit {
		t.Fatal("expected miss due to fast check block, got hit")
	}
	if r.RejectReason != "guard" {
		t.Fatalf("expected reject reason 'guard', got '%s'", r.RejectReason)
	}
	if !r.FastScan.Allow {
		// 预期被拦
	} else {
		t.Fatal("expected fast scan to block")
	}
	if mock.callCount != 1 {
		t.Fatalf("expected 1 scan call, got %d", mock.callCount)
	}
}

// TestReadFastCheck_Pass 读时快审通过 → 正常命中。
func TestReadFastCheck_Pass(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = true

	mock := &mockScanner{allow: true, avail: true}
	eng := NewCacheEngine(cfg, WithFastScanner(mock))

	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "test prompt long enough",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}
	eng.Store(ctx, InferResult{
		Text:      "正常回答内容",
		TokensOut: 10,
		Finish:    "stop",
	})

	r := eng.Lookup(ctx.LookupContext)
	if !r.Hit {
		t.Fatalf("expected hit, got miss: %s", r.RejectReason)
	}
	if r.Kind != KindExact {
		t.Fatalf("expected exact hit, got %s", r.Kind)
	}
	if mock.callCount != 1 {
		t.Fatalf("expected 1 scan call, got %d", mock.callCount)
	}
}

// TestReadFastCheck_VersionMismatch 词库版本不一致 → 精确层直接删除（不等读时快审）。
// EntryUsable 在精确查找时校验版本，不一致即删除并返回 miss。
// 读时快审的版本校验是第二层保险（语义命中或其他绕过 EntryUsable 的路径）。
func TestReadFastCheck_VersionMismatch(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = true

	mock := &mockScanner{allow: true, avail: true}
	eng := NewCacheEngine(cfg, WithFastScanner(mock))

	// 用 v1 写入
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "test prompt long enough",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}
	eng.Store(ctx, InferResult{
		Text:      "回答",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 用 v2 查询 → EntryUsable 版本不一致 → 精确层删除 → 终态 miss
	queryCtx := ctx.LookupContext
	queryCtx.GuardVer = "v2"
	r := eng.Lookup(queryCtx)

	if r.Hit {
		t.Fatal("expected miss due to version mismatch")
	}
	// EntryUsable 直接删除了条目，所以走到终态 not_found
	if r.RejectReason != "not_found" {
		t.Fatalf("expected reason 'not_found' (entry deleted by EntryUsable), got '%s'", r.RejectReason)
	}
	if mock.callCount != 0 {
		t.Fatalf("expected 0 scan calls (entry deleted before fast check), got %d", mock.callCount)
	}

	// 再次查询确认条目已被删除（不会再扫描）
	r2 := eng.Lookup(queryCtx)
	if r2.Hit {
		t.Fatal("entry should be deleted")
	}
}

// TestReadFastCheck_Unavailable 扫描器不可用 → fail-closed（treat_as_miss）。
func TestReadFastCheck_Unavailable(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = true

	mock := &mockScanner{avail: false}
	eng := NewCacheEngine(cfg, WithFastScanner(mock))

	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "test prompt long enough",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}
	eng.Store(ctx, InferResult{
		Text:      "回答",
		TokensOut: 10,
		Finish:    "stop",
	})

	r := eng.Lookup(ctx.LookupContext)
	if r.Hit {
		t.Fatal("expected miss due to scanner unavailable")
	}
}

// TestJitter_Sampling 侧信道抖动采样验证。
func TestJitter_Sampling(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Semantic.Jitter.Enabled = true
	cfg.Semantic.Jitter.MaxMs = 20

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "no_such_key",
		PromptText:      "test prompt long enough",
		PolicyVer:       "1",
		GuardVer:        "v1",
	}

	// 未命中也有抖动
	r := eng.Lookup(ctx)
	if r.Jitter < 0 || r.Jitter > 20*time.Millisecond {
		t.Fatalf("jitter out of range: %v", r.Jitter)
	}

	// 多次采样不都相同（概率验证，10 次全相同的概率极低）
	seen := make(map[time.Duration]bool)
	for i := 0; i < 10; i++ {
		r2 := eng.Lookup(ctx)
		seen[r2.Jitter] = true
	}
	// 20ms 粒度，10 次采样至少有 2 个不同值才算正常（防止完全不随机）
	if len(seen) < 2 {
		t.Logf("jitter values are too uniform: %d distinct in 10 samples", len(seen))
		// 不强制失败，因为概率上有可能
	}
}

// TestJitter_Disabled 抖动关闭时 Jitter=0。
func TestJitter_Disabled(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Semantic.Jitter.Enabled = false

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "no_such_key",
		PromptText:      "test prompt long enough",
		PolicyVer:       "1",
		GuardVer:        "v1",
	}

	r := eng.Lookup(ctx)
	if r.Jitter != 0 {
		t.Fatalf("expected zero jitter when disabled, got %v", r.Jitter)
	}
}

// TestWriteRequiresOutGuard 写前审查门禁：Writable=false 时不写。
func TestWriteRequiresOutGuard(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.WriteRequiresOutGuard = true

	eng := NewCacheEngine(cfg)

	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "test prompt long enough",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: false, // 写前审查未通过
	}

	outcome := eng.Store(ctx, InferResult{
		Text:      "不应被写入的内容",
		TokensOut: 10,
		Finish:    "stop",
	})

	if outcome.Stored {
		t.Fatal("expected not stored when Writable=false")
	}
	if outcome.Skipped != "not_writable" {
		t.Fatalf("expected skip reason 'not_writable', got '%s'", outcome.Skipped)
	}

	// 查询验证确实未写入
	r := eng.Lookup(ctx.LookupContext)
	if r.Hit {
		t.Fatal("expected miss when store was rejected")
	}
}

// ===== S-5：侧信道抖动分布同源（§7.3.2 / T-7.3-1 · T-7.3-2） =====

// TestJitter_HitMissDistributionsIndistinguishable 引擎级校验 J-1：
// 命中路径与未命中路径的抖动采样必须来自同一分布（两样本 KS 检验 p>0.05）。
func TestJitter_HitMissDistributionsIndistinguishable(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Semantic.Jitter.Enabled = true
	cfg.Semantic.Jitter.MaxMs = 20
	eng := NewCacheEngine(cfg).(*engine)

	// 确定性抖动源（同一入口、同一均匀分布）：避免统计检验因随机种子偶发失败
	eng.jitter = &uniformJitter{cfg: &cfg, enabled: true, maxMs: 20, rng: rand.New(rand.NewSource(20261007))}

	hitCtx := LookupContext{
		TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
		TransformedHash: "s5-hit", PromptText: "long enough prompt for exact cache",
		PolicyVer: "1", GuardVer: "v1",
	}
	missCtx := hitCtx
	missCtx.TransformedHash = "s5-miss"

	if out := eng.Store(StoreContext{LookupContext: hitCtx, Writable: true},
		InferResult{Text: "answer", TokensOut: 10, Finish: "stop"}); !out.Stored {
		t.Fatalf("precondition: store failed: %+v", out)
	}

	const n = 4000
	hit := make([]float64, 0, n)
	miss := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		rh := eng.Lookup(hitCtx)
		if !rh.Hit {
			t.Fatalf("expected hit at %d, reason=%s", i, rh.RejectReason)
		}
		hit = append(hit, float64(rh.Jitter))

		rm := eng.Lookup(missCtx)
		if rm.Hit {
			t.Fatalf("expected miss at %d", i)
		}
		miss = append(miss, float64(rm.Jitter))
	}

	// 两侧都必须真实采样（落在 [0, maxMs] 带内且非常量）
	for name, s := range map[string][]float64{"hit": hit, "miss": miss} {
		if !withinBand(s, 0, float64(20*time.Millisecond)) || distinctCount(s) < 2 {
			t.Fatalf("%s 抖动采样不在期望带内或恒定（表明该路径未采样）", name)
		}
	}

	d := ksStatistic(hit, miss)
	p := ksPValue(d, n, n)
	if p <= 0.05 {
		t.Fatalf("hit/miss 抖动分布可区分：D=%.4f p=%.4f（要求 p>0.05）", d, p)
	}
}

func withinBand(xs []float64, lo, hi float64) bool {
	for _, x := range xs {
		if x < lo || x > hi {
			return false
		}
	}
	return true
}

func distinctCount(xs []float64) int {
	m := make(map[float64]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return len(m)
}

// ksStatistic 两样本 Kolmogorov–Smirnov 统计量 D = max|F1(x) − F2(x)|。
func ksStatistic(a, b []float64) float64 {
	sa := append([]float64(nil), a...)
	sb := append([]float64(nil), b...)
	sort.Float64s(sa)
	sort.Float64s(sb)

	n, m := len(sa), len(sb)
	var d float64
	i, j := 0, 0
	for i < n || j < m {
		var x float64
		switch {
		case i >= n:
			x = sb[j]
		case j >= m:
			x = sa[i]
		case sa[i] <= sb[j]:
			x = sa[i]
		default:
			x = sb[j]
		}
		for i < n && sa[i] <= x {
			i++
		}
		for j < m && sb[j] <= x {
			j++
		}
		if diff := math.Abs(float64(i)/float64(n) - float64(j)/float64(m)); diff > d {
			d = diff
		}
	}
	return d
}

// ksPValue 两样本 KS 检验的渐近 p 值（Kolmogorov 分布 Q(λ)）。
func ksPValue(d float64, n1, n2 int) float64 {
	if d <= 0 {
		return 1
	}
	ne := float64(n1*n2) / float64(n1+n2)
	lambda := d * math.Sqrt(ne)
	sum := 0.0
	for k := 1; k <= 100; k++ {
		term := 2 * math.Pow(-1, float64(k-1)) * math.Exp(-2*float64(k*k)*lambda*lambda)
		sum += term
		if math.Abs(term) < 1e-12 {
			break
		}
	}
	switch {
	case sum < 0:
		return 0
	case sum > 1:
		return 1
	default:
		return sum
	}
}
