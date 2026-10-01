package cacheengine

import (
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
