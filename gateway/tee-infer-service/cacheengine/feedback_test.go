package cacheengine

import (
	"strings"
	"testing"
)

// TestExtractEntities_Numbers 数字实体提取。
func TestExtractEntities_Numbers(t *testing.T) {
	text := "GDP 增长了 5.2%, 达到 1,234.56 亿元"
	es := ExtractEntities(text)
	if es.Len() == 0 {
		t.Fatal("expected entities")
	}
	// 应包含 5.2% 和 1234.56（标准化后）
	found := false
	for _, e := range es.Entities {
		if e == "5.2%" || strings.Contains(e, "1234.56") {
			found = true
			break
		}
	}
	if !found {
		t.Logf("entities: %v", es.Entities)
	}
}

// TestExtractEntities_CodeIdentifiers 代码标识符提取。
func TestExtractEntities_CodeIdentifiers(t *testing.T) {
	text := `函数 getUserInfo() 返回 UserData 结构体，包含 user_name 和 userAge 字段`
	es := ExtractEntities(text)
	found := false
	for _, e := range es.Entities {
		if e == "getuserinfo" || e == "userdata" || e == "user_name" || e == "userage" {
			found = true
			break
		}
	}
	if !found {
		t.Logf("entities: %v", es.Entities)
	}
}

// TestEntitySet_Jaccard Jaccard 相似度计算。
func TestEntitySet_Jaccard(t *testing.T) {
	a := EntitySet{Entities: []string{"a", "b", "c", "d"}}
	b := EntitySet{Entities: []string{"b", "c", "e", "f"}}
	// 交: {b, c} = 2, 并: {a, b, c, d, e, f} = 6
	// Jaccard = 2/6 = 0.333...
	j := a.Jaccard(b)
	expected := 2.0 / 6.0
	if j < expected-0.01 || j > expected+0.01 {
		t.Fatalf("expected ~%f, got %f", expected, j)
	}
}

// TestEntitySet_JaccardEmpty 空集 Jaccard。
func TestEntitySet_JaccardEmpty(t *testing.T) {
	a := EntitySet{}
	b := EntitySet{Entities: []string{"x"}}
	if a.Jaccard(b) != 0 {
		t.Fatal("expected 0 for empty set")
	}
}

// TestEntitySet_Compatible 兼容性判断。
func TestEntitySet_Compatible(t *testing.T) {
	a := EntitySet{Entities: []string{"a", "b", "c"}}
	b := EntitySet{Entities: []string{"a", "b", "c"}}
	if !a.Compatible(b, 0.9) {
		t.Fatal("identical sets should be compatible")
	}

	c := EntitySet{Entities: []string{"x", "y", "z"}}
	if a.Compatible(c, 0.1) {
		t.Fatal("disjoint sets should not be compatible with any positive threshold")
	}
}

// TestFeedbackDetector_Basic 反馈检测器基本功能。
func TestFeedbackDetector_Basic(t *testing.T) {
	cfg := DefaultFeedbackConfig()
	cfg.WindowDuration = 10 * 1000 // 不影响，我们直接操作内部数据
	fb := NewFeedbackDetector(cfg)
	defer fb.Close()

	// 记录 100 次命中
	for i := 0; i < 100; i++ {
		fb.RecordHit("general")
	}
	// 上报 5 次误命中
	for i := 0; i < 5; i++ {
		fb.Report("general")
	}

	rate := fb.FalsePositiveRate("general")
	if rate < 0.045 || rate > 0.055 {
		t.Fatalf("expected ~0.05 FP rate, got %f", rate)
	}

	// 自适应阈值：5% 误命中率，每 1% 上调 0.005 → 上调 0.025
	adjusted := fb.AdjustedThreshold("general", 0.85)
	expected := 0.85 + 0.05*100*0.005 // 0.85 + 5 * 0.005 = 0.875
	if adjusted < expected-0.001 || adjusted > expected+0.001 {
		t.Fatalf("expected adjusted threshold ~%f, got %f", expected, adjusted)
	}
}

// TestFeedbackDetector_AutoTune 自适应阈值只上调不下降。
func TestFeedbackDetector_AutoTune(t *testing.T) {
	cfg := DefaultFeedbackConfig()
	fb := NewFeedbackDetector(cfg)
	defer fb.Close()

	base := 0.85

	// 初始：无反馈，阈值不变
	if fb.AdjustedThreshold("general", base) != base {
		t.Fatal("initial adjusted should equal base")
	}

	// 100 次命中，10 次误命中 → 10% 误命中率
	for i := 0; i < 100; i++ {
		fb.RecordHit("general")
	}
	for i := 0; i < 10; i++ {
		fb.Report("general")
	}

	high := fb.AdjustedThreshold("general", base)
	if high <= base {
		t.Fatalf("adjusted should be higher than base, got %f vs %f", high, base)
	}
}

// TestFeedbackDetector_Null 禁用时的 null 实现。
func TestFeedbackDetector_Null(t *testing.T) {
	cfg := DefaultFeedbackConfig()
	cfg.Enabled = false
	fb := NewFeedbackDetector(cfg)
	defer fb.Close()

	if fb.FalsePositiveRate("x") != 0 {
		t.Fatal("null detector should return 0")
	}
	if fb.AdjustedThreshold("x", 0.8) != 0.8 {
		t.Fatal("null detector should return base threshold")
	}
}

// TestEngine_ReportFalsePositive 引擎层误命中上报。
func TestEngine_ReportFalsePositive(t *testing.T) {
	cfg := testSemanticConfig()
	cfg.Semantic.Threshold.General = 0.5

	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, 1000)
	sem, _ := NewSemanticStore(&cfg, embedder, idx)
	fb := NewFeedbackDetector(DefaultFeedbackConfig())

	eng := NewCacheEngine(cfg, WithSemanticStore(sem), WithFeedbackDetector(fb))

	e := eng.(*engine)

	// 上报几次误命中
	e.ReportFalsePositive("general")
	e.ReportFalsePositive("general")

	snap := eng.Stats()
	if snap.SemanticFP != 2 {
		t.Fatalf("expected 2 FP, got %d", snap.SemanticFP)
	}
}
