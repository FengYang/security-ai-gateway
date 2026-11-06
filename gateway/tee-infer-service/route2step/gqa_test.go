package route2step

import (
	"errors"
	"testing"

	"github.com/FengYang/masked-infer/plan"
)

// gqaCfg 一个 GQA 配置：Heads=4 / KVHeads=2 / HeadDim=4 ⇒ Dim=16，KVDim=8（!= Dim）。
// 用于验证 KV cache 行宽跟随 KVDim 而非 Dim，以及 plan 装配不依赖 KV 维度硬编码。
func gqaCfg() route2plan.ModelConfig {
	return route2plan.ModelConfig{
		ModelID:   "gqa-test",
		Blocks:    2,
		Dim:       16,
		Heads:     4,
		KVHeads:   2,
		HeadDim:   4,
		FFNDim:    32,
		Vocab:     64,
		NormEps:   1e-6,
		RopeTheta: 1e4,
		MaxTokens: 128,
	}
}

// TestKVCacheGQAWidth 验证 GQA 下 KV 行宽 == KVDim（KVHeads*HeadDim），
// 以 Dim 宽度的向量追加必须被拒（ErrVecLength）。
func TestKVCacheGQAWidth(t *testing.T) {
	cfg := gqaCfg()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("GQA 配置非法: %v", err)
	}
	if cfg.KVDim() != 8 {
		t.Fatalf("KVDim 应为 8，实际 %d", cfg.KVDim())
	}
	if cfg.AttnDim() != 16 {
		t.Fatalf("AttnDim 应为 16（== Dim），实际 %d", cfg.AttnDim())
	}

	c, err := NewKVCache(cfg)
	if err != nil {
		t.Fatalf("NewKVCache 失败: %v", err)
	}
	// 正确宽度（KVDim=8）追加成功
	if err := c.AppendK(0, make([]float64, 8)); err != nil {
		t.Fatalf("AppendK(KVDim 宽) 应成功: %v", err)
	}
	if err := c.AppendV(0, make([]float64, 8)); err != nil {
		t.Fatalf("AppendV(KVDim 宽) 应成功: %v", err)
	}
	// 错误宽度（Dim=16）追加必须被拒
	if err := c.AppendK(0, make([]float64, 16)); !errors.Is(err, ErrVecLength) {
		t.Errorf("AppendK(Dim 宽) 应拒 ErrVecLength，得到 %v", err)
	}
}

// TestBuildTurnGQA 验证 GQA 配置能正常产出 plan（不依赖 KV 维度硬编码）。
func TestBuildTurnGQA(t *testing.T) {
	cfg := gqaCfg()
	p, err := route2plan.Build(cfg)
	if err != nil {
		t.Fatalf("Build(GQA) 失败: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("GQA plan 自校验失败: %v", err)
	}
	// 末步必须是 argmax，且 plan 长度符合 Blocks*StepsPerBlock + TailSteps
	want := cfg.Blocks*route2plan.StepsPerBlock + route2plan.TailSteps
	if len(p) != want {
		t.Errorf("plan 长度 %d != %d", len(p), want)
	}
}
