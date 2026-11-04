package orchestrator

import (
	"math/rand"
	"testing"

	"security-ai-gateway/gateway/teecore/adapters/qwen"
	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// 编译期断言：qwen 适配器满足网关侧 ModelAdapter 契约。
var _ ModelAdapter = (*qwen.Weights)(nil)

func smallCfg() qwen.QwenConfig {
	return qwen.QwenConfig{
		Layers: 2, Dim: 16, Heads: 4, KVHeads: 2, HeadDim: 4,
		FFN: 32, Vocab: 50, RopeTheta: 1e6, NormEps: 1e-6, MaxTokens: 64, TiedEmb: true,
	}
}

// TestFormAEquivalence 验证形态A（词表在网关）与形态B（词表在后端）数值等价。
//   - 形态B：ForwardMasked 直接返回 logits（Embed/LMHead 均在后端）
//   - 形态A：网关加掩嵌入 → 后端 ForwardMaskedEmb（吐掩码 hidden）→ 网关 GatewayLMHead
//     二者应给出完全相同（int8 量化下一致）的 argmax 与可忽略的 logits 差。
func TestFormAEquivalence(t *testing.T) {
	rand.Seed(123)
	cfg := smallCfg()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	w := qwen.SyntheticWeights(cfg, 1)
	tokens := []int{1, 2, 3}
	rGW := GenOTP(cfg.Dim, maskedinfer.Mod64)

	// 形态B：词表在后端
	logitsB, err := qwen.ForwardMasked(w, tokens)
	if err != nil {
		t.Fatalf("ForwardMasked: %v", err)
	}
	// 形态A：词表在网关（OTP 加掩嵌入 → 后端 → 网关 LMHead）
	logitsA, err := ForwardMaskedFormA(w, tokens, rGW)
	if err != nil {
		t.Fatalf("ForwardMaskedFormA: %v", err)
	}
	// 真值参照：去量化 int8 权重（无掩码/无定点）
	ref, err := qwen.ForwardRef(w, tokens)
	if err != nil {
		t.Fatalf("ForwardRef: %v", err)
	}

	repAB, err := qwen.Compare(logitsA, logitsB, 0, 5e-2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("形态A vs 形态B: MaxAbsDiff=%.3e MaxRelDiff=%.3f Top1=%d/%d",
		repAB.MaxAbsDiff, repAB.MaxRelDiff, repAB.Top1Agree, repAB.Steps)
	if !repAB.Top1All {
		t.Fatalf("形态A 与形态B top-1 未全一致 %d/%d", repAB.Top1Agree, repAB.Steps)
	}
	// L2 验收门控（方案 §4 步骤4 / §6.1 R2）：形态A 与形态B 的 logits 绝对误差须 ≤5e-3。
	// 只断言 Top1 会漏掉"名次对但数值漂"的情形——而数值漂正是缩放域（÷Embed.Scale）
	// 写错时的唯一早期信号（§6.1 R2：3.87/19.5 级前向爆炸复发）。
	if repAB.MaxAbsDiff > 5e-3 {
		t.Fatalf("形态A 与形态B MaxAbsDiff=%.3e 超阈值 5e-3（缩放域/掩码量化契约被破坏？）", repAB.MaxAbsDiff)
	}
	if repAB.MaxRelDiff > 1.0 {
		t.Fatalf("形态A 与形态B 误差过大 MaxRelDiff=%.3f（应 <=1.0）", repAB.MaxRelDiff)
	}

	repAR, err := qwen.Compare(logitsA, ref, 0, 5e-2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("形态A vs 参照: MaxAbsDiff=%.3e MaxRelDiff=%.3f Top1=%d/%d",
		repAR.MaxAbsDiff, repAR.MaxRelDiff, repAR.Top1Agree, repAR.Steps)
	if !repAR.Top1All {
		t.Fatalf("形态A 与参照 top-1 未全一致 %d/%d", repAR.Top1Agree, repAR.Steps)
	}
}

// TestFormAKVConsistency 验证形态A 的「prefill+decode 分步」与「一次性前向」给出相同掩码 hidden。
func TestFormAKVConsistency(t *testing.T) {
	rand.Seed(7)
	cfg := smallCfg()
	w := qwen.SyntheticWeights(cfg, 3)
	rGW := GenOTP(cfg.Dim, maskedinfer.Mod64)

	embAll, err := w.EmbedRows([]int{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	maskedAll := MaskEmbedding(w, embAll, rGW)
	all, err := qwen.ForwardMaskedEmb(w, maskedAll, rGW)
	if err != nil {
		t.Fatal(err)
	}
	lastAll := all[len(all)-1]

	embP, err := w.EmbedRows([]int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	maskedP := MaskEmbedding(w, embP, rGW)
	r := qwen.NewRunner(w)
	if _, err := r.StepEmb(maskedP, rGW); err != nil {
		t.Fatal(err)
	}
	emb4, err := w.EmbedRows([]int{4})
	if err != nil {
		t.Fatal(err)
	}
	masked4 := MaskEmbedding(w, emb4, rGW)
	dec2, err := r.StepEmb(masked4, rGW)
	if err != nil {
		t.Fatal(err)
	}
	lastDec := dec2[len(dec2)-1]

	maxd := 0.0
	for i := range lastAll {
		// 末层 hidden 是掩码域；比较其「掩码像本身」是否一致（同一 OTP 下应逐位相同）
		xa := int64(lastAll[i])
		xb := int64(lastDec[i])
		d := xa - xb
		if d < 0 {
			d = -d
		}
		df := float64(d)
		if df > maxd {
			maxd = df
		}
	}
	t.Logf("形态A KV 一致性 末位掩码 hidden 最大差=%v", maxd)
	if maxd != 0 {
		t.Fatalf("形态A prefill+decode 与一次性前向掩码 hidden 不一致 maxd=%v", maxd)
	}
}
