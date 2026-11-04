package qwen

import (
	"testing"

	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
)

func tinyMat(rows, cols int) *maskedinfer.QuantizedMatrix {
	data := make([]int32, rows*cols)
	for i := range data {
		data[i] = int32(i % 7)
	}
	return &maskedinfer.QuantizedMatrix{
		Rows: rows, Cols: cols, Scale: 0.01, Data: data,
		ModBits: maskedinfer.Mod64, InputScale: maskedinfer.InputScale,
	}
}

// buildTinyWeights 构造一份结构合法、尺寸极小的 *Weights，用于验证 ModelWeights 契约，
// 不依赖任何 safetensors 文件。
func buildTinyWeights(t *testing.T) *Weights {
	t.Helper()
	cfg := QwenConfig{
		Layers: 2, Dim: 4, Heads: 2, KVHeads: 1, HeadDim: 2,
		FFN: 6, Vocab: 8, RopeTheta: 1e6, NormEps: 1e-6, MaxTokens: 16, TiedEmb: true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tiny cfg 非法: %v", err)
	}
	w := &Weights{Cfg: cfg}
	w.EmbedMat = tinyMat(cfg.Vocab, cfg.Dim)
	w.LMHeadMat = w.EmbedMat // tied
	for L := 0; L < cfg.Layers; L++ {
		w.AttnQ = append(w.AttnQ, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.AttnDim(), cfg.Dim)})
		w.AttnK = append(w.AttnK, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.KVDim(), cfg.Dim)})
		w.AttnV = append(w.AttnV, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.KVDim(), cfg.Dim)})
		w.AttnO = append(w.AttnO, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.Dim, cfg.AttnDim())})
		w.Gate = append(w.Gate, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.FFN, cfg.Dim)})
		w.Up = append(w.Up, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.FFN, cfg.Dim)})
		w.Down = append(w.Down, []*maskedinfer.QuantizedMatrix{tinyMat(cfg.Dim, cfg.FFN)})
		w.LNIn = append(w.LNIn, []float64{1, 1, 1, 1})
		w.LNPost = append(w.LNPost, []float64{1, 1, 1, 1})
		w.QNorm = append(w.QNorm, []float64{1, 1}) // 长度 = HeadDim
		w.KNorm = append(w.KNorm, []float64{1, 1})
	}
	w.LNFinal = []float64{1, 1, 1, 1}
	return w
}

func TestWeightsImplementsModelWeights(t *testing.T) {
	w := buildTinyWeights(t)
	// 编译期接口断言 + 运行期断言
	var _ route2demo.ModelWeights = w
	if _, ok := interface{}(w).(route2demo.ModelWeights); !ok {
		t.Fatal("*Weights 未实现 route2demo.ModelWeights")
	}

	// Config()
	cfg := w.Config()
	if cfg.Blocks != w.Cfg.Layers || cfg.FFNDim != w.Cfg.FFN {
		t.Fatalf("Config() 字段错: blocks=%d(=%d) ffnDim=%d(=%d)", cfg.Blocks, w.Cfg.Layers, cfg.FFNDim, w.Cfg.FFN)
	}
	if cfg.FFNType != route2plan.FFNTypeSwiGLU {
		t.Fatalf("Config().FFNType=%q 应为 swiglu", cfg.FFNType)
	}
	if !cfg.QKNorm {
		t.Fatal("Config().QKNorm 应为 true（tiny weights 带 QK-norm）")
	}
	// RoPE 配对约定必须显式为 Qwen/LLaMA 的前后半劈：缺省会让生产链路沿用 demo 的
	// 相邻对，数值"接近但错"，且只有外部 golden 能发现（T5 实测）。
	if cfg.RopeStyle != route2plan.RopeStyleHalf {
		t.Fatalf("Config().RopeStyle=%q 应为 %q", cfg.RopeStyle, route2plan.RopeStyleHalf)
	}
	if cfg.KVHeads != w.Cfg.KVHeads {
		t.Fatalf("Config().KVHeads=%d 应为 %d", cfg.KVHeads, w.Cfg.KVHeads)
	}

	// Matrix 各张量形状正确
	checks := []struct {
		key                route2plan.TensorKey
		wantRows, wantCols int
	}{
		{route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorAttnQ}, w.Cfg.AttnDim(), w.Cfg.Dim},
		{route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK}, w.Cfg.KVDim(), w.Cfg.Dim},
		{route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnV}, w.Cfg.KVDim(), w.Cfg.Dim},
		{route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnO}, w.Cfg.Dim, w.Cfg.AttnDim()},
		{route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorFFNUp}, w.Cfg.FFN, w.Cfg.Dim},
		{route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorGate}, w.Cfg.FFN, w.Cfg.Dim},
		{route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorFFNDown}, w.Cfg.Dim, w.Cfg.FFN},
		{route2plan.TensorKey{Block: w.Cfg.Layers, Tensor: route2plan.TensorLMHead}, w.Cfg.Vocab, w.Cfg.Dim},
		{route2plan.TensorKey{Block: w.Cfg.Layers, Tensor: route2plan.TensorTokEmb}, w.Cfg.Vocab, w.Cfg.Dim},
	}
	for _, c := range checks {
		m, err := w.Matrix(c.key)
		if err != nil {
			t.Fatalf("Matrix(%s) 报错: %v", c.key.String(), err)
		}
		if m.Rows != c.wantRows || m.Cols != c.wantCols {
			t.Fatalf("Matrix(%s) 形状 = %dx%d, want %dx%d", c.key.String(), m.Rows, m.Cols, c.wantRows, c.wantCols)
		}
	}

	// Affine 各归一化张量
	gi, _, err := w.Affine(route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorLNIn})
	if err != nil || len(gi) != w.Cfg.Dim {
		t.Fatalf("Affine(ln_in) 异常: len=%d err=%v", len(gi), err)
	}
	gf, _, err := w.Affine(route2plan.TensorKey{Block: w.Cfg.Layers, Tensor: route2plan.TensorLNFinal})
	if err != nil || len(gf) != w.Cfg.Dim {
		t.Fatalf("Affine(ln_final) 异常: len=%d err=%v", len(gf), err)
	}
	gq, _, err := w.Affine(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorQNorm})
	if err != nil || len(gq) != w.Cfg.HeadDim {
		t.Fatalf("Affine(q_norm) 异常: len=%d err=%v", len(gq), err)
	}
	gk, _, err := w.Affine(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorKNorm})
	if err != nil || len(gk) != w.Cfg.HeadDim {
		t.Fatalf("Affine(k_norm) 异常: len=%d err=%v", len(gk), err)
	}

	// ln_final 错误 block 必须 fail-closed
	if _, _, err := w.Affine(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNFinal}); err == nil {
		t.Fatal("ln_final 错误 block 应报错")
	}
}

// TestRealQwen3PlanBuilds 验证真实 Qwen3-0.6b（attnDim=2048 ≠ Dim=1024）能走通
// 生产链路 plan：route2plan 必须支持「注意力投影宽度 attnDim 与残差流宽度 Dim 解耦」，
// 否则真实权重接入（T4）根本无法构建 plan——这是 T4 多角色评估暴露的阻塞点。
//
// 关键不变量（最小化修改后必须保持）：
//   - attention 步的输出宽度 == attnDim（Heads*HeadDim），因为它产出的是拼接多头注意力结果，
//     紧接着由 attn_residual 步里的 Wo（[Dim, attnDim]）映回 Dim；
//   - attn_residual 步的第一输入（注意力输出）宽度 == attnDim，第二输入（残差 h）== Dim。
func TestRealQwen3PlanBuilds(t *testing.T) {
	cfg := Qwen3_06B().ToModelConfig(true)
	// 生产链路里 model_id 由 resolveModel 在返回前填入（ToModelConfig 自身不知晓部署侧
	// model_id），此处镜像该行为，避免被「ModelID 为空」这条护栏挡在 attnDim 解耦问题之前。
	cfg.ModelID = "qwen3-0.6b" // 须与 tee-infer-service/state_machine.go 的 realQwenModelID 一致
	if cfg.AttnDim() == cfg.Dim {
		t.Fatalf("测试前提失效：Qwen3-0.6b 应 attnDim=%d ≠ Dim=%d 才能压测解耦路径", cfg.AttnDim(), cfg.Dim)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("真实 Qwen3 cfg 被 route2plan.Validate 拒绝（attnDim≠Dim 未被支持）: %v", err)
	}
	plan, err := route2plan.Build(cfg)
	if err != nil {
		t.Fatalf("真实 Qwen3 的 route2 plan 构建失败（attnDim=%d≠Dim=%d 未被支持）: %v",
			cfg.AttnDim(), cfg.Dim, err)
	}

	var attn, ares, kvk, kvv *route2plan.StepSpec
	for i := range plan {
		s := &plan[i]
		if s.Coord.Step == route2plan.StepKVAppend && s.Coord.Branch == route2plan.BranchQ {
			attn = s
		}
		if s.Coord.Step == route2plan.StepAttnResidual && s.Coord.Branch == route2plan.BranchMain {
			ares = s
		}
		if s.Coord.Step == route2plan.StepKVAppend && s.Coord.Branch == route2plan.BranchK {
			kvk = s
		}
		if s.Coord.Step == route2plan.StepKVAppend && s.Coord.Branch == route2plan.BranchV {
			kvv = s
		}
	}
	if attn == nil {
		t.Fatal("plan 缺少 attention 步（StepKVAppend/BranchQ）")
	}
	if ares == nil {
		t.Fatal("plan 缺少 attn_residual 步（StepAttnResidual/BranchMain）")
	}
	if kvk == nil || kvv == nil {
		t.Fatal("plan 缺少 kv_append_k / kv_append_v 步")
	}
	if attn.Op != route2plan.OpAttention {
		t.Fatalf("attn 步 op=%q 应为 %q", attn.Op, route2plan.OpAttention)
	}
	// attention：输入（Q 投影输出）宽 attnDim，输出（多头拼接）宽 attnDim。
	if attn.InDim[0] != cfg.AttnDim() {
		t.Fatalf("attention 步输入宽度=%d 应等于 attnDim=%d（Q 投影输出）", attn.InDim[0], cfg.AttnDim())
	}
	if attn.OutDim != cfg.AttnDim() {
		t.Fatalf("attention 步 OutDim=%d 应等于 attnDim=%d（多头拼接宽度）", attn.OutDim, cfg.AttnDim())
	}
	// kv_append_k/v：输入宽 == KVDim（GQA 下 K/V 投影输出宽度，非 attnDim）。
	if kvk.InDim[0] != cfg.KVDim() {
		t.Fatalf("kv_append_k 输入宽度=%d 应等于 KVDim=%d（GQA 下 ≠ attnDim）", kvk.InDim[0], cfg.KVDim())
	}
	if kvv.InDim[0] != cfg.KVDim() {
		t.Fatalf("kv_append_v 输入宽度=%d 应等于 KVDim=%d（GQA 下 ≠ attnDim）", kvv.InDim[0], cfg.KVDim())
	}
	if cfg.KVDim() == cfg.AttnDim() {
		t.Fatal("测试前提失效：Qwen3-0.6b 应 KVDim≠attnDim 才能压测 GQA 解耦路径")
	}
	if got := ares.InDim[0]; got != cfg.AttnDim() {
		t.Fatalf("attn_residual 第一输入宽度=%d 应等于 attnDim=%d", got, cfg.AttnDim())
	}
	if got := ares.InDim[1]; got != cfg.Dim {
		t.Fatalf("attn_residual 残差输入宽度=%d 应等于 Dim=%d", got, cfg.Dim)
	}
	// 整体 plan 自洽性
	if err := plan.Validate(); err != nil {
		t.Fatalf("真实 Qwen3 plan 自校验失败: %v", err)
	}
}
