// plain_forward_test.go - 双基线参照前向测试（T02 验收项 1、2、5）
package route2ref

import (
	"math"
	"strings"
	"testing"

	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// demoCfg 引用 T01 的唯一常量源（禁止在本文件另抄一份数字）。
func demoCfg() route2plan.ModelConfig {
	return route2plan.DemoTinyConfig()
}

// demoTokens 确定性 token 序列（全部落在词表内）。
func demoTokens(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = (i*7 + 3) % route2plan.DemoVocab
	}
	return out
}

// sequential 逐个 token 喂（模拟"每步 decode 一次"），返回每步的 logits。
func sequential(t *testing.T, w Weights, cfg route2plan.ModelConfig, tokens []int) [][]float64 {
	t.Helper()
	r, err := NewRunner(w, cfg)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]float64, 0, len(tokens))
	for _, tok := range tokens {
		lg, err := r.Step([]int{tok})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, lg[0])
	}
	return out
}

// requireFinite 断言 logits 全部有限且维度正确（崩坏门禁：NaN/Inf 即失败，不分档）。
func requireFinite(t *testing.T, name string, logits [][]float64, wantRows, wantVocab int) {
	t.Helper()
	if len(logits) != wantRows {
		t.Fatalf("%s: logits 行数 = %d, want %d", name, len(logits), wantRows)
	}
	allSame := true
	first := logits[0][0]
	for i, row := range logits {
		if len(row) != wantVocab {
			t.Fatalf("%s: 第 %d 行的 logits 长度 = %d, want Vocab=%d", name, i, len(row), wantVocab)
		}
		for j, v := range row {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("%s: logits[%d][%d] = %v 非有限（触发 §8.1 崩坏门禁）", name, i, j, v)
			}
			if v != first {
				allSame = false
			}
		}
	}
	if allSame {
		t.Fatalf("%s: 所有 logits 完全相同（%v），前向退化掉了", name, first)
	}
}

// ---------- 验收项 1：自洽性 ----------

// TestForwardExactAndFP32Finite 两条基线在 prefill + decode 下都必须产出有限、非退化的 logits。
func TestForwardExactAndFP32Finite(t *testing.T) {
	cfg := demoCfg()
	toks := demoTokens(8)

	exact, err := ForwardExact(cfg, toks)
	if err != nil {
		t.Fatalf("ref-exact 前向失败: %v", err)
	}
	requireFinite(t, "ref-exact prefill", exact, len(toks), cfg.Vocab)

	fp32, err := ForwardFP32(cfg, toks)
	if err != nil {
		t.Fatalf("ref-fp32 前向失败: %v", err)
	}
	requireFinite(t, "ref-fp32 prefill", fp32, len(toks), cfg.Vocab)

	// decode：prefill 后连续再推 3 轮
	dec, err := ForwardExact(cfg, []int{toks[0], toks[1], toks[2]})
	if err != nil {
		t.Fatal(err)
	}
	requireFinite(t, "ref-exact decode", dec, 3, cfg.Vocab)
}

// TestGenerateProducesTokens 自回归生成必须产出词表内 token 且形状自洽。
func TestGenerateProducesTokens(t *testing.T) {
	cfg := demoCfg()
	w, err := NewExactWeights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logits, generated, err := Generate(w, cfg, demoTokens(4), 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated) != 6 {
		t.Fatalf("生成 token 数 = %d, want 6", len(generated))
	}
	if len(logits) != 6 {
		t.Fatalf("logits 步数 = %d, want 6", len(logits))
	}
	for i, tok := range generated {
		if tok < 0 || tok >= cfg.Vocab {
			t.Fatalf("生成 token[%d] = %d 越界", i, tok)
		}
	}
	requireFinite(t, "generate", logits, 6, cfg.Vocab)
}

// TestForwardDeterministic 同一输入两次前向必须逐位相同（§8.1 附加崩坏门禁之一）。
func TestForwardDeterministic(t *testing.T) {
	cfg := demoCfg()
	toks := demoTokens(6)
	a, err := ForwardExact(cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ForwardExact(cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				t.Fatalf("两次前向不逐位相同: [%d][%d] %v vs %v（确定性被破坏）", i, j, a[i][j], b[i][j])
			}
		}
	}
}

// ---------- 验收项 2：因果一致性（黄金判据） ----------

// TestPrefillEqualsSequentialDecode 批量 prefill 与「逐 token decode」必须逐位一致。
//
// 这是 Transformer 推理正确性的黄金判据：它同时拷问了
// ① batch 内每行的绝对位置是否算对、② 因果掩码是否真的屏蔽了同批次的"未来行"、
// ③ KV 追加顺序是否单调。任一处写错，这里都会炸，而别的检查（维度/NaN）全绿。
func TestPrefillEqualsSequentialDecode(t *testing.T) {
	cfg := demoCfg()
	toks := demoTokens(9)
	for _, kind := range []string{KindExact, KindFP32} {
		var w Weights
		var err error
		if kind == KindExact {
			w, err = NewExactWeights(cfg)
		} else {
			w, err = NewFP32Weights(cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		batch, err := Forward(w, cfg, toks)
		if err != nil {
			t.Fatal(err)
		}
		seq := sequential(t, w, cfg, toks)
		for i := range batch {
			for j := range batch[i] {
				if math.Abs(batch[i][j]-seq[i][j]) > 1e-12*math.Max(1, math.Abs(seq[i][j])) {
					t.Fatalf("[%s] 第 %d 个位置: batch=%v vs sequential=%v（因果性/位置错）",
						kind, i, batch[i][j], seq[i][j])
				}
			}
		}
	}
}

// TestPrefillThenDecodeEqualsLongerPrefill prefill→decode 交接：
// 「先喂前 k 个 token，再喂剩下的」== 「一次性喂全部」的对应位置结果。
func TestPrefillThenDecodeEqualsLongerPrefill(t *testing.T) {
	cfg := demoCfg()
	toks := demoTokens(10)
	w, err := NewExactWeights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oneShot, err := Forward(w, cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	split := 6
	r, err := NewRunner(w, cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.Step(toks[:split])
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Step(toks[split:])
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < split; i++ {
		for j := range first[i] {
			if math.Abs(first[i][j]-oneShot[i][j]) > 1e-12*math.Max(1, math.Abs(oneShot[i][j])) {
				t.Fatalf("prefill 段第 %d 行不一致: %v vs %v", i, first[i][j], oneShot[i][j])
			}
		}
	}
	for i := 0; i < len(second); i++ {
		for j := range second[i] {
			if math.Abs(second[i][j]-oneShot[split+i][j]) > 1e-12*math.Max(1, math.Abs(oneShot[split+i][j])) {
				t.Fatalf("decode 段第 %d 行不一致: %v vs %v", i, second[i][j], oneShot[split+i][j])
			}
		}
	}
	if r.Positions() != len(toks) {
		t.Fatalf("位置计数 = %d, want %d", r.Positions(), len(toks))
	}
}

// TestRunnerResetIsolatesSequences Reset 之后位置与 KV 必须归零，隔离不同序列。
func TestRunnerResetIsolatesSequences(t *testing.T) {
	cfg := demoCfg()
	w, err := NewExactWeights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(w, cfg)
	if err != nil {
		t.Fatal(err)
	}
	toks := demoTokens(5)
	a, err := r.Step(toks)
	if err != nil {
		t.Fatal(err)
	}
	r.Reset()
	if r.Positions() != 0 {
		t.Fatalf("Reset 后位置 = %d, want 0", r.Positions())
	}
	b, err := r.Step(toks)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				t.Fatalf("Reset 后同序列结果漂移: %v vs %v", a[i][j], b[i][j])
			}
		}
	}
}

// ---------- 验收项 5：双基线差异观测 ----------

// TestBaselineDivergence 观测 ref-exact 与 ref-fp32 之间的偏差（= int8 量化噪声）。
//
// 【重要·不要把它当成 G2 门禁】这里比较的是**两条参照基线之间的差异**，
// 而设计 §8.1 的档 A 比较的是「生产掩码管线 vs ref-exact」。二者不是同一件事。
//
// 本用例的做法：
//   - 用设计原文的档 B 阈值（rtol=5e-2，见 GradeBRtol）作为硬断言——这是设计自己给
//     "vs ref-fp32" 的容差，我不另invent 一个数；
//   - 同时把档 A 口径（rtol=1e-3）下的比值打印出来，交给团队判断是否需要调档；
//   - 额外断言 top-1 命中，避免"数值接近但语义已经不同"的情况被放过。
func TestBaselineDivergence(t *testing.T) {
	cfg := demoCfg()
	toks := demoTokens(8)
	exact, err := ForwardExact(cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	fp32, err := ForwardFP32(cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	atol := GradeAAtol * maxAbsLogit(fp32)

	// (a) 设计档 B 口径（rtol=5e-2）
	repB, err := Compare(exact, fp32, atol, GradeBRtol)
	if err != nil {
		t.Fatal(err)
	}
	if repB.MaxRelDiff > 1 {
		t.Fatalf("ref-exact vs ref-fp32 超出设计档 B 容差: 比值 %.4g > 1（atol=%g rtol=%g, maxAbs=%g）",
			repB.MaxRelDiff, atol, GradeBRtol, repB.MaxAbsDiff)
	}
	if !repB.Top1AgreeAll {
		t.Errorf("两条基线 top-1 不一致: %d/%d 步一致", repB.Top1Agree, repB.Steps)
	}
	t.Logf("档 B 口径(rtol=5e-2): MaxRelDiff=%.4g MaxAbsDiff=%.4g top1一致=%d/%d",
		repB.MaxRelDiff, repB.MaxAbsDiff, repB.Top1Agree, repB.Steps)

	// (b) 观测值：档 A 口径（rtol=1e-3）下的比值，仅记录，供团队裁定
	repA, err := Compare(exact, fp32, atol, GradeARtol)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("【观测·非门禁】档 A 口径(rtol=1e-3) 下 ref-exact vs ref-fp32: MaxRelDiff=%.4g MaxAbsDiff=%.4g maxAbs|logits|=%.4g",
		repA.MaxRelDiff, repA.MaxAbsDiff, maxAbsLogit(fp32))
	t.Logf("结论提示：若该数值远大于 1，说明 int8 量化噪声本身大于档 A 阈值，" +
		"档 A 只能用于「掩码管线 vs ref-exact」的对比，不能用于跨基线对比（详见回报）")
}

// ---------- ref-exact 语义锚定：与既有内核 PlainLinear 对拍 ----------

// TestExactWeightsMatchPlainLinear ref-exact 的取值必须与既有内核 QuantizedMatrix.PlainLinear
// 逐项一致（w = Scale*Data，且累加次序相同）。
//
// 这条用例的作用是防止"参照实现自己写了一套算子、自带一套 bug"：
// matVecRows 是 T02 新写的，PlainLinear 是 M0 就在用的内核，二者对得上才说明
// 我们对 int8 去量化的理解与既有内核一致。
func TestExactWeightsMatchPlainLinear(t *testing.T) {
	cfg := demoCfg()
	w, err := NewExactWeights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	keys := []route2plan.TensorKey{
		{Block: 0, Tensor: route2plan.TensorAttnQ},
		{Block: 1, Tensor: route2plan.TensorFFNUp},
		{Block: 2, Tensor: route2plan.TensorFFNDown},
		{Block: cfg.Blocks, Tensor: route2plan.TensorLMHead},
	}
	for _, k := range keys {
		m, err := route2demo.TensorWeights(cfg, k)
		if err != nil {
			t.Fatal(err)
		}
		x := [][]float64{deterministicVec(m.Cols, int64(k.Block)*31+7)}
		mine, err := matVecRows(w, k, x)
		if err != nil {
			t.Fatal(err)
		}
		kernel := m.PlainLinear(x)
		if len(mine[0]) != len(kernel[0]) {
			t.Fatalf("%s: 维度 %d vs %d", k, len(mine[0]), len(kernel[0]))
		}
		for i := range kernel[0] {
			d := math.Abs(mine[0][i] - kernel[0][i])
			scale := math.Max(1e-12, math.Abs(kernel[0][i]))
			if d/scale > 1e-12 {
				t.Fatalf("%s: ref-exact[%d]=%v 与 PlainLinear[%d]=%v 不一致（相对差 %g）",
					k, i, mine[0][i], i, kernel[0][i], d/scale)
			}
		}
	}
}

// TestWeightsBiasUnsupported fail-closed：含 bias 的权重矩阵必须报错而非静默丢弃。
func TestWeightsMatrixKeyGuards(t *testing.T) {
	cfg := demoCfg()
	e, err := NewExactWeights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNIn}); err == nil {
		t.Error("对归一化张量索取矩阵应报错")
	}
	// fp32 侧同样
	f, err := NewFP32Weights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNFinal}); err == nil {
		t.Error("哨兵块号的 ln_final 不是矩阵应报错")
	}
	if e.Kind() != KindExact || f.Kind() != KindFP32 {
		t.Fatalf("Kind() 错: %q / %q", e.Kind(), f.Kind())
	}
}

// ---------- 其它：入口 / 错误处理 / 对比工具 ----------

// TestSelftestEntry selftest 入口（供 cmd/route2-client --selftest 用）必须可用。
func TestSelftestEntry(t *testing.T) {
	rep, err := Selftest(demoCfg(), demoTokens(8))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Steps != 8 {
		t.Fatalf("Steps = %d, want 8", rep.Steps)
	}
	if rep.Logits != 8*demoCfg().Vocab {
		t.Fatalf("参与比较的 logit 数 = %d, want %d", rep.Logits, 8*demoCfg().Vocab)
	}
	if rep.MaxAbsDiff <= 0 {
		t.Fatal("两条基线不应完全相等（否则说明 ref-fp32 没真的用上未量化权重）")
	}
	if rep.Atol <= 0 || rep.Rtol <= 0 {
		t.Fatalf("atol/rtol 必须为正: %v / %v", rep.Atol, rep.Rtol)
	}
}

// TestCompareRejects Compare 的崩坏门禁（NaN/Inf 与形状不一致）。
func TestCompareRejects(t *testing.T) {
	a := [][]float64{{1, 2}, {3, 4}}
	if _, err := Compare(a, [][]float64{{1, 2}}, 0, 1e-3); err == nil {
		t.Error("步数不一致应报错")
	}
	if _, err := Compare(a, [][]float64{{1, 2}, {3}}, 0, 1e-3); err == nil {
		t.Error("logits 长度不一致应报错")
	}
	nan := [][]float64{{1, math.NaN()}, {3, 4}}
	if _, err := Compare(a, nan, 0, 1e-3); err == nil {
		t.Error("含 NaN 应报错（崩坏门禁）")
	}
	inf := [][]float64{{math.Inf(1), 2}, {3, 4}}
	if _, err := Compare(a, inf, 0, 1e-3); err == nil {
		t.Error("含 Inf 应报错（崩坏门禁）")
	}
	if _, err := Compare(a, a, -1, 1e-3); err == nil {
		t.Error("负 atol 应报错")
	}
	// 逐位相同 ⇒ MaxRelDiff 必须为 0
	rep, err := Compare(a, a, 0, 1e-3)
	if err != nil {
		t.Fatal(err)
	}
	if rep.MaxRelDiff != 0 || rep.MaxAbsDiff != 0 {
		t.Fatalf("相同输入的最大偏差应为 0，got rel=%v abs=%v", rep.MaxRelDiff, rep.MaxAbsDiff)
	}
	if !rep.Top1AgreeAll {
		t.Fatal("相同输入的 top-1 必须完全一致")
	}
}

// TestForwardErrorCases 前向的 fail-closed 边界。
func TestForwardErrorCases(t *testing.T) {
	cfg := demoCfg()
	if _, err := ForwardExact(cfg, nil); err == nil {
		t.Error("空 token 序列应报错")
	}
	if _, err := ForwardExact(cfg, []int{cfg.Vocab}); err == nil {
		t.Error("越界 token 应报错")
	}
	if _, err := ForwardExact(cfg, []int{-1}); err == nil {
		t.Error("负 token 应报错")
	}
	// 超出 MaxTokens：先构造一个小上限的 cfg
	small := demoCfg()
	small.MaxTokens = 4
	if _, err := ForwardExact(small, demoTokens(5)); err == nil {
		t.Error("超出 MaxTokens 应报错")
	}
	// 非法 cfg
	bad := demoCfg()
	bad.Heads = 3
	if _, err := ForwardExact(bad, demoTokens(2)); err == nil {
		t.Error("非法 cfg 应报错")
	}
	if _, err := NewRunner(nil, cfg); err == nil {
		t.Error("nil Weights 应报错")
	}
	if _, _, err := Generate(nil, cfg, demoTokens(2), 1); err == nil {
		t.Error("Generate 用 nil Weights 应报错")
	}
	if _, _, err := Generate(mustExact(t, cfg), cfg, nil, 1); err == nil {
		t.Error("空 prompt 应报错")
	}
	if _, _, err := Generate(mustExact(t, cfg), cfg, demoTokens(2), -1); err == nil {
		t.Error("负 steps 应报错")
	}
	// 错误信息必须可读（不含 %! 之类的格式化残留）
	if _, err := ForwardExact(cfg, []int{cfg.Vocab}); err == nil {
		t.Fatal("越界 token 应报错")
	} else if strings.Contains(err.Error(), "%!") {
		t.Fatalf("错误信息含格式化残留: %v", err)
	}
}

// TestEmbeddingDeterministic 嵌入必须确定性、有界、且随 token 变化。
func TestEmbeddingDeterministic(t *testing.T) {
	cfg := demoCfg()
	a, err := Embedding(cfg, []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Embedding(cfg, []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				t.Fatal("嵌入不确定")
			}
			// 派生公式的值域是 [-0.75, 0.25)，均值约 -0.25（继承既有 route2demo 公式）
			if a[i][j] < -0.76 || a[i][j] > 0.26 {
				t.Fatalf("嵌入值 %v 越界（应在 [-0.75, 0.25) 附近）", a[i][j])
			}
		}
	}
	if a[0][0] == a[1][0] {
		t.Fatal("不同 token 的嵌入不应相同")
	}
	if _, err := Embedding(cfg, []int{cfg.Vocab}); err == nil {
		t.Error("越界 token 应报错")
	}
	if _, err := Embedding(demoCfgBadHeads(), []int{0}); err == nil {
		t.Error("非法 cfg 应报错")
	}
}

// TestCachedKVFeedsSharedOperators 一个 batch 之后，KV 缓存必须能被 teecore 的
// attention 算子直接消费——这证明 Runner 没有把 K/V 缓存变成某种私有格式，
// 也就无从长出一份「只有参考实现才有的算子」。
//
// 我们不去逐项重算 Runner 的内部中间值来证明同一性（那会把测试写成生产的镜像实现），
// 而是验证契约：缓存的行维度 == AttnDim、K/V 一一对应、且直接喂给 teecore.Attention
// 能产出有限输出。真正的数值同一性由 TestPrefillEqualsSequentialDecode 与
// TestExactWeightsMatchPlainLinear 两条共同兜住。
func TestCachedKVFeedsSharedOperators(t *testing.T) {
	cfg := demoCfg()
	w := mustExact(t, cfg)
	toks := demoTokens(3)
	r, err := NewRunner(w, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Step(toks); err != nil {
		t.Fatal(err)
	}
	for b := 0; b < cfg.Blocks; b++ {
		if len(r.k[b]) != len(toks) {
			t.Fatalf("block %d 的 K 行数 = %d, want %d", b, len(r.k[b]), len(toks))
		}
		if len(r.k[b]) != len(r.v[b]) {
			t.Fatalf("block %d 的 K/V 行数不一致 %d != %d", b, len(r.k[b]), len(r.v[b]))
		}
		for i := range r.k[b] {
			if len(r.k[b][i]) != cfg.AttnDim() {
				t.Fatalf("block %d 行 %d 的 K 长度 %d != AttnDim %d", b, i, len(r.k[b][i]), cfg.AttnDim())
			}
			if len(r.v[b][i]) != cfg.AttnDim() {
				t.Fatalf("block %d 行 %d 的 V 长度 %d != AttnDim %d", b, i, len(r.v[b][i]), cfg.AttnDim())
			}
			sameAsV := true
			for d := range r.k[b][i] {
				if r.k[b][i][d] != r.v[b][i][d] {
					sameAsV = false
					break
				}
			}
			if sameAsV {
				t.Fatalf("block %d 行 %d 的 K 与 V 完全相同（K 未被投影/RoPE？）", b, i)
			}
		}
		q := deterministicVec(cfg.AttnDim(), int64(b)*13+1)
		out, err := teecore.Attention(q, r.k[b], r.v[b], cfg.Heads, cfg.HeadDim, 0, len(r.k[b])-1, true)
		if err != nil {
			t.Fatalf("block %d: teecore.Attention 直接消费缓存失败: %v", b, err)
		}
		if len(out) != cfg.AttnDim() {
			t.Fatalf("block %d: attention 输出长度 = %d, want %d", b, len(out), cfg.AttnDim())
		}
		for i, v := range out {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				t.Fatalf("block %d: attention 输出[%d] = %v 非有限", b, i, v)
			}
		}
	}
}

// TestEmbeddingIsSingleSourced route2ref 不得自带一份嵌入派生：
// 它的 Embedding 必须与 route2demo 的**逐位相等**（本包只做转发）。
//
// 这条用例专门防"参考实现悄悄另起炉灶"：一旦有人在 route2ref 里重写了一份嵌入派生，
// 两条基线仍会各自跑通（甚至看起来都对），但客户端注入值与服务端的表已经分叉，
// 而分叉的症状——随机错 token——在没有任何一层会报错。
func TestEmbeddingIsSingleSourced(t *testing.T) {
	cfg := demoCfg()
	toks := demoTokens(5)
	mine, err := Embedding(cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := route2demo.Embedding(cfg, toks)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != len(theirs) {
		t.Fatalf("行数 %d != %d", len(mine), len(theirs))
	}
	for i := range mine {
		for j := range mine[i] {
			if mine[i][j] != theirs[i][j] {
				t.Fatalf("第 %d 行第 %d 维: route2ref=%v 与 route2demo=%v 不一致（嵌入表分叉）",
					i, j, mine[i][j], theirs[i][j])
			}
		}
	}
}

// ---------- 辅助 ----------

// mustExact 构造 ref-exact 权重，失败即 Fatal。
func mustExact(t *testing.T, cfg route2plan.ModelConfig) Weights {
	t.Helper()
	w, err := NewExactWeights(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// demoCfgBadHeads 返回一个 Heads*HeadDim != Dim 的非法配置。
func demoCfgBadHeads() route2plan.ModelConfig {
	c := demoCfg()
	c.Heads = 3
	return c
}

// deterministicVec 生成确定性浮点向量（不引入 math/rand 全局状态）。
func deterministicVec(n int, seed int64) []float64 {
	out := make([]float64, n)
	s := seed
	for i := range out {
		s = s*6364136223846793005 + 1442695040888963407
		out[i] = float64(int64(s>>11)%2001-1000) / 1000
	}
	return out
}
