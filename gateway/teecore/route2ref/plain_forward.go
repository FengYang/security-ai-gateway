// Package route2ref 双基线**纯浮点**参照前向（T02 · D13）。
//
// ============================== 它为什么存在 ==============================
//
// 掩码管线可以「不报错地全错」：层序校验全绿、HTTP 全绿、日志全绿，只有数值是错的
// （掩码域差一位、双重掩码、掩码 reuse 全都长这个样子）。要把这类 bug 变成可判、可证伪的失败，
// 就必须有一个**不含任何掩码/定点/量化环节**的参照实现，用它来**隔离变量**：
//
//	┌──────────────┬──────────────────────┬────────────────────────────┐
//	│ 基线          │ 权重                  │ 隔离掉了什么                │
//	├──────────────┼──────────────────────┼────────────────────────────┤
//	│ ref-exact    │ 已去量化的同款 int8    │ 消除量化误差，只剩定点截断   │
//	│              │ （Scale*Data）        │ 与掩码管线误差（档 A 用）    │
//	│ ref-fp32     │ 未量化的原始派生权重   │ 模拟真实模型语义，含全部量化 │
//	│              │                      │ 损失（档 B 用）             │
//	└──────────────┴──────────────────────┴────────────────────────────┘
//
// 两条基线共用**同一份算子实现**（teecore 的 RoPE / Scores / CausalMask / Softmax /
// WeightedSum / RMSNorm / GELU / ArgMax），只在「权重精度」这一处分叉。
// 这一点很重要：如果参照实现自带一套算子，它就会自带一套 bug，
// 对拍结果既不证实也不证伪任何东西。
//
// ============================== 我（本包）不负的责任 ==============================
//
// 本包**不含任何掩码、定点、模运算**，也不触碰 KV 安全策略、配额、审计。
// 它是 pemanggil (调用方) teecore 纯函数的计算器：given tokens → logits。
// 生产路径（T03/T04）不得把本包当成可上线的推理实现——它没有 KV 隔离、
// 没有租户命名空间、没有审计字段。
//
// ============================== 与其它包的关系 ==============================
//
//	route2ref → teecore（算子） + route2plan（配置/plan 契约） + route2demo（权重派生）
//
// 注意 go.mod 不变、零第三方依赖。
package route2ref

import (
	"errors"
	"fmt"
	"math"

	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
	"security-ai-gateway/gateway/teecore/trustedops"
)

// 基线类别名（D13 / §8.1）。
const (
	// KindExact `ref-exact`：用**已去量化的同款 int8 权重**（m.Scale*m.Data）做 fp64 前向。
	KindExact = "ref-exact"
	// KindFP32 `ref-fp32`：用**未经量化的原始派生权重**做 fp64 前向。
	KindFP32 = "ref-fp32"
)

// Weights 参照前向使用的**浮点**权重视图。
//
// 之所以不直接用 route2demo.ModelWeights（它返回 QuantizedMatrix）：这里要的就是
// "把 int8 去量化回 fp64" 与 "根本不量化" 两种取值，二者都落在 [][]float64 上，
// 这样才能让下游 forward 完全不知道自己跑的是哪条基线。
//
// fail-closed：任何非法 key / 缺失张量一律 error，不允许返回零矩阵蒙混过关
// （零矩阵会让 RMSNorm 的 invStd 退化、GELU 全零，前向"能跑"但结论无意义）。
type Weights interface {
	// Matrix 返回行优先矩阵；调用方只读，禁止就地修改返回值。
	Matrix(k route2plan.TensorKey) ([][]float64, error)
	// Affine 返回归一化仿射参数 gamma 与 eps。
	Affine(k route2plan.TensorKey) ([]float64, float64, error)
	// Kind 返回基线类别（KindExact / KindFP32）。
	Kind() string
}

// ---------- 两条基线的权重实现 ----------

// exactWeights ref-exact：先把 route2demo 的量化矩阵**去量化**回 fp64
// （w = Scale * Data，与 maskedinfer.PlainLinear 同语义），再做前向。
type exactWeights struct {
	provider *route2demo.Weights
	cache    map[route2plan.TensorKey][][]float64
}

// NewExactWeights 构造 ref-exact 权重视图（去量化的同款 int8 权重）。
func NewExactWeights(cfg route2plan.ModelConfig) (Weights, error) {
	p, err := route2demo.NewWeights(cfg)
	if err != nil {
		return nil, fmt.Errorf("route2ref: 构造 ref-exact 权重失败: %w", err)
	}
	return &exactWeights{provider: p, cache: make(map[route2plan.TensorKey][][]float64)}, nil
}

// Kind 返回 KindExact。
func (e *exactWeights) Kind() string { return KindExact }

// Matrix 返回去量化后的浮点矩阵。
func (e *exactWeights) Matrix(k route2plan.TensorKey) ([][]float64, error) {
	if cached, ok := e.cache[k]; ok {
		return cached, nil
	}
	m, err := e.provider.Matrix(k)
	if err != nil {
		return nil, err
	}
	if len(m.Bias) != 0 {
		// 与其静默丢掉 bias（那样 ref-exact 与 maskedinfer.PlainLinear 就不再同语义），
		// 不如当场失败。若日后确实要支持 bias，正确的加法是按 PlainLinear：
		// out[i] += Bias[i] * Scale / InputScale。
		return nil, fmt.Errorf("route2ref: %s 含 bias，ref-exact 暂不支持（请按 PlainLinear 语义扩展本分支）", k)
	}
	w := make([][]float64, m.Rows)
	for i := range w {
		row := make([]float64, m.Cols)
		for j := range row {
			row[j] = m.Scale * float64(m.Data[i*m.Cols+j])
		}
		w[i] = row
	}
	e.cache[k] = w
	return w, nil
}

// Affine 返回归一化仿射参数。
func (e *exactWeights) Affine(k route2plan.TensorKey) ([]float64, float64, error) {
	return e.provider.Affine(k)
}

// fp32Weights ref-fp32：直接用 route2demo.RawWeights 的**未量化**原始派生权重。
type fp32Weights struct {
	cfg   route2plan.ModelConfig
	cache map[route2plan.TensorKey][][]float64
}

// NewFP32Weights 构造 ref-fp32 权重视图（未量化原始权重）。
func NewFP32Weights(cfg route2plan.ModelConfig) (Weights, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2ref: 构造 ref-fp32 权重失败: %w", err)
	}
	return &fp32Weights{cfg: cfg, cache: make(map[route2plan.TensorKey][][]float64)}, nil
}

// Kind 返回 KindFP32。
func (f *fp32Weights) Kind() string { return KindFP32 }

// Matrix 返回未量化的原始权重。
func (f *fp32Weights) Matrix(k route2plan.TensorKey) ([][]float64, error) {
	if cached, ok := f.cache[k]; ok {
		return cached, nil
	}
	w, err := route2demo.RawWeights(f.cfg, k)
	if err != nil {
		return nil, err
	}
	f.cache[k] = w
	return w, nil
}

// Affine 返回归一化仿射参数（归一化的 gamma 本身就不参与量化，两条基线取值相同）。
func (f *fp32Weights) Affine(k route2plan.TensorKey) ([]float64, float64, error) {
	return route2demo.NormParams(f.cfg, k)
}

// ---------- 运行态 ----------

// Runner 参照前向的运行态：KV 缓存 + 位置计数器。
//
// 与生产实现的差别：这里的 KV 就是两个 [][]float64，**明文、无租户隔离、无配额**，
// 因为它必须在可信域之外也能被单测和 CI 直接调用（设计 §8.1 要求 CI 可跑）。
// 生产路径的 KVCache 由 T03 实现，不得把本结构搬过去当生产实现。
type Runner struct {
	cfg route2plan.ModelConfig
	w   Weights
	pos int
	k   [][][]float64
	v   [][][]float64
}

// NewRunner 用给定权重构造一个空的参照前向运行态。
func NewRunner(w Weights, cfg route2plan.ModelConfig) (*Runner, error) {
	if w == nil {
		return nil, errors.New("route2ref: Weights 不可为 nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2ref: 模型配置非法: %w", err)
	}
	if err := checkRefSupported(cfg); err != nil {
		return nil, err
	}
	return &Runner{
		cfg: cfg,
		w:   w,
		k:   make([][][]float64, cfg.Blocks),
		v:   make([][][]float64, cfg.Blocks),
	}, nil
}

// checkRefSupported 拦截本参考前向（demo 版明文实现）无法忠实执行的结构。
//
// 本实现硬编码 GELU-MLP、无 QK-norm、KV cache 按 Q 头布局存放（无 GQA 扩展）。
// 自 T4 起 route2plan.Validate 允许真实 Qwen3 那样的 SwiGLU / QK-norm / GQA / attnDim≠Dim，
// 若此处不拦，参考前向会**静默算出错误 logits**而不是报错——"两边都对"式的假绿最难查。
// 故一律 fail-closed，真实 Qwen3 的明文真值请走 adapters/qwen.ForwardRef（它实现了这三者）。
func checkRefSupported(cfg route2plan.ModelConfig) error {
	if cfg.FFNType == route2plan.FFNTypeSwiGLU {
		return errors.New("route2ref: 参考前向仅实现 GELU-MLP，不支持 SwiGLU（真实 Qwen3 请用 adapters/qwen.ForwardRef）")
	}
	if cfg.QKNorm {
		return errors.New("route2ref: 参考前向未实现 QK-norm（真实 Qwen3 请用 adapters/qwen.ForwardRef）")
	}
	if cfg.KVHeads > 0 && cfg.KVHeads != cfg.Heads {
		return fmt.Errorf("route2ref: 参考前向未实现 GQA 的 KV 头扩展（KVHeads=%d != Heads=%d）", cfg.KVHeads, cfg.Heads)
	}
	if cfg.RopeStyle == route2plan.RopeStyleHalf {
		return errors.New("route2ref: 参考前向只实现相邻对 RoPE，未实现 Qwen/LLaMA 的前后半劈（真实 Qwen3 请用 adapters/qwen.ForwardRef）")
	}
	return nil
}

// Positions 返回已追加的 KV 行数（== 下一个 token 的绝对位置）。
func (r *Runner) Positions() int { return r.pos }

// Reset 清空 KV 与位置计数（供同一 Runner 复用于多条独立序列）。
func (r *Runner) Reset() {
	r.pos = 0
	r.k = make([][][]float64, r.cfg.Blocks)
	r.v = make([][][]float64, r.cfg.Blocks)
}

// Step 处理一个 batch（一笔 prefill 的全部位置，或一轮 decode 的 1 个位置），
// 返回**每一行各自的 logits**（行序与入参 tokens 一致）。
//
// 语义对齐设计 §2.5.5：batch 内第 i 行的绝对位置是 `Positions()+i`；
// prefill 时先多行写 KV 再多行读 KV，decode 时每次各写 1 行。
//
// 每个 block 的执行次序严格按 T01 的 plan（route2plan.StepsPerBlock=8）展开：
//
//	attn_norm → 投影 Q/K/V → RoPE(Q,K) → KV 追加 → attention → Wo → 残差 →
//	ffn_norm → Wup → GELU → Wdown → 残差
//
// 收尾：ln_final → lm_head ⇒ logits。
func (r *Runner) Step(tokens []int) ([][]float64, error) {
	if len(tokens) == 0 {
		return nil, errors.New("route2ref: 空 batch")
	}
	if r.pos+len(tokens) > r.cfg.MaxTokens {
		return nil, fmt.Errorf("route2ref: 位置 %d + batch %d 超出 MaxTokens=%d",
			r.pos, len(tokens), r.cfg.MaxTokens)
	}
	for _, t := range tokens {
		if t < 0 || t >= r.cfg.Vocab {
			return nil, fmt.Errorf("route2ref: token=%d 越界（词表 0..%d）", t, r.cfg.Vocab-1)
		}
	}
	base := r.pos
	h, err := Embedding(r.cfg, tokens)
	if err != nil {
		return nil, err
	}
	heads, headDim, theta := r.cfg.Heads, r.cfg.HeadDim, r.cfg.RopeTheta

	for b := 0; b < r.cfg.Blocks; b++ {
		gIn, epsIn, err := r.w.Affine(route2plan.TensorKey{Block: b, Tensor: route2plan.TensorLNIn})
		if err != nil {
			return nil, fmt.Errorf("route2ref: block %d ln_in 加载失败: %w", b, err)
		}
		hn, err := rowRMSNorm(h, gIn, epsIn)
		if err != nil {
			return nil, err
		}
		q, err := matVecRows(r.w, route2plan.TensorKey{Block: b, Tensor: route2plan.TensorAttnQ}, hn)
		if err != nil {
			return nil, err
		}
		kRows, err := matVecRows(r.w, route2plan.TensorKey{Block: b, Tensor: route2plan.TensorAttnK}, hn)
		if err != nil {
			return nil, err
		}
		vRows, err := matVecRows(r.w, route2plan.TensorKey{Block: b, Tensor: route2plan.TensorAttnV}, hn)
		if err != nil {
			return nil, err
		}
		// RoPE 只作用于 Q/K（V 不旋转，D8），且**在 KV 追加之前**完成。
		for i := range q {
			if err := trustedops.ApplyRoPEInPlace(q[i], base+i, headDim, theta); err != nil {
				return nil, err
			}
			if err := trustedops.ApplyRoPEInPlace(kRows[i], base+i, headDim, theta); err != nil {
				return nil, err
			}
		}
		r.k[b] = append(r.k[b], kRows...)
		r.v[b] = append(r.v[b], vRows...)

		h2 := make([][]float64, len(tokens))
		for i := range q {
			o, err := trustedops.Attention(q[i], r.k[b], r.v[b], heads, headDim, 0, base+i, true)
			if err != nil {
				return nil, fmt.Errorf("route2ref: block %d attention 失败: %w", b, err)
			}
			ao, err := matVecRow(r.w, route2plan.TensorKey{Block: b, Tensor: route2plan.TensorAttnO}, o)
			if err != nil {
				return nil, err
			}
			h2[i], err = addVec(h[i], ao)
			if err != nil {
				return nil, err
			}
		}

		gPost, epsPost, err := r.w.Affine(route2plan.TensorKey{Block: b, Tensor: route2plan.TensorLNPost})
		if err != nil {
			return nil, fmt.Errorf("route2ref: block %d ln_post 加载失败: %w", b, err)
		}
		hn2, err := rowRMSNorm(h2, gPost, epsPost)
		if err != nil {
			return nil, err
		}
		up, err := matVecRows(r.w, route2plan.TensorKey{Block: b, Tensor: route2plan.TensorFFNUp}, hn2)
		if err != nil {
			return nil, err
		}
		act := make([][]float64, len(up))
		for i := range up {
			act[i] = make([]float64, len(up[i]))
			for j := range up[i] {
				act[i][j] = trustedops.GELU(up[i][j])
			}
		}
		down, err := matVecRows(r.w, route2plan.TensorKey{Block: b, Tensor: route2plan.TensorFFNDown}, act)
		if err != nil {
			return nil, err
		}
		for i := range h {
			h[i], err = addVec(h2[i], down[i])
			if err != nil {
				return nil, err
			}
		}
	}

	gFinal, epsFinal, err := r.w.Affine(route2plan.TensorKey{Block: r.cfg.Blocks, Tensor: route2plan.TensorLNFinal})
	if err != nil {
		return nil, fmt.Errorf("route2ref: ln_final 加载失败: %w", err)
	}
	hn, err := rowRMSNorm(h, gFinal, epsFinal)
	if err != nil {
		return nil, err
	}
	logits, err := matVecRows(r.w, route2plan.TensorKey{Block: r.cfg.Blocks, Tensor: route2plan.TensorLMHead}, hn)
	if err != nil {
		return nil, err
	}
	r.pos += len(tokens)
	return logits, nil
}

// ---------- 公开入口 ----------

// Forward 用指定权重跑一遍完整前向，返回每步 logits
// （一次前向：prefill batch 情形下返回全部 T 行的 logits，行序 == token 序）。
func Forward(w Weights, cfg route2plan.ModelConfig, tokens []int) ([][]float64, error) {
	r, err := NewRunner(w, cfg)
	if err != nil {
		return nil, err
	}
	return r.Step(tokens)
}

// ForwardExact `ref-exact` 基线：去量化 int8 权重的纯 fp64 前向（设计 §8.1）。
//
// 这条基线消掉了量化误差，因此「生产管线 vs ForwardExact」的偏差只可能来自
// 定点截断与掩码管线自身错误——这正是 §8.1 档 A（rtol=1e-3）想要隔离的东西。
func ForwardExact(cfg route2plan.ModelConfig, tokens []int) ([][]float64, error) {
	w, err := NewExactWeights(cfg)
	if err != nil {
		return nil, err
	}
	return Forward(w, cfg, tokens)
}

// ForwardFP32 `ref-fp32` 基线：未量化原始权重的纯 fp64 前向（设计 §8.1）。
//
// 这条基线含全部量化损失，代表"真实模型语义"，是 §8.1 档 B（rtol=5e-2）
// 与生成序列 top-1 命中率门禁的参照对象。
func ForwardFP32(cfg route2plan.ModelConfig, tokens []int) ([][]float64, error) {
	w, err := NewFP32Weights(cfg)
	if err != nil {
		return nil, err
	}
	return Forward(w, cfg, tokens)
}

// Generate 自回归生成：先把 prompt 一次性 prefill，再逐 token decode `steps` 步。
//
// 返回：
//   - logits：每步生成的 logits（行序 == 生成序，含 prefill 末位那一步）；
//   - generated：解码出来的 token 序列（长度 == steps）。
//
// next token 由 trustedops.ArgMax 决定（方案 C：TEE 内 argmax），与服务端判据一致。
func Generate(w Weights, cfg route2plan.ModelConfig, prompt []int, steps int) (logits [][]float64, generated []int, err error) {
	if steps < 0 {
		return nil, nil, fmt.Errorf("route2ref: steps=%d 不可为负", steps)
	}
	r, err := NewRunner(w, cfg)
	if err != nil {
		return nil, nil, err
	}
	if len(prompt) == 0 {
		return nil, nil, errors.New("route2ref: prompt 不可为空")
	}
	prefill, err := r.Step(prompt)
	if err != nil {
		return nil, nil, err
	}
	logits = append(logits, prefill[len(prefill)-1])
	next := trustedops.ArgMax(prefill[len(prefill)-1])
	generated = append(generated, next)
	for i := 1; i < steps; i++ {
		outs, err := r.Step([]int{next})
		if err != nil {
			return nil, nil, err
		}
		logits = append(logits, outs[0])
		next = trustedops.ArgMax(outs[0])
		generated = append(generated, next)
	}
	return logits, generated, nil
}

// Embedding token 嵌入：本包**不自己派生**嵌入表，只做一次转发。
//
// 唯一真值源在 route2demo.Embedding（`tok.emb` 张量，见 route2plan.TensorTokEmb）：
// 客户端注入与服务端 Gather 必须共用同一张表，两边各派生一份是不可接受的
// （漂移症状是"输出随机错 token"，且没有任何一层会报错）。
// 这里保留包装只是为了给参考前向一个就近入口，并让调用方不必知道张量 key 的构造细节。
//
// 【量化噪声因果链 · 留档，勿删】跨基线（ref-exact vs ref-fp32）那 ~0.2% 的偏差来自：
//
//	demo 权重公式 (int16/32768)*0.5 - 0.25 的真实值域是 [-0.75, 0.25)、均值约 -0.25
//	  ⇒ scale = maxAbs/127 被负半轴主导
//	  ⇒ 正半轴的 int8 分辨率变差
//	  ⇒ 单个权重的相对误差 ~0.4~0.8%，32 项累加后剩 ~0.2%
//
// 这不是"标定坏了"：档 A 的对照方 ref-exact 与生产管线共用同一份量化权重，
// 该噪声在档 A 里被完全对消，不影响任何门禁的判别力。
// **将来若要压低跨基线偏差，改这里（去均值 / 按实际 min-max 非对称标定 / per-channel
// scale）是首选杠杆**——但那是动 route2demo 的量化标定，须经团队裁定，不得顺手改。
func Embedding(cfg route2plan.ModelConfig, tokens []int) ([][]float64, error) {
	rows, err := route2demo.Embedding(cfg, tokens)
	if err != nil {
		return nil, fmt.Errorf("route2ref: 嵌入表加载失败: %w", err)
	}
	return rows, nil
}

// ---------- 双基线对比（供 T05 与 --selftest 复用） ----------

// Report 一次双基线对比的结果（设计 §8.1 的混合容差口径）。
type Report struct {
	// Atol / Rtol 本次比较使用的混合容差参数（|x-y| <= Atol + Rtol*|y|）。
	Atol float64
	Rtol float64
	// MaxAbsDiff 逐 logit 绝对偏差的最大值。
	MaxAbsDiff float64
	// MaxRelDiff 逐 logit 容差比 |x-y|/(Atol + Rtol*|y|) 的最大值；<= 1 即通过当前档位。
	MaxRelDiff float64
	// Steps 参与比较的步数（每个 step 一行 logits）。
	Steps int
	// Logits 参与比较的 logit 个数。
	Logits int
	// Top1Agree 两条基线 top-1 相同的步数。
	Top1Agree int
	// Top1AgreeAll 是否所有步的 top-1 都一致。
	Top1AgreeAll bool
}

// Compare 两条基线 logits 的混合容差对比（设计 §8.1）：
//
//	|x-y| <= atol + rtol*|y|
//
// 同时附带 top-1 命中统计。任一 logits 形状不一致或含 NaN/Inf 一律 error
// （§8.1 的附加崩坏门禁：出现 NaN/Inf 即判失败，不分档）。
func Compare(a, b [][]float64, atol, rtol float64) (Report, error) {
	rep := Report{Atol: atol, Rtol: rtol, Steps: len(a)}
	if len(a) != len(b) {
		return Report{}, fmt.Errorf("route2ref: 两条基线步数不一致 %d != %d", len(a), len(b))
	}
	if atol < 0 || rtol < 0 {
		return Report{}, fmt.Errorf("route2ref: atol=%v rtol=%v 不可为负", atol, rtol)
	}
	for s := range a {
		if len(a[s]) != len(b[s]) {
			return Report{}, fmt.Errorf("route2ref: 第 %d 步 logits 维度不一致 %d != %d", s, len(a[s]), len(b[s]))
		}
		for i := range a[s] {
			x, y := a[s][i], b[s][i]
			if math.IsNaN(x) || math.IsInf(x, 0) || math.IsNaN(y) || math.IsInf(y, 0) {
				return Report{}, fmt.Errorf("route2ref: 第 %d 步第 %d 个 logit 非有限（x=%v y=%v）——触发崩坏门禁", s, i, x, y)
			}
			tol := atol + rtol*math.Abs(y)
			d := math.Abs(x - y)
			rep.Logits++
			if d > rep.MaxAbsDiff {
				rep.MaxAbsDiff = d
			}
			if tol > 0 {
				ratio := d / tol
				if ratio > rep.MaxRelDiff {
					rep.MaxRelDiff = ratio
				}
			} else if d > 0 {
				rep.MaxRelDiff = math.Inf(1)
			}
		}
		if len(a[s]) > 0 && trustedops.ArgMax(a[s]) == trustedops.ArgMax(b[s]) {
			rep.Top1Agree++
		}
	}
	rep.Top1AgreeAll = rep.Top1Agree == rep.Steps
	return rep, nil
}

// GradeAAtol 设计 §8.1 档 A 的绝对项系数：`atol = 1e-6 · max|logits|`。
const GradeAAtol = 1e-6

// GradeARtol 设计 §8.1 档 A 的相对项：`rtol = 1e-3`。
const GradeARtol = 1e-3

// GradeBRtol 设计 §8.1 档 B 的相对项：`rtol = 5e-2`。
const GradeBRtol = 5e-2

// Selftest 供 `cmd/route2-client --selftest` 直接调用的入口（T04 会用）。
//
// 它做三件事：
//  1. 跑 ref-exact 与 ref-fp32 两条基线（同一份 tokens，同一份算子）；
//  2. 用 §8.1 档 A 的 atol/rtol 口径报告两条基线之间的偏差；
//  3. 触发附加崩坏门禁检查（NaN/Inf）。
//
// 注意：`MaxRelDiff` 是**两条基线之间的量化噪声观测值**，不等于最终 G2 的
// 「生产管线 vs ref-exact」门禁值；后者要等 T03/T04 接好后才有意义。
// 在 team-lead 重新审定之前，请勿用本返回值替代任何一档的判定。
func Selftest(cfg route2plan.ModelConfig, tokens []int) (Report, error) {
	exact, err := ForwardExact(cfg, tokens)
	if err != nil {
		return Report{}, fmt.Errorf("route2ref: ref-exact 前向失败: %w", err)
	}
	fp32, err := ForwardFP32(cfg, tokens)
	if err != nil {
		return Report{}, fmt.Errorf("route2ref: ref-fp32 前向失败: %w", err)
	}
	atol := GradeAAtol * maxAbsLogit(fp32)
	return Compare(exact, fp32, atol, GradeARtol)
}

// maxAbsLogit 取 logits 的绝对值上界（档 A 的 atol 基准）。
func maxAbsLogit(logits [][]float64) float64 {
	m := 0.0
	for _, row := range logits {
		for _, v := range row {
			if a := math.Abs(v); a > m {
				m = a
			}
		}
	}
	return m
}

// ---------- 内部：矩阵 / 向量工具 ----------

// matVecRows 对 batch 的每一行做 `out = W·x`（W: rows×cols 行优先）。
func matVecRows(w Weights, k route2plan.TensorKey, x [][]float64) ([][]float64, error) {
	m, err := w.Matrix(k)
	if err != nil {
		return nil, err
	}
	if len(m) == 0 || len(m[0]) == 0 {
		return nil, fmt.Errorf("route2ref: %s 是空矩阵", k)
	}
	cols := len(m[0])
	out := make([][]float64, len(x))
	for i, row := range x {
		if len(row) != cols {
			return nil, fmt.Errorf("route2ref: %s 的列数 %d != 输入行维度 %d", k, cols, len(row))
		}
		o := make([]float64, len(m))
		for r := range m {
			if len(m[r]) != cols {
				return nil, fmt.Errorf("route2ref: %s 非矩形矩阵", k)
			}
			var acc float64
			for j := 0; j < cols; j++ {
				acc += m[r][j] * row[j]
			}
			o[r] = acc
		}
		out[i] = o
	}
	return out, nil
}

// matVecRow 单行版本。
func matVecRow(w Weights, k route2plan.TensorKey, x []float64) ([]float64, error) {
	rows, err := matVecRows(w, k, [][]float64{x})
	if err != nil {
		return nil, err
	}
	return rows[0], nil
}

// rowRMSNorm 逐行 RMSNorm（直接复用 trustedops.RMSNorm，不另写一份）。
func rowRMSNorm(rows [][]float64, gamma []float64, eps float64) ([][]float64, error) {
	out := make([][]float64, len(rows))
	for i, row := range rows {
		if len(gamma) != len(row) {
			return nil, fmt.Errorf("route2ref: gamma 长度 %d != 行维度 %d", len(gamma), len(row))
		}
		out[i] = trustedops.RMSNorm(row, gamma, eps)
	}
	return out, nil
}

// addVec 逐元素相加。
func addVec(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("route2ref: 残差相加维度不一致 %d != %d", len(a), len(b))
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return out, nil
}

// 【Semantics 锚定】ref-exact 的取值恒等于「去量化的 int8 权重」，即
//
//	w_exact[i][j] = QuantizedMatrix.Scale * float64(QuantizedMatrix.Data[i*Cols+j])
//
// 与 maskedinfer 既有内核 QuantizedMatrix.PlainLinear（`masked_linear.go:178`）逐项同义。
// 这条等价关系由 plain_forward_test.go 的 CrossCheck 用例直接对拍，不容许口头保证：
// 一旦 PlainLinear 的语义变更（例如先乘 scale 后取模的旧次序被恢复），该用例会立即失败。
