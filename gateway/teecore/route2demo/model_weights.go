package route2demo

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// 本文件是 route2demo 的 **Attention/FFN/lm_head 权重派生扩展**（设计 §2.4.5）。
// 与既有 weights.go 的 LayerWeights 同处一个包、同一套 sha256 风格，
// 但 ModelID/Block/Tensor 进入盐值，因此与 LayerWeights **互不冲突**（后者盐值为
// "layer-<L>-<i>-<j>"），两条派生路径互不干扰。
//
// LayerWeights(layer, dim) 按 D15 裁定**保留不删**：既有 MLP demo 与既有测试仍在使用。
//
// 派生公式（与既有实现逐字同源）：
//
//	h      = sha256("<modelID>/<block>/<tensor>/<i>-<j>")
//	w[i][j] = (int16(h[0]) | int16(h[1])<<8) / 32768 * 0.5 - 0.25
//
// 说明：h[0]/h[1] 组合成 int16 ⇒ u ∈ [-32768, 32767] ⇒ 实际值域是
//
//	[-0.75, 0.25)，**均值约 -0.25**（不是对称的 [-0.25, 0.25)）
//
// 这是从既有 LayerWeights 继承过来的公式形态，属于既有 demo 权重的事实语义，
// 不在 T01/T02 范围内改动（改了会让既有 demo 基线与历史数值对不上）。
// 副作用仅一条：量化时 scale = maxAbs/127 由负半轴主导，正半轴量化分辨率略差，
// 这正是 §8.1 里 int8 量化噪声的一部分来源（详见 T02 回报的观测数据）。
// 再经 NewQuantizedMatrixMod(w, 8, Mod64) 量化（scale = maxAbs/127）。
// 「确定性」的全部含义：给定 (cfg, key)，客户端与服务端各自算出来的 Data 逐位相等，
// 从而两侧 MaskImage / CipherLinear 的结果才有共同的整数域基准（否则脱掩码必然出乱码）。
//
// 生产路径应替换为本接口的真实权重加载实现（safetensors/gguf），本文件只服务 demo/CI。

// weightBitWidth 量化位宽（int8，与既有 LayerWeights 一致）。
const weightBitWidth = 8

// gammaSpread NormParams 中 gamma 的抖动幅度：gamma ∈ [1-γ, 1+γ]，γ = gammaSpread/2。
// 取 0.25 ⇒ gamma ∈ [0.875, 1.125]，既避免「全 1」使 RMSNorm 退化为恒等映射
// （那样多条 bug 会被自动化验收放过），又不至于极端到让数值崩坏。
const gammaSpread = 0.25

// ModelWeights 权重提供者契约（设计 §2.4.5）。
//
// 服务端推荐的接入方式：T03 的 step_exec 只依赖本接口，具体实现可以是本文件的
// 确定性 demo 实现（Weights），也可以是日后的真实权重加载器，两者对上层透明。
type ModelWeights interface {
	// Matrix 返回张量的量化权重矩阵（int8 / Mod64）。
	Matrix(k route2plan.TensorKey) (*maskedinfer.QuantizedMatrix, error)
	// Affine 返回归一化仿射参数 gamma 与 eps（仅 ln_* 类张量）。
	Affine(k route2plan.TensorKey) (gamma []float64, eps float64, err error)
	// Config 返回本提供者绑定的模型配置（供 eager check 与维度校验）。
	Config() route2plan.ModelConfig
}

// Weights ModelWeights 的确定性 demo 实现（零 I/O、零网络、零第三方依赖）。
type Weights struct {
	cfg route2plan.ModelConfig
}

// NewWeights 用已校验的 cfg 构造 demo 权重提供者。cfg 非法即 error（fail-closed）。
func NewWeights(cfg route2plan.ModelConfig) (*Weights, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2demo: 模型配置非法: %w", err)
	}
	return &Weights{cfg: cfg}, nil
}

// Config 返回绑定的模型配置。
func (w *Weights) Config() route2plan.ModelConfig {
	return w.cfg
}

// Matrix 返回量化权重矩阵。
func (w *Weights) Matrix(k route2plan.TensorKey) (*maskedinfer.QuantizedMatrix, error) {
	return TensorWeights(w.cfg, k)
}

// Affine 返回归一化仿射参数。QK-norm 张量（q_norm/k_norm）走独立的 QKNormParams，
// 其余（ln_in/ln_post/ln_final）走 NormParams。
func (w *Weights) Affine(k route2plan.TensorKey) ([]float64, float64, error) {
	if k.Tensor == route2plan.TensorQNorm || k.Tensor == route2plan.TensorKNorm {
		return QKNormParams(w.cfg, k)
	}
	return NormParams(w.cfg, k)
}

// TensorWeights 确定性派生一张**线性权重**矩阵（Rows 行 × Cols 列，int8 / Mod64）。
//
// 非方阵天然支持：QuantizedMatrix.Rows 与 Cols 本就是分离字段（masked_linear.go:31-39），
// 故 lm_head（Dim × Vocab）不需要对数值内核做任何改动。
//
// 当前实现**不带 bias**（与既有 LayerWeights 一致）。设计不变式：MaskImage 绝不含 bias。
// 调用方确需 bias 请用 m.WithBias() 追加——即便如此，MaskImage 依旧不含 bias，
// 这一条不可破坏，否则 Unmask 之后 bias 会被重复计一次。
func TensorWeights(cfg route2plan.ModelConfig, k route2plan.TensorKey) (*maskedinfer.QuantizedMatrix, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2demo: 模型配置非法: %w", err)
	}
	w, err := rawWeightsChecked(cfg, k)
	if err != nil {
		return nil, err
	}
	m, err := maskedinfer.NewQuantizedMatrixMod(w, weightBitWidth, maskedinfer.Mod64)
	if err != nil {
		return nil, fmt.Errorf("route2demo: 量化张量 %s 失败: %w", k.String(), err)
	}
	return m, nil
}

// RawWeights 返回**未经量化**的原始浮点权重（行优先）。
//
// 用途：为 T02 的 ref-fp32 基线提供 hooks——ref-fp32 需要用未量化的派生权重做 fp64 前向，
// 才能把「量化损失」与「掩码管线自身误差」正交分解（§8.1 双基线）。
func RawWeights(cfg route2plan.ModelConfig, k route2plan.TensorKey) ([][]float64, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2demo: 模型配置非法: %w", err)
	}
	return rawWeightsChecked(cfg, k)
}

// rawWeightsChecked 派生未量化的原始浮点权重：形状统一由 TensorShape 裁定，
// 数值统一过 ensureFinite 护栏。TensorWeights 与 RawWeights 共用此一处实现，
// 二者唯一的差别就是「要不要再过一遍量化」。
func rawWeightsChecked(cfg route2plan.ModelConfig, k route2plan.TensorKey) ([][]float64, error) {
	rows, cols, err := TensorShape(cfg, k)
	if err != nil {
		return nil, err
	}
	w := make([][]float64, rows)
	for i := range w {
		row := make([]float64, cols)
		for j := range row {
			row[j] = deriveScalar(cfg.ModelID, k.Block, k.Tensor, deriveWeight(i, j))
		}
		w[i] = row
	}
	if err := ensureFinite(w); err != nil {
		return nil, fmt.Errorf("route2demo: 派生张量 %s 数值非法: %w", k.String(), err)
	}
	return w, nil
}

// NormParams 确定性派生 RMSNorm 的仿射参数 gamma 与 eps。
//
// gamma 的派生同样走 sha256，但落在 1 附近（而非权重那样的 0 附近），因为 RMSNorm
// 的 gamma 在真实模型里就是尺度系数，恒为 1 会让算子退化。
//
// 派生公式：
//
//	h      = sha256("<modelID>/<block>/<tensor>/gamma/<i>")
//	gamma[i] = 1 + (int16(h[0]) | int16(h[1])<<8) / 32768 * (gammaSpread/2)
//
// block 号的取值纪律（fail-closed，专门防 R5 那种 off-by-one）：
//   - ln_in / ln_post 是 per-block 的 ⇒ Block ∈ [0, cfg.Blocks-1]；
//   - ln_final 是全局的 ⇒ Block 必须 == cfg.Blocks（哨兵块号）。
func NormParams(cfg route2plan.ModelConfig, k route2plan.TensorKey) (gamma []float64, eps float64, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, 0, fmt.Errorf("route2demo: 模型配置非法: %w", err)
	}
	if err := k.Validate(); err != nil {
		return nil, 0, fmt.Errorf("route2demo: 张量 key 非法: %w", err)
	}
	if !k.IsNorm() {
		return nil, 0, fmt.Errorf("route2demo: %s 不是归一化参数张量（不可用于 NormParams）", k.String())
	}
	switch k.Tensor {
	case route2plan.TensorLNIn, route2plan.TensorLNPost:
		if k.Block < 0 || k.Block >= cfg.Blocks {
			return nil, 0, fmt.Errorf("route2demo: %s 的 Block=%d 越界，per-block 归一化张量须落在 0..%d",
				k.String(), k.Block, cfg.Blocks-1)
		}
	case route2plan.TensorLNFinal:
		if k.Block != cfg.Blocks {
			return nil, 0, fmt.Errorf("route2demo: %s 的 Block=%d 应为哨兵块号 %d（全局收尾）",
				k.String(), k.Block, cfg.Blocks)
		}
	default:
		return nil, 0, fmt.Errorf("route2demo: 未知归一化张量 %s", k.String())
	}
	gamma = make([]float64, cfg.Dim)
	for i := range gamma {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s/gamma/%d", cfg.ModelID, k.Block, k.Tensor, i)))
		u := int16(h[0]) | int16(h[1])<<8
		gamma[i] = 1 + (float64(u)/32768.0)*(gammaSpread/2)
	}
	return gamma, cfg.NormEps, nil
}

// QKNormParams 确定性派生 Qwen3 的 q_norm / k_norm 仿射参数 gamma（长度 = HeadDim）。
//
// 与 NormParams 的差别：gamma 长度不是 Dim 而是 HeadDim，因为 QK-norm 在 head_dim 维上
// 逐头归一、所有头共享同一组 gamma（见 trustedops.PerHeadRMSNorm）。block 纪律同 ln_in/ln_post：
// per-block ⇒ Block ∈ [0, cfg.Blocks-1]。
func QKNormParams(cfg route2plan.ModelConfig, k route2plan.TensorKey) (gamma []float64, eps float64, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, 0, fmt.Errorf("route2demo: 模型配置非法: %w", err)
	}
	if err := k.Validate(); err != nil {
		return nil, 0, fmt.Errorf("route2demo: 张量 key 非法: %w", err)
	}
	if k.Tensor != route2plan.TensorQNorm && k.Tensor != route2plan.TensorKNorm {
		return nil, 0, fmt.Errorf("route2demo: %s 不是 QK-norm 张量", k.String())
	}
	if k.Block < 0 || k.Block >= cfg.Blocks {
		return nil, 0, fmt.Errorf("route2demo: %s 的 Block=%d 越界，QK-norm 张量须落在 0..%d",
			k.String(), k.Block, cfg.Blocks-1)
	}
	gamma = make([]float64, cfg.HeadDim)
	for i := range gamma {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s/gamma/%d", cfg.ModelID, k.Block, k.Tensor, i)))
		u := int16(h[0]) | int16(h[1])<<8
		gamma[i] = 1 + (float64(u)/32768.0)*(gammaSpread/2)
	}
	return gamma, cfg.NormEps, nil
}

// TensorShape 返回张量的逻辑形状 (rows, cols)：rows = 输出维，cols = 输入维。
// 所有 Caller（TensorWeights / RawWeights / T02 的 ref 前向）都必须走这一处，
// 杜绝「客户端按 (in,out) 造、服务端按 (out,in) 造」这类维度转置事故。
func TensorShape(cfg route2plan.ModelConfig, k route2plan.TensorKey) (rows int, cols int, err error) {
	if err := k.Validate(); err != nil {
		return 0, 0, fmt.Errorf("route2demo: 张量 key 非法: %w", err)
	}
	if k.IsNorm() {
		return 0, 0, fmt.Errorf("route2demo: %s 是归一化参数张量，不是矩阵，请用 NormParams", k.String())
	}
	if err := checkBlockBounds(cfg, k); err != nil {
		return 0, 0, err
	}
	d := cfg.Dim
	a := cfg.AttnDim() // Q 投影输出宽度 Heads*HeadDim（真实 Qwen3 下可 != Dim）
	switch k.Tensor {
	case route2plan.TensorAttnQ:
		return a, d, nil
	case route2plan.TensorAttnK, route2plan.TensorAttnV:
		// GQA：K/V 投影输出宽度 = KVHeads*HeadDim（< Dim），注意力前由 route2step 扩展回 Q 头布局。
		return cfg.KVDim(), d, nil
	case route2plan.TensorAttnO:
		return d, a, nil
	case route2plan.TensorFFNUp:
		return cfg.FFNDim, d, nil
	case route2plan.TensorGate:
		return cfg.FFNDim, d, nil
	case route2plan.TensorFFNDown:
		return d, cfg.FFNDim, nil
	case route2plan.TensorLMHead:
		return cfg.Vocab, d, nil
	case route2plan.TensorTokEmb:
		// 嵌入表按 (token, dim) 组织：第 token 行即该 token 的嵌入向量。
		return cfg.Vocab, d, nil
	default:
		return 0, 0, fmt.Errorf("route2demo: 未知矩阵张量 %s", k.String())
	}
}

// TokEmbKey 返回该 cfg 的 token 嵌入表 key（唯一来源，禁止各处手搓 block 号）。
//
// 嵌入是全局张量，与其它收尾张量一样取哨兵块号 cfg.Blocks。
func TokEmbKey(cfg route2plan.ModelConfig) route2plan.TensorKey {
	return route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorTokEmb}
}

// Embedding 返回 tokens 对应的嵌入向量（**未经量化**的原始派生值）。
//
// 这是**客户端注入**与**服务端 Gather** 必须共用的唯一嵌入表入口：两侧各自算一份
// 是不可接受的（一旦漂移，症状是"输出随机错 token"，且没有任何一层会报错）。
//
// 派生与 RawWeights 逐位同源：取 RawWeights(TokEmbKey(cfg)) 的第 token 行，
// 只是按需只算需要的行（不必为 1 个 token 派生整张 Vocab×Dim 表）。
// 二者的一致性由 TestEmbeddingMatchesRawTable 逐位断言，不是口头保证。
func Embedding(cfg route2plan.ModelConfig, tokens []int) ([][]float64, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("route2demo: 模型配置非法: %w", err)
	}
	key := TokEmbKey(cfg)
	out := make([][]float64, len(tokens))
	for i, tok := range tokens {
		if tok < 0 || tok >= cfg.Vocab {
			return nil, fmt.Errorf("route2demo: token=%d 越界（词表 0..%d）", tok, cfg.Vocab-1)
		}
		row := make([]float64, cfg.Dim)
		for d := range row {
			row[d] = deriveScalar(cfg.ModelID, key.Block, key.Tensor, deriveWeight(tok, d))
		}
		if err := ensureFinite([][]float64{row}); err != nil {
			return nil, fmt.Errorf("route2demo: token=%d 的嵌入数值非法: %w", tok, err)
		}
		out[i] = row
	}
	return out, nil
}

// checkBlockBounds 校验 block 号：block 内张量 ∈ [0, Blocks-1]，收尾张量 == Blocks。
func checkBlockBounds(cfg route2plan.ModelConfig, k route2plan.TensorKey) error {
	switch k.Tensor {
	case route2plan.TensorLNFinal, route2plan.TensorLMHead, route2plan.TensorTokEmb:
		if k.Block != cfg.Blocks {
			return fmt.Errorf("route2demo: %s 的 Block=%d 应为哨兵块号 %d（收尾张量不属于任何 block）",
				k.String(), k.Block, cfg.Blocks)
		}
		return nil
	}
	if k.Block < 0 || k.Block >= cfg.Blocks {
		return fmt.Errorf("route2demo: %s 的 Block=%d 越界，block 内张量须落在 0..%d",
			k.String(), k.Block, cfg.Blocks-1)
	}
	return nil
}

// deriveWeight 生成单个派生串的后缀（"<i>-<j>"），与既有 weights.go 的盐值风格保持一致。
func deriveWeight(i, j int) string {
	return fmt.Sprintf("%d-%d", i, j)
}

// deriveScalar 按派生 key 计算单个标量：
//
//	h = sha256(modelID/block/tensor/suffix)
//	v = (int16(h[0]) | int16(h[1])<<8) / 32768 * 0.5 - 0.25
//
// 注意此处必须先把两个 byte 组合成 **有符号 int16** 再转 float64：
// 若误按无符号 uint16 处理，全部权重会落在 [0, 0.5) 而失去负数，
// RMSNorm/GELU 的下半分支就再也不会被激活覆盖（这是本项目历史上踩过的同类坑）。
func deriveScalar(modelID string, block int, tensor, suffix string) float64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d/%s/%s", modelID, block, tensor, suffix)))
	u := int16(h[0]) | int16(h[1])<<8
	return (float64(u)/32768.0)*0.5 - 0.25
}

// ErrWeightsNotLoaded 供上层把「权重缺失」与其他错误区分开（fail-closed 语义）：
// 宁可报错，也不得用零矩阵冒充权重——零矩阵会让 NewQuantizedMatrixMod 直接失败，
// 但更坏的是别人填上 1 让它悄悄通过。
var ErrWeightsNotLoaded = errors.New("route2demo: 权重未加载")

// ensureFinite 数值护栏：派生出的权重若不合法（NaN/Inf）必须当场失败，
// 否则 NaN 会流进下游的定点化环节，届时错误会以「掩码错位」的假象出现，极难定位。
func ensureFinite(w [][]float64) error {
	for _, row := range w {
		for _, v := range row {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("%w: 派生权重含 NaN/Inf", ErrWeightsNotLoaded)
			}
		}
	}
	return nil
}
