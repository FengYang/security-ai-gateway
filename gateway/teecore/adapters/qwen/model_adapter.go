package qwen

import (
	"fmt"

	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// 本文件把 *Weights 接入网关生产链路：实现 route2demo.ModelWeights 契约，
// 使 route2step 的 ExecStep 能直接消费真实 Qwen 权重（透明替换 demo 权重）。
// 张量命名/形状以 route2plan.TensorKey 为准，与 demo 同源，杜绝拼写漂移。

// 接口断言：*Weights 必须满足网关侧 ModelWeights 契约。
var _ route2demo.ModelWeights = (*Weights)(nil)

// ToModelConfig 把 QwenConfig 投影为 route2plan.ModelConfig（生产链的 plan 真值源）。
//
// 关键映射：Blocks=Layers、FFNDim=FFN、KVHeads/HeadDim 原样、FFNType=swiglu、
// QKNorm 由真实权重是否带 q_norm/k_norm 决定（qkNorm=true 表示加载出的权重确有 QK-norm）。
// ModelID 仅作标识，不影响 plan 结构；实际 model_id 由调用方按请求填入。
func (c QwenConfig) ToModelConfig(qkNorm bool) route2plan.ModelConfig {
	return route2plan.ModelConfig{
		Blocks:    c.Layers,
		Dim:       c.Dim,
		Heads:     c.Heads,
		KVHeads:   c.KVHeads,
		HeadDim:   c.HeadDim,
		FFNDim:    c.FFN,
		Vocab:     c.Vocab,
		NormEps:   c.NormEps,
		RopeTheta: c.RopeTheta,
		// Qwen2/Qwen3 的 RoPE 是**前后半劈**（rotate_half），不是相邻对；
		// 不显式置位会让生产链路沿用 demo 的相邻对约定，数值"接近但错"。
		RopeStyle: route2plan.RopeStyleHalf,
		MaxTokens: c.MaxTokens,
		FFNType:   route2plan.FFNTypeSwiGLU,
		QKNorm:    qkNorm,
	}
}

// Config 返回绑定权重的模型配置（route2demo.ModelWeights 契约）。
// QKNorm 由实际加载出的权重决定（w.QNorm != nil 表示确有逐头归一）。
func (w *Weights) Config() route2plan.ModelConfig {
	return w.Cfg.ToModelConfig(w.QNorm != nil)
}

// Matrix 返回张量的量化权重矩阵（route2demo.ModelWeights 契约）。
func (w *Weights) Matrix(k route2plan.TensorKey) (*maskedinfer.QuantizedMatrix, error) {
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("qwen: 张量 key 非法: %w", err)
	}
	switch k.Tensor {
	case route2plan.TensorAttnQ:
		return w.layerMat(w.AttnQ, k.Block, "attn.q")
	case route2plan.TensorAttnK:
		return w.layerMat(w.AttnK, k.Block, "attn.k")
	case route2plan.TensorAttnV:
		return w.layerMat(w.AttnV, k.Block, "attn.v")
	case route2plan.TensorAttnO:
		return w.layerMat(w.AttnO, k.Block, "attn.o")
	case route2plan.TensorFFNUp:
		return w.layerMat(w.Up, k.Block, "ffn.up")
	case route2plan.TensorGate:
		return w.layerMat(w.Gate, k.Block, "ffn.gate")
	case route2plan.TensorFFNDown:
		return w.layerMat(w.Down, k.Block, "ffn.down")
	case route2plan.TensorLMHead:
		return w.LMHeadMat, nil
	case route2plan.TensorTokEmb:
		return w.EmbedMat, nil
	default:
		return nil, fmt.Errorf("qwen: 未知/非矩阵张量 %s", k.String())
	}
}

// layerMat 取第 block 层的 [layer][0] 矩阵（线性层在 adapter 中按单层单列存储）。
func (w *Weights) layerMat(s [][]*maskedinfer.QuantizedMatrix, block int, name string) (*maskedinfer.QuantizedMatrix, error) {
	if block < 0 || block >= len(s) {
		return nil, fmt.Errorf("qwen: %s 的 block=%d 越界（层数 %d）", name, block, len(s))
	}
	if len(s[block]) == 0 || s[block][0] == nil {
		return nil, fmt.Errorf("qwen: %s block=%d 权重未加载", name, block)
	}
	return s[block][0], nil
}

// Affine 返回归一化仿射参数 gamma（route2demo.ModelWeights 契约）。
// ln_final 的 block 哨兵号 == Layers（与 route2plan 约定一致）。
func (w *Weights) Affine(k route2plan.TensorKey) ([]float64, float64, error) {
	if err := k.Validate(); err != nil {
		return nil, 0, fmt.Errorf("qwen: 张量 key 非法: %w", err)
	}
	switch k.Tensor {
	case route2plan.TensorLNIn:
		return w.layerGamma(w.LNIn, k.Block, "ln_in")
	case route2plan.TensorLNPost:
		return w.layerGamma(w.LNPost, k.Block, "ln_post")
	case route2plan.TensorLNFinal:
		if k.Block != w.Cfg.Layers {
			return nil, 0, fmt.Errorf("qwen: ln_final 的 block=%d 应为哨兵层号 %d", k.Block, w.Cfg.Layers)
		}
		return w.LNFinal, w.Cfg.NormEps, nil
	case route2plan.TensorQNorm:
		return w.layerGamma(w.QNorm, k.Block, "q_norm")
	case route2plan.TensorKNorm:
		return w.layerGamma(w.KNorm, k.Block, "k_norm")
	default:
		return nil, 0, fmt.Errorf("qwen: 未知归一化张量 %s", k.String())
	}
}

// layerGamma 取第 block 层的 gamma 向量（仿射参数按层存储）。
func (w *Weights) layerGamma(s [][]float64, block int, name string) ([]float64, float64, error) {
	if block < 0 || block >= len(s) {
		return nil, 0, fmt.Errorf("qwen: %s 的 block=%d 越界（层数 %d）", name, block, len(s))
	}
	return s[block], w.Cfg.NormEps, nil
}
