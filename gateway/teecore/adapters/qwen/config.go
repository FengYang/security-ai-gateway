// Package qwen 路线2 适配 Qwen2.5 系列（Qwen2 架构）的真实开源模型推理。
//
// 定位：把路线2 的掩码像推理内核（maskedinfer 的 MaskedLinear/CipherLinear/Unmask/Decode）
// 接到一个**真实、知名、开源**的小模型上，做端到端的 CPU 数值验证。
//
// 与路线2 现有 demo（route2demo）的关系：
//   - demo 的权重是 sha256 确定性派生的玩具权重；本包加载 Qwen2.5 的**真实权重**。
//   - demo 的架构是「无门控 MLP + MHA」；Qwen2.5 是「SwiGLU 门控 MLP + GQA」，
//     故本包自带 GQA + SwiGLU + Qwen 版 RoPE 前向，不复用 demo 的 plan/Build。
//   - 掩码像内核（QuantizedMatrix）与可信域算子（trustedops.RMSNorm/Attention/Softmax）
//     是通用的，直接复用，本包不重新发明。
//
// 安全边界：本包仅做「可信域明文 float64」上的参照前向与「整数域掩码」的脱掩码校验，
// 不引入任何网络/客户端编排。生产部署所需的 plan 集成（Build/服务端 step 执行器）
// 是后续工作，不在本包范围内。
package qwen

import "fmt"

// QwenConfig 描述 Qwen2（Qwen2.5 同架构）的结构参数。
// 字段名直接对齐官方 config.json。
type QwenConfig struct {
	Layers    int     // num_hidden_layers
	Dim       int     // hidden_size
	Heads     int     // num_attention_heads（Q 头数）
	KVHeads   int     // num_key_value_heads（GQA 的 KV 头数）
	HeadDim   int     // hidden_size / heads
	FFN       int     // intermediate_size（SwiGLU 中间宽）
	Vocab     int     // vocab_size
	RopeTheta float64 // rope_theta
	NormEps   float64 // rms_norm_eps
	MaxTokens int     // 单会话最大位置数
	TiedEmb   bool    // tie_word_embeddings（lm_head 复用 embed_tokens）
}

// Qwen25_05B 返回 Qwen2.5-0.5B-Instruct 的精确结构配置（来自官方 config.json）。
func Qwen25_05B() QwenConfig {
	return QwenConfig{
		Layers:    24,
		Dim:       896,
		Heads:     14,
		KVHeads:   2,
		HeadDim:   64,
		FFN:       4864,
		Vocab:     151936,
		RopeTheta: 1e6,
		NormEps:   1e-6,
		MaxTokens: 32768,
		TiedEmb:   true,
	}
}

// Qwen3_06B 返回 Qwen3-0.6B 的结构配置（Qwen3Guard-Gen-0.6B 与之同构，
// 取自其 config.json：model_type=qwen3 / 28 层 / hidden 1024 / 16 Q 头 / 8 KV 头 /
// head_dim 128 / FFN 3072 / vocab 151936 / θ=1e6 / tied embeddings）。
//
// 与 Qwen2.5 的两点结构差异（本包均已支持）：
//  1. head_dim 与 hidden_size/num_heads **解耦**（128 vs 64）⇒ AttnDim=2048 ≠ Dim=1024；
//  2. 每层带 q_norm/k_norm（对每个头的 head_dim 维做 RMSNorm）⇒ 由 LoadWeights 按张量存在性启用。
func Qwen3_06B() QwenConfig {
	return QwenConfig{
		Layers:    28,
		Dim:       1024,
		Heads:     16,
		KVHeads:   8,
		HeadDim:   128,
		FFN:       3072,
		Vocab:     151936,
		RopeTheta: 1e6,
		NormEps:   1e-6,
		MaxTokens: 32768,
		TiedEmb:   true,
	}
}

// Validate 校验结构自洽（fail-closed）。
func (c QwenConfig) Validate() error {
	if c.Layers < 1 || c.Dim < 1 || c.Heads < 1 || c.KVHeads < 1 {
		return fmt.Errorf("qwen: 基础维度非法 L=%d D=%d H=%d KV=%d", c.Layers, c.Dim, c.Heads, c.KVHeads)
	}
	// head_dim：Qwen2/2.5 恒等于 Dim/Heads；自 Qwen3 起允许解耦（0.6B: 128 vs 64），
	// 故不再强制相等。仍要求上界受 Dim 约束，避免把 1280 之类的笔误静默放过
	// （HeadDim 偏大不会报错，只会让 Q/K 投影宽度与权重形状对不上，最终在 quantize 处报错——
	// 那里信息更差，故提前到此处拦截）。
	if c.HeadDim < 1 || c.HeadDim > c.Dim {
		return fmt.Errorf("qwen: HeadDim=%d 非法（须 1..Dim=%d）", c.HeadDim, c.Dim)
	}
	if c.KVHeads > c.Heads || c.Heads%c.KVHeads != 0 {
		return fmt.Errorf("qwen: GQA 不整除 Heads=%d KVHeads=%d", c.Heads, c.KVHeads)
	}
	if c.FFN < 1 || c.Vocab < 2 {
		return fmt.Errorf("qwen: FFN=%d Vocab=%d 非法", c.FFN, c.Vocab)
	}
	if !(c.RopeTheta > 0) || !(c.NormEps > 0) || c.MaxTokens < 1 {
		return fmt.Errorf("qwen: RopeTheta/NormEps/MaxTokens 须为正")
	}
	return nil
}

// KVDim 单个 token 的 K/V 投影输出宽度（KVHeads * HeadDim）。
func (c QwenConfig) KVDim() int { return c.KVHeads * c.HeadDim }

// AttnDim Q 投影输出宽度（Heads * HeadDim）。
//
// Qwen2/2.5 恒等于 Dim；Qwen3 起可大于 Dim（0.6B: 2048 vs 1024），o_proj 负责映回 Dim。
func (c QwenConfig) AttnDim() int { return c.Heads * c.HeadDim }
