// Package route2qwen 路线2 适配 Qwen2.5 系列（Qwen2 架构）的真实开源模型推理。
//
// 定位：把路线2 的掩码像推理内核（maskedinfer 的 MaskedLinear/CipherLinear/Unmask/Decode）
// 接到一个**真实、知名、开源**的小模型上，做端到端的 CPU 数值验证。
//
// 与路线2 现有 demo（route2demo）的关系：
//   - demo 的权重是 sha256 确定性派生的玩具权重；本包加载 Qwen2.5 的**真实权重**。
//   - demo 的架构是「无门控 MLP + MHA」；Qwen2.5 是「SwiGLU 门控 MLP + GQA」，
//     故本包自带 GQA + SwiGLU + Qwen 版 RoPE 前向，不复用 demo 的 plan/Build。
//   - 掩码像内核（QuantizedMatrix）与可信域算子（teecore.RMSNorm/Attention/Softmax）
//     是通用的，直接复用，本包不重新发明。
//
// 安全边界：本包仅做「可信域明文 float64」上的参照前向与「整数域掩码」的脱掩码校验，
// 不引入任何网络/客户端编排。生产部署所需的 plan 集成（Build/服务端 step 执行器）
// 是后续工作，不在本包范围内。
package route2qwen

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

// Validate 校验结构自洽（fail-closed）。
func (c QwenConfig) Validate() error {
	if c.Layers < 1 || c.Dim < 1 || c.Heads < 1 || c.KVHeads < 1 {
		return fmt.Errorf("route2qwen: 基础维度非法 L=%d D=%d H=%d KV=%d", c.Layers, c.Dim, c.Heads, c.KVHeads)
	}
	if c.HeadDim != c.Dim/c.Heads {
		return fmt.Errorf("route2qwen: HeadDim=%d != Dim/Heads=%d", c.HeadDim, c.Dim/c.Heads)
	}
	if c.KVHeads > c.Heads || c.Heads%c.KVHeads != 0 {
		return fmt.Errorf("route2qwen: GQA 不整除 Heads=%d KVHeads=%d", c.Heads, c.KVHeads)
	}
	if c.FFN < 1 || c.Vocab < 2 {
		return fmt.Errorf("route2qwen: FFN=%d Vocab=%d 非法", c.FFN, c.Vocab)
	}
	if !(c.RopeTheta > 0) || !(c.NormEps > 0) || c.MaxTokens < 1 {
		return fmt.Errorf("route2qwen: RopeTheta/NormEps/MaxTokens 须为正")
	}
	return nil
}

// KVDim 单个 token 的 K/V 投影输出宽度（KVHeads * HeadDim）。
func (c QwenConfig) KVDim() int { return c.KVHeads * c.HeadDim }

// AttnDim Q 投影输出宽度（Heads * HeadDim == Dim）。
func (c QwenConfig) AttnDim() int { return c.Heads * c.HeadDim }
