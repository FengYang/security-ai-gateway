package trustedops

import (
	"fmt"
	"math"
)

// 非线性算子补算。
//
// 真实模型推理中，非线性层无法在密文域计算，
// 需在 TEE 内解密后计算并重新加密。本文件实现各算子纯函数
// （浮点域，与 vLLM 权重精度对齐），供 M7 推理服务调用。

// ReLU 修正线性单元：max(0, x)。
func ReLU(x float64) float64 {
	if x < 0 {
		return 0
	}
	return x
}

// GELU 高斯误差线性单元：x * Φ(x)，Φ 为标准正态 CDF。
// 使用 erf 近似（Go math.Erf 高精度实现）。
func GELU(x float64) float64 {
	return 0.5 * x * (1 + math.Erf(x/math.Sqrt2))
}

// SiLU Sigmoid 线性单元（Swish 的 β=1 特例）：x * σ(x) = x / (1 + e^{-x})。
// Qwen3 等模型 SwiGLU 门控激活，与 vLLM/huggingface 权重精度对齐。
func SiLU(x float64) float64 {
	return x / (1 + math.Exp(-x))
}

// SiLUMul 逐元素 silu(gate) ⊙ up，即 SwiGLU 门控乘法：
//
//	out[i] = SiLU(gate[i]) * up[i]
//
// gate / up 长度必须相等（fail-closed：不等返回 error，绝不在长度错配下静默截断）。
func SiLUMul(gate, up []float64) ([]float64, error) {
	if len(gate) != len(up) {
		return nil, fmt.Errorf("trustedops: SiLUMul 两输入长度不等 gate=%d up=%d", len(gate), len(up))
	}
	out := make([]float64, len(gate))
	for i := range gate {
		out[i] = SiLU(gate[i]) * up[i]
	}
	return out, nil
}

// Softmax 稳定 softmax：概率和为 1。
// 减去最大值防止指数溢出。
//
// 【调用方约定 · D9】本算子**要求输入全部为有限值**：传入 `-Inf` 会在形如
// `v[i] - maxV` 的步骤上得到 `-Inf - (-Inf) = NaN`，并把 NaN 顺着算子链放大到全链路。
// 因此因果掩码一律使用**有限哨兵** `-1e30`（trustedops.CausalMaskValue）而非 `-Inf`；
// 需要"屏蔽"的分数请写成 -1e30，本算子会自动给出 0 概率，不会发生 NaN。
//
// 【共用纪律】本文件与 attention.go 的算子是 `route2ref` 参照前向与 TEE 服务端
// 共用的同一份实现：任何一处语义改动都会同时改变两条基线，故不得在其中任一侧
// 另起炉灶地"优化"。
func Softmax(v []float64) []float64 {
	out := make([]float64, len(v))
	maxV := math.Inf(-1)
	for _, x := range v {
		if x > maxV {
			maxV = x
		}
	}
	var sum float64
	for i, x := range v {
		out[i] = math.Exp(x - maxV)
		sum += out[i]
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

// RMSNorm 均方根归一化：x / sqrt(mean(x^2) + eps) * gamma（无均值减法）。
// vLLM 的 RMSNorm（layernorm.py）语义，供路线 2 补算服务使用。
func RMSNorm(x, gamma []float64, eps float64) []float64 {
	n := len(x)
	out := make([]float64, n)
	if n == 0 {
		return out
	}
	var sqSum float64
	for _, v := range x {
		sqSum += v * v
	}
	invStd := 1 / math.Sqrt(sqSum/float64(n)+eps)
	for i, v := range x {
		norm := v * invStd
		if gamma != nil {
			norm *= gamma[i]
		}
		out[i] = norm
	}
	return out
}

// PerHeadRMSNorm 逐头 RMSNorm（Qwen3 的 q_norm / k_norm）。
//
// 与 RMSNorm 的差别：不是整行归一，而是把一行按 headDim 切成 Heads 段、**每段独立**归一；
// q_norm/k_norm.weight 形状是 [head_dim]，所有头共享同一组 gamma。用于 Q/K 投影后、RoPE 之前的
// 逐头归一（真实 Qwen3 结构；V 不做 QK-norm）。
//
// 长度护栏：len(v) 须为 headDim 整数倍，len(gamma) 须 == headDim，否则 fail-closed。
func PerHeadRMSNorm(v, gamma []float64, headDim int, eps float64) ([]float64, error) {
	if headDim <= 0 || len(v)%headDim != 0 {
		return nil, fmt.Errorf("trustedops: PerHeadRMSNorm 向量长度 %d 不是 headDim=%d 的整数倍", len(v), headDim)
	}
	if len(gamma) != headDim {
		return nil, fmt.Errorf("trustedops: PerHeadRMSNorm gamma 长度 %d != headDim=%d", len(gamma), headDim)
	}
	out := make([]float64, len(v))
	for off := 0; off < len(v); off += headDim {
		copy(out[off:off+headDim], RMSNorm(v[off:off+headDim], gamma, eps))
	}
	return out, nil
}

// LayerNorm 层归一化：(x - mean) / sqrt(var + eps) * gamma + beta。
// x 为激活向量，gamma/beta 为仿射参数（可为 nil，此时忽略缩放平移）。
func LayerNorm(x, gamma, beta []float64, eps float64) []float64 {
	n := len(x)
	out := make([]float64, n)
	if n == 0 {
		return out
	}
	var mean float64
	for _, v := range x {
		mean += v
	}
	mean /= float64(n)
	var variance float64
	for _, v := range x {
		d := v - mean
		variance += d * d
	}
	variance /= float64(n)
	invStd := 1 / math.Sqrt(variance+eps)
	for i, v := range x {
		norm := (v - mean) * invStd
		if gamma != nil {
			norm *= gamma[i]
		}
		if beta != nil {
			norm += beta[i]
		}
		out[i] = norm
	}
	return out
}

// ArgMax 采样（方案 C：TEE 内 argmax 取 token ID，）。
func ArgMax(logits []float64) int {
	if len(logits) == 0 {
		return -1
	}
	idx := 0
	for i := 1; i < len(logits); i++ {
		if logits[i] > logits[idx] {
			idx = i
		}
	}
	return idx
}

// BatchArgMax 批处理采样。
// 对每个 logits 向量执行 ArgMax，批量返回 token ID；空向量返回 -1。
// vLLM 连续批处理下 logits 按批次批量回传 TEE，TEE 批量执行 ArgMax 后统一加密返回。
func BatchArgMax(batch [][]float64) []int {
	out := make([]int, len(batch))
	for i, logits := range batch {
		out[i] = ArgMax(logits)
	}
	return out
}
