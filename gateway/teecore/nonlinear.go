package teecore

import "math"

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

// Softmax 稳定 softmax：概率和为 1。
// 减去最大值防止指数溢出。
//
// 【调用方约定 · D9】本算子**要求输入全部为有限值**：传入 `-Inf` 会在形如
// `v[i] - maxV` 的步骤上得到 `-Inf - (-Inf) = NaN`，并把 NaN 顺着算子链放大到全链路。
// 因此因果掩码一律使用**有限哨兵** `-1e30`（teecore.CausalMaskValue）而非 `-Inf`；
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
