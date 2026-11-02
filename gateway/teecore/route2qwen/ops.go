package route2qwen

import (
	"errors"
	"fmt"
	"math"
)

// 本地可信域纯算子（与 gateway/teecore 的逐字同源实现，仅去掉了跨包依赖）。
// 目的：让 route2qwen 自包含，避免引入 teecore 包的 cryptop 依赖树，
// 从而真机最小集编译只需 maskedinfer + route2qwen + cmd。
// 算子语义冻结，改动须与 teecore 同步。

// CausalMaskValue 因果掩码哨兵：-1e30 而非 -Inf，避免 Softmax 在整行全掩码时出 NaN。
const CausalMaskValue = -1e30

// RMSNorm 均方根归一化：x / sqrt(mean(x^2)+eps) * gamma（无均值减法）。
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

// Softmax 稳定 softmax（减最大值防溢出）。
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

// Scores 多头打分：逐 head 计算 scores[h][j] = <q_h, k_{j,h}> / sqrt(headDim)。
func Scores(q []float64, kRows [][]float64, heads, headDim int) ([][]float64, error) {
	if heads <= 0 || headDim <= 0 {
		return nil, fmt.Errorf("route2qwen: heads=%d headDim=%d 非法", heads, headDim)
	}
	if err := checkHeadLayout("q", q, heads, headDim); err != nil {
		return nil, err
	}
	invSqrtHD := 1 / math.Sqrt(float64(headDim))
	out := make([][]float64, heads)
	for h := 0; h < heads; h++ {
		row := make([]float64, len(kRows))
		qOff := h * headDim
		for j, k := range kRows {
			if err := checkHeadLayout("k", k, heads, headDim); err != nil {
				return nil, fmt.Errorf("route2qwen: kRows[%d] 布局非法: %w", j, err)
			}
			var dot float64
			for d := 0; d < headDim; d++ {
				dot += q[qOff+d] * k[qOff+d]
			}
			if math.IsNaN(dot) || math.IsInf(dot, 0) {
				return nil, fmt.Errorf("route2qwen: head=%d 行=%d 点积非有限", h, j)
			}
			row[j] = dot * invSqrtHD
		}
		out[h] = row
	}
	return out, nil
}

// CausalMask 就地施加因果掩码（kvStart+j <= qPos 才允许 attend）。
func CausalMask(scores [][]float64, qPos, kvStart int) [][]float64 {
	for h := range scores {
		for j := range scores[h] {
			if kvStart+j > qPos {
				scores[h][j] = CausalMaskValue
			}
		}
	}
	return scores
}

// SoftmaxScores 逐头 softmax + 有限性护栏。
func SoftmaxScores(scores [][]float64) ([][]float64, error) {
	if len(scores) == 0 {
		return nil, errors.New("route2qwen: scores 为空")
	}
	out := make([][]float64, len(scores))
	for h, row := range scores {
		if len(row) == 0 {
			return nil, fmt.Errorf("route2qwen: head=%d scores 为空", h)
		}
		for i, v := range row {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("route2qwen: head=%d scores[%d] 非有限", h, i)
			}
		}
		prob := Softmax(row)
		for i := range prob {
			if math.IsNaN(prob[i]) || math.IsInf(prob[i], 0) {
				return nil, fmt.Errorf("route2qwen: head=%d softmax 非有限", h)
			}
		}
		out[h] = prob
	}
	return out, nil
}

// WeightedSum 逐头加权求和：out_h = Σ_j probs[h][j]·V_{j,h}。
func WeightedSum(probs [][]float64, vRows [][]float64, heads, headDim int) ([]float64, error) {
	if heads <= 0 || headDim <= 0 {
		return nil, fmt.Errorf("route2qwen: heads=%d headDim=%d 非法", heads, headDim)
	}
	if len(probs) != heads {
		return nil, fmt.Errorf("route2qwen: probs 有 %d 行，应为 heads=%d", len(probs), heads)
	}
	out := make([]float64, heads*headDim)
	for h := 0; h < heads; h++ {
		if len(probs[h]) != len(vRows) {
			return nil, fmt.Errorf("route2qwen: head=%d probs 长度 %d != KV 行数 %d", h, len(probs[h]), len(vRows))
		}
		vOff := h * headDim
		for j, p := range probs[h] {
			if err := checkHeadLayout("v", vRows[j], heads, headDim); err != nil {
				return nil, fmt.Errorf("route2qwen: vRows[%d] 布局非法: %w", j, err)
			}
			for d := 0; d < headDim; d++ {
				out[vOff+d] += p * vRows[j][vOff+d]
			}
		}
	}
	for i, v := range out {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("route2qwen: 加权和 out[%d] 非有限", i)
		}
	}
	return out, nil
}

// Attention 组合算子（全注意核）：Scores → 因果掩码 → Softmax → WeightedSum。
func Attention(q []float64, kRows, vRows [][]float64, heads, headDim, kvStart, qPos int, causal bool) ([]float64, error) {
	if len(kRows) != len(vRows) {
		return nil, fmt.Errorf("route2qwen: K/V 行数不一致 %d != %d", len(kRows), len(vRows))
	}
	if len(kRows) == 0 {
		return nil, errors.New("route2qwen: KV 缓存为空")
	}
	if kvStart < 0 || qPos < 0 {
		return nil, fmt.Errorf("route2qwen: kvStart=%d qPos=%d 不可为负", kvStart, qPos)
	}
	if causal && qPos < kvStart+len(kRows)-1 {
		if qPos < kvStart {
			return nil, fmt.Errorf("route2qwen: causal 下 qPos=%d < kvStart=%d，整行全掩码", qPos, kvStart)
		}
	}
	scores, err := Scores(q, kRows, heads, headDim)
	if err != nil {
		return nil, err
	}
	if causal {
		CausalMask(scores, qPos, kvStart)
	}
	probs, err := SoftmaxScores(scores)
	if err != nil {
		return nil, err
	}
	return WeightedSum(probs, vRows, heads, headDim)
}

// ArgMax 取最大 logit 的下标（TEE 内 argmax 取 token）。
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

func checkHeadLayout(name string, vec []float64, heads, headDim int) error {
	if len(vec) != heads*headDim {
		return fmt.Errorf("%s 长度 %d != heads*headDim=%d", name, len(vec), heads*headDim)
	}
	return nil
}
