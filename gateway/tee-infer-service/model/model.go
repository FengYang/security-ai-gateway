// Package model — 小型密态推理模型
//
// 路径 A 的"明文域推理"实现：在 TEE 内对解密后的明文向量执行
// 浮点模型推理（线性层 + ReLU + Softmax + ArgMax 采样），输出 token ID。
//
// 说明：这是确定性小型演示模型（词表 16，dim 8），用于验证：
// 1. teecore.nonlinear 算子在真实推理流程中的正确性
// 2. 密态推理（经 OTP 掩码 → 解密）与明文推理结果完全一致（精度 0 损失）
//
// 自回归文本生成（逐 token 循环 + 完整词表）为 M8 扩展。
package model

import (
	"math"

	"security-ai-gateway/gateway/teecore"
)

// VocabSize 词表大小（演示模型）。
const VocabSize = 16

// InputDim 输入维度（与 embedding-service 默认 dim 对齐）。
const InputDim = 8

// Model 小型确定性模型：y = softmax(W·relu(W0·x + b0) + b1)，argmax 采样。
type Model struct {
	// W0 [InputDim][InputDim]float64 — 隐藏层
	W0 [InputDim][InputDim]float64
	b0 [InputDim]float64
	// W1 [VocabSize][InputDim]float64 — 输出层
	W1 [VocabSize][InputDim]float64
	b1 [VocabSize]float64
}

// New 构造确定性模型（权重由固定公式生成，可复现、跨进程一致）。
func New() *Model {
	m := &Model{}
	for i := 0; i < InputDim; i++ {
		m.b0[i] = math.Sin(float64(i)*0.3) * 0.5
		for j := 0; j < InputDim; j++ {
			m.W0[i][j] = math.Sin(float64(i)*0.11+float64(j)*0.07) * 0.8
		}
	}
	for i := 0; i < VocabSize; i++ {
		m.b1[i] = math.Cos(float64(i) * 0.17)
		for j := 0; j < InputDim; j++ {
			m.W1[i][j] = math.Sin(float64(i)*0.13+float64(j)*0.19) * 0.9
		}
	}
	return m
}

// matVec 矩阵乘向量。
func matVec(W [][]float64, x []float64) []float64 {
	out := make([]float64, len(W))
	for i := range W {
		var s float64
		for j := range x {
			s += W[i][j] * x[j]
		}
		out[i] = s
	}
	return out
}

// Predict 前向推理：x（dim=8 明文浮点向量）→ token ID。
// 流程：h = ReLU(W0·x + b0) → logits = W1·h + b1 → softmax → argmax。
func (m *Model) Predict(x []float64) int {
	W0 := make([][]float64, InputDim)
	for i := range m.W0 {
		W0[i] = m.W0[i][:]
	}
	h0 := matVec(W0, x)
	for i := range h0 {
		h0[i] += m.b0[i]
		h0[i] = teecore.ReLU(h0[i])
	}
	W1 := make([][]float64, VocabSize)
	for i := range m.W1 {
		W1[i] = m.W1[i][:]
	}
	logits := matVec(W1, h0)
	for i := range logits {
		logits[i] += m.b1[i]
	}
	probs := teecore.Softmax(logits)
	return teecore.ArgMax(probs)
}

// TokenToRune 演示词表映射：token ID → 字符（0-15 → 'a'-'p'）。
func TokenToRune(id int) rune {
	if id < 0 || id >= VocabSize {
		return '?'
	}
	return rune('a' + id)
}
