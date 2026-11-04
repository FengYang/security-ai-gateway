// demo.go 确定性演示引擎（原 gateway/tee-infer-service/model/model.go 的实现主体）。
//
// 归属本包而非宿主的理由：`gateway/vllm-adapter` 也要用它做「无 GPU 环境下的对等 mock」，
// 而该适配器是独立进程、不得 import 宿主包（方案 §8.2④）。放在明文引擎平面包里，
// 两侧共享同一份实现，既去掉跨二进制依赖，又避免复制权重公式（复制必然漂移）。
package modelengine

import (
	"math"

	"security-ai-gateway/gateway/teecore/trustedops"
)

// VocabSize 词表大小（演示模型）。
const VocabSize = 16

// InputDim 输入维度（与 embedding-service 默认 dim 对齐）。
const InputDim = 8

// Demo 小型确定性模型：y = softmax(W·relu(W0·x + b0) + b1)，argmax 采样。
//
// 用途：① 验证 trustedops 算子在真实推理流程中的正确性；② 验证密态推理与明文推理
// 结果逐位一致（精度 0 损失）。词表 16、dim 8，非生产模型。
type Demo struct {
	// W0 [InputDim][InputDim]float64 — 隐藏层
	W0 [InputDim][InputDim]float64
	b0 [InputDim]float64
	// W1 [VocabSize][InputDim]float64 — 输出层
	W1 [VocabSize][InputDim]float64
	b1 [VocabSize]float64
}

// NewDemo 构造确定性模型（权重由固定公式生成，可复现、跨进程一致）。
func NewDemo() *Demo {
	m := &Demo{}
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
func (m *Demo) Predict(x []float64) int {
	W0 := make([][]float64, InputDim)
	for i := range m.W0 {
		W0[i] = m.W0[i][:]
	}
	h0 := matVec(W0, x)
	for i := range h0 {
		h0[i] += m.b0[i]
		h0[i] = trustedops.ReLU(h0[i])
	}
	W1 := make([][]float64, VocabSize)
	for i := range m.W1 {
		W1[i] = m.W1[i][:]
	}
	logits := matVec(W1, h0)
	for i := range logits {
		logits[i] += m.b1[i]
	}
	probs := trustedops.Softmax(logits)
	return trustedops.ArgMax(probs)
}

// Generate 演示实现：确定性回显最后一条 user 消息（按 rune 分块流式）。
// 真实生成由 Remote(vLLM)/Cmaas 承担；演示引擎保持无外部依赖的确定性可测性。
func (m *Demo) Generate(req GenerateRequest, onDelta func(delta string) error) error {
	last := ""
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			last = msg.Content
		}
	}
	for _, r := range last {
		if err := onDelta(string(r)); err != nil {
			return err
		}
	}
	return nil
}

// TokenToRune 演示词表映射：token ID → 字符（0-15 → 'a'-'p'）。
func TokenToRune(id int) rune {
	if id < 0 || id >= VocabSize {
		return '?'
	}
	return rune('a' + id)
}

// 编译期断言：演示引擎满足明文引擎契约。
var _ Engine = (*Demo)(nil)
