// Package orchestrator 路线2 网关侧模型无关密态编排。
//
// 本包只依赖 ModelAdapter 契约完成「加掩嵌入 → 后端掩码 step → LMHead/argmax」三段，
// 全程模型无关；具体模型（qwen/llama/…）由 github.com/FengYang/masked-infer/adapters/* 实现该契约。
//
// 安全边界：本包处理明文 Embedding/OTP/LMHead/argmax，必须运行于**可信网关侧①**，
// 不得部署到不可信加速器；后端掩码 step 全程只见掩码态（见 INV-1）。
package orchestrator

import "github.com/FengYang/masked-infer/core"

// ModelAdapter 网关侧编排器对模型适配器的唯一依赖。
//
// 词表进出（Encode/Decode）与 Embedding/LMHead 权重都在适配器内，使编排器保持模型无关；
// BackendStep 调后端掩码单步（输入/输出均为掩码态）。RoPE 等模型特定后端算子不在此契约内，
// 由适配器后端实现（在 TEE 内、runLayers 中执行）。
type ModelAdapter interface {
	Dim() int
	Encode(text string) []int
	Decode(ids []int) string
	Embed() *maskedinfer.QuantizedMatrix
	EmbedRows(tokens []int) ([][]float64, error)
	LMHead() *maskedinfer.QuantizedMatrix
	BackendStep(maskedEmb [][]uint64, rGW []uint64) ([][]uint64, error)
}
