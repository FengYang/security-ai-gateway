package qwen

import "security-ai-gateway/gateway/teecore/maskedinfer"

// 网关侧 ModelAdapter 契约由 gateway/route2/orchestrator 定义；本文件以 *Weights 的
// 方法集满足之。**不反向 import orchestrator**（依赖方向 orchestrator → adapters，反之禁止）。
//
// 词表进出（Encode/Decode）与 Embedding/LMHead 权重都在适配器内，使编排器保持模型无关；
// 后端掩码 step（BackendStep）仍由本包 Runner 执行、全程只见掩码态。

// Dim 隐藏维。
func (w *Weights) Dim() int { return w.Cfg.Dim }

// Encode 文本→token；未绑定分词器时返回 nil。
func (w *Weights) Encode(text string) []int {
	if w.Tok == nil {
		return nil
	}
	return w.Tok.Encode(text)
}

// Decode token→文本；未绑定分词器时返回空串。
func (w *Weights) Decode(ids []int) string {
	if w.Tok == nil {
		return ""
	}
	return w.Tok.Decode(ids)
}

// Embed 返回明文 Embedding 权重矩阵（网关侧加掩所需）。
func (w *Weights) Embed() *maskedinfer.QuantizedMatrix { return w.EmbedMat }

// EmbedRows 取 tokens 的明文嵌入行。
func (w *Weights) EmbedRows(tokens []int) ([][]float64, error) { return w.embedRows(tokens) }

// LMHead 返回明文 LM head 权重矩阵。
func (w *Weights) LMHead() *maskedinfer.QuantizedMatrix { return w.LMHeadMat }

// BackendStep 调后端掩码单步（形态A 后端入口），输入/输出均为掩码态。
func (w *Weights) BackendStep(maskedEmb [][]uint64, rGW []uint64) ([][]uint64, error) {
	return ForwardMaskedEmb(w, maskedEmb, rGW)
}
