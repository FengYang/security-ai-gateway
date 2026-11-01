// Package route2demo 提供路线2「确定性 demo 权重」。
//
// 定位：在没有真实权重文件时，让**客户端编排器**（cmd/route2-client）与 **TEE 服务端**
// （gateway/tee-infer-service 的 NewMockWeightProvider）对同一层权重达成逐位一致——
// 双方各自用本包按 (layer, dim) 重算即可，无需通过线路传输权重。
//
// 生成算法与 tee-infer-service 既有 mock 完全一致（迁移自 recompute.go，逐位等价）：
//
//	h = sha256("layer-<L>-<i>-<j>")
//	w[i][j] = (int16(h[0]) | int16(h[1])<<8) / 32768 * 0.5 - 0.25
//
// 再经 NewQuantizedMatrixMod(w, bitWidth=8, Mod64) 量化（scale = maxW/127，无 bias）。
//
// 生产路径应替换为真实权重加载器（safetensors/gguf）；本包仅服务 demo/云测基线。
package route2demo

import (
	"crypto/sha256"
	"fmt"

	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// DefaultDim 默认 demo 维度，与服务端 NewMockWeightProvider(32) 对齐。
const DefaultDim = 32

// LayerWeights 返回第 layer 层的确定性量化权重（int8、Mod64、无 bias）。
// dim 须与服务端一致（默认 32），否则客户端与服务端权重不匹配（MaskImage 维度校验失败）。
func LayerWeights(layer, dim int) (*maskedinfer.QuantizedMatrix, error) {
	if dim <= 0 {
		return nil, fmt.Errorf("route2demo: dim 必须为正，得到 %d", dim)
	}
	weights := make([][]float64, dim)
	for i := range weights {
		weights[i] = make([]float64, dim)
		for j := range weights[i] {
			h := sha256.Sum256([]byte(fmt.Sprintf("layer-%d-%d-%d", layer, i, j)))
			weights[i][j] = (float64(int16(h[0])|int16(h[1])<<8)/32768.0)*0.5 - 0.25
		}
	}
	return maskedinfer.NewQuantizedMatrixMod(weights, 8, maskedinfer.Mod64)
}
