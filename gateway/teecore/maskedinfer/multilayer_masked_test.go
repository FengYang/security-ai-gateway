package maskedinfer

// 多层层叠端到端验证（M3 前置 / 用户路线2 步骤②）。
// 复用 M0/M1 已验证内核（int128 累加 + Mod64）与 docs §4.4 预处理客户端契约，
// 证明"掩码像推理"可在多层 Transformer/MLP 上逐层正确堆叠：
//   - r 仅在第 0 层由客户端派生注入；ℓ≥1 各层掩码项由 TEE remask 输出原样转发（杜绝双重掩码）。
//   - 线性层委托"不可信加速器"模拟（CipherLinear 在整数域 W·V mod 2^64）。
//   - 逐层断言：掩码解码输出 == 同量化权重的明文线性（仅浮点舍入差，证明掩码数学严格正确）；
//     并逼近全精度真模型（int8 量化容差，证明端到端可信）。

import (
	"fmt"
	"math"
	"testing"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/teecore"
)

// testRoute2Modulus 与 recompute.go 的 route2MaskModulus 同源（2^64-1，统计等价 2^64）。
const testRoute2Modulus uint64 = ^uint64(0)

// plaintextGELUMLP 明文基准：每层 Linear 后（末层不激活）GELU；返回末层输出与逐层中间线性值。
func plaintextGELUMLP(weights [][][]float64, biases [][]float64, x []float64) ([]float64, [][]float64) {
	z := make([]float64, len(x))
	copy(z, x)
	inter := make([][]float64, 0, len(weights))
	for ℓ := range weights {
		row := make([]float64, len(weights[ℓ]))
		for i := range row {
			var acc float64
			for j := range z {
				acc += weights[ℓ][i][j] * z[j]
			}
			acc += biases[ℓ][i]
			row[i] = acc
		}
		// inter 保存每层 RAW 线性输出（GELU 前），供掩码路径逐层比对。
		// 必须 append 副本，否则后续对 row 原地 GELU 会污染 inter[ℓ]。
		inter = append(inter, append([]float64(nil), row...))
		if ℓ < len(weights)-1 {
			for i := range row {
				row[i] = teecore.GELU(row[i])
			}
		}
		z = row
	}
	return z, inter
}

// TestMultilayerMaskedInferenceRealWeights 真实权重量化 + Mod64 + 客户契约 多层层叠端到端。
func TestMultilayerMaskedInferenceRealWeights(t *testing.T) {
	if len(realMLPWeights) == 0 {
		t.Fatal("realMLP fixture 缺失")
	}
	dims := realMLPDims
	L := len(dims) - 1

	// 构建真实权重量化矩阵（int8 + Mod64 + 真实 bias）
	mats := make([]*QuantizedMatrix, L)
	for ℓ := 0; ℓ < L; ℓ++ {
		m, err := NewQuantizedMatrixMod(realMLPWeights[ℓ], 8, Mod64)
		if err != nil {
			t.Fatalf("layer %d NewQuantizedMatrixMod: %v", ℓ, err)
		}
		m.WithBias(realMLPBiases[ℓ])
		mats[ℓ] = m
	}

	// 明文基准
	x0 := make([]float64, dims[0])
	for i := range x0 {
		x0[i] = (float64(i) - float64(dims[0])/2) * 0.13
	}
	ref, plainInter := plaintextGELUMLP(realMLPWeights, realMLPBiases, x0)

	// 会话 seed（TEE 与客户端共享；生产环境由 KDF(K_enc) 派生，此处直接提供同源 seed）
	seed := []byte("route2-confllm-seed-2026-1123-4567890A")

	// 客户端：第 0 层掩码（仅此处注入 r_0）
	s0, err := mask.NewStreamDomain(seed, testRoute2Modulus, []byte("otpmask/layer/0/v1"))
	if err != nil {
		t.Fatalf("stream0: %v", err)
	}
	r0 := make([]uint64, dims[0])
	for i := range r0 {
		r0[i] = s0.Next() % testRoute2Modulus
	}
	xMask0 := mats[0].ToMaskDomain(x0)
	V := make([]uint64, dims[0])
	for i := range V {
		V[i] = xMask0[i] + r0[i] // uint64 自然回绕 = mod 2^64（Mod64）
	}

	// xAct 跟踪喂入各层的明文激活（用于精确掩码校验）
	xAct := make([]float64, len(x0))
	copy(xAct, x0)

	var finalLogits []float64
	for ℓ := 0; ℓ < L; ℓ++ {
		// 不可信加速器：yCipher = W_ℓ · V mod 2^64
		ycOut, err := mats[ℓ].CipherLinear([][]uint64{V})
		if err != nil {
			t.Fatalf("layer %d CipherLinear: %v", ℓ, err)
		}
		yCipher := ycOut[0]

		// TEE：派生 rMask_ℓ（与 recompute.go newLayerStream 同源：seed + domain）
		sℓ, err := mask.NewStreamDomain(seed, testRoute2Modulus, []byte(fmt.Sprintf("otpmask/layer/%d/v1", ℓ)))
		if err != nil {
			t.Fatalf("stream %d: %v", ℓ, err)
		}
		rMask := make([]uint64, dims[ℓ])
		for i := range rMask {
			rMask[i] = sℓ.Next() % testRoute2Modulus
		}
		maskImage, err := mats[ℓ].MaskImage(rMask)
		if err != nil {
			t.Fatalf("layer %d MaskImage: %v", ℓ, err)
		}
		y, err := mats[ℓ].Unmask(yCipher, maskImage)
		if err != nil {
			t.Fatalf("layer %d Unmask: %v", ℓ, err)
		}
		yFloat := mats[ℓ].Decode(y) // = W_ℓ · x_ℓ + b_ℓ（明文线性输出，量化权重）

		// (A) 掩码数学严格正确：解码输出 == 同量化权重的明文线性（仅浮点舍入差）。
		// 这隔离了"掩码/脱掩码/重掩码"逻辑本身的正确性，与量化无关。
		plainQ := mats[ℓ].PlainLinear([][]float64{xAct})[0]
		for i := range yFloat {
			if math.Abs(yFloat[i]-plainQ[i]) > 1e-3 {
				t.Fatalf("layer %d dim %d: 掩码解码 %.6f 与量化明文 %.6f 偏差过大（掩码逻辑错误）",
					ℓ, i, yFloat[i], plainQ[i])
			}
		}

		// (B) 端到端逼近真模型（int8 量化容差 15%）。注意：掩码数学正确性已由 (A) 严格保证，
		// 此处仅作 int8 量化保真度健康度检查——量化引入的相对误差通常 <10%，若逼近 100% 必为逻辑错误。
		for i := range yFloat {
			want := plainInter[ℓ][i]
			rel := math.Abs(yFloat[i]-want) / (math.Abs(want) + 1e-6)
			if rel > 0.15 {
				t.Fatalf("layer %d dim %d: 解码 %.6f 与真模型 %.6f 量化偏差过大 (rel=%.4f)",
					ℓ, i, yFloat[i], want, rel)
			}
		}

		if ℓ < L-1 {
			// 隐藏层：GELU + 重掩码，原样转发为下一层 V_{ℓ+1}（含 r_{ℓ+1} 掩码项）
			for i := range yFloat {
				yFloat[i] = teecore.GELU(yFloat[i])
			}
			fY := mats[ℓ].ToMaskDomain(yFloat)
			sNext, err := mask.NewStreamDomain(seed, testRoute2Modulus, []byte(fmt.Sprintf("otpmask/layer/%d/v1", ℓ+1)))
			if err != nil {
				t.Fatalf("next stream %d: %v", ℓ, err)
			}
			rNext := make([]uint64, dims[ℓ+1])
			for i := range rNext {
				rNext[i] = sNext.Next() % testRoute2Modulus
			}
			remasked, err := mats[ℓ].Remask(fY, rNext)
			if err != nil {
				t.Fatalf("layer %d Remask: %v", ℓ, err)
			}
			V = remasked // 转发：r_{ℓ+1} 已嵌入，下一层 TEE 以同 domain 重派生得到同一 r 完成 Unmask
			xAct = yFloat // 下一层明文激活（GELU 后）
		} else {
			finalLogits = yFloat
		}
	}

	for i := range finalLogits {
		if math.Abs(finalLogits[i]-ref[i]) > 0.15*(math.Abs(ref[i])+1e-6) {
			t.Fatalf("末层 dim %d: 掩码 %v 与明文 %v 量化偏差超 15%%", i, finalLogits[i], ref[i])
		}
	}
	t.Logf("多层层叠端到端通过：masked 末层 logits=%v 明文基准=%v（层数=%d，权重=真实 torch 默认初始化）", finalLogits, ref, L)
}
