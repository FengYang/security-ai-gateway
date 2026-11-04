package orchestrator

import (
	"fmt"
	"math/rand"

	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// GenOTP 生成一次一密掩码 rGW（长度 = Dim）。网关与后端共享同一 rGW 用于输入/输出边界。
func GenOTP(dim int, modBits maskedinfer.MaskModulusBits) []uint64 {
	r := make([]uint64, dim)
	if modBits == maskedinfer.Mod64 {
		for i := range r {
			r[i] = rand.Uint64()
		}
	} else {
		for i := range r {
			r[i] = uint64(rand.Uint32())
		}
	}
	return r
}

// MaskEmbedding 网关侧：对明文嵌入逐行加 OTP 掩码（ToMaskDomain(x) + rGW）。
func MaskEmbedding(a ModelAdapter, embRows [][]float64, rGW []uint64) [][]uint64 {
	em := a.Embed()
	out := make([][]uint64, len(embRows))
	for i, row := range embRows {
		rm, err := em.Remask(em.ToMaskDomain(row), rGW)
		if err != nil {
			// Remask 报错仅当维度不符，属编程错误；用 panic 暴露以符合包内 must* 约定
			panic(fmt.Sprintf("orchestrator: MaskEmbedding Remask 失败: %v", err))
		}
		out[i] = rm
	}
	return out
}

// GatewayLMHead 形态A 网关侧：对后端返回的掩码 hidden 做 LMHead 线性（可仍在 GPU 掩码盲算），
// 用 OTP rGW 脱掩码得明文 logits，随后由网关做 argmax/采样。LMHead 是线性层，无需 TEE 明文 matmul。
func GatewayLMHead(lmHead *maskedinfer.QuantizedMatrix, maskedHidden [][]uint64, rGW []uint64) ([][]float64, error) {
	out := make([][]float64, len(maskedHidden))
	for b, v := range maskedHidden {
		yc, err := lmHead.CipherLinear([][]uint64{v})
		if err != nil {
			return nil, err
		}
		mi, err := lmHead.MaskImage(rGW)
		if err != nil {
			return nil, err
		}
		yu, err := lmHead.Unmask(yc[0], mi)
		if err != nil {
			return nil, err
		}
		out[b] = lmHead.Decode(yu)
	}
	return out, nil
}

// ForwardMaskedFormA 形态A 便捷入口：模拟「网关加掩嵌入 → 后端 → 网关 LMHead」三段。
// 真实部署中三段由网关(①)与路线2(②)分别执行；此处合在一起仅为对拍验证。
func ForwardMaskedFormA(a ModelAdapter, tokens []int, rGW []uint64) ([][]float64, error) {
	emb, err := a.EmbedRows(tokens)
	if err != nil {
		return nil, err
	}
	maskedEmb := MaskEmbedding(a, emb, rGW)
	maskedHidden, err := a.BackendStep(maskedEmb, rGW)
	if err != nil {
		return nil, err
	}
	return GatewayLMHead(a.LMHead(), maskedHidden, rGW)
}
