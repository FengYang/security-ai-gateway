package route2qwen

import (
	"math/rand"

	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// SyntheticWeights 生成一份「形状正确」的随机权重（非真实训练权重），
// 用于单元自测和对拍——验证 GQA + SwiGLU + Qwen RoPE 的掩码像管线数学正确，
// 无需下载真实大模型。cfg 通常取一个远小于真实模型的小配置（如 Dim=16/Layers=2）。
func SyntheticWeights(cfg QwenConfig, seed int64) *Weights {
	rng := rand.New(rand.NewSource(seed))
	rf := func(rows, cols int) []float32 {
		f := make([]float32, rows*cols)
		for i := range f {
			f[i] = (rng.Float32()*2 - 1) * 0.5 // 小幅度，避免 int8 量化溢出
		}
		return f
	}
	rfGamma := func(n int) []float64 {
		g := make([]float64, n)
		for i := range g {
			g[i] = 0.9 + rng.Float64()*0.2
		}
		return g
	}

	w := &Weights{Cfg: cfg}
	w.Embed, _ = quantize(cfg.Vocab, cfg.Dim, rf(cfg.Vocab, cfg.Dim))
	// tie_word_embeddings=true：LMHead 复用 Embed 本身（[Vocab×Dim]），logits = Embed·hn -> [Vocab]。
	w.LMHead = w.Embed

	for L := 0; L < cfg.Layers; L++ {
		// QuantizedMatrix 约定 [rows=out_features, cols=in_features]，与 PyTorch Linear 一致。
		q, _ := quantize(cfg.AttnDim(), cfg.Dim, rf(cfg.AttnDim(), cfg.Dim))
		k, _ := quantize(cfg.KVDim(), cfg.Dim, rf(cfg.KVDim(), cfg.Dim))
		v, _ := quantize(cfg.KVDim(), cfg.Dim, rf(cfg.KVDim(), cfg.Dim))
		o, _ := quantize(cfg.Dim, cfg.AttnDim(), rf(cfg.Dim, cfg.AttnDim()))
		g, _ := quantize(cfg.FFN, cfg.Dim, rf(cfg.FFN, cfg.Dim))
		u, _ := quantize(cfg.FFN, cfg.Dim, rf(cfg.FFN, cfg.Dim))
		d, _ := quantize(cfg.Dim, cfg.FFN, rf(cfg.Dim, cfg.FFN))
		w.AttnQ = append(w.AttnQ, []*maskedinfer.QuantizedMatrix{q})
		w.AttnK = append(w.AttnK, []*maskedinfer.QuantizedMatrix{k})
		w.AttnV = append(w.AttnV, []*maskedinfer.QuantizedMatrix{v})
		w.AttnO = append(w.AttnO, []*maskedinfer.QuantizedMatrix{o})
		w.Gate = append(w.Gate, []*maskedinfer.QuantizedMatrix{g})
		w.Up = append(w.Up, []*maskedinfer.QuantizedMatrix{u})
		w.Down = append(w.Down, []*maskedinfer.QuantizedMatrix{d})
		w.LNIn = append(w.LNIn, rfGamma(cfg.Dim))
		w.LNPost = append(w.LNPost, rfGamma(cfg.Dim))
	}
	w.LNFinal = rfGamma(cfg.Dim)
	return w
}
