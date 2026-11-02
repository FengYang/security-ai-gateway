package route2qwen

import (
	"fmt"
	"math"
	"math/rand"

	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// Weights 一个 Qwen 模型的真实（int8/Mod64 量化）权重视图。
//
// 设计：所有线性层权重都以 QuantizedMatrix（int8 + Mod64 定点）持有；
// RMSNorm 的 gamma 是仿射参数，不参与量化，直接存 float64。
// 归一化权重本身就在 [-1,1] 附近，定点误差可忽略，且 demo 的对照基线也把 gamma 当 fp 处理。
type Weights struct {
	Cfg    QwenConfig
	Embed  *maskedinfer.QuantizedMatrix // Vocab × Dim
	LMHead *maskedinfer.QuantizedMatrix // Dim × Vocab（tie 时由 Embed 转置得到）

	AttnQ [][]*maskedinfer.QuantizedMatrix // [layer][0]
	AttnK [][]*maskedinfer.QuantizedMatrix
	AttnV [][]*maskedinfer.QuantizedMatrix
	AttnO [][]*maskedinfer.QuantizedMatrix
	Gate  [][]*maskedinfer.QuantizedMatrix // SwiGLU gate_proj
	Up    [][]*maskedinfer.QuantizedMatrix // SwiGLU up_proj
	Down  [][]*maskedinfer.QuantizedMatrix // SwiGLU down_proj

	LNIn    [][]float64 // [layer] gamma
	LNPost  [][]float64 // [layer] gamma
	LNFinal []float64   // 全局 ln_final gamma
}

// quantize 把扁平 float32 张量（行优先，rows×cols）量化成 int8/Mod64 的 QuantizedMatrix。
//
// 直接由 float32 计算 int8 Data 与 scale，**不构造中间 [][]float64**，
// 以免在 embed_tokens 等大矩阵（1.3 亿参数）上瞬时消耗双倍内存导致 OOM。
func quantize(rows, cols int, f []float32) (*maskedinfer.QuantizedMatrix, error) {
	if len(f) != rows*cols {
		return nil, fmt.Errorf("route2qwen: 张量长度 %d != %d×%d", len(f), rows, cols)
	}
	maxW := 0.0
	for _, v := range f {
		if a := math.Abs(float64(v)); a > maxW {
			maxW = a
		}
	}
	if maxW == 0 {
		return nil, fmt.Errorf("route2qwen: 权重全零，无法量化")
	}
	maxQ := float64((int64(1) << 7) - 1) // INT8 上限 127
	scale := maxW / maxQ
	data := make([]int32, rows*cols)
	for i, v := range f {
		data[i] = int32(math.Round(float64(v) / scale))
	}
	return &maskedinfer.QuantizedMatrix{
		Rows:       rows,
		Cols:       cols,
		Scale:      scale,
		Data:       data,
		ModBits:    maskedinfer.Mod64,
		InputScale: maskedinfer.InputScale,
	}, nil
}

// LoadWeights 从 safetensors 文件加载 Qwen2.5 权重并量化为 int8/Mod64。
//
// 张量名映射（PyTorch Linear 权重形状为 [out_features, in_features]，对应 QuantizedMatrix 的 [rows=out, cols=in]）：
//
//	model.embed_tokens.weight              -> Embed (Vocab×Dim)
//	model.layers.{L}.self_attn.q_proj      -> AttnQ[L] (AttnDim × Dim)
//	model.layers.{L}.self_attn.k_proj      -> AttnK[L] (KVDim × Dim)
//	model.layers.{L}.self_attn.v_proj      -> AttnV[L] (KVDim × Dim)
//	model.layers.{L}.self_attn.o_proj      -> AttnO[L] (Dim × AttnDim)
//	model.layers.{L}.mlp.gate_proj         -> Gate[L]  (FFN × Dim)
//	model.layers.{L}.mlp.up_proj           -> Up[L]    (FFN × Dim)
//	model.layers.{L}.mlp.down_proj         -> Down[L]  (Dim × FFN)
//	model.layers.{L}.input_layernorm       -> LNIn[L]  gamma (Dim)
//	model.layers.{L}.post_attention_layernorm -> LNPost[L] gamma (Dim)
//	model.norm.weight                       -> LNFinal  gamma (Dim)
//	model.lm_head.weight（若独立存在）      -> LMHead (Vocab×Dim)；否则复用 Embed 本身（tie，不做转置）
func LoadWeights(path string, cfg QwenConfig) (*Weights, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	st, err := LoadSafeTensors(path)
	if err != nil {
		return nil, err
	}
	get := func(name string) (STTensor, error) {
		t, ok := st.Tensors[name]
		if !ok {
			return STTensor{}, fmt.Errorf("route2qwen: 缺失张量 %q", name)
		}
		return t, nil
	}
	quantOf := func(t STTensor, rows, cols int) (*maskedinfer.QuantizedMatrix, error) {
		f, err := t.Float32(st)
		if err != nil {
			return nil, err
		}
		return quantize(rows, cols, f)
	}

	w := &Weights{Cfg: cfg}
	if t, err := get("model.embed_tokens.weight"); err != nil {
		return nil, err
	} else {
		w.Embed, err = quantOf(t, cfg.Vocab, cfg.Dim)
		if err != nil {
			return nil, err
		}
	}
	// lm_head：Qwen2.5 tie_word_embeddings=true，复用 embed 的转置
	if t, ok := st.Tensors["model.lm_head.weight"]; ok {
		w.LMHead, err = quantOf(t, cfg.Vocab, cfg.Dim)
		if err != nil {
			return nil, err
		}
	} else {
		// tie_word_embeddings=true：lm_head 与 embed_tokens 共享同一权重矩阵 [Vocab×Dim]，
		// logits = Embed · hn 即 [Vocab×Dim]·[Dim]=[Vocab]，无需转置（转置会输出 [Dim] 维度错误）。
		w.LMHead = w.Embed
	}

	for L := 0; L < cfg.Layers; L++ {
		p := fmt.Sprintf("model.layers.%d.", L)
		qT, _ := get(p + "self_attn.q_proj.weight")
		kT, _ := get(p + "self_attn.k_proj.weight")
		vT, _ := get(p + "self_attn.v_proj.weight")
		oT, _ := get(p + "self_attn.o_proj.weight")
		gT, _ := get(p + "mlp.gate_proj.weight")
		uT, _ := get(p + "mlp.up_proj.weight")
		dT, _ := get(p + "mlp.down_proj.weight")
		liT, _ := get(p + "input_layernorm.weight")
		lpT, _ := get(p + "post_attention_layernorm.weight")

		var e error
		var qm, km, vm, om, gm, um, dm *maskedinfer.QuantizedMatrix
		// 注意：QuantizedMatrix 约定 [rows=out_features, cols=in_features]，
		// 即 PyTorch Linear 权重 [out, in] 直接对应，matmul 为 [rows×cols]·[cols]=[rows]。
		if qm, e = quantOf(qT, cfg.AttnDim(), cfg.Dim); e != nil {
			return nil, e
		}
		if km, e = quantOf(kT, cfg.KVDim(), cfg.Dim); e != nil {
			return nil, e
		}
		if vm, e = quantOf(vT, cfg.KVDim(), cfg.Dim); e != nil {
			return nil, e
		}
		if om, e = quantOf(oT, cfg.Dim, cfg.AttnDim()); e != nil {
			return nil, e
		}
		if gm, e = quantOf(gT, cfg.FFN, cfg.Dim); e != nil {
			return nil, e
		}
		if um, e = quantOf(uT, cfg.FFN, cfg.Dim); e != nil {
			return nil, e
		}
		if dm, e = quantOf(dT, cfg.Dim, cfg.FFN); e != nil {
			return nil, e
		}
		w.AttnQ = append(w.AttnQ, []*maskedinfer.QuantizedMatrix{qm})
		w.AttnK = append(w.AttnK, []*maskedinfer.QuantizedMatrix{km})
		w.AttnV = append(w.AttnV, []*maskedinfer.QuantizedMatrix{vm})
		w.AttnO = append(w.AttnO, []*maskedinfer.QuantizedMatrix{om})
		w.Gate = append(w.Gate, []*maskedinfer.QuantizedMatrix{gm})
		w.Up = append(w.Up, []*maskedinfer.QuantizedMatrix{um})
		w.Down = append(w.Down, []*maskedinfer.QuantizedMatrix{dm})

		var liF, lpF []float32
		if liF, e = liT.Float32(st); e != nil {
			return nil, e
		}
		if lpF, e = lpT.Float32(st); e != nil {
			return nil, e
		}
		w.LNIn = append(w.LNIn, toF64(liF))
		w.LNPost = append(w.LNPost, toF64(lpF))
	}
	if t, err := get("model.norm.weight"); err != nil {
		return nil, err
	} else {
		f, err := t.Float32(st)
		if err != nil {
			return nil, err
		}
		w.LNFinal = toF64(f)
	}
	return w, nil
}

// toF64 把 float32 切片转 float64。
func toF64(f []float32) []float64 {
	out := make([]float64, len(f))
	for i, v := range f {
		out[i] = float64(v)
	}
	return out
}

// embedRows 取 tokens 的嵌入向量（去量化 embed 矩阵对应行）。
// 嵌入是客户端注入的明文，不做掩码。
func (w *Weights) embedRows(tokens []int) ([][]float64, error) {
	out := make([][]float64, len(tokens))
	for i, t := range tokens {
		if t < 0 || t >= w.Cfg.Vocab {
			return nil, fmt.Errorf("route2qwen: token=%d 越界（词表 0..%d）", t, w.Cfg.Vocab-1)
		}
		row := make([]float64, w.Cfg.Dim)
		base := t * w.Cfg.Dim
		for j := 0; j < w.Cfg.Dim; j++ {
			row[j] = w.Embed.Scale * float64(w.Embed.Data[base+j])
		}
		out[i] = row
	}
	return out, nil
}

// dequant 把 QuantizedMatrix 去量化回 fp64 矩阵（行优先）。
func dequant(m *maskedinfer.QuantizedMatrix) [][]float64 {
	out := make([][]float64, m.Rows)
	for i := 0; i < m.Rows; i++ {
		row := make([]float64, m.Cols)
		for j := 0; j < m.Cols; j++ {
			row[j] = m.Scale * float64(m.Data[i*m.Cols+j])
		}
		out[i] = row
	}
	return out
}

// maskedLinear 掩码像线性层：y = W_q · x（int8/Mod64 定点 + 一次掩码脱掩码）。
//
// 每调用一次生成独立随机掩码 r，按路线2 的 V = ToMaskDomain(x) + r (mod R) 注入；
// 不可信加速器侧算 CipherLinear(W, V)，可信侧用 MaskImage(W, r) 脱掩码后 Decode 还原 W·x。
// 该路径与 demo 的掩码内核同语义，是「端到端真模型 × 掩码像」数值验证的核心。
func maskedLinear(m *maskedinfer.QuantizedMatrix, x [][]float64) ([][]float64, error) {
	out := make([][]float64, len(x))
	for b, xr := range x {
		Vx := m.ToMaskDomain(xr)
		r := make([]uint64, len(xr))
		V := make([]uint64, len(xr))
		if m.ModBits == maskedinfer.Mod64 {
			// 模数 2^64 无法表示为 uint64；uint64 加法自然回绕即 mod 2^64
			for i := range r {
				r[i] = rand.Uint64()
				V[i] = Vx[i] + r[i]
			}
		} else {
			const mod32 = uint64(1) << 32
			for i := range r {
				ri := uint64(rand.Uint32())
				r[i] = ri
				V[i] = (Vx[i] + ri) % mod32
			}
		}
		yc, err := m.CipherLinear([][]uint64{V})
		if err != nil {
			return nil, err
		}
		mi, err := m.MaskImage(r)
		if err != nil {
			return nil, err
		}
		yu, err := m.Unmask(yc[0], mi)
		if err != nil {
			return nil, err
		}
		out[b] = m.Decode(yu)
	}
	return out, nil
}

// refLinear 参照线性层：用去量化（Scale·Data）的 int8 权重做 fp64 矩阵乘。
// 与 maskedLinear 的区别仅在掩码/定点环节，用于隔离量化误差（档 A 对照）。
func refLinear(m *maskedinfer.QuantizedMatrix, x [][]float64) ([][]float64, error) {
	f := dequant(m)
	out := make([][]float64, len(x))
	for b, xr := range x {
		if len(xr) != len(f[0]) {
			return nil, fmt.Errorf("route2qwen: refLinear 维度不符 %d != %d", len(xr), len(f[0]))
		}
		o := make([]float64, len(f))
		for i := range f {
			var acc float64
			for j := range f[i] {
				acc += f[i][j] * xr[j]
			}
			o[i] = acc
		}
		out[b] = o
	}
	return out, nil
}
