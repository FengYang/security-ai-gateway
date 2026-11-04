package qwen

import (
	"bytes"
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
	Cfg       QwenConfig
	EmbedMat  *maskedinfer.QuantizedMatrix // Vocab × Dim
	LMHeadMat *maskedinfer.QuantizedMatrix // Dim × Vocab（tie 时由 EmbedMat 转置得到）

	// Tok 可选：绑定后使 *Weights 满足网关侧 ModelAdapter 的文本进出（Encode/Decode）。
	// 仅加载权重、只用 token 级接口时可留 nil。
	Tok *Tokenizer

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

	// QNorm / KNorm 每层 q_norm / k_norm 的 gamma（长度 = HeadDim），Qwen3 起才有。
	// nil 表示该模型无 QK-norm（Qwen2/2.5），runLayers 据此跳过逐头归一。
	QNorm [][]float64
	KNorm [][]float64
}

// quantize 把扁平 float32 张量（行优先，rows×cols）量化成 int8/Mod64 的 QuantizedMatrix。
//
// 直接由 float32 计算 int8 Data 与 scale，**不构造中间 [][]float64**，
// 以免在 embed_tokens 等大矩阵（1.3 亿参数）上瞬时消耗双倍内存导致 OOM。
func quantize(rows, cols int, f []float32) (*maskedinfer.QuantizedMatrix, error) {
	if len(f) != rows*cols {
		return nil, fmt.Errorf("qwen: 张量长度 %d != %d×%d", len(f), rows, cols)
	}
	maxW := 0.0
	for _, v := range f {
		if a := math.Abs(float64(v)); a > maxW {
			maxW = a
		}
	}
	if maxW == 0 {
		return nil, fmt.Errorf("qwen: 权重全零，无法量化")
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
			return STTensor{}, fmt.Errorf("qwen: 缺失张量 %q", name)
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
		w.EmbedMat, err = quantOf(t, cfg.Vocab, cfg.Dim)
		if err != nil {
			return nil, err
		}
	}
	// lm_head：tie_word_embeddings=true 时与 embed_tokens 是同一份权重，直接复用
	// （0.6B 规模下 embed 占 155M 参数，再量化一份等于白吃 ~0.6GB；构建机只有 7GB 内存，
	// 这点在真实权重链路上是能不能跑起来的分界）。复用前做一次前缀逐字节抽查，
	// 配置与权重矛盾时 fail-closed，而不是静默用错矩阵。
	if t, ok := st.Tensors["model.lm_head.weight"]; ok {
		if cfg.TiedEmb {
			if !sameTensorPrefix(st, t, st.Tensors["model.embed_tokens.weight"], 1<<16) {
				return nil, fmt.Errorf("qwen: tie_word_embeddings=true 但 lm_head 与 embed_tokens 前缀不一致（权重与配置矛盾）")
			}
			w.LMHeadMat = w.EmbedMat
		} else if w.LMHeadMat, err = quantOf(t, cfg.Vocab, cfg.Dim); err != nil {
			return nil, err
		}
	} else {
		// tie_word_embeddings=true：lm_head 与 embed_tokens 共享同一权重矩阵 [Vocab×Dim]，
		// logits = Embed · hn 即 [Vocab×Dim]·[Dim]=[Vocab]，无需转置（转置会输出 [Dim] 维度错误）。
		w.LMHeadMat = w.EmbedMat
	}

	var qNorms, kNorms [][]float64

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

		// Qwen3 起每层带 q_norm/k_norm（逐头 RMSNorm，gamma 长度 = HeadDim）。
		// 二者必须同时存在或同时缺失：只出现一个说明权重被裁剪/版本混杂，直接 fail-closed，
		// 否则会静默退化成"只归一 Q 不归一 K"，数值全错但不报错。
		qnT, hasQN := st.Tensors[p+"self_attn.q_norm.weight"]
		knT, hasKN := st.Tensors[p+"self_attn.k_norm.weight"]
		if hasQN != hasKN {
			return nil, fmt.Errorf("qwen: 层 %d 的 q_norm/k_norm 只存在其一（QK-norm 权重不完整）", L)
		}
		if hasQN {
			var qnF, knF []float32
			if qnF, e = qnT.Float32(st); e != nil {
				return nil, e
			}
			if knF, e = knT.Float32(st); e != nil {
				return nil, e
			}
			if len(qnF) != cfg.HeadDim || len(knF) != cfg.HeadDim {
				return nil, fmt.Errorf("qwen: 层 %d q_norm/k_norm 长度 %d/%d != HeadDim=%d",
					L, len(qnF), len(knF), cfg.HeadDim)
			}
			qNorms = append(qNorms, toF64(qnF))
			kNorms = append(kNorms, toF64(knF))
		}
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
	// Qwen3 才有：全部层都带 QK-norm 时启用；否则保持 nil（runLayers 跳过逐头归一）。
	w.QNorm, w.KNorm = qNorms, kNorms
	return w, nil
}

// sameTensorPrefix 比较两个张量在数据区里前 nbytes 字节是否相同（tie 的廉价抽查）。
//
// 只做前缀比对、不做全量比对的理由：全量比对 embed/lm_head 等于把 1.2GB 再扫一遍，
// 而复用的目的正是省内存/省时间；前缀抽查足以拦住"配置写 tie、权重其实是两套"的矛盾，
// 真正的数值正确性由真实权重 golden 对拍兜底（top-1/logits 容差）。
func sameTensorPrefix(st *SafeTensors, a, b STTensor, nbytes int) bool {
	if a.DType != b.DType || a.Length != b.Length {
		return false
	}
	if a.Offset < 0 || b.Offset < 0 || a.Offset+a.Length > len(st.data) || b.Offset+b.Length > len(st.data) {
		return false
	}
	if nbytes > a.Length {
		nbytes = a.Length
	}
	return bytes.Equal(st.data[a.Offset:a.Offset+nbytes], st.data[b.Offset:b.Offset+nbytes])
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
			return nil, fmt.Errorf("qwen: token=%d 越界（词表 0..%d）", t, w.Cfg.Vocab-1)
		}
		row := make([]float64, w.Cfg.Dim)
		base := t * w.Cfg.Dim
		for j := 0; j < w.Cfg.Dim; j++ {
			row[j] = w.EmbedMat.Scale * float64(w.EmbedMat.Data[base+j])
		}
		out[i] = row
	}
	return out, nil
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
//
// 【逐行流式，不整体反量化】旧实现先 dequant(m) 得到整矩阵 [][]float64：对 0.6B 模型的
// embed/LMHead（151936×1024）瞬时就是 1.24GB，真实权重 golden 在 7GB 构建机上会 OOM。
// 现按输出行累加，峰值内存 O(输出行数)；运算次序与 dequant 版逐元素一致（Scale·Data 再乘 x）。
func refLinear(m *maskedinfer.QuantizedMatrix, x [][]float64) ([][]float64, error) {
	out := make([][]float64, len(x))
	for b, xr := range x {
		if len(xr) != m.Cols {
			return nil, fmt.Errorf("qwen: refLinear 维度不符 %d != %d", len(xr), m.Cols)
		}
		o := make([]float64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			base := i * m.Cols
			var acc float64
			for j, xv := range xr {
				acc += float64(m.Data[base+j]) * m.Scale * xv
			}
			o[i] = acc
		}
		out[b] = o
	}
	return out, nil
}
