// step_exec.go - proto=2 单步执行引擎（脱掩码 → Decode → 算子 → ToMaskDomain → 重掩码）
//
// 【掩码域归属 · 最容易写反的一条】输出重掩码用的是**产出步自己的域**
// （StepSpec.MaskDomain() == Coord.MaskDomain()），**不是**下一层的域。旧实现
// recompute.go:168/175 用「第 L+1 层的域给第 L 层的输出重掩码」，那是已废弃的旧约定；
// 写反不报编译错、不报运行错，只产出普遍性随机大误差。本文件一律走 spec.MaskDomain()，
// 禁止手写任何层号/坐标字符串拼接（设计 §2.5.1 规则 4 / C1）。
//
// 【输入侧】逐行取域：plan.SrcMaskDomain(seq, row)；是否算掩码像看 InWeight[row].Applied
// （false = 残差/注入直通，掩码像恒等于 ρ_src 本身）。fan-in 步（residual_add）两行
// 来源不同 ⇒ 域不同 ⇒ 必须逐行分别脱掩码（解 G12）。
//
// 【锁】本文件在 st.mu 临界区内被调用（runStep），故不得回调 teeServer / state() /
// 审计 / 遥测；KV 的 Read* 自带 kv.mu，且只在临界区内做浅拷贝，浮点运算在其外。
package route2step

import (
	"fmt"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
	"security-ai-gateway/gateway/teecore/trustedops"
)

// StepContext 一步执行所需的全部上下文（纯数据，由 runStep 在 st.mu 内装配）。
type StepContext struct {
	Cfg      route2plan.ModelConfig
	Weights  route2demo.ModelWeights
	Plan     route2plan.Plan
	Seq      int
	Spec     route2plan.StepSpec
	Stage    route2plan.Stage
	Turn     uint32
	TurnBase int // 本轮位置基准（服务端自持）
	KV       *KVCache
	Seed     []byte
	Batch    [][]uint64

	// NewStream 按当前密码档构造掩码流（由宿主注入，避免本包依赖宿主的 cryptoProvider）。
	NewStream func(seed []byte, modulus uint64, domain []byte) (*mask.Stream, error)

	// Ref 直通行的还原基准矩阵（惰性加载；仅取 ModBits 与 InputScale 两个标量）。
	Ref *maskedinfer.QuantizedMatrix
}

// ExecStep 执行一步，返回 (result, token, err)。
//
// result：非 kv_append / 非 terminal 步为每位置一行重掩码结果；
// kv_append_* 返回空（§7.2：这类步没有下游消费者，返回 remask 身份值纯属浪费带宽
// 且会让客户端误接）；argmax 不填 result，token 单独返回（G11 形态歧义修复）。
func ExecStep(ctx *StepContext) ([][]uint64, int, *StepError) {
	arity := len(ctx.Spec.InSrc)
	if arity <= 0 || len(ctx.Batch)%arity != 0 {
		return nil, 0, NewStepError(400, AuditRecomputeShapeMismatch,
			"batch 行数 %d 与 arity=%d 不匹配", len(ctx.Batch), arity)
	}
	nPos := len(ctx.Batch) / arity

	// ---- 输入侧：每行的源掩码流（按行类各一条）+ 被施加的权重 ----
	srcStream := make([]*mask.Stream, arity)
	srcMatrix := make([]*maskedinfer.QuantizedMatrix, arity)
	for r := 0; r < arity; r++ {
		domain, err := ctx.Plan.SrcMaskDomain(ctx.Seq, r)
		if err != nil {
			return nil, 0, NewStepError(500, AuditRecomputeStreamFailed,
				"行 %d 的源掩码域解析失败: %v", r, err)
		}
		s, err := ctx.NewStream(ctx.Seed, Route2MaskModulus, []byte(domain))
		if err != nil {
			return nil, 0, NewStepError(500, AuditRecomputeStreamFailed,
				"行 %d 的源掩码流派生失败: %v", r, err)
		}
		srcStream[r] = s
		if ctx.Spec.InWeight[r].Applied {
			m, err := ctx.Weights.Matrix(ctx.Spec.InWeight[r].Key)
			if err != nil {
				return nil, 0, NewStepError(500, AuditRecomputeWeightLoadFailed,
					"行 %d 的权重 %s 加载失败: %v", r, ctx.Spec.InWeight[r].Key.String(), err)
			}
			srcMatrix[r] = m
		}
	}

	// ---- 输出侧：产出步 own 自己的域 ----
	isKVAppend := ctx.Spec.Op == route2plan.OpKVAppendK || ctx.Spec.Op == route2plan.OpKVAppendV
	var outStream *mask.Stream
	if !isKVAppend && !ctx.Spec.Terminal {
		s, err := ctx.NewStream(ctx.Seed, Route2MaskModulus, []byte(ctx.Spec.MaskDomain()))
		if err != nil {
			return nil, 0, NewStepError(500, AuditRecomputeStreamFailed,
				"输出掩码流派生失败(域=%s): %v", ctx.Spec.MaskDomain(), err)
		}
		outStream = s
	}

	// 归一化参数按步派生（服务端权威；客户端提交的 gamma/beta 不参与任何判定）。
	var gamma []float64
	var normEps float64
	if ctx.Spec.Op == route2plan.OpRMSNorm {
		key, err := normTensorKey(ctx.Spec, ctx.Cfg)
		if err != nil {
			return nil, 0, NewStepError(500, AuditRecomputeNormFailed, "归一化张量定位失败: %v", err)
		}
		gamma, normEps, err = ctx.Weights.Affine(key)
		if err != nil {
			return nil, 0, NewStepError(500, AuditRecomputeNormFailed,
				"归一化参数 %s 加载失败: %v", key.String(), err)
		}
	}

	ref, serr := ctx.refMatrix()
	if serr != nil {
		return nil, 0, serr
	}

	block := int(ctx.Spec.Coord.Block)
	result := make([][]uint64, 0, nPos)
	var token int = -1 // 非 argmax 步骤哨兵；argmax 覆盖为真实 token

	for j := 0; j < nPos; j++ {
		pos := ctx.TurnBase + j // 位置由服务端自持（客户端不得提交）
		// ---- 逐行脱掩码 → Decode ----
		x := make([][]float64, arity)
		for r := 0; r < arity; r++ {
			v := ctx.Batch[BatchRowIndex(arity, nPos, j, r)]
			var xv []float64
			if ctx.Spec.InWeight[r].Applied {
				m := srcMatrix[r]
				rho := nextMaskVec(srcStream[r], m.Cols) // 源掩码维度 = 权重的输入侧列数
				img, err := m.MaskImage(rho)
				if err != nil {
					return nil, 0, NewStepError(500, AuditRecomputeMaskImageFailed,
						"行 %d 掩码像计算失败: %v", r, err)
				}
				y, err := m.Unmask(v, img)
				if err != nil {
					return nil, 0, NewStepError(500, AuditRecomputeUnmaskFailed,
						"行 %d 脱掩码失败: %v", r, err)
				}
				xv = m.Decode(y)
			} else {
				// 直通：掩码像恒等于 ρ_src 本身；还原是「单位矩阵」的 Decode（scale=1）。
				rho := nextMaskVec(srcStream[r], len(v))
				y, err := ref.Unmask(v, rho)
				if err != nil {
					return nil, 0, NewStepError(500, AuditRecomputeUnmaskFailed,
						"行 %d（直通）脱掩码失败: %v", r, err)
				}
				xv = decodePassthrough(ref, y)
			}
			x[r] = xv
		}

		// ---- 算子 ----
		switch ctx.Spec.Op {
		case route2plan.OpRMSNorm:
			x[0] = trustedops.RMSNorm(x[0], gamma, normEps)

		case route2plan.OpGELU:
			for i := range x[0] {
				x[0][i] = trustedops.GELU(x[0][i])
			}

		case route2plan.OpLinear:
			// 投影步的占位非线性：脱掩码后原样透传。
			// 线性权重已在输入侧 InWeight 经 Unmask 施加，此处无需任何变换。

		case route2plan.OpSwiGLUMul:
			// 逐元素 silu(gate) ⊙ up（SwiGLU 门控，arity=2：x[0]=up，x[1]=gate）。
			if len(x[0]) != len(x[1]) {
				return nil, 0, NewStepError(500, AuditRecomputeShapeMismatch,
					"SwiGLUMul 两行维度不等 %d vs %d", len(x[0]), len(x[1]))
			}
			out, err := trustedops.SiLUMul(x[1], x[0]) // gate=x[1], up=x[0]
			if err != nil {
				return nil, 0, NewStepError(500, AuditRecomputeNonlinearFailed,
					"SwiGLUMul 失败: %v", err)
			}
			x[0] = out

		case route2plan.OpKVAppendK, route2plan.OpKVAppendV:
			vec := x[0]
			// QK-norm（Qwen3）：K 在 RoPE 之前做逐头 RMSNorm；V 不做。Q 的 QK-norm 在 attention 分支处理。
			if ctx.Cfg.QKNorm && ctx.Spec.Op == route2plan.OpKVAppendK {
				kGamma, serr := ctx.qkNormGamma(route2plan.TensorKNorm, block)
				if serr != nil {
					return nil, 0, serr
				}
				normed, nerr := trustedops.PerHeadRMSNorm(vec, kGamma, ctx.Cfg.HeadDim, ctx.Cfg.NormEps)
				if nerr != nil {
					return nil, 0, NewStepError(500, AuditRecomputeNormFailed,
						"K 的 QK-norm 失败(pos=%d): %v", pos, nerr)
				}
				vec = normed
			}
			if ctx.Spec.Op == route2plan.OpKVAppendK {
				// RoPE 只作用于 K，且**必须在追加之前**施加（D8/§3.2 序 3-4）。
				// V 绝不旋转；此处也不得二次旋转（读侧再旋一次会"数值全错但全绿"）。
				// 配对约定按 cfg.RopeStyle 选择：Qwen/LLaMA 用前后半劈，demo 用相邻对。
				rotated, err := ropeK(ctx.Cfg, vec, pos)
				if err != nil {
					return nil, 0, NewStepError(500, AuditRecomputeAttentionFailed,
						"K 的 RoPE 失败(pos=%d): %v", pos, err)
				}
				vec = rotated
			}
			if ctx.Spec.Op == route2plan.OpKVAppendK {
				if err := ctx.KV.AppendK(block, vec); err != nil {
					return nil, 0, kvStepError("AppendK", block, err)
				}
			} else {
				if err := ctx.KV.AppendV(block, vec); err != nil {
					return nil, 0, kvStepError("AppendV", block, err)
				}
			}
			continue // kv_append_* 无下游消费者：不产出任何 result 行

		case route2plan.OpAttention:
			// QK-norm（Qwen3）：Q 在 RoPE 之前做逐头 RMSNorm。
			if ctx.Cfg.QKNorm {
				qGamma, serr := ctx.qkNormGamma(route2plan.TensorQNorm, block)
				if serr != nil {
					return nil, 0, serr
				}
				normed, nerr := trustedops.PerHeadRMSNorm(x[0], qGamma, ctx.Cfg.HeadDim, ctx.Cfg.NormEps)
				if nerr != nil {
					return nil, 0, NewStepError(500, AuditRecomputeNormFailed,
						"Q 的 QK-norm 失败(pos=%d): %v", pos, nerr)
				}
				x[0] = normed
			}
			q, err := ropeK(ctx.Cfg, x[0], pos)
			if err != nil {
				return nil, 0, NewStepError(500, AuditRecomputeAttentionFailed,
					"Q 的 RoPE 失败(pos=%d): %v", pos, err)
			}
			// Read* 在 kv.mu 内只做浅拷贝，返回深拷贝快照；下面的 O(T²·hd) 全程在锁外。
			kRows, err := ctx.KV.ReadK(block)
			if err != nil {
				return nil, 0, kvStepError("ReadK", block, err)
			}
			vRows, err := ctx.KV.ReadV(block)
			if err != nil {
				return nil, 0, kvStepError("ReadV", block, err)
			}
			// GQA：KV cache 行是 KVHeads*HeadDim（KVDim），注意力要求 Q 头布局（Heads*HeadDim），
			// 故先把 KV 扩展回 Q 头布局（MHA 时 kvHeads==heads 为恒等变换，零开销）。
			kvHeads := ctx.Cfg.KVHeads
			if kvHeads <= 0 {
				kvHeads = ctx.Cfg.Heads
			}
			if kvHeads != ctx.Cfg.Heads {
				if kRows, err = trustedops.ExpandGQA(kRows, kvHeads, ctx.Cfg.Heads, ctx.Cfg.HeadDim); err != nil {
					return nil, 0, NewStepError(500, AuditRecomputeAttentionFailed,
						"GQA 扩展 K 失败(pos=%d): %v", pos, err)
				}
				if vRows, err = trustedops.ExpandGQA(vRows, kvHeads, ctx.Cfg.Heads, ctx.Cfg.HeadDim); err != nil {
					return nil, 0, NewStepError(500, AuditRecomputeAttentionFailed,
						"GQA 扩展 V 失败(pos=%d): %v", pos, err)
				}
			}
			out, err := trustedops.Attention(q, kRows, vRows, ctx.Cfg.Heads, ctx.Cfg.HeadDim,
				0 /*kvStart*/, pos, true /*causal*/)
			if err != nil {
				return nil, 0, NewStepError(500, AuditRecomputeAttentionFailed,
					"注意力计算失败(block=%d pos=%d): %v", block, pos, err)
			}
			x[0] = out

		case route2plan.OpResidualAdd:
			if len(x[0]) != len(x[1]) {
				return nil, 0, NewStepError(500, AuditRecomputeShapeMismatch,
					"残差两行维度不等 %d vs %d", len(x[0]), len(x[1]))
			}
			out := make([]float64, len(x[0]))
			for i := range out {
				out[i] = x[0][i] + x[1][i]
			}
			x[0] = out

		case route2plan.OpArgMax:
			idx := trustedops.ArgMax(x[0])
			token = idx
			continue // terminal：明文 token，不再重掩码（D12 注明下行未加密）

		default:
			return nil, 0, NewStepError(400, AuditRecomputeUnknownOp, "未知算子 %q", ctx.Spec.Op)
		}

		// ---- ToMaskDomain → 重掩码（产出步 own 自己的域）----
		fY := ref.ToMaskDomain(x[0])
		rhoOut := nextMaskVec(outStream, len(fY))
		row, err := ref.Remask(fY, rhoOut)
		if err != nil {
			return nil, 0, NewStepError(500, AuditRecomputeRemaskFailed, "重掩码失败: %v", err)
		}
		result = append(result, row)
	}
	return result, token, nil
}

// normTensorKey 由步坐标定位归一化张量。
//
// 之所以要看坐标而不是 op：三个归一化步的 op 都是 rmsnorm，但张量分别是
// ln_in / ln_post / ln_final，取错即"归一化参数错配"，与掩码错位同属静默失败。
func normTensorKey(spec route2plan.StepSpec, cfg route2plan.ModelConfig) (route2plan.TensorKey, error) {
	b := int(spec.Coord.Block)
	switch spec.Coord.Step {
	case route2plan.StepAttnNorm:
		return route2plan.TensorKey{Block: b, Tensor: route2plan.TensorLNIn}, nil
	case route2plan.StepFFNNorm:
		return route2plan.TensorKey{Block: b, Tensor: route2plan.TensorLNPost}, nil
	case route2plan.StepFinalNorm:
		return route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorLNFinal}, nil
	}
	return route2plan.TensorKey{}, fmt.Errorf("步 %s（Step=%d）不是归一化步", spec.Coord.Wire(), uint8(spec.Coord.Step))
}

// kvStepError 把 KVCache 的哨兵 error 映射为 HTTP 码与审计码。
func kvStepError(call string, block int, err error) *StepError {
	switch {
	case err == ErrKVCacheFull, err == ErrKVCacheBytesExceeded:
		return NewStepError(429, AuditKVCacheFull, "%s(block=%d) 超限: %v", call, block, err)
	case err == ErrKVCacheReleased:
		return NewStepError(409, AuditRecomputeReplay, "%s(block=%d): %v", call, block, err)
	default:
		return NewStepError(500, AuditRecomputeKVFailed, "%s(block=%d) 失败: %v", call, block, err)
	}
}

// nextMaskVec 从掩码流取 n 个掩码分量（沿用既有取模方式：stream.Next() % R）。
func nextMaskVec(s *mask.Stream, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = s.Next() % Route2MaskModulus
	}
	return out
}

// decodePassthrough 还原**直通**行的浮点真值。
//
// 直通行的掩码像恒等于源掩码 ρ 本身（Applied=false 时没有线性搬运项），
// 等价于「单位矩阵」的 Decode，即 scale=1：
//
//	x_i = SignedValue(y_i) / InputScale
//
// 绝不能直接用权重矩阵的 Decode——那会额外乘上该权重的量化标度 scale，
// 使残差/注入行被静默缩放（不报错、数值全错）。
func decodePassthrough(m *maskedinfer.QuantizedMatrix, y []uint64) []float64 {
	out := make([]float64, len(y))
	for i, v := range y {
		out[i] = float64(m.SignedValue(v)) / m.InputScale
	}
	return out
}

// ropeK 按模型配置的配对约定对 Q 或 K 的一行施加 RoPE。
//
// 配对约定是**模型结构属性**，不是实现细节：Qwen2/Qwen3、LLaMA、HuggingFace 用前后半劈
// （rotate_half），GPT-J/NeoX 用相邻对。用错不会报错，只会让注意力"略微"偏掉，
// logits 仍在合理量级——只有外部 golden 能发现（T5 实测 top-1 由 23811 偏到 264）。
// 默认（"" / interleaved）保持 demo 既有行为逐位不变。
func ropeK(cfg route2plan.ModelConfig, vec []float64, pos int) ([]float64, error) {
	if cfg.RopeStyle == route2plan.RopeStyleHalf {
		return trustedops.ApplyRoPEHalf(vec, pos, cfg.HeadDim, cfg.RopeTheta)
	}
	return trustedops.ApplyRoPE(vec, pos, cfg.HeadDim, cfg.RopeTheta)
}

// qkNormGamma 加载某 block 的 QK-norm 仿射参数 gamma（Qwen3 的 q_norm/k_norm）。
// eps 统一取自 cfg.NormEps（与 HF 一致）。加载失败即 fail-closed 返回 StepError。
func (ctx *StepContext) qkNormGamma(tensor string, block int) ([]float64, *StepError) {
	key := route2plan.TensorKey{Block: block, Tensor: tensor}
	gamma, _, err := ctx.Weights.Affine(key)
	if err != nil {
		return nil, NewStepError(500, AuditRecomputeNormFailed,
			"QK-norm 参数 %s 加载失败: %v", key.String(), err)
	}
	return gamma, nil
}

// refMatrix 直通行的还原基准矩阵（惰性加载）。
//
// 只取 ModBits 与 InputScale 两个标量：Unmask 依赖模数、ToMaskDomain/Remask/decodePassthrough
// 依赖 InputScale，均与具体权重无关。取一张确定存在的张量作基准，避免"为了取两个
// 标量而凭空造矩阵"。
func (ctx *StepContext) refMatrix() (*maskedinfer.QuantizedMatrix, *StepError) {
	if ctx.Ref != nil {
		return ctx.Ref, nil
	}
	key := route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ}
	m, err := ctx.Weights.Matrix(key)
	if err != nil {
		return nil, NewStepError(500, AuditRecomputeWeightLoadFailed,
			"基准张量 %s 加载失败: %v", key.String(), err)
	}
	ctx.Ref = m
	return m, nil
}
