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
package main

import (
	"fmt"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2demo"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// stepContext 一步执行所需的全部上下文（纯数据，由 runStep 在 st.mu 内装配）。
type stepContext struct {
	cfg      route2plan.ModelConfig
	weights  route2demo.ModelWeights
	plan     route2plan.Plan
	seq      int
	spec     route2plan.StepSpec
	stage    route2plan.Stage
	turn     uint32
	turnBase int   // 本轮位置基准（服务端自持）
	kv       *KVCache
	seed     []byte
	batch    [][]uint64

	// ref 直通行的还原基准矩阵（惰性加载；仅取 ModBits 与 InputScale 两个标量）。
	ref *maskedinfer.QuantizedMatrix
}

// execStep 执行一步，返回 (result, token, err)。
//
// result：非 kv_append / 非 terminal 步为每位置一行重掩码结果；
// kv_append_* 返回空（§7.2：这类步没有下游消费者，返回 remask 身份值纯属浪费带宽
// 且会让客户端误接）；argmax 不填 result，token 单独返回（G11 形态歧义修复）。
func execStep(ctx *stepContext) ([][]uint64, int, *stepError) {
	arity := len(ctx.spec.InSrc)
	if arity <= 0 || len(ctx.batch)%arity != 0 {
		return nil, 0, newStepError(400, auditRecomputeShapeMismatch,
			"batch 行数 %d 与 arity=%d 不匹配", len(ctx.batch), arity)
	}
	nPos := len(ctx.batch) / arity

	// ---- 输入侧：每行的源掩码流（按行类各一条）+ 被施加的权重 ----
	srcStream := make([]*mask.Stream, arity)
	srcMatrix := make([]*maskedinfer.QuantizedMatrix, arity)
	for r := 0; r < arity; r++ {
		domain, err := ctx.plan.SrcMaskDomain(ctx.seq, r)
		if err != nil {
			return nil, 0, newStepError(500, auditRecomputeStreamFailed,
				"行 %d 的源掩码域解析失败: %v", r, err)
		}
		s, err := newLayerStream(ctx.seed, route2MaskModulus, []byte(domain))
		if err != nil {
			return nil, 0, newStepError(500, auditRecomputeStreamFailed,
				"行 %d 的源掩码流派生失败: %v", r, err)
		}
		srcStream[r] = s
		if ctx.spec.InWeight[r].Applied {
			m, err := ctx.weights.Matrix(ctx.spec.InWeight[r].Key)
			if err != nil {
				return nil, 0, newStepError(500, auditRecomputeWeightLoadFailed,
					"行 %d 的权重 %s 加载失败: %v", r, ctx.spec.InWeight[r].Key.String(), err)
			}
			srcMatrix[r] = m
		}
	}

	// ---- 输出侧：产出步 own 自己的域 ----
	isKVAppend := ctx.spec.Op == route2plan.OpKVAppendK || ctx.spec.Op == route2plan.OpKVAppendV
	var outStream *mask.Stream
	if !isKVAppend && !ctx.spec.Terminal {
		s, err := newLayerStream(ctx.seed, route2MaskModulus, []byte(ctx.spec.MaskDomain()))
		if err != nil {
			return nil, 0, newStepError(500, auditRecomputeStreamFailed,
				"输出掩码流派生失败(域=%s): %v", ctx.spec.MaskDomain(), err)
		}
		outStream = s
	}

	// 归一化参数按步派生（服务端权威；客户端提交的 gamma/beta 不参与任何判定）。
	var gamma []float64
	var normEps float64
	if ctx.spec.Op == route2plan.OpRMSNorm {
		key, err := normTensorKey(ctx.spec, ctx.cfg)
		if err != nil {
			return nil, 0, newStepError(500, auditRecomputeNormFailed, "归一化张量定位失败: %v", err)
		}
		gamma, normEps, err = ctx.weights.Affine(key)
		if err != nil {
			return nil, 0, newStepError(500, auditRecomputeNormFailed,
				"归一化参数 %s 加载失败: %v", key.String(), err)
		}
	}

	ref, serr := ctx.refMatrix()
	if serr != nil {
		return nil, 0, serr
	}

	block := int(ctx.spec.Coord.Block)
	result := make([][]uint64, 0, nPos)
	var token int = -1 // 非 argmax 步骤哨兵；argmax 覆盖为真实 token

	for j := 0; j < nPos; j++ {
		pos := ctx.turnBase + j // 位置由服务端自持（客户端不得提交）
		// ---- 逐行脱掩码 → Decode ----
		x := make([][]float64, arity)
		for r := 0; r < arity; r++ {
			v := ctx.batch[batchRowIndex(arity, nPos, j, r)]
			var xv []float64
			if ctx.spec.InWeight[r].Applied {
				m := srcMatrix[r]
				rho := nextMaskVec(srcStream[r], m.Cols) // 源掩码维度 = 权重的输入侧列数
				img, err := m.MaskImage(rho)
				if err != nil {
					return nil, 0, newStepError(500, auditRecomputeMaskImageFailed,
						"行 %d 掩码像计算失败: %v", r, err)
				}
				y, err := m.Unmask(v, img)
				if err != nil {
					return nil, 0, newStepError(500, auditRecomputeUnmaskFailed,
						"行 %d 脱掩码失败: %v", r, err)
				}
				xv = m.Decode(y)
			} else {
				// 直通：掩码像恒等于 ρ_src 本身；还原是「单位矩阵」的 Decode（scale=1）。
				rho := nextMaskVec(srcStream[r], len(v))
				y, err := ref.Unmask(v, rho)
				if err != nil {
					return nil, 0, newStepError(500, auditRecomputeUnmaskFailed,
						"行 %d（直通）脱掩码失败: %v", r, err)
				}
				xv = decodePassthrough(ref, y)
			}
			x[r] = xv
		}

		// ---- 算子 ----
		switch ctx.spec.Op {
		case route2plan.OpRMSNorm:
			x[0] = teecore.RMSNorm(x[0], gamma, normEps)

		case route2plan.OpGELU:
			for i := range x[0] {
				x[0][i] = teecore.GELU(x[0][i])
			}

		case route2plan.OpKVAppendK, route2plan.OpKVAppendV:
			vec := x[0]
			if ctx.spec.Op == route2plan.OpKVAppendK {
				// RoPE 只作用于 K，且**必须在追加之前**施加（D8/§3.2 序 3-4）。
				// V 绝不旋转；此处也不得二次旋转（读侧再旋一次会"数值全错但全绿"）。
				rotated, err := teecore.ApplyRoPE(vec, pos, ctx.cfg.HeadDim, ctx.cfg.RopeTheta)
				if err != nil {
					return nil, 0, newStepError(500, auditRecomputeAttentionFailed,
						"K 的 RoPE 失败(pos=%d): %v", pos, err)
				}
				vec = rotated
			}
			if ctx.spec.Op == route2plan.OpKVAppendK {
				if err := ctx.kv.AppendK(block, vec); err != nil {
					return nil, 0, kvStepError("AppendK", block, err)
				}
			} else {
				if err := ctx.kv.AppendV(block, vec); err != nil {
					return nil, 0, kvStepError("AppendV", block, err)
				}
			}
			continue // kv_append_* 无下游消费者：不产出任何 result 行

		case route2plan.OpAttention:
			q, err := teecore.ApplyRoPE(x[0], pos, ctx.cfg.HeadDim, ctx.cfg.RopeTheta)
			if err != nil {
				return nil, 0, newStepError(500, auditRecomputeAttentionFailed,
					"Q 的 RoPE 失败(pos=%d): %v", pos, err)
			}
			// Read* 在 kv.mu 内只做浅拷贝，返回深拷贝快照；下面的 O(T²·hd) 全程在锁外。
			kRows, err := ctx.kv.ReadK(block)
			if err != nil {
				return nil, 0, kvStepError("ReadK", block, err)
			}
			vRows, err := ctx.kv.ReadV(block)
			if err != nil {
				return nil, 0, kvStepError("ReadV", block, err)
			}
			out, err := teecore.Attention(q, kRows, vRows, ctx.cfg.Heads, ctx.cfg.HeadDim,
				0 /*kvStart*/, pos, true /*causal*/)
			if err != nil {
				return nil, 0, newStepError(500, auditRecomputeAttentionFailed,
					"注意力计算失败(block=%d pos=%d): %v", block, pos, err)
			}
			x[0] = out

		case route2plan.OpResidualAdd:
			if len(x[0]) != len(x[1]) {
				return nil, 0, newStepError(500, auditRecomputeShapeMismatch,
					"残差两行维度不等 %d vs %d", len(x[0]), len(x[1]))
			}
			out := make([]float64, len(x[0]))
			for i := range out {
				out[i] = x[0][i] + x[1][i]
			}
			x[0] = out

		case route2plan.OpArgMax:
			idx := teecore.ArgMax(x[0])
		token = idx
		continue // terminal：明文 token，不再重掩码（D12 注明下行未加密）

		default:
			return nil, 0, newStepError(400, auditRecomputeUnknownOp, "未知算子 %q", ctx.spec.Op)
		}

		// ---- ToMaskDomain → 重掩码（产出步 own 自己的域）----
		fY := ref.ToMaskDomain(x[0])
		rhoOut := nextMaskVec(outStream, len(fY))
		row, err := ref.Remask(fY, rhoOut)
		if err != nil {
			return nil, 0, newStepError(500, auditRecomputeRemaskFailed, "重掩码失败: %v", err)
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
func kvStepError(call string, block int, err error) *stepError {
	switch {
	case err == ErrKVCacheFull, err == ErrKVCacheBytesExceeded:
		return newStepError(429, auditKVCacheFull, "%s(block=%d) 超限: %v", call, block, err)
	case err == ErrKVCacheReleased:
		return newStepError(409, auditRecomputeReplay, "%s(block=%d): %v", call, block, err)
	default:
		return newStepError(500, auditRecomputeKVFailed, "%s(block=%d) 失败: %v", call, block, err)
	}
}

// nextMaskVec 从掩码流取 n 个掩码分量（沿用既有取模方式：stream.Next() % R）。
func nextMaskVec(s *mask.Stream, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = s.Next() % route2MaskModulus
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

// refMatrix 直通行的还原基准矩阵（惰性加载）。
//
// 只取 ModBits 与 InputScale 两个标量：Unmask 依赖模数、ToMaskDomain/Remask/decodePassthrough
// 依赖 InputScale，均与具体权重无关。取一张确定存在的张量作基准，避免"为了取两个
// 标量而凭空造矩阵"。
func (ctx *stepContext) refMatrix() (*maskedinfer.QuantizedMatrix, *stepError) {
	if ctx.ref != nil {
		return ctx.ref, nil
	}
	key := route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ}
	m, err := ctx.weights.Matrix(key)
	if err != nil {
		return nil, newStepError(500, auditRecomputeWeightLoadFailed,
			"基准张量 %s 加载失败: %v", key.String(), err)
	}
	ctx.ref = m
	return m, nil
}
