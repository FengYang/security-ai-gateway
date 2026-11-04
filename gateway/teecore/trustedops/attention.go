// Package trustedops 的 attention 算子文件（T02 · G7）。
//
// ============================ 可信边界声明（务必先读） ============================
//
// 本文件的全部函数都运行在**可信域的明文 float64** 上。它们的输入是 `Unmask → Decode`
// 之后的真实激活值，它们的输出会被 `ToMaskDomain → Remask` 重新打上掩码后才可能离域。
// 换言之：**不可信加速器（及其 GPU 内核）从头到尾只见三类数据**——
//
//	① 量化权重 QuantizedMatrix（模型公开部分）；
//	② 掩码态张量 V = ToMaskDomain(x) + r (mod R)；
//	③ 掩码态计算结果。
//
// 它**永远看不到任何明文激活**。
//
// 因此把 `Q·Kᵀ` 与 `scores·V` 放在可信域不是 M2 的退让——整条链路的安全性完全押在
// 可信域上，而不是押在"注意力机制被加密"上（设计 §0.1/§0.2/D1）。
// 由本文件导出的算子若被放到可信域之外调用，等于把 `Q·Kᵀ` 的明文结果交出去，
// 属于信任模型破坏，不是性能取舍。
//
// 【数值约定冻结 · RoPE 排布（T02 裁定，团队已确认）】
//
// 本代码库**冻结为 Su et al. (2021) 的相邻对旋转排布**：
//
//	θ_i = pos · theta^(-2i/headDim)，旋转的对象是第 i 对的 (2i, 2i+1) 两个相邻分量
//
// 它与 LLaMA 式的「前后半劈开」排布（旋转 (i, i+headDim/2)）**数值不兼容**：
// 两者给出的注意力分数不同，而**两者都能通过"相对位置不变性"测试**
// （相对位置不变性只要求旋转矩阵正交且相位随位置线性，两种排布都满足）。
// ⇒ **不得仅凭相对位置测试判定 RoPE 实现正确**；
// 必须另有显式用例锁住排布本身（见 attention_test.go 的 TestRoPEPairExplicit 与
// TestRoPERelativePosition 末尾的"非恒等"反向护栏）。
//
// RoPE 只在可信域执行、且作用在 K 追加之前，因此不存在跨方一致性问题；
// 但它必须与 Forward 里的位置推进一致（由 route2ref 的 prefill/decode 交接用例锁住）。
//
// 由此可见本文件的两条硬纪律：
//  1. 只做纯算子（无状态、无 I/O、无网络、无缓存复用），可被 route2ref / TEE 服务端
//     同时引用，从而保证「参考实现」与「生产实现」共用同一份代码；
//  2. 失败一律显式 error（fail-closed）：维度不匹配、含 NaN/Inf、非法 head 配置，
//     一律报错而不是返回半截结果——让一个 NaN 溜进 Softmax，会顺着算子链污染整条链路，
//     静默产出整链路 NaN，而上线后才暴露的 NaN，排查成本是灾难级的。
package trustedops

import (
	"errors"
	"fmt"
	"math"
)

// CausalMaskValue 因果掩码哨兵值：** -1e30 而非 -Inf **（设计 §2.6 D9 / 风险表 R9）。
//
// 原因写在 nonlinear.go 的 Softmax 实现里（`nonlinear.go:27-43`）：
//
//	maxV = max(v)；out[i] = Exp(v[i] - maxV) / Σ Exp(v[j] - maxV)
//
// 一旦某一行**全部**被掩码且用 -Inf 填充，则 maxV = -Inf，
// `v[i] - maxV` = `-Inf - (-Inf)` = NaN，于是整行概率变成 NaN 并污染后续所有层。
// 而 -1e30 是有限值：全掩码时 `Exp(-1e30 - (-1e30)) = Exp(0) = 1`，退化成均匀分布，
// 既不崩也不 NaN（这种行在因果语义下不应出现，出现了也不应炸掉整条链路）。
const CausalMaskValue = -1e30

// RoPEPair 对第 pairIdx 对分量做旋转位置编码（RoPE）。
//
// 采用 Su et al. (2021) 的**相邻对旋转**形式（设计 §2.6 D8「成对旋转」）：
//
//	θ_i = pos · theta^(-2i/headDim)          i = pairIdx
//	x'  = x·cosθ_i - y·sinθ_i
//	y'  = x·sinθ_i + y·cosθ_i
//
// 关键性质（有单测）：旋转矩阵正交 ⇒ `<R_p a, R_p b> = <a, b>`，
// 且 `<R_{p} a, R_{q} b>` 只依赖相对位置 `(p-q)`，不依赖绝对值。
//
// 【实现约定 · 需与下游对齐】业界另有「前半/后半劈开」的排布（LLaMA 式，
// 旋转的是 (i, i+headDim/2) 而非相邻对）。本实现用相邻对；二者**不可混用**。
// RoPE 只在可信域对 Q/K 执行，加速器不参与，因此只要 TEE 侧唯一即可。
func RoPEPair(x, y float64, pairIdx, headDim, pos int, theta float64) (float64, float64) {
	ang := float64(pos) * math.Pow(theta, -float64(2*pairIdx)/float64(headDim))
	c, s := math.Cos(ang), math.Sin(ang)
	return x*c - y*s, x*s + y*c
}

// ApplyRoPE 对整个 Q/K 行（长度 heads*headDim）施加 RoPE，返回新切片。
//
// pos 为该行的**绝对位置**（不是行内下标），多头按 headDim 切片各自独立旋转。
func ApplyRoPE(vec []float64, pos, headDim int, theta float64) ([]float64, error) {
	if headDim <= 0 || headDim%2 != 0 {
		return nil, fmt.Errorf("teecore: headDim=%d 非法（须为正偶数，RoPE 成对旋转）", headDim)
	}
	if len(vec) == 0 || len(vec)%headDim != 0 {
		return nil, fmt.Errorf("teecore: 向量长度 %d 不是 headDim=%d 的整数倍", len(vec), headDim)
	}
	if pos < 0 {
		return nil, fmt.Errorf("teecore: pos=%d 不可为负", pos)
	}
	if !(theta > 0) {
		return nil, fmt.Errorf("teecore: theta=%v 必须为正", theta)
	}
	out := make([]float64, len(vec))
	copy(out, vec)
	if err := ApplyRoPEInPlace(out, pos, headDim, theta); err != nil {
		return nil, err
	}
	return out, nil
}

// ApplyRoPEInPlace 原地版本（KV 追加前改写 K 行可省一次拷贝）。语义同 ApplyRoPE。
func ApplyRoPEInPlace(vec []float64, pos, headDim int, theta float64) error {
	if headDim <= 0 || headDim%2 != 0 {
		return fmt.Errorf("teecore: headDim=%d 非法（须为正偶数，RoPE 成对旋转）", headDim)
	}
	if len(vec) == 0 || len(vec)%headDim != 0 {
		return fmt.Errorf("teecore: 向量长度 %d 不是 headDim=%d 的整数倍", len(vec), headDim)
	}
	if pos < 0 {
		return fmt.Errorf("teecore: pos=%d 不可为负", pos)
	}
	if !(theta > 0) {
		return fmt.Errorf("teecore: theta=%v 必须为正", theta)
	}
	pairs := headDim / 2
	for base := 0; base < len(vec); base += headDim {
		for i := 0; i < pairs; i++ {
			a, b := 2*i, 2*i+1
			vec[base+a], vec[base+b] = RoPEPair(vec[base+a], vec[base+b], i, headDim, pos, theta)
		}
	}
	return nil
}

// Scores 多头打分：逐 head 计算 `scores[h][j] = <q_h, k_j,h> / sqrt(headDim)`。
//
// 入参：
//   - q：单个查询行，长度 heads*headDim（多头拼接，每头连续）；
//   - kRows：KV 缓存中的 K 行，**行序 == 位置序**（第 j 行的绝对位置由调用方给出，
//     本函数只按 kRows 的下标 j 线性遍历）；每行的布局与 q 相同；
//   - 返回值外层下标是 head，内层下标是 KV 行 j。
//
// 除以 sqrt(headDim) 是标准缩放点积注意力；漏除会让 Softmax 在大 headDim 下饱和，
// 表现为「注意力几乎 one-hot，梯度/数值的信息丢失」——这是一个不报错但静默劣化的 bug。
func Scores(q []float64, kRows [][]float64, heads, headDim int) ([][]float64, error) {
	if heads <= 0 || headDim <= 0 {
		return nil, fmt.Errorf("teecore: heads=%d headDim=%d 非法（须为正）", heads, headDim)
	}
	if err := checkHeadLayout("q", q, heads, headDim); err != nil {
		return nil, err
	}
	invSqrtHD := 1 / math.Sqrt(float64(headDim))
	out := make([][]float64, heads)
	for h := 0; h < heads; h++ {
		row := make([]float64, len(kRows))
		qOff := h * headDim
		for j, k := range kRows {
			if err := checkHeadLayout("k", k, heads, headDim); err != nil {
				return nil, fmt.Errorf("teecore: kRows[%d] 布局非法: %w", j, err)
			}
			var dot float64
			for d := 0; d < headDim; d++ {
				dot += q[qOff+d] * k[qOff+d]
			}
			if math.IsNaN(dot) || math.IsInf(dot, 0) {
				return nil, fmt.Errorf("teecore: head=%d 行=%d 的点积非有限（%v）", h, j, dot)
			}
			row[j] = dot * invSqrtHD
		}
		out[h] = row
	}
	return out, nil
}

// CausalMask 就地施加因果掩码：第 j 个 KV 行的绝对位置 = kvStart+j，
// 仅当 `kvStart+j <= qPos` 时允许 attend，其余位置写成 CausalMaskValue(-1e30)。
//
// 就地修改并返回同一切片（便于链式书写）；调用方如需保留原 scores 请先拷贝。
//
// 【为什么这里不用 -Inf】见 CausalMaskValue 的注释（设计 D9 / 风险表 R9）：
// 整行全掩码时 -Inf 会让 Softmax 出 NaN。
func CausalMask(scores [][]float64, qPos, kvStart int) [][]float64 {
	for h := range scores {
		for j := range scores[h] {
			if kvStart+j > qPos {
				scores[h][j] = CausalMaskValue
			}
		}
	}
	return scores
}

// SoftmaxScores 逐头 softmax（包装 trustedops.Softmax），并加一层有限性护栏。
//
// 之所以额外加护栏而不是直接调 Softmax：Softmax 本身对 -Inf 输入会产出 NaN 且**不报错**，
// 而 NaN 一旦流出本函数，下游 WeightedSum / RMSNorm / GELU 会一路把它放大成
// 全链路 NaN。与其在五层之后看到 NaN，不如在这里就地 fail。
func SoftmaxScores(scores [][]float64) ([][]float64, error) {
	if len(scores) == 0 {
		return nil, errors.New("teecore: scores 为空（至少需要一个 head）")
	}
	out := make([][]float64, len(scores))
	for h, row := range scores {
		if len(row) == 0 {
			return nil, fmt.Errorf("teecore: head=%d 的 scores 为空（KV 行数为 0，无法计算注意力）", h)
		}
		for i, v := range row {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("teecore: head=%d 的 scores[%d]=%v 非有限（因果掩码是否误用了 -Inf？）", h, i, v)
			}
		}
		prob := Softmax(row)
		for i, p := range prob {
			if math.IsNaN(p) || math.IsInf(p, 0) {
				return nil, fmt.Errorf("teecore: head=%d 的 softmax[%d]=%v 非有限", h, i, p)
			}
		}
		out[h] = prob
	}
	return out, nil
}

// WeightedSum 逐头加权求和：`out_h = Σ_j probs[h][j] · V_j,h`，
// 输出为 heads*headDim 的拼接向量（与 Q/K 的布局一致，便于直接喂给下一个算子）。
func WeightedSum(probs [][]float64, vRows [][]float64, heads, headDim int) ([]float64, error) {
	if heads <= 0 || headDim <= 0 {
		return nil, fmt.Errorf("teecore: heads=%d headDim=%d 非法（须为正）", heads, headDim)
	}
	if len(probs) != heads {
		return nil, fmt.Errorf("teecore: probs 有 %d 行，应为 heads=%d", len(probs), heads)
	}
	out := make([]float64, heads*headDim)
	for h := 0; h < heads; h++ {
		if len(probs[h]) != len(vRows) {
			return nil, fmt.Errorf("teecore: head=%d 的 probs 长度 %d != KV 行数 %d", h, len(probs[h]), len(vRows))
		}
		vOff := h * headDim
		for j, p := range probs[h] {
			if err := checkHeadLayout("v", vRows[j], heads, headDim); err != nil {
				return nil, fmt.Errorf("teecore: vRows[%d] 布局非法: %w", j, err)
			}
			for d := 0; d < headDim; d++ {
				out[vOff+d] += p * vRows[j][vOff+d]
			}
		}
	}
	for i, v := range out {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("teecore: 加权和 out[%d]=%v 非有限", i, v)
		}
	}
	return out, nil
}

// Attention 组合算子（全注意核，设计 §3.2 Ⓐ）：
//
//	foreach head: S = Q'·K_cacheᵀ/√hd → 因果掩码(-1e30) → Softmax → O_head = Σ_j p·V_cache,j
//	返回 concat(O_head)
//
// 入参语义：
//   - q：本行的查询向量（**调用方必须先自行施加过 RoPE**，且不得在调用后再旋转一次）；
//   - kRows / vRows：KV 缓存全量 K/V 行，行序 == 位置序，**K 已施加过 RoPE、V 未施加**；
//   - kvStart：第 0 行的绝对位置（通常为 0；分段缓存场景下为段起始位置）；
//   - qPos ：本行查询的绝对位置；
//   - causal：是否施加因果掩码（decode 与 prefill 都为 true；留 false 仅便于单测/对照）。
//
// 【位置纪律 · 最容易静默写错的地方】RoPE 必须作用在 Q/K 上且**在 KV 追加之前**完成：
// RoPE 是按**绝对位置**旋转的：若把未旋转的 K 写进缓存、等到读的时候才旋转，
// 就会出现「同一行被重复旋转」或「Q/K 位置错位」——二者都不报错，
// 只表现为困惑度莫名劣化（设计 §2.6 D8 / §3.2 序 3-4）。
func Attention(q []float64, kRows, vRows [][]float64, heads, headDim, kvStart, qPos int, causal bool) ([]float64, error) {
	if len(kRows) != len(vRows) {
		return nil, fmt.Errorf("teecore: K/V 行数不一致 %d != %d", len(kRows), len(vRows))
	}
	if len(kRows) == 0 {
		return nil, errors.New("teecore: KV 缓存为空，至少要有本行自己")
	}
	if kvStart < 0 || qPos < 0 {
		return nil, fmt.Errorf("teecore: kvStart=%d qPos=%d 不可为负", kvStart, qPos)
	}
	if causal && qPos < kvStart+len(kRows)-1 {
		// 不是错误：某些 prefill/causal 组合下 q 允许看不到最末几行（例如分块上界），
		// 但至少要能看到自己所在位置之前的一行，否则整行全掩码。
		if qPos < kvStart {
			return nil, fmt.Errorf("teecore: causal 下 qPos=%d 小于 kvStart=%d，整行将被全掩码", qPos, kvStart)
		}
	}
	scores, err := Scores(q, kRows, heads, headDim)
	if err != nil {
		return nil, err
	}
	if causal {
		CausalMask(scores, qPos, kvStart)
	}
	probs, err := SoftmaxScores(scores)
	if err != nil {
		return nil, err
	}
	return WeightedSum(probs, vRows, heads, headDim)
}

// ApplyRoPEHalf Qwen/LLaMA 风格 RoPE 的**非原地**版本，语义同 ApplyRoPEHalfInPlace。
func ApplyRoPEHalf(vec []float64, pos, headDim int, theta float64) ([]float64, error) {
	out := make([]float64, len(vec))
	copy(out, vec)
	if err := ApplyRoPEHalfInPlace(out, pos, headDim, theta); err != nil {
		return nil, err
	}
	return out, nil
}

// ApplyRoPEHalfInPlace Qwen / LLaMA / HuggingFace 风格的 RoPE：**前后半劈**旋转 (i, i+headDim/2)。
//
// 与 ApplyRoPEInPlace（**相邻对** (2i, 2i+1)，GPT-J/NeoX 风格）是两种不同约定，
// headDim>2 时二者算出的 Q/K **完全不同**，且错用不会报任何错：注意力只"略微"偏掉，
// logits 仍在合理量级，唯有外部 golden 能发现（T5 实测 top-1 由 23811 偏到 264）。
//
// 判别：Qwen/Qwen2/Qwen3、LLaMA 系用本函数（rotate_half 前后半劈）；GPT-J/NeoX 用相邻对。
// 角度表与已有实现一致：inv_freq[i] = theta^(-2i/headDim)，差别只在配对方式。
func ApplyRoPEHalfInPlace(vec []float64, pos, headDim int, theta float64) error {
	if headDim <= 0 || headDim%2 != 0 {
		return fmt.Errorf("teecore: headDim=%d 非法（须为正偶数，RoPE 成对旋转）", headDim)
	}
	if len(vec) == 0 || len(vec)%headDim != 0 {
		return fmt.Errorf("teecore: 向量长度 %d 不是 headDim=%d 的整数倍", len(vec), headDim)
	}
	if pos < 0 {
		return fmt.Errorf("teecore: pos=%d 不可为负", pos)
	}
	if !(theta > 0) {
		return fmt.Errorf("teecore: theta=%v 必须为正", theta)
	}
	half := headDim / 2
	for base := 0; base < len(vec); base += headDim {
		for i := 0; i < half; i++ {
			ang := float64(pos) * math.Pow(theta, -float64(2*i)/float64(headDim))
			c, s := math.Cos(ang), math.Sin(ang)
			x0 := vec[base+i]
			x1 := vec[base+i+half]
			vec[base+i] = x0*c - x1*s
			vec[base+i+half] = x0*s + x1*c
		}
	}
	return nil
}

// ExpandGQA 把 KV 缓存行从 GQA 布局（kvHeads*headDim）扩展为 Q 头布局（heads*headDim）。
//
// 第 qh 个 Q 头复用第 qh/(heads/kvHeads) 个 KV 头（逐元素复制，其余头不变）。
// 当 kvHeads==heads（MHA，即无 GQA）时为恒等变换，直接返回原切片，零拷贝。
// 调用方须保证 heads%kvHeads==0（ModelConfig.Validate 已强制）。
//
// 之所以放在 trustedops 而非具体适配器：掩码单步引擎（route2step）是共享层，不得反向
// 依赖任何具体模型适配器（adapters/qwen 等）；GQA 扩展是纯算子，属可信域共享计算。
func ExpandGQA(rows [][]float64, kvHeads, heads, headDim int) ([][]float64, error) {
	if kvHeads <= 0 || heads <= 0 || headDim <= 0 {
		return nil, fmt.Errorf("teecore: ExpandGQA 参数非法 kvHeads=%d heads=%d headDim=%d", kvHeads, heads, headDim)
	}
	if heads%kvHeads != 0 {
		return nil, fmt.Errorf("teecore: heads=%d 不能被 kvHeads=%d 整除", heads, kvHeads)
	}
	if kvHeads == heads {
		return rows, nil
	}
	group := heads / kvHeads
	out := make([][]float64, len(rows))
	for i, row := range rows {
		if len(row) != kvHeads*headDim {
			return nil, fmt.Errorf("teecore: ExpandGQA 第 %d 行长度 %d != kvHeads*headDim=%d", i, len(row), kvHeads*headDim)
		}
		exp := make([]float64, heads*headDim)
		for qh := 0; qh < heads; qh++ {
			kvh := qh / group
			copy(exp[qh*headDim:(qh+1)*headDim], row[kvh*headDim:(kvh+1)*headDim])
		}
		out[i] = exp
	}
	return out, nil
}

// checkHeadLayout 校验一个 Q/K/V 行的多头布局是否自洽（长度 == heads*headDim）。
func checkHeadLayout(name string, vec []float64, heads, headDim int) error {
	if len(vec) != heads*headDim {
		return fmt.Errorf("%s 长度 %d != heads*headDim = %d", name, len(vec), heads*headDim)
	}
	return nil
}
