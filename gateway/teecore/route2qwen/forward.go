package route2qwen

import (
	"fmt"
	"math"

	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// linearFn 一个线性层求值器：输入 batch 行，输出 batch 行。
// maskedLinear（掩码像内核）与 refLinear（去量化参照）都满足此签名，
// 使前向逻辑只写一份、两条路径共享。
type linearFn func(m *maskedinfer.QuantizedMatrix, x [][]float64) ([][]float64, error)

// Runner Qwen 前向运行态：KV 缓存 + 位置计数。
// KV 缓存存的是可信域明文（脱掩码后的值），注意力在可信域计算（与 teecore 约定一致）。
type Runner struct {
	w   *Weights
	pos int
	k   [][][]float64
	v   [][][]float64
}

// NewRunner 构造空运行态。
func NewRunner(w *Weights) *Runner {
	return &Runner{
		w: w,
		k: make([][][]float64, w.Cfg.Layers),
		v: make([][][]float64, w.Cfg.Layers),
	}
}

// Positions 已追加的 KV 行数。
func (r *Runner) Positions() int { return r.pos }

// Reset 清空 KV 与位置计数。
func (r *Runner) Reset() {
	r.pos = 0
	r.k = make([][][]float64, r.w.Cfg.Layers)
	r.v = make([][][]float64, r.w.Cfg.Layers)
}

// Step 处理一个 batch（prefill 多行或 decode 单行），返回每行 logits。
// fn 决定线性层走掩码像还是参照路径。
func (r *Runner) Step(fn linearFn, tokens []int) ([][]float64, error) {
	cfg := r.w.Cfg
	if len(tokens) == 0 {
		return nil, fmt.Errorf("route2qwen: 空 batch")
	}
	if r.pos+len(tokens) > cfg.MaxTokens {
		return nil, fmt.Errorf("route2qwen: 位置 %d + batch %d 超出 MaxTokens=%d", r.pos, len(tokens), cfg.MaxTokens)
	}
	base := r.pos
	h, err := r.w.embedRows(tokens)
	if err != nil {
		return nil, err
	}

	for L := 0; L < cfg.Layers; L++ {
		// attention 前 RMSNorm
		hn := make([][]float64, len(tokens))
		for i := range h {
			hn[i] = RMSNorm(h[i], r.w.LNIn[L], cfg.NormEps)
		}
		q := mustBatch(fn(r.w.AttnQ[L][0], hn))
		k := mustBatch(fn(r.w.AttnK[L][0], hn))
		vv := mustBatch(fn(r.w.AttnV[L][0], hn))

		// RoPE 只作用于 Q/K（V 不旋转），且必须在 KV 追加之前完成（Qwen/LLaMA 约定）
		for i := range q {
			if err := applyRoPEQwen(q[i], base+i, cfg.HeadDim, cfg.RopeTheta); err != nil {
				return nil, err
			}
			if err := applyRoPEQwen(k[i], base+i, cfg.HeadDim, cfg.RopeTheta); err != nil {
				return nil, err
			}
		}
		r.k[L] = append(r.k[L], k...)
		r.v[L] = append(r.v[L], vv...)

		h2 := make([][]float64, len(tokens))
		for i := range q {
			o, err := attentionQwen(q[i], r.k[L], r.v[L], cfg, base+i)
			if err != nil {
				return nil, fmt.Errorf("route2qwen: 层 %d 注意力失败: %w", L, err)
			}
			ao := mustOne(fn(r.w.AttnO[L][0], [][]float64{o}))
			h2[i], err = addVec(h[i], ao)
			if err != nil {
				return nil, err
			}
		}

		// FFN 前 RMSNorm + SwiGLU
		hn2 := make([][]float64, len(tokens))
		for i := range h2 {
			hn2[i] = RMSNorm(h2[i], r.w.LNPost[L], cfg.NormEps)
		}
		gate := mustBatch(fn(r.w.Gate[L][0], hn2))
		up := mustBatch(fn(r.w.Up[L][0], hn2))
		act := siluMul(gate, up)
		down := mustBatch(fn(r.w.Down[L][0], act))
		for i := range h {
			h[i], err = addVec(h2[i], down[i])
			if err != nil {
				return nil, err
			}
		}
	}

	hn := make([][]float64, len(h))
	for i := range h {
		hn[i] = RMSNorm(h[i], r.w.LNFinal, cfg.NormEps)
	}
	logits := mustBatch(fn(r.w.LMHead, hn))
	r.pos += len(tokens)
	return logits, nil
}

// applyRoPEQwen Qwen/LLaMA 风格 RoPE：**前后半劈开**旋转（旋转 (i, i+headDim/2)）。
//
// 注意：本仓库 teecore 冻结为 Su et al. 相邻对旋转，与 Qwen/LLaMA 数值不兼容；
// 故 Qwen 前向必须在此使用正确的前后半劈开排布，否则 RoPE 相位错误、注意力错位。
func applyRoPEQwen(vec []float64, pos, headDim int, theta float64) error {
	if headDim <= 0 || headDim%2 != 0 {
		return fmt.Errorf("route2qwen: headDim=%d 须为正偶数", headDim)
	}
	if len(vec)%headDim != 0 {
		return fmt.Errorf("route2qwen: 向量长度 %d 不是 headDim=%d 整数倍", len(vec), headDim)
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

// expandKVRow 把 KV 头布局（KVHeads*HeadDim）扩展为 Q 头布局（Heads*HeadDim）。
// 第 qh 个 Q 头复用第 qh/(Heads/KVHeads) 个 KV 头。
func expandKVRow(row []float64, cfg QwenConfig) []float64 {
	hd := cfg.HeadDim
	group := cfg.Heads / cfg.KVHeads
	out := make([]float64, cfg.Heads*hd)
	for qh := 0; qh < cfg.Heads; qh++ {
		kvh := qh / group
		src := kvh * hd
		dst := qh * hd
		copy(out[dst:dst+hd], row[src:src+hd])
	}
	return out
}

// attentionQwen 单查询行注意力：先把 KV 缓存按 GQA 扩展到 Q 头布局，再走 teecore.Attention。
func attentionQwen(q []float64, kCache, vCache [][]float64, cfg QwenConfig, pos int) ([]float64, error) {
	kExp := make([][]float64, len(kCache))
	vExp := make([][]float64, len(vCache))
	for i := range kCache {
		kExp[i] = expandKVRow(kCache[i], cfg)
		vExp[i] = expandKVRow(vCache[i], cfg)
	}
	return Attention(q, kExp, vExp, cfg.Heads, cfg.HeadDim, 0, pos, true)
}

// siluMul SwiGLU 激活：out = silu(gate) * up，逐元素。
func siluMul(gate, up [][]float64) [][]float64 {
	out := make([][]float64, len(gate))
	for i := range gate {
		row := make([]float64, len(gate[i]))
		for j := range gate[i] {
			s := gate[i][j] / (1 + math.Exp(-gate[i][j]))
			row[j] = s * up[i][j]
		}
		out[i] = row
	}
	return out
}

func addVec(a, b []float64) ([]float64, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("route2qwen: 残差维度不一致 %d != %d", len(a), len(b))
	}
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return out, nil
}

// ---------- 便捷入口与对拍 ----------

// ForwardMasked 用掩码像内核（int8/Mod64）跑完整前向，返回每行 logits。
func ForwardMasked(w *Weights, tokens []int) ([][]float64, error) {
	r := NewRunner(w)
	return r.Step(maskedLinear, tokens)
}

// ForwardRef 用去量化 int8 参照权重（无掩码/无定点）跑完整前向。
func ForwardRef(w *Weights, tokens []int) ([][]float64, error) {
	r := NewRunner(w)
	return r.Step(refLinear, tokens)
}

// MUST 辅助：把单/批量结果从 (out,err) 取出，err 直接 panic（仅用于内部已保证合法的调用）。
func mustBatch(out [][]float64, err error) [][]float64 {
	if err != nil {
		panic(fmt.Sprintf("route2qwen: 内部线性层失败: %v", err))
	}
	return out
}

func mustOne(out [][]float64, err error) []float64 {
	if err != nil {
		panic(fmt.Sprintf("route2qwen: 内部线性层失败: %v", err))
	}
	return out[0]
}

// Report 两条路径 logits 的对比结果。
type Report struct {
	Atol       float64
	Rtol       float64
	MaxAbsDiff float64
	MaxRelDiff float64
	Steps      int
	Logits     int
	Top1Agree  int
	Top1All    bool
}

// Compare 混合容差对比 |a-b| <= atol + rtol*|b|，并统计 top-1 命中。
func Compare(a, b [][]float64, atol, rtol float64) (Report, error) {
	rep := Report{Atol: atol, Rtol: rtol, Steps: len(a)}
	if len(a) != len(b) {
		return Report{}, fmt.Errorf("route2qwen: 步数不一致 %d != %d", len(a), len(b))
	}
	for s := range a {
		if len(a[s]) != len(b[s]) {
			return Report{}, fmt.Errorf("route2qwen: 第 %d 步 logits 维度不一致 %d != %d", s, len(a[s]), len(b[s]))
		}
		for i := range a[s] {
			x, y := a[s][i], b[s][i]
			if math.IsNaN(x) || math.IsInf(x, 0) || math.IsNaN(y) || math.IsInf(y, 0) {
				return Report{}, fmt.Errorf("route2qwen: 第 %d 步第 %d 个 logit 非有限（x=%v y=%v）", s, i, x, y)
			}
			d := math.Abs(x - y)
			rep.Logits++
			if d > rep.MaxAbsDiff {
				rep.MaxAbsDiff = d
			}
			if tol := atol + rtol*math.Abs(y); tol > 0 {
				if ratio := d / tol; ratio > rep.MaxRelDiff {
					rep.MaxRelDiff = ratio
				}
			}
		}
		if len(a[s]) > 0 && ArgMax(a[s]) == ArgMax(b[s]) {
			rep.Top1Agree++
		}
	}
	rep.Top1All = rep.Top1Agree == rep.Steps
	return rep, nil
}
