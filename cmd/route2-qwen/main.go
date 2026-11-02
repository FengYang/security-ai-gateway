// Command route2-qwen 路线2 适配 Qwen2.5 的真实模型端到端 CPU 验证 harness。
//
// 用法：
//
//	route2-qwen --selftest
//	    用一份「形状正确」的合成小模型，验证 GQA+SwiGLU+Qwen-RoPE 的掩码像管线数学正确。
//
//	route2-qwen --model <model.safetensors> --tokens 80524 80525
//	    加载真实 Qwen2.5 权重，对给定 token 序列跑掩码像前向（int8/Mod64）与
//	    去量化参照前向，对拍并给出 Report。
//
//	route2-qwen --model <model.safetensors> --tokenizer <tokenizer.json> --prompt "文本"
//	    加载真实权重 + 真实 tokenizer，把文本编码为 token，跑前向并解码「下一 token」预测，
//	    验证 tokenizer 接入后整条链路（文本→token→掩码像前向→logits→token→文本）数值正确。
//
// 注意：本 harness 仅做 CPU 数值验证，掩码像内核走 math/big 精确模拟（与 GPU 内核同语义）。
// 真机 GPU 加速（CUDA/昇腾）待硬件就绪后再接入。
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"security-ai-gateway/gateway/teecore/route2qwen"
)

func main() {
	selftest := flag.Bool("selftest", false, "用合成小模型验证掩码像管线数学正确")
	model := flag.String("model", "", "真实模型 safetensors 路径")
	tokPath := flag.String("tokenizer", "", "tokenizer.json 路径（文本模式必需）")
	prompt := flag.String("prompt", "", "文本 prompt（配合 -tokenizer）")
	tokensArg := flag.String("tokens", "", "逗号/空格分隔的 token id（无 tokenizer 时用）")
	flag.Parse()

	switch {
	case *selftest:
		runSelftest()
	case *model != "":
		switch {
		case *prompt != "":
			if err := runText(*model, *tokPath, *prompt); err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}
		default:
			tokens := []int{1, 2, 3, 4}
			if *tokensArg != "" {
				tokens = parseTokens(*tokensArg)
			}
			if err := runReal(*model, tokens); err != nil {
				fmt.Fprintf(os.Stderr, "错误: %v\n", err)
				os.Exit(1)
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "用法: route2-qwen --selftest | --model M [--tokens ids | --tokenizer T --prompt \"文本\"]")
		os.Exit(2)
	}
}

func parseTokens(s string) []int {
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		v, err := strconv.Atoi(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "非法 token %q: %v\n", f, err)
			os.Exit(2)
		}
		out = append(out, v)
	}
	return out
}

func runSelftest() {
	cfg := route2qwen.QwenConfig{
		Layers: 2, Dim: 16, Heads: 4, KVHeads: 2, HeadDim: 4,
		FFN: 32, Vocab: 50, RopeTheta: 1e6, NormEps: 1e-6, MaxTokens: 64, TiedEmb: true,
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config 非法:", err)
		os.Exit(1)
	}
	w := route2qwen.SyntheticWeights(cfg, 1)
	masked, err := route2qwen.ForwardMasked(w, []int{1, 2, 3})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ForwardMasked:", err)
		os.Exit(1)
	}
	ref, err := route2qwen.ForwardRef(w, []int{1, 2, 3})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ForwardRef:", err)
		os.Exit(1)
	}
	rep, err := route2qwen.Compare(masked, ref, 0, 5e-2)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Compare:", err)
		os.Exit(1)
	}
	fmt.Printf("=== route2-qwen --selftest ===\n")
	fmt.Printf("模型: 合成 Qwen 形状 (L=%d D=%d H=%d KV=%d FFN=%d V=%d)\n",
		cfg.Layers, cfg.Dim, cfg.Heads, cfg.KVHeads, cfg.FFN, cfg.Vocab)
	pass := rep.MaxRelDiff <= 1.0 && rep.Top1All
	fmt.Printf("MaxAbsDiff=%.3e  MaxRelDiff=%.4f  Top1=%d/%d  Pass=%v\n",
		rep.MaxAbsDiff, rep.MaxRelDiff, rep.Top1Agree, rep.Steps, pass)
	if !pass {
		os.Exit(1)
	}
}

func runReal(path string, tokens []int) error {
	cfg := route2qwen.Qwen25_05B()
	fmt.Printf("=== route2-qwen 真实模型（token 模式）===\n")
	fmt.Printf("加载 %s (Qwen2.5-0.5B: L=%d D=%d H=%d KV=%d FFN=%d V=%d)\n",
		path, cfg.Layers, cfg.Dim, cfg.Heads, cfg.KVHeads, cfg.FFN, cfg.Vocab)
	w, err := route2qwen.LoadWeights(path, cfg)
	if err != nil {
		return fmt.Errorf("加载权重失败: %w", err)
	}
	fmt.Printf("权重加载完成（int8/Mod64 量化）。\n")

	masked, err := route2qwen.ForwardMasked(w, tokens)
	if err != nil {
		return fmt.Errorf("掩码像前向失败: %w", err)
	}
	ref, err := route2qwen.ForwardRef(w, tokens)
	if err != nil {
		return fmt.Errorf("参照前向失败: %w", err)
	}
	rep, err := route2qwen.Compare(masked, ref, 0, 5e-2)
	if err != nil {
		return fmt.Errorf("对拍失败: %w", err)
	}
	agree := argmax(masked[len(masked)-1]) == argmax(ref[len(ref)-1])
	pass := rep.Top1All && rep.MaxAbsDiff <= 1e-1
	fmt.Printf("tokens=%v\n", tokens)
	fmt.Printf("MaxAbsDiff=%.3e  Top1=%d/%d  argmax一致=%v\n",
		rep.MaxAbsDiff, rep.Top1Agree, rep.Steps, agree)
	fmt.Printf("注: MaxRelDiff=%.4f 由接近 0 的 logit 主导(非正确性信号)，以绝对误差+argmax 为准\n", rep.MaxRelDiff)
	fmt.Printf("端到端真模型验证 Pass=%v\n", pass)
	if !pass {
		return fmt.Errorf("验证未通过")
	}
	return nil
}

// runText 文本模式：tokenizer 接入后的完整链路验证。
func runText(modelPath, tokPath, prompt string) error {
	if tokPath == "" {
		return fmt.Errorf("文本模式需要 -tokenizer <tokenizer.json>")
	}
	cfg := route2qwen.Qwen25_05B()
	fmt.Printf("=== route2-qwen 真实模型（文本模式）===\n")
	fmt.Printf("加载 %s (Qwen2.5-0.5B)\n", modelPath)
	w, err := route2qwen.LoadWeights(modelPath, cfg)
	if err != nil {
		return fmt.Errorf("加载权重失败: %w", err)
	}
	tok, err := route2qwen.LoadTokenizer(tokPath)
	if err != nil {
		return fmt.Errorf("加载 tokenizer 失败: %w", err)
	}
	tokens := tok.Encode(prompt)
	if len(tokens) == 0 {
		return fmt.Errorf("prompt 编码为空")
	}
	fmt.Printf("prompt=%q\n", prompt)
	fmt.Printf("编码 token 数=%d  tokens=%v\n", len(tokens), tokens)

	masked, err := route2qwen.ForwardMasked(w, tokens)
	if err != nil {
		return fmt.Errorf("掩码像前向失败: %w", err)
	}
	ref, err := route2qwen.ForwardRef(w, tokens)
	if err != nil {
		return fmt.Errorf("参照前向失败: %w", err)
	}
	rep, err := route2qwen.Compare(masked, ref, 0, 5e-2)
	if err != nil {
		return fmt.Errorf("对拍失败: %w", err)
	}
	// 最后一行 logits = 下一 token 预测
	nextM := argmax(masked[len(masked)-1])
	nextR := argmax(ref[len(ref)-1])
	agree := nextM == nextR
	pass := rep.Top1All && rep.MaxAbsDiff <= 1e-1
	fmt.Printf("MaxAbsDiff=%.3e  Top1=%d/%d  argmax一致=%v\n",
		rep.MaxAbsDiff, rep.Top1Agree, rep.Steps, agree)
	fmt.Printf("掩码像预测下一 token: id=%d  text=%q\n", nextM, tok.Decode([]int{nextM}))
	fmt.Printf("参照预测下一 token:   id=%d  text=%q\n", nextR, tok.Decode([]int{nextR}))
	fmt.Printf("端到端真模型（文本→token→掩码像前向→token→文本）Pass=%v\n", pass)
	if !pass {
		return fmt.Errorf("验证未通过")
	}
	return nil
}

func argmax(v []float64) int {
	idx := 0
	for i := 1; i < len(v); i++ {
		if v[i] > v[idx] {
			idx = i
		}
	}
	return idx
}
