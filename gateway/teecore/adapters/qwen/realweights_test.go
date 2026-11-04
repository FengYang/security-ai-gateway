// realweights_test.go — 真实权重 golden 门控（方案 §6.2·D2 / §8.2 完成判据①②）
//
// 【为什么必须有这一层】本包的三条路径（ForwardMasked 形态B / ForwardRef 参照浮点 /
// orchestrator 的形态A）共用同一份前向实现，互相对拍只能证明"掩码链路没写错"，
// 不能证明"模型结构实现正确"——QK-norm 放错位置、RoPE 与 norm 顺序颠倒、
// GQA 头映射错位这类缺陷会让三条路径**一起错且完全同向**，自洽对拍永远绿。
// 故取独立实现（transformers fp32 CPU）产出的 golden 作锚点，见
// scripts/gen-qwen3-golden.py 与 testdata/qwen3-06b-golden.json。
//
// 【门槛设计】权重不在本机时 Skip（不伪造 PASS），并在 skip 消息里写明"D2 未执行"。
// CI 无真实权重，本用例在 CI 恒 Skip；它由"发布/里程碑验收"环节显式执行：
//
//	ROUTE2_QWEN_DIR=.tools/models/Qwen3Guard-Gen-0.6B \
//	  go test -run TestRealWeightsGolden -v ./gateway/teecore/adapters/qwen/
package qwen

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// defaultRealWeightsDir 相对**包目录**的默认权重路径（qwen → adapters → teecore → gateway → 仓库根）。
const defaultRealWeightsDir = "../../../../.tools/models/Qwen3Guard-Gen-0.6B"

// goldenFile 与 scripts/gen-qwen3-golden.py 的输出结构一一对应。
type goldenFile struct {
	Model     string `json:"model"`
	Arch      string `json:"arch"`
	Reference string `json:"reference"`
	Config    struct {
		Layers    int     `json:"layers"`
		Dim       int     `json:"dim"`
		Heads     int     `json:"heads"`
		KVHeads   int     `json:"kv_heads"`
		HeadDim   int     `json:"head_dim"`
		FFN       int     `json:"ffn"`
		Vocab     int     `json:"vocab"`
		RopeTheta float64 `json:"rope_theta"`
		NormEps   float64 `json:"norm_eps"`
		Tied      bool    `json:"tied"`
	} `json:"config"`
	TokenIDs []int     `json:"token_ids"`
	TopK     int       `json:"top_k"`
	Indices  []int     `json:"indices"`
	Logits   []float64 `json:"logits"`
}

// TestRealWeightsGolden 真实 Qwen3 权重 × 外部参考对拍（D2 门控）。
//
// 断言三件事：
//  1. 结构自洽：内置 Qwen3_06B() 预设与 golden 记录的 config 一致（防 preset 漂移）；
//  2. 参照浮点路径与 transformers fp32 的金 top-K 一致（结构/算子实现正确）；
//  3. 掩码路径（形态B，int8+Mod64 定点的完整 28 层）与同一 golden 的 top-1 一致、
//     top-K 相对误差在容差内（掩码链路端到端可用）。
func TestRealWeightsGolden(t *testing.T) {
	dir := os.Getenv("ROUTE2_QWEN_DIR")
	if dir == "" {
		dir = defaultRealWeightsDir
	}
	weightsPath := filepath.Join(dir, "model.safetensors")
	if _, err := os.Stat(weightsPath); err != nil {
		t.Skipf("真实权重不存在（%s）：**D2 门控未执行**，不得据此宣称支持真实模型。设置 ROUTE2_QWEN_DIR 后重跑", weightsPath)
	}

	g := loadGolden(t, "testdata/qwen3-06b-golden.json")

	cfg := Qwen3_06B()
	assertCfgMatchesGolden(t, cfg, g)

	w, err := LoadWeights(weightsPath, cfg)
	if err != nil {
		t.Fatalf("加载真实权重失败: %v", err)
	}
	if w.QNorm == nil || w.KNorm == nil {
		t.Fatal("Qwen3 权重应加载出 q_norm/k_norm；为 nil 说明 QK-norm 未启用（结构实现不完整）")
	}
	if len(w.QNorm) != cfg.Layers || len(w.KNorm) != cfg.Layers {
		t.Fatalf("QK-norm 层数 %d/%d != Layers=%d", len(w.QNorm), len(w.KNorm), cfg.Layers)
	}

	// 1) 参照浮点（无掩码/无定点，仅 int8 量化）vs 外部 fp32 golden
	refOut, err := ForwardRef(w, g.TokenIDs)
	if err != nil {
		t.Fatalf("ForwardRef 前向失败: %v", err)
	}
	refRep := compareGolden(t, "ForwardRef", lastRow(t, refOut), g)
	t.Logf("ForwardRef vs golden: top1=%d/%d maxRelErr=%.4f", refRep.top1, g.Indices[0], refRep.maxRelErr)

	// 2) 掩码形态B（完整掩码链路）vs 同一 golden —— 默认不跑，见下方说明。
	//
	// 【实测成本】宿主机 2 核 / 7GB：整条 28 层 × 6 token + 151936 词表 LMHead 的掩码前向
	// 实测 983s（约 16 分钟），因为掩码内核走 math/big 的 O(Rows×Cols) 大整数乘加。
	// 作为默认门控会把 `go test` 拖成一刻钟，故改为显式开启；CI 无权重本就 Skip。
	maskedRep := goldenReport{}
	if os.Getenv("ROUTE2_QWEN_MASKED") == "" {
		t.Log("掩码形态B 对拍已跳过（实测约 16 分钟；设 ROUTE2_QWEN_MASKED=1 启用）")
	} else {
		maskedOut, err := ForwardMasked(w, g.TokenIDs)
		if err != nil {
			t.Fatalf("ForwardMasked 前向失败: %v", err)
		}
		maskedRep = compareGolden(t, "ForwardMasked", lastRow(t, maskedOut), g)
		t.Logf("ForwardMasked vs golden: top1=%d/%d maxRelErr=%.4f", maskedRep.top1, g.Indices[0], maskedRep.maxRelErr)
		if maskedRep.maxRelErr > 0.08 {
			t.Errorf("ForwardMasked 与参考偏差过大 maxRelErr=%.4f > 0.08（掩码链路或定点精度异常）", maskedRep.maxRelErr)
		}
	}

	// 阈值 = 实测值 0.0390（2026-11-04，Qwen3Guard-Gen-0.6B）的 2 倍余量。
	// 该误差几乎全部来自逐行 int8 权重（scale=max|W|/127），与掩码/定点无关——
	// 形态B 与参照路径实测同为 0.0390，说明掩码链路本身没引入额外误差。
	if refRep.maxRelErr > 0.08 {
		t.Errorf("ForwardRef 与 transformers 参考偏差过大 maxRelErr=%.4f > 0.08（结构实现有误，非量化噪声）", refRep.maxRelErr)
	}
}

// assertCfgMatchesGolden 用 golden 里记录的 config 反查内置预设，防止 preset 改错而测试仍绿。
func assertCfgMatchesGolden(t *testing.T, c QwenConfig, g goldenFile) {
	t.Helper()
	got := QwenConfig{
		Layers: c.Layers, Dim: c.Dim, Heads: c.Heads, KVHeads: c.KVHeads, HeadDim: c.HeadDim,
		FFN: c.FFN, Vocab: c.Vocab, RopeTheta: c.RopeTheta, NormEps: c.NormEps, TiedEmb: c.TiedEmb,
	}
	want := QwenConfig{
		Layers: g.Config.Layers, Dim: g.Config.Dim, Heads: g.Config.Heads, KVHeads: g.Config.KVHeads,
		HeadDim: g.Config.HeadDim, FFN: g.Config.FFN, Vocab: g.Config.Vocab,
		RopeTheta: g.Config.RopeTheta, NormEps: g.Config.NormEps, TiedEmb: g.Config.Tied,
	}
	if got != want {
		t.Fatalf("Qwen3_06B() 预设与 golden 记录的配置不一致：\n got=%+v\nwant=%+v", got, want)
	}
}

type goldenReport struct {
	top1      int     // 我们算出的 argmax
	maxRelErr float64 // top-K 内逐项相对误差最大值
}

// compareGolden 把一行 logits 与 golden 的 top-K 逐项比对。
//
// 只比 golden 给出的 K 个下标：golden 是有意裁剪的小文件（全量 15 万 logits 会让
// 仓库体积与审阅成本失控），而这 K 项恰是"模型是否学会了同一件事"的最敏感位置。
func compareGolden(t *testing.T, name string, row []float64, g goldenFile) goldenReport {
	t.Helper()
	if len(row) != g.Config.Vocab {
		t.Fatalf("%s: logits 长度 %d != vocab %d", name, len(row), g.Config.Vocab)
	}
	arg := argmax(row)
	rep := goldenReport{top1: arg}
	for i, idx := range g.Indices {
		if idx < 0 || idx >= len(row) {
			t.Fatalf("%s: golden 下标 %d 越界", name, idx)
		}
		want := g.Logits[i]
		d := math.Abs(row[idx] - want)
		rel := d / math.Max(math.Abs(want), 1.0)
		if rel > rep.maxRelErr {
			rep.maxRelErr = rel
		}
	}
	if arg != g.Indices[0] {
		ours := topKIndices(row, g.TopK)
		t.Fatalf("%s: top-1 不符 got=%d want=%d\n ours top-%d=%v\n golden   =%v",
			name, arg, g.Indices[0], g.TopK, ours, g.Indices)
	}
	return rep
}

// topKIndices 返回概率/分数最高的 K 个下标（降序），仅用于失败诊断。
func topKIndices(row []float64, k int) []int {
	idx := make([]int, len(row))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return row[idx[a]] > row[idx[b]] })
	if k > len(idx) {
		k = len(idx)
	}
	return idx[:k]
}

func argmax(row []float64) int {
	best := 0
	for i, v := range row {
		if v > row[best] {
			best = i
		}
	}
	return best
}

// lastRow 取批内最后一行（因果 LM 的"下一个 token"预测位）。
func lastRow(t *testing.T, out [][]float64) []float64 {
	t.Helper()
	if len(out) == 0 {
		t.Fatal("前向返回空结果")
	}
	return out[len(out)-1]
}

func loadGolden(t *testing.T, path string) goldenFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 golden 失败: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}
	if len(g.Indices) != len(g.Logits) || len(g.Indices) == 0 {
		t.Fatalf("golden 结构非法：indices/logits 长度 %d/%d", len(g.Indices), len(g.Logits))
	}
	if len(g.TokenIDs) == 0 {
		t.Fatal("golden 缺 token_ids")
	}
	return g
}
