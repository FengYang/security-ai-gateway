package qwen

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// buildSafetensors 在内存里构造一个最小的 safetensors 文件（用于解析器单测）。
func buildSafetensors(t *testing.T, tensors map[string]struct {
	dtype string
	shape []int
	f32   []float32
}) []byte {
	t.Helper()
	names := make([]string, 0, len(tensors))
	for n := range tensors {
		names = append(names, n)
	}
	sort.Strings(names)

	offsets := map[string][2]int{}
	pos := 0
	for _, n := range names {
		nbytes := 0
		switch tensors[n].dtype {
		case "F32":
			nbytes = len(tensors[n].f32) * 4
		case "BF16":
			nbytes = len(tensors[n].f32) * 2
		default:
			t.Fatalf("未知 dtype %s", tensors[n].dtype)
		}
		offsets[n] = [2]int{pos, pos + nbytes}
		pos += nbytes
	}

	type tinfo struct {
		DType       string `json:"dtype"`
		Shape       []int  `json:"shape"`
		DataOffsets [2]int `json:"data_offsets"`
	}
	h := map[string]interface{}{"__metadata__": map[string]string{"format": "pt"}}
	for _, n := range names {
		h[n] = tinfo{DType: tensors[n].dtype, Shape: tensors[n].shape, DataOffsets: offsets[n]}
	}
	hb, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	var buf bytes.Buffer
	var lenField [8]byte
	binary.LittleEndian.PutUint64(lenField[:], uint64(len(hb)))
	buf.Write(lenField[:])
	buf.Write(hb)
	for _, n := range names {
		switch tensors[n].dtype {
		case "F32":
			for _, v := range tensors[n].f32 {
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
				buf.Write(b[:])
			}
		case "BF16":
			for _, v := range tensors[n].f32 {
				u16 := uint16(math.Float32bits(v) >> 16)
				var b [2]byte
				binary.LittleEndian.PutUint16(b[:], u16)
				buf.Write(b[:])
			}
		}
	}
	return buf.Bytes()
}

func TestSafetensorsParse(t *testing.T) {
	a := []float32{1.5, -2.25, 3.125, 0, 1e-3, -7.5}
	b := []float32{-0.1, 123.4}
	raw := buildSafetensors(t, map[string]struct {
		dtype string
		shape []int
		f32   []float32
	}{
		"a": {"F32", []int{2, 3}, a},
		"b": {"BF16", []int{2}, b},
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "m.safetensors")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := LoadSafeTensors(path)
	if err != nil {
		t.Fatalf("LoadSafeTensors: %v", err)
	}
	ta, ok := st.Tensors["a"]
	if !ok {
		t.Fatal("缺失张量 a")
	}
	got, err := ta.Float32(st)
	if err != nil {
		t.Fatalf("a.Float32: %v", err)
	}
	for i := range a {
		if math.Abs(float64(got[i]-a[i])) > 1e-6 {
			t.Fatalf("F32 解码错误 [%d] %v != %v", i, got[i], a[i])
		}
	}
	tb, _ := st.Tensors["b"]
	gotB, err := tb.Float32(st)
	if err != nil {
		t.Fatalf("b.Float32: %v", err)
	}
	for i := range b {
		// BF16 仅 7 位尾数，固有相对误差约 0.8%；用「1% 相对 + 1e-3 绝对地板」判据，
		// 仅当解码彻底走偏（如符号/指数错位成完全不同量级）才失败。
		if d := math.Abs(float64(gotB[i] - b[i])); d > 0.01*math.Abs(float64(b[i]))+1e-3 {
			t.Fatalf("BF16 解码误差过大 [%d] %v vs %v (err=%v)", i, gotB[i], b[i], d)
		}
	}
}

// smallQwenCfg 一个远小于真实模型的小配置，用于单测 GQA+SwiGLU+RoPE 管线。
func smallQwenCfg() QwenConfig {
	return QwenConfig{
		Layers: 2, Dim: 16, Heads: 4, KVHeads: 2, HeadDim: 4,
		FFN: 32, Vocab: 50, RopeTheta: 1e6, NormEps: 1e-6, MaxTokens: 64, TiedEmb: true,
	}
}

func TestSyntheticMaskedVsRef(t *testing.T) {
	rand.Seed(42) // 掩码随机源确定性
	cfg := smallQwenCfg()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	w := SyntheticWeights(cfg, 1)
	tokens := []int{1, 2, 3}

	masked, err := ForwardMasked(w, tokens)
	if err != nil {
		t.Fatalf("ForwardMasked: %v", err)
	}
	ref, err := ForwardRef(w, tokens)
	if err != nil {
		t.Fatalf("ForwardRef: %v", err)
	}
	rep, err := Compare(masked, ref, 0, 5e-2)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	t.Logf("合成小模型 掩码vs参照: MaxAbsDiff=%.3e MaxRelDiff=%.3f Top1=%d/%d",
		rep.MaxAbsDiff, rep.MaxRelDiff, rep.Top1Agree, rep.Steps)
	if rep.MaxRelDiff > 1.0 {
		t.Fatalf("掩码管线误差过大 MaxRelDiff=%.3f（应 <=1.0）", rep.MaxRelDiff)
	}
	if !rep.Top1All {
		t.Fatalf("top-1 未全一致 %d/%d", rep.Top1Agree, rep.Steps)
	}
}

// TestKVConsistency 验证「一次性前向」与「prefill+decode 分步」在 GQA 下给出相同末位 logits。
func TestKVConsistency(t *testing.T) {
	rand.Seed(7)
	cfg := smallQwenCfg()
	w := SyntheticWeights(cfg, 3)

	// 一次性 prefill 4 个 token
	all, err := ForwardMasked(w, []int{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	lastAll := all[len(all)-1]

	// 分步：先 prefill 3 个，再 decode 第 4 个
	r := NewRunner(w)
	if _, err := r.Step(maskedLinear, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	dec, err := r.Step(maskedLinear, []int{4})
	if err != nil {
		t.Fatal(err)
	}
	lastDec := dec[0]

	maxd := 0.0
	for i := range lastAll {
		d := math.Abs(lastAll[i] - lastDec[i])
		if d > maxd {
			maxd = d
		}
	}
	t.Logf("KV 一致性 末位 logits 最大差=%.3e", maxd)
	if maxd > 1e-6 {
		t.Fatalf("prefill+decode 与一次性前向不一致 maxd=%.3e", maxd)
	}
}

// TestGQAExpansion 验证 GQA 的 KV 头扩展到 Q 头布局正确（每 Q 头取对应 KV 头切片）。
func TestGQAExpansion(t *testing.T) {
	cfg := QwenConfig{Heads: 4, KVHeads: 2, HeadDim: 3}
	// KV 行布局：[kv0(3) | kv1(3)]
	kv := []float64{1, 2, 3, 7, 8, 9}
	exp := expandKVRow(kv, cfg)
	// 期待 Q 头 0,1 -> kv0；Q 头 2,3 -> kv1
	want := []float64{1, 2, 3, 1, 2, 3, 7, 8, 9, 7, 8, 9}
	if len(exp) != len(want) {
		t.Fatalf("长度 %d != %d", len(exp), len(want))
	}
	for i := range want {
		if exp[i] != want[i] {
			t.Fatalf("expandKVRow[%d] = %v != %v", i, exp[i], want[i])
		}
	}
}

// TestPerHeadRMSNorm 逐头 RMSNorm 与手算逐元素对齐（Qwen3 的 q_norm/k_norm）。
//
// 为什么单独测：该函数只在"权重里带 q_norm/k_norm"时才被调用，而合成权重默认不带，
// 唯一的端到端覆盖是真实权重 golden 门控（~16 分钟、且需本机有权重）。缺了这条便宜用例，
// 一旦 perHeadRMSNorm 被改坏（例如按整行归一、gamma 用错段），常规 CI 全绿而无感知。
func TestPerHeadRMSNorm(t *testing.T) {
	const headDim = 4
	gamma := []float64{1, 1.2, 0.8, 1}
	v := []float64{1, -2, 3, -4, 0.5, 1.5, -2.5, 0.25} // 2 个头 × headDim
	const eps = 1e-6

	got, err := perHeadRMSNorm(v, gamma, headDim, eps)
	if err != nil {
		t.Fatalf("perHeadRMSNorm: %v", err)
	}
	for h := 0; h < len(v)/headDim; h++ {
		seg := v[h*headDim : (h+1)*headDim]
		var sq float64
		for _, x := range seg {
			sq += x * x
		}
		inv := 1 / math.Sqrt(sq/float64(headDim)+eps)
		for i := range seg {
			want := seg[i] * inv * gamma[i]
			if math.Abs(got[h*headDim+i]-want) > 1e-12 {
				t.Fatalf("head %d elem %d: got %.12f want %.12f", h, i, got[h*headDim+i], want)
			}
		}
	}

	// 失败路径：gamma 长度不符 / 向量长度不是 headDim 整数倍，均须 fail-closed。
	if _, err := perHeadRMSNorm(v, gamma[:3], headDim, eps); err == nil {
		t.Fatal("gamma 长度 != head_dim 应报错")
	}
	if _, err := perHeadRMSNorm(v, gamma, 3, eps); err == nil {
		t.Fatal("向量长度不是 head_dim 整数倍应报错")
	}
}

// TestForwardAppliesQKNorm 合成权重上验证 QK-norm 真的接进了前向。
//
// 判据：给同一份权重补上 gamma=1 的 q_norm/k_norm 后，logits 必须**发生变化**
// （RMSNorm 即使 gamma 全 1 也不是恒等变换——归一化会改写幅度）；若不变化，
// 说明 runLayers 里的 QK-norm 分支没生效或接错了位置。
func TestForwardAppliesQKNorm(t *testing.T) {
	cfg := QwenConfig{
		Layers: 2, Dim: 16, Heads: 4, KVHeads: 2, HeadDim: 4,
		FFN: 32, Vocab: 50, RopeTheta: 1e6, NormEps: 1e-6, MaxTokens: 64, TiedEmb: true,
	}
	w := SyntheticWeights(cfg, 11)
	base, err := ForwardRef(w, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("baseline ForwardRef: %v", err)
	}

	w.QNorm = make([][]float64, cfg.Layers)
	w.KNorm = make([][]float64, cfg.Layers)
	for l := 0; l < cfg.Layers; l++ {
		w.QNorm[l] = make([]float64, cfg.HeadDim)
		w.KNorm[l] = make([]float64, cfg.HeadDim)
		for i := range w.QNorm[l] {
			w.QNorm[l][i], w.KNorm[l][i] = 1, 1
		}
	}
	withNorm, err := ForwardRef(w, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("QK-norm ForwardRef: %v", err)
	}

	same := true
	for i := range base {
		for j := range base[i] {
			if math.Abs(base[i][j]-withNorm[i][j]) > 1e-9 {
				same = false
				break
			}
		}
		if !same {
			break
		}
	}
	if same {
		t.Fatal("启用 QK-norm 后 logits 未变化：runLayers 的 QK-norm 分支未生效")
	}
}
