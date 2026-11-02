// model_weights_test.go - 权重派生确定性 / 非方阵 / 与 LayerWeights 共存 / maskedinfer 冒烟（T01 验收项 5、6）
package route2demo

import (
	"math"
	"reflect"
	"testing"

	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2plan"
)

// demoCfg 测试用配置：直接引用 T01 的唯一常量源，禁止在本文件里另抄一份数字。
func demoCfg() route2plan.ModelConfig {
	return route2plan.DemoTinyConfig()
}

// TestTensorWeightsDeterministic 同一 (cfg, key) 两次派生必须逐位相等——
// 这是客户端与服务端能对上账的唯一依据。
func TestTensorWeightsDeterministic(t *testing.T) {
	cfg := demoCfg()
	keys := []route2plan.TensorKey{
		{Block: 0, Tensor: route2plan.TensorAttnQ},
		{Block: 0, Tensor: route2plan.TensorAttnK},
		{Block: 0, Tensor: route2plan.TensorAttnV},
		{Block: 0, Tensor: route2plan.TensorAttnO},
		{Block: 3, Tensor: route2plan.TensorFFNUp},
		{Block: 3, Tensor: route2plan.TensorFFNDown},
		{Block: cfg.Blocks, Tensor: route2plan.TensorLMHead},
	}
	for _, k := range keys {
		a, err := TensorWeights(cfg, k)
		if err != nil {
			t.Fatalf("TensorWeights(%s) 报错: %v", k, err)
		}
		b, err := TensorWeights(cfg, k)
		if err != nil {
			t.Fatalf("TensorWeights(%s) 第二次报错: %v", k, err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("张量 %s 两次派生不一致", k)
		}
		if a.ModBits != maskedinfer.Mod64 {
			t.Errorf("张量 %s 的 ModBits = %v, want Mod64", k, a.ModBits)
		}
		if a.InputScale != maskedinfer.InputScale {
			t.Errorf("张量 %s 的 InputScale = %v, want %v", k, a.InputScale, maskedinfer.InputScale)
		}
		if len(a.Bias) != 0 {
			t.Errorf("张量 %s 不应带 bias（MaskImage 不含 bias 是设计不变式）", k)
		}
	}
}

// TestTensorWeightsDiffersAcrossKeysAndBlocks 不同 block / 不同张量必须派生出不同权重。
func TestTensorWeightsDiffersAcrossKeysAndBlocks(t *testing.T) {
	cfg := demoCfg()
	a, err := TensorWeights(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	b, err := TensorWeights(cfg, route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Data, b.Data) {
		t.Fatal("不同 block 的 attn.q 派生出完全相同的权重（盐值未包含 block）")
	}
	k, err := TensorWeights(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Data, k.Data) {
		t.Fatal("attn.q 与 attn.k 派生出完全相同的权重（盐值未包含张量名）")
	}
	// 换 ModelID 也应换出一整套不同的权重
	other := cfg
	other.ModelID = "route2-demo-other"
	c, err := TensorWeights(other, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Data, c.Data) {
		t.Fatal("不同 ModelID 派生出相同权重（盐值未包含 modelID）")
	}
}

// TestTensorShapes 逐张量断言形状，重点是**非方阵**（lm_head / ffn）。
func TestTensorShapes(t *testing.T) {
	cfg := demoCfg()
	cases := []struct {
		key        route2plan.TensorKey
		wantRows   int
		wantCols   int
		wantSquare bool
	}{
		{route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ}, cfg.AttnDim(), cfg.Dim, true},
		{route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnK}, cfg.AttnDim(), cfg.Dim, true},
		{route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorAttnV}, cfg.AttnDim(), cfg.Dim, true},
		{route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorAttnO}, cfg.Dim, cfg.AttnDim(), true},
		{route2plan.TensorKey{Block: 2, Tensor: route2plan.TensorFFNUp}, cfg.FFNDim, cfg.Dim, false},
		{route2plan.TensorKey{Block: 2, Tensor: route2plan.TensorFFNDown}, cfg.Dim, cfg.FFNDim, false},
		{route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorLMHead}, cfg.Vocab, cfg.Dim, false},
	}
	for _, tc := range cases {
		t.Run(tc.key.String(), func(t *testing.T) {
			m, err := TensorWeights(cfg, tc.key)
			if err != nil {
				t.Fatal(err)
			}
			if m.Rows != tc.wantRows || m.Cols != tc.wantCols {
				t.Fatalf("形状 = %dx%d, want %dx%d", m.Rows, m.Cols, tc.wantRows, tc.wantCols)
			}
			if len(m.Data) != m.Rows*m.Cols {
				t.Fatalf("Data 长度 %d != Rows*Cols=%d", len(m.Data), m.Rows*m.Cols)
			}
			isSquare := m.Rows == m.Cols
			if isSquare != tc.wantSquare {
				t.Fatalf("方阵性 = %v, want %v", isSquare, tc.wantSquare)
			}
			// int8：量化后的整数必须落在 [-127, 127]
			for _, v := range m.Data {
				if v < -127 || v > 127 {
					t.Fatalf("量化值 %d 超出 int8 范围", v)
				}
			}
		})
	}
}

// TestLMHeadNonSquare lm_head 是 Dim×Vocab 的非方阵；单列一条用例并跑完整管线冒烟。
func TestLMHeadNonSquareRoundTrip(t *testing.T) {
	cfg := demoCfg()
	k := route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorLMHead}
	m, err := TensorWeights(cfg, k)
	if err != nil {
		t.Fatal(err)
	}
	if m.Rows != cfg.Vocab || m.Cols != cfg.Dim {
		t.Fatalf("lm_head 形状 = %dx%d, want %dx%d", m.Rows, m.Cols, cfg.Vocab, cfg.Dim)
	}
	// 一组确定性输入
	x := deterministicVec(cfg.Dim, 0x11)
	V, r, err := maskWith(t, m, x)
	if err != nil {
		t.Fatal(err)
	}
	got, err := roundTrip(m, V, r)
	if err != nil {
		t.Fatal(err)
	}
	want := m.PlainLinear([][]float64{x})[0]
	assertClose(t, "lm_head 还原", got, want, 1e-3)
}

// TestQuantizedMatrixPipelineSmoke 派生出的 QuantizedMatrix 必须能被
// MaskImage / CipherLinear / Unmask / Decode 正常处理：这证明数据形态合法，
// 后续 T02/T03 的 operator 接线才是安全的。
//
// 次序铁律：ToMaskDomain → CipherLinear → MaskImage → Unmask → Decode
// （绝不可先乘 scale 后取模，也不可省掉 MaskImage）。
func TestQuantizedMatrixPipelineSmoke(t *testing.T) {
	cfg := demoCfg()
	k := route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ}
	m, err := TensorWeights(cfg, k)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		seed int64
	}{
		{"全正输入", 0x21},
		{"含负输入", 0x22},
		{"含零输入", 0x23},
		{"量级较大输入", 0x24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := make([]float64, m.Cols)
			for i := range x {
				x[i] = synthetic(i, tc.seed)
			}
			V, r, err := maskWith(t, m, x)
			if err != nil {
				t.Fatal(err)
			}
			got, err := roundTrip(m, V, r)
			if err != nil {
				t.Fatal(err)
			}
			want := m.PlainLinear([][]float64{x})[0]
			assertClose(t, "密态线性 == 明态线性", got, want, 1e-3)
		})
	}
}

// TestMaskImageExcludesBias 即便给矩阵挂上 bias，MaskImage 也不得含 bias
// （这是设计不变式：偏置只能由 CipherLinear 加一次）。
func TestMaskImageExcludesBias(t *testing.T) {
	cfg := demoCfg()
	m, err := TensorWeights(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	withBias := m.WithBias(deterministicVec(m.Rows, 0x31))
	r := deterministicMask(m.Cols, 0x32)
	img, err := withBias.MaskImage(r)
	if err != nil {
		t.Fatal(err)
	}
	// 以全零输入验证：Unmask(CipherLinear(0), MaskImage(r)) == bias 的定点表示，
	// 与 PlainLinear(0)（== bias）必须一致 —— 这同时证明 MaskImage 未把 bias 算进去
	// （若 MaskImage 含 bias，Unmask 的结果会归零而非等于 bias）。
	zeros := make([]float64, m.Cols)
	V, err := withBias.Remask(withBias.ToMaskDomain(zeros), r)
	if err != nil {
		t.Fatal(err)
	}
	y, err := withBias.CipherLinear([][]uint64{V})
	if err != nil {
		t.Fatal(err)
	}
	u, err := withBias.Unmask(y[0], img)
	if err != nil {
		t.Fatal(err)
	}
	decoded := withBias.Decode(u)
	plain := withBias.PlainLinear([][]float64{zeros})[0]
	assertClose(t, "含 bias 时 Unmask→Decode == PlainLinear", decoded, plain, 1e-3)
}

// TestLayerWeightsStillWorks 既有 LayerWeights 必须仍然可用且未受影响（D15 保留不删）。
func TestLayerWeightsStillWorks(t *testing.T) {
	a, err := LayerWeights(0, DefaultDim)
	if err != nil {
		t.Fatalf("既有 LayerWeights 报错: %v", err)
	}
	if a.Rows != DefaultDim || a.Cols != DefaultDim {
		t.Fatalf("LayerWeights 形状 = %dx%d, want %dx%d", a.Rows, a.Cols, DefaultDim, DefaultDim)
	}
	b, err := LayerWeights(1, DefaultDim)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Data, b.Data) {
		t.Fatal("不同 layer 的既有权重竟相同（既有实现被破坏）")
	}
	// 两层派生路径互不冲突：新的 TensorWeights 不得等于旧的 LayerWeights
	n, err := TensorWeights(demoCfg(), route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Data, n.Data) {
		t.Fatal("新的 TensorWeights 与既有 LayerWeights 派生结果撞车（盐值空间重叠）")
	}
	// 旧实现的负参数仍应报错
	if _, err := LayerWeights(0, 0); err == nil {
		t.Fatal("LayerWeights(dim=0) 应报错")
	}
}

// TestNormParamsDeterministic Norm 参数（RMSNorm gamma）的确定性派生。
func TestNormParamsDeterministic(t *testing.T) {
	cfg := demoCfg()
	cases := []route2plan.TensorKey{
		{Block: 0, Tensor: route2plan.TensorLNIn},
		{Block: 0, Tensor: route2plan.TensorLNPost},
		{Block: cfg.Blocks - 1, Tensor: route2plan.TensorLNPost},
		{Block: cfg.Blocks, Tensor: route2plan.TensorLNFinal},
	}
	for _, k := range cases {
		g1, eps1, err := NormParams(cfg, k)
		if err != nil {
			t.Fatalf("NormParams(%s) 报错: %v", k, err)
		}
		if len(g1) != cfg.Dim {
			t.Fatalf("gamma 长度 = %d, want Dim=%d", len(g1), cfg.Dim)
		}
		if eps1 != cfg.NormEps {
			t.Fatalf("eps = %v, want %v", eps1, cfg.NormEps)
		}
		for _, g := range g1 {
			if math.IsNaN(g) || math.IsInf(g, 0) {
				t.Fatalf("gamma 含非法值 %v", g)
			}
			if g <= 0 {
				t.Fatalf("gamma=%v 非正，会把 RMSNorm 输出翻转/塌缩", g)
			}
			if g < 1-gammaSpread || g > 1+gammaSpread {
				t.Fatalf("gamma=%v 越出 [1-%v, 1+%v] 区间", g, gammaSpread, gammaSpread)
			}
		}
		g2, _, err := NormParams(cfg, k)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(g1, g2) {
			t.Fatalf("NormParams(%s) 两次派生不一致", k)
		}
	}
	// 不同 key 必须不同
	a, _, _ := NormParams(cfg, cases[0])
	b, _, _ := NormParams(cfg, cases[1])
	if reflect.DeepEqual(a, b) {
		t.Fatal("ln_in 与 ln_post 派生出相同 gamma")
	}
}

// TestNormParamsRejects 张量类型 / block 越界必须被拒（含 R5 式的 off-by-one 防护）。
func TestNormParamsRejects(t *testing.T) {
	cfg := demoCfg()
	bad := []route2plan.TensorKey{
		{Block: cfg.Blocks, Tensor: route2plan.TensorLNIn},        // per-block 张量用了哨兵块号
		{Block: cfg.Blocks - 1, Tensor: route2plan.TensorLNFinal}, // 收尾张量用了块内块号
		{Block: -1, Tensor: route2plan.TensorLNIn},
		{Block: 9999, Tensor: route2plan.TensorLNPost},
		{Block: 0, Tensor: route2plan.TensorAttnQ}, // 矩阵张量走 NormParams
		{Block: 0, Tensor: "unknown.tensor"},
	}
	for _, k := range bad {
		if _, _, err := NormParams(cfg, k); err == nil {
			t.Errorf("NormParams(%s) 应被拒绝却被接受", k)
		}
	}
	// 非法 cfg
	broken := cfg
	broken.Heads = 3
	if _, _, err := NormParams(broken, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNIn}); err == nil {
		t.Error("非法 cfg 应被拒绝")
	}
}

// TestTensorShapeMissuse 形状查询的负面路径。
func TestTensorShapeMissuse(t *testing.T) {
	cfg := demoCfg()
	if _, _, err := TensorShape(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNIn}); err == nil {
		t.Error("归一化张量不应有矩阵形状")
	}
	if _, _, err := TensorShape(cfg, route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorAttnQ}); err == nil {
		t.Error("block 内张量用了哨兵块号，应被拒绝")
	}
	if _, _, err := TensorShape(cfg, route2plan.TensorKey{Block: cfg.Blocks - 1, Tensor: route2plan.TensorLMHead}); err == nil {
		t.Error("收尾张量用了块内块号，应被拒绝")
	}
	if _, err := TensorWeights(cfg, route2plan.TensorKey{Block: -1, Tensor: route2plan.TensorAttnQ}); err == nil {
		t.Error("负 block 应被拒绝")
	}
	if _, err := TensorWeights(cfg, route2plan.TensorKey{Block: 0, Tensor: "nope"}); err == nil {
		t.Error("未知张量名应被拒绝")
	}
}

// TestModelWeightsInterface ModelWeights 契约（设计 §2.4.5）可被正常实现与调用。
func TestModelWeightsInterface(t *testing.T) {
	var provider ModelWeights
	w, err := NewWeights(demoCfg())
	if err != nil {
		t.Fatal(err)
	}
	provider = w
	if provider.Config().ModelID != route2plan.DemoModelID {
		t.Fatalf("Config().ModelID = %q", provider.Config().ModelID)
	}
	m, err := provider.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	if m.Rows != m.Cols {
		t.Fatalf("attn.q 应为方阵，got %dx%d", m.Rows, m.Cols)
	}
	g, eps, err := provider.Affine(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNIn})
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != provider.Config().Dim {
		t.Fatalf("gamma 长度 = %d, want %d", len(g), provider.Config().Dim)
	}
	if eps != route2plan.DemoNormEps {
		t.Fatalf("eps = %v, want %v", eps, route2plan.DemoNormEps)
	}
	if _, err := NewWeights(route2plan.ModelConfig{}); err == nil {
		t.Fatal("非法 cfg 构造 Weights 应报错")
	}
}

// TestRawWeightsMatchQuantization 原始（未量化）权重与量化结果的整数部分必须同源：
// Data[i][j] == round(raw[i][j] / Scale)（不超过 ±1 的取整差，作为 ref-fp32 基线的钩子契约）。
func TestRawWeightsMatchQuantization(t *testing.T) {
	cfg := demoCfg()
	k := route2plan.TensorKey{Block: 1, Tensor: route2plan.TensorFFNDown}
	raw, err := RawWeights(cfg, k)
	if err != nil {
		t.Fatal(err)
	}
	m, err := TensorWeights(cfg, k)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != m.Rows || len(raw[0]) != m.Cols {
		t.Fatalf("raw 形状 %dx%d != 量化形状 %dx%d", len(raw), len(raw[0]), m.Rows, m.Cols)
	}
	maxAbsRaw := 0.0
	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			wantI := int32(math.Round(raw[i][j] / m.Scale))
			if got := m.Data[i*m.Cols+j]; got != wantI {
				t.Fatalf("Data[%d][%d] = %d, want round(raw/scale) = %d", i, j, got, wantI)
			}
			if a := math.Abs(raw[i][j]); a > maxAbsRaw {
				maxAbsRaw = a
			}
		}
	}
	// Scale 必须等于 maxAbs/127（与内核约定一致）
	if math.Abs(m.Scale-maxAbsRaw/127) > 1e-12 {
		t.Fatalf("Scale = %v, want maxAbs/127 = %v", m.Scale, maxAbsRaw/127)
	}
}

// TestWeightsHaveNegativeAndPositive 派生权重必须覆盖正负两侧，
// 否则 GELU/RMSNorm 的负半分支永远不会被覆盖到（测试会假绿）。
func TestWeightsHaveNegativeAndPositive(t *testing.T) {
	cfg := demoCfg()
	m, err := TensorWeights(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatal(err)
	}
	neg, pos, zero := 0, 0, 0
	for _, v := range m.Data {
		switch {
		case v < 0:
			neg++
		case v > 0:
			pos++
		default:
			zero++
		}
	}
	if neg == 0 || pos == 0 {
		t.Fatalf("量化权重符号分布失衡: neg=%d pos=%d zero=%d", neg, pos, zero)
	}
}

// ---------- 测试辅助 ----------

// maskWith 把一个明文向量变成掩码态：V = ToMaskDomain(x) + r (mod R)。
// 返回 V 与掩码 r 二者：后续 MaskImage(W, r) 需要同一条 r。
func maskWith(t *testing.T, m *maskedinfer.QuantizedMatrix, x []float64) ([]uint64, []uint64, error) {
	t.Helper()
	if len(x) != m.Cols {
		t.Fatalf("输入长度 %d != 列数 %d", len(x), m.Cols)
	}
	r := deterministicMask(m.Cols, 0x5A)
	V, err := m.Remask(m.ToMaskDomain(x), r)
	if err != nil {
		return nil, nil, err
	}
	return V, r, nil
}

// roundTrip 完整脱掩码管线：V → CipherLinear → (MaskImage + Unmask) → Decode → float。
//
// 次序铁律：①整数域先脱掩码、后缩放；②MaskImage 绝不含 bias；
// 二者任一写错，本测试就会以 1e-1 量级的偏差炸掉（见设计 §8.1 档 A 的动机）。
func roundTrip(m *maskedinfer.QuantizedMatrix, V, r []uint64) ([]float64, error) {
	y, err := m.CipherLinear([][]uint64{V})
	if err != nil {
		return nil, err
	}
	img, err := m.MaskImage(r)
	if err != nil {
		return nil, err
	}
	u, err := m.Unmask(y[0], img)
	if err != nil {
		return nil, err
	}
	return m.Decode(u), nil
}

// deterministicVec 生成确定性浮点向量（值域 [-1, 1)）。
func deterministicVec(n int, seed int64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = synthetic(i, seed)
	}
	return out
}

// deterministicMask 生成确定性掩码（Mod64 域内的伪随机 uint64）。
func deterministicMask(n int, seed int64) []uint64 {
	out := make([]uint64, n)
	state := seed
	for i := range out {
		// xorshift64*：无第三方依赖、无 math/rand 全局状态污染，跨进程逐位一致
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		out[i] = uint64(state * 0x2545F4914F6CDD1D)
	}
	return out
}

// synthetic 生成 [-1,1) 区间内的确定性浮点（含候选负值/零值）。
func synthetic(i int, seed int64) float64 {
	v := float64(int64(i)*2654435761 ^ seed)
	v = math.Mod(v, 1000) / 500 // [-1, 1)
	// 掺入零值与较小量级，覆盖定点化/SignedValue 的边界
	switch (i + int(seed)) % 7 {
	case 0:
		return 0
	case 3:
		return v * 0.01
	}
	return v
}

// assertClose 逐元素混合容差断言。
func assertClose(t *testing.T, name string, got, want []float64, atol float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: 长度 got=%d want=%d", name, len(got), len(want))
	}
	worst := 0.0
	worstIdx := -1
	for i := range want {
		d := math.Abs(got[i] - want[i])
		if d > worst {
			worst = d
			worstIdx = i
		}
	}
	if worst > atol {
		t.Fatalf("%s: 最大偏差 %.3e 超过阈值 %.3e（位置 %d: got=%.9f want=%.9f）",
			name, worst, atol, worstIdx, got[worstIdx], want[worstIdx])
	}
	t.Logf("%s: 最大偏差 %.3e <= atol %.3e", name, worst, atol)
}
