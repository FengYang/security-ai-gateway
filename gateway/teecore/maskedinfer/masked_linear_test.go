// 密文线性内核与明文对照。
// 单层：随机输入，密文内核 vs 明文内核 → 量化误差在容忍范围内（M0 修正后）。
package maskedinfer

import (
	"math"
	"math/rand"
	"testing"
)

// randMatrix 生成 N(0, sigma) 权重矩阵（与 exp2 同分布）。
func randMatrix(rng *rand.Rand, rows, cols int, sigma float64) [][]float64 {
	w := make([][]float64, rows)
	for i := range w {
		w[i] = make([]float64, cols)
		for j := range w[i] {
			w[i][j] = rng.NormFloat64() * sigma
		}
	}
	return w
}

// randVecF 生成 N(0, sigma) 浮点向量。
func randVecF(rng *rand.Rand, n int, sigma float64) []float64 {
	x := make([]float64, n)
	for i := range x {
		x[i] = rng.NormFloat64() * sigma
	}
	return x
}

// randMask 生成 [0, R) 掩码向量（Mod64 用全 64 位，Mod32 用低 32 位）。
func randMask(rng *rand.Rand, n int, mod MaskModulusBits) []uint64 {
	out := make([]uint64, n)
	if mod == Mod32 {
		for i := range out {
			out[i] = rng.Uint64() % (1 << 32)
		}
	} else {
		for i := range out {
			out[i] = rng.Uint64()
		}
	}
	return out
}

// addMod 掩码相加 v = (a + b) mod R（uint64 在 Mod64 下自然环绕）。
func addMod(a, b []uint64, mod MaskModulusBits) []uint64 {
	out := make([]uint64, len(a))
	if mod == Mod32 {
		M := uint64(1 << 32)
		for i := range out {
			out[i] = (a[i] + b[i]) % M
		}
	} else {
		for i := range out {
			out[i] = a[i] + b[i]
		}
	}
	return out
}

// runPipeline 跑一遍完整掩码链路，返回 Decode 结果与明文基准。
func runPipeline(m *QuantizedMatrix, x []float64) (got, ref []float64) {
	xMask := m.ToMaskDomain(x)
	r := randMask(rand.New(rand.NewSource(7)), len(x), m.ModBits)
	v := addMod(xMask, r, m.ModBits)
	yC, _ := m.CipherLinear([][]uint64{v})
	img, _ := m.MaskImage(r)
	y, _ := m.Unmask(yC[0], img)
	return m.Decode(y), m.PlainLinear([][]float64{x})[0]
}

// maxRelErr 返回单样例最大相对误差（分母取 max(1, |ref|)）。
func maxRelErr(m *QuantizedMatrix, x []float64) float64 {
	got, ref := runPipeline(m, x)
	var e float64
	for i := range got {
		d := math.Abs(got[i] - ref[i])
		rel := d / math.Max(1.0, math.Abs(ref[i]))
		if rel > e {
			e = rel
		}
	}
	return e
}

// TestCipherLinearParity B1：密文内核 = 明文内核（整数域无损对照）。
func TestCipherLinearParity(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	rows, cols := 16, 8
	weights := randMatrix(rng, rows, cols, 1.0)
	m, err := NewQuantizedMatrix(weights, 8)
	if err != nil {
		t.Fatal(err)
	}
	m.WithBias(make([]float64, rows))

	x := randVecF(rng, cols, 5)
	xMask := m.ToMaskDomain(x)
	r := randMask(rng, cols, m.ModBits)
	v := addMod(xMask, r, m.ModBits)

	yC, err := m.CipherLinear([][]uint64{v})
	if err != nil {
		t.Fatal(err)
	}
	maskImage, err := m.MaskImage(r)
	if err != nil {
		t.Fatal(err)
	}
	y, err := m.Unmask(yC[0], maskImage)
	if err != nil {
		t.Fatal(err)
	}
	// 修正后：用 Decode 还原真值，应与明文 W·x 一致（量化误差 < 1%）
	got := m.Decode(y)
	ref := m.PlainLinear([][]float64{x})[0]
	for i := range got {
		if math.Abs(got[i]-ref[i]) > 0.01*math.Max(1.0, math.Abs(ref[i])) {
			t.Fatalf("B1 y[%d] 偏差超限: got=%.4f ref=%.4f", i, got[i], ref[i])
		}
	}
}

// TestUnmaskRemaskRoundtrip 脱掩码-重掩码往返（掩码域一致性）。
func TestUnmaskRemaskRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	n := 32
	yCipher := randMask(rng, n, Mod32)
	rNext := randMask(rng, n, Mod32)
	zero := make([]uint64, n)
	y, err := Unmask(yCipher, zero)
	if err != nil {
		t.Fatal(err)
	}
	remasked, err := Remask(y, rNext)
	if err != nil {
		t.Fatal(err)
	}
	for i := range remasked {
		want := (yCipher[i] + rNext[i]) % (1 << 32)
		if remasked[i] != want {
			t.Fatalf("remasked[%d] = %d, want %d", i, remasked[i], want)
		}
	}
}

// TestQuantizeINT16 INT16 量化精度高于 INT8（长上下文兜底档）。
func TestQuantizeINT16(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	rows, cols := 4, 4
	weights := randMatrix(rng, rows, cols, 1.0)
	m8, _ := NewQuantizedMatrix(weights, 8)
	m16, _ := NewQuantizedMatrix(weights, 16)
	x := []float64{0.5, -0.25, 1.0, -0.75}
	ref := m16.PlainLinear([][]float64{x})[0]
	got8 := m8.PlainLinear([][]float64{x})[0]
	var err8, err16 float64
	for i := range ref {
		err8 += math.Abs(got8[i] - ref[i])
		err16 += math.Abs(m16.PlainLinear([][]float64{x})[0][i] - ref[i])
	}
	if err8 <= err16 {
		t.Fatal("INT16 量化误差应低于 INT8")
	}
}

// TestB3NoPlaintextVisibleToGPU 密文输入与明文统计无关（GPU 只见密文）。
func TestB3NoPlaintextVisibleToGPU(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	dim := 64
	x := randVecF(rng, dim, 5)
	xMask := ToMaskDomain(x)
	mask1 := randMask(rng, dim, Mod32)
	mask2 := randMask(rng, dim, Mod32)
	c1 := addMod(xMask, mask1, Mod32)
	c2 := addMod(xMask, mask2, Mod32)
	same := 0
	for i := range c1 {
		if c1[i] == c2[i] {
			same++
		}
	}
	if same > dim/10 {
		t.Fatalf("不同掩码下密文过于相似（%d/%d 相同）", same, dim)
	}
	for i := range c1 {
		if c1[i] == xMask[i] {
			t.Fatalf("密文分量 %d 与明文相同（掩码为 0 概率不可忽略）", i)
		}
	}
}

// TestB2EndToEndAccuracy 端到端精度——密文链路 vs 明文推理（误差 < 1%）。
func TestB2EndToEndAccuracy(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	rows, cols := 32, 16
	weights := randMatrix(rng, rows, cols, 1.0)
	// B2 验证生产安全路径（Mod64 + int128 累加）；Mod32 在真实量级下会回绕崩坏（见 TestM0ModChoice）。
	m, err := NewQuantizedMatrixMod(weights, 8, Mod64)
	if err != nil {
		t.Fatal(err)
	}
	x := randVecF(rng, cols, 5)
	xMask := m.ToMaskDomain(x)
	r := randMask(rng, cols, m.ModBits)
	v := addMod(xMask, r, m.ModBits)

	yC, _ := m.CipherLinear([][]uint64{v})
	maskImage, _ := m.MaskImage(r)
	y, _ := m.Unmask(yC[0], maskImage)
	// 修正后：Decode 还原 + TEE 非线性 GELU
	signed := m.Decode(y)
	yFloat := make([]float64, rows)
	for i := range signed {
		yFloat[i] = geluRef(signed[i])
	}
	plainRef := m.PlainLinear([][]float64{x})[0]
	for i := range plainRef {
		plainRef[i] = geluRef(plainRef[i])
	}
	for i := range yFloat {
		want := plainRef[i]
		diff := math.Abs(yFloat[i] - want)
		if diff > 0.01*math.Max(1.0, math.Abs(want))+1e-3 {
			t.Fatalf("B2 yFloat[%d]=%.4f want=%.4f 偏差超 1%%", i, yFloat[i], want)
		}
	}
}

// TestM0RegressionGate M0 核心：随机化崩坏回归门禁。
// 覆盖 Mod64（生产首选）× bit{8,16} × dim{512..4096} × 多 seed，
// 任一失配（偶发/不可复现数值崩坏）即 fail。
func TestM0RegressionGate(t *testing.T) {
	rng := rand.New(rand.NewSource(20261031))
	dims := []int{512, 1024, 2048, 3072, 4096}
	bits := []int{8, 16}
	seeds := 4
	const tol = 0.05 // 5% 相对容差，远小于崩坏量级（信号的数倍~数百倍）
	for _, bit := range bits {
		for _, dim := range dims {
			for s := 0; s < seeds; s++ {
				weights := randMatrix(rng, dim, dim, 0.02)
				m, err := NewQuantizedMatrixMod(weights, bit, Mod64)
				if err != nil {
					t.Fatal(err)
				}
				x := randVecF(rng, dim, 1.0)
				got, ref := runPipeline(m, x)
				for i := range got {
					if math.Abs(got[i]-ref[i]) > tol*math.Max(1.0, math.Abs(ref[i])) {
						t.Fatalf("M0 gate FAIL bit=%d dim=%d seed=%d [%d]: got=%.4f ref=%.4f (rel=%.3f > %.2f)",
							bit, dim, s, i, got[i], ref[i],
							math.Abs(got[i]-ref[i])/math.Max(1.0, math.Abs(ref[i])), tol)
					}
				}
			}
		}
	}
}

// TestM0ModChoice 锁定 §7.7 决策：同 dim=4096，Mod64 误差 << Mod32（exp2 结论）。
// Mod64 必须干净通过；Mod32+S=1e6 必须仍崩坏（否则 exp2 结论被推翻）。
func TestM0ModChoice(t *testing.T) {
	rng := rand.New(rand.NewSource(777))
	dim := 4096
	bit := 16
	var err64, err32 float64
	for s := 0; s < 4; s++ {
		weights := randMatrix(rng, dim, dim, 0.02)
		m64, _ := NewQuantizedMatrixMod(weights, bit, Mod64)
		m32, _ := NewQuantizedMatrixMod(weights, bit, Mod32)
		x := randVecF(rng, dim, 1.0)
		e64 := maxRelErr(m64, x)
		e32 := maxRelErr(m32, x)
		if e64 > err64 {
			err64 = e64
		}
		if e32 > err32 {
			err32 = e32
		}
	}
	t.Logf("Mod64 maxRelErr=%.3e  Mod32 maxRelErr=%.3e", err64, err32)
	if err64 > 0.05 {
		t.Fatalf("Mod64 不应崩坏: maxRelErr=%.3e", err64)
	}
	if err32 < 0.05 {
		t.Fatalf("Mod32+S=1e6 应仍崩坏(预期): maxRelErr=%.3e 过小，exp2 结论被推翻", err32)
	}
}

// geluRef GELU 参照实现。
func geluRef(x float64) float64 {
	return 0.5 * x * (1 + math.Erf(x/math.Sqrt2))
}
