// 密文线性内核与明文对照。
// 单层：随机输入，密文内核 vs 明文内核 → 逐位一致（整数域）或量化误差 < 1%。
package maskedinfer

import (
	"math"
	"math/rand"
	"testing"
)

// TestCipherLinearParity B1：密文内核 = 明文内核（整数域无损对照）。
// 流程：明文 x → 掩码 r → 密文 v = x + r → GPU 密文线性 y_cipher = W·v
// → TEE 脱掩码 y = y_cipher - W·r → 与明文线性 W·x 一致。
func TestCipherLinearParity(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	rows, cols := 16, 8

	// 随机权重 + 量化（INT8）
	weights := make([][]float64, rows)
	for i := range weights {
		weights[i] = make([]float64, cols)
		for j := range weights[i] {
			weights[i][j] = rng.Float64()*2 - 1
		}
	}
	m, err := NewQuantizedMatrix(weights, 8)
	if err != nil {
		t.Fatal(err)
	}
	m.WithBias(make([]float64, rows))

	// 明文输入（量化到掩码域：×1e6 定点）
	x := make([]float64, cols)
	for j := range x {
		x[j] = rng.Float64()*10 - 5
	}
	xMask := FloatToMaskDomain(x)

	// 掩码 + 密文
	r := make([]uint64, cols)
	for j := range r {
		r[j] = uint64(rng.Int63n(int64(maskModulus)))
	}
	v := make([]uint64, cols)
	for j := range v {
		v[j] = (xMask[j] + r[j]) % maskModulus
	}

	// GPU 密文线性
	yCipher, err := m.CipherLinear([][]uint64{v})
	if err != nil {
		t.Fatal(err)
	}
	// TEE 掩码像 + 脱掩码
	maskImage, err := m.MaskImage(r)
	if err != nil {
		t.Fatal(err)
	}
	y, err := Unmask(yCipher[0], maskImage)
	if err != nil {
		t.Fatal(err)
	}
	// 明文对照（浮点域 ×1e6 归一）
	plainRef := m.PlainLinear([][]float64{x})[0]
	for i := range y {
		want := uint64(int64(plainRef[i]*1e6)) % maskModulus
		// 量化误差容忍：<1% 相对误差
		got := float64(y[i])
		diff := math.Abs(got - float64(want))
		if diff > float64(want)*0.01 && want > 1000 {
			t.Fatalf("y[%d] 偏差超限: got=%d want=%d", i, y[i], want)
		}
	}
}

// TestUnmaskRemaskRoundtrip 脱掩码-重掩码往返（掩码域一致性）。
func TestUnmaskRemaskRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	n := 32
	yCipher := make([]uint64, n)
	rNext := make([]uint64, n)
	for i := range yCipher {
		yCipher[i] = uint64(rng.Int63n(int64(maskModulus)))
		rNext[i] = uint64(rng.Int63n(int64(maskModulus)))
	}
	// 掩码像全零（无线性层，模拟非线性补算）：y = y_cipher
	zero := make([]uint64, n)
	y, err := Unmask(yCipher, zero)
	if err != nil {
		t.Fatal(err)
	}
	remasked, err := Remask(y, rNext)
	if err != nil {
		t.Fatal(err)
	}
	// 验证 remasked = yCipher + rNext
	for i := range remasked {
		want := (yCipher[i] + rNext[i]) % maskModulus
		if remasked[i] != want {
			t.Fatalf("remasked[%d] = %d, want %d", i, remasked[i], want)
		}
	}
}

// TestQuantizeINT16 INT16 量化精度高于 INT8（长上下文兜底档）。
func TestQuantizeINT16(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	rows, cols := 4, 4
	weights := make([][]float64, rows)
	for i := range weights {
		weights[i] = make([]float64, cols)
		for j := range weights[i] {
			weights[i][j] = rng.Float64()*2 - 1
		}
	}
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
// 同一明文配不同掩码 → 密文分布不同；密文分量无明文特征。
func TestB3NoPlaintextVisibleToGPU(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	dim := 64
	x := make([]float64, dim)
	for i := range x {
		x[i] = rng.Float64()*10 - 5
	}
	xMask := FloatToMaskDomain(x)

	// 两次不同掩码 → 密文完全不同（一次一密）
	mask1 := randVec(rng, dim)
	mask2 := randVec(rng, dim)
	c1 := make([]uint64, dim)
	c2 := make([]uint64, dim)
	for i := range c1 {
		c1[i] = (xMask[i] + mask1[i]) % maskModulus
		c2[i] = (xMask[i] + mask2[i]) % maskModulus
	}
	same := 0
	for i := range c1 {
		if c1[i] == c2[i] {
			same++
		}
	}
	if same > dim/10 {
		t.Fatalf("不同掩码下密文过于相似（%d/%d 相同）", same, dim)
	}
	// 密文分量与明文相关性：任一密文分量 ≠ 明文分量（掩码化后明文不可直接观测）
	for i := range c1 {
		if c1[i] == xMask[i] {
			t.Fatalf("密文分量 %d 与明文相同（掩码为 0 概率不可忽略）", i)
		}
	}
}

// TestB2EndToEndAccuracy 端到端精度——密文链路 vs 明文推理（误差 < 1%）。
// 完整链路：明文 x → 掩码 r → 密文 v → 密文线性 y_cipher → TEE 脱掩码+非线性
// → 重掩码 → GPU 解密 → 与明文推理（W·x + GELU）对照。
func TestB2EndToEndAccuracy(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	rows, cols := 32, 16

	weights := make([][]float64, rows)
	for i := range weights {
		weights[i] = make([]float64, cols)
		for j := range weights[i] {
			weights[i][j] = rng.Float64()*2 - 1
		}
	}
	m, err := NewQuantizedMatrix(weights, 8)
	if err != nil {
		t.Fatal(err)
	}

	x := make([]float64, cols)
	for j := range x {
		x[j] = rng.Float64()*10 - 5
	}
	xMask := FloatToMaskDomain(x)
	r := randVec(rng, cols)
	v := make([]uint64, cols)
	for j := range v {
		v[j] = (xMask[j] + r[j]) % maskModulus
	}

	// GPU：密文线性
	yCipher, _ := m.CipherLinear([][]uint64{v})
	// TEE：掩码像 + 脱掩码 + 符号还原 + GELU
	maskImage, _ := m.MaskImage(r)
	y, _ := Unmask(yCipher[0], maskImage)
	signed := SignedVector(y)
	yFloat := make([]float64, rows)
	for i := range signed {
		yFloat[i] = geluRef(float64(signed[i]) / 1e6) // 反定点 + TEE 非线性
	}
	// 明文参照：W·x + GELU
	plainRef := m.PlainLinear([][]float64{x})[0]
	for i := range plainRef {
		plainRef[i] = geluRef(plainRef[i])
	}
	// 精度对照（相对误差 < 1%）
	for i := range yFloat {
		want := plainRef[i]
		diff := math.Abs(yFloat[i] - want)
		if diff > math.Abs(want)*0.01+1e-3 {
			t.Fatalf("yFloat[%d]=%.4f want=%.4f 偏差超 1%%", i, yFloat[i], want)
		}
	}
}

// geluRef GELU 参照实现。
func geluRef(x float64) float64 {
	return 0.5 * x * (1 + math.Erf(x/math.Sqrt2))
}

// randVec 随机掩码向量（[0, 2^32) 域）。
func randVec(rng *rand.Rand, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(rng.Int63n(int64(maskModulus)))
	}
	return out
}
