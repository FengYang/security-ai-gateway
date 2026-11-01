package maskedinfer

// 步骤③ 算法验证：原生 128 位内核 CipherLinearInt128 须与 math/big 神谕 CipherLinear
// 逐位一致。GPU 内核（cipher_linear_int128.cu）移植同一算法，故本对拍等价于证明 GPU
// 内核算法正确（执行后端可替换，mod 2^64 语义不变）。

import (
	"math/rand"
	"testing"
)

func TestCipherLinearInt128MatchesBig(t *testing.T) {
	rng := rand.New(rand.NewSource(20261101))
	const trials = 200
	for trial := 0; trial < trials; trial++ {
		rows := 1 + rng.Intn(24)
		cols := 1 + rng.Intn(64)
		// 随机 int8 权重（含负值）
		w := make([][]float64, rows)
		for i := range w {
			w[i] = make([]float64, cols)
			for j := range w[i] {
				w[i][j] = (float64(rng.Intn(255)-127) / 127.0) * (0.2 + rng.Float64())
			}
		}
		m, err := NewQuantizedMatrixMod(w, 8, Mod64)
		if err != nil {
			t.Fatalf("trial %d NewQuantizedMatrixMod: %v", trial, err)
		}
		// 随机 int32 偏置（含负值）
		bias := make([]float64, rows)
		for i := range bias {
			bias[i] = float64(rng.Intn(4096) - 2048)
		}
		m.WithBias(bias)

		// 随机掩码域向量 V（uint64，mod 2^64；模拟 xMask+r）
		V := make([]uint64, cols)
		for j := range V {
			V[j] = rng.Uint64()
		}

		bigOut, err := m.CipherLinear([][]uint64{V})
		if err != nil {
			t.Fatalf("trial %d CipherLinear: %v", trial, err)
		}
		i128Out, err := m.CipherLinearInt128([][]uint64{V})
		if err != nil {
			t.Fatalf("trial %d CipherLinearInt128: %v", trial, err)
		}
		if len(bigOut[0]) != len(i128Out[0]) {
			t.Fatalf("trial %d: 长度不一致", trial)
		}
		for i := range bigOut[0] {
			if bigOut[0][i] != i128Out[0][i] {
				t.Fatalf("trial %d dim %d: math/big=%d int128=%d 不一致", trial, i, bigOut[0][i], i128Out[0][i])
			}
		}
	}
	t.Logf("CipherLinearInt128 与 math/big 神谕逐位一致（%d 组随机 int8 权重+随机掩码向量+随机偏置）", trials)
}

// 真实形态 V：ToMaskDomain(x)+r（与 recompute.go 客户端契约一致），确认端到端语义不漂移。
func TestCipherLinearInt128RealMaskVector(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for trial := 0; trial < 50; trial++ {
		dims := []int{8, 16, 8, 4}
		mats := make([]*QuantizedMatrix, len(dims)-1)
		var V []uint64
		x0 := make([]float64, dims[0])
		for i := range x0 {
			x0[i] = (float64(i) - float64(dims[0])/2) * 0.13
		}
		for ℓ := 0; ℓ < len(dims)-1; ℓ++ {
			w := make([][]float64, dims[ℓ+1])
			for i := range w {
				w[i] = make([]float64, dims[ℓ])
				for j := range w[i] {
					w[i][j] = (float64(rng.Intn(255)-127) / 127.0) * (0.2 + rng.Float64())
				}
			}
			m, err := NewQuantizedMatrixMod(w, 8, Mod64)
			if err != nil {
				t.Fatalf("ℓ=%d NewQuantizedMatrixMod: %v", ℓ, err)
			}
			mats[ℓ] = m
		}
		// layer 0 客户端掩码 V = ToMaskDomain(x0) + r0
		m0 := mats[0]
		xMask := m0.ToMaskDomain(x0)
		r0 := make([]uint64, len(xMask))
		for i := range r0 {
			r0[i] = rng.Uint64()
		}
		V = make([]uint64, len(xMask))
		for i := range V {
			V[i] = xMask[i] + r0[i]
		}

		// 仅校验 layer0；int128 与 math/big 须逐位一致（覆盖真实 V 形态）
		bigOut, err := m0.CipherLinear([][]uint64{V})
		if err != nil {
			t.Fatalf("trial %d CipherLinear: %v", trial, err)
		}
		i128Out, err := m0.CipherLinearInt128([][]uint64{V})
		if err != nil {
			t.Fatalf("trial %d CipherLinearInt128: %v", trial, err)
		}
		for i := range bigOut[0] {
			if bigOut[0][i] != i128Out[0][i] {
				t.Fatalf("trial %d dim %d: math/big=%d int128=%d 不一致（真实 V 形态）", trial, i, bigOut[0][i], i128Out[0][i])
			}
		}
	}
	t.Logf("CipherLinearInt128 与 math/big 在真实掩码向量 V=ToMaskDomain(x)+r 形态下逐位一致（50 组）")
}
