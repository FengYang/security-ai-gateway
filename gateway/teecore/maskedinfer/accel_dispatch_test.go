package maskedinfer

// 步骤③ 多后端派发验证：
//   - 未配置后端（env TEST_ACCEL_LIB 为空）时，AccelLinearInt128 必须优雅返回
//     ErrAccelUnavailable（由调用方回退 CPU 路径），不得 panic / 不得误报成功；
//   - 当 env TEST_ACCEL_LIB 指向一个实现了 accel_cipher_linear_int128 的 .so 时，
//     AccelLinearInt128 输出须与 CPU 基准 CipherLinearInt128 逐位一致，
//     从而端到端验证"统一 ABI + 后端无关派发 + 任一硬件后端"的管线。

import (
	"math/rand"
	"os"
	"testing"
)

func TestAccelDispatch(t *testing.T) {
	lib := os.Getenv("TEST_ACCEL_LIB")
	if lib == "" {
		// —— 回退路径：未配置任何加速后端 ——
		// 抹除可能由外层环境带入的 ACCEL_BACKEND_LIB，并重置惰性加载 Once，
		// 确保本分支不受全局环境 / 其它测试副作用影响（测试确定性，QA-H1）。
		os.Unsetenv("ACCEL_BACKEND_LIB")
		resetAccelStateForTest()
		w := [][]float64{{0.1, -0.2, 0.3}, {-0.4, 0.5, -0.6}}
		m, err := NewQuantizedMatrixMod(w, 8, Mod64)
		if err != nil {
			t.Fatalf("NewQuantizedMatrixMod: %v", err)
		}
		m.WithBias([]float64{0.01, -0.02})
		_, aerr := m.AccelLinearInt128([][]uint64{{1, 2, 3}})
		if aerr == nil {
			t.Fatal("期望 ErrAccelUnavailable，但 AccelLinearInt128 返回 nil 错误")
		}
		t.Logf("无后端时优雅回退 ErrAccelUnavailable：%v", aerr)
		return
	}

	// —— 真实后端路径：加载 .so 并与 CPU 基准逐位对拍 ——
	if err := InitAccelBackend(lib); err != nil {
		t.Fatalf("InitAccelBackend(%s) 失败: %v", lib, err)
	}
	rng := rand.New(rand.NewSource(20261101))
	const trials = 50
	for trial := 0; trial < trials; trial++ {
		rows := 1 + rng.Intn(16)
		cols := 1 + rng.Intn(48)
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
		bias := make([]float64, rows)
		for i := range bias {
			bias[i] = float64(rng.Intn(4096) - 2048)
		}
		m.WithBias(bias)

		batch := 1 + rng.Intn(4)
		V := make([][]uint64, batch)
		for b := range V {
			V[b] = make([]uint64, cols)
			for j := range V[b] {
				V[b][j] = rng.Uint64()
			}
		}

		cpuOut, err := m.CipherLinearInt128(V)
		if err != nil {
			t.Fatalf("trial %d CipherLinearInt128: %v", trial, err)
		}
		accelOut, err := m.AccelLinearInt128(V)
		if err != nil {
			t.Fatalf("trial %d AccelLinearInt128: %v", trial, err)
		}
		for b := 0; b < batch; b++ {
			for i := 0; i < rows; i++ {
				if cpuOut[b][i] != accelOut[b][i] {
					t.Fatalf("trial %d b=%d i=%d: CPU=%d 后端=%d 不一致", trial, b, i, cpuOut[b][i], accelOut[b][i])
				}
			}
		}
	}
	t.Logf("AccelLinearInt128(后端=%s) 与 CipherLinearInt128 逐位一致（%d 组随机 int8 权重+随机掩码向量+随机偏置）", lib, trials)
}
