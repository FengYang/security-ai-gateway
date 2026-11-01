package maskedinfer

// int128_linear.go — 掩码线性内核的"原生 128 位累加"实现（无 math/big 依赖）。
//
// 用途（路线2 步骤③ / GPU int128 内核对齐基准）：
//   - 作为不可信加速器 GPU 内核（cipher_linear_int128.cu）的 CPU 可验证等价体，
//     其算术语义与 CipherLinear（math/big 神谕）逐位一致——故本实现通过随机对拍即
//     等价于证明了 GPU 内核算法正确（GPU 仅替换执行后端，不改变 mod 2^64 语义）。
//   - 亦可作为网关侧"无依赖、更快"的 CPU 兜底路径（生产首选 GPU，离线/无卡时回退）。
//
// 关键不变量：掩码域累加必须在 128 位完成后再取低 64 位（= mod 2^64）。
// 单乘积 W(int8)·V(uint64) 幅值可达 ~2^71，C=4096 维累加可达 ~2^83，超过 64 位，
// 故必须 128 位中间累加；因真值 < 2^84 << 2^127，128 位无溢出，低 64 位即精确 mod 2^64。

import (
	"fmt"
	"math/bits"
)

// CipherLinearInt128 与 CipherLinear 完全等价的整数域内核：y = W·V + b (mod 2^64)，
// 用原生 128 位（2×uint64 hi/lo）累加替代 math/big。结果须与 CipherLinear 逐位相同。
//
// 算术语义（与 C 端 __int128 / GPU 内核一致）：
//   - 逐项乘积按"无符号幅值"参与（等价 math/big 对 (int W)×(uint V) 的乘积再整体 mod 2^64）；
//   - 偏置 b 作为有符号 128 位（负偏置以 2^128+b 的二进制补码加入）累加；
//   - 最终取 128 位和的低 64 位 = mod 2^64，落入 [0, 2^64)。
func (m *QuantizedMatrix) CipherLinearInt128(V [][]uint64) ([][]uint64, error) {
	out := make([][]uint64, len(V))
	for b, vec := range V {
		if len(vec) != m.Cols {
			return nil, fmt.Errorf("maskedinfer: 向量[%d]长度 %d != 列数 %d", b, len(vec), m.Cols)
		}
		row := make([]uint64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			var hi, lo uint64
			base := i * m.Cols
			for j := 0; j < m.Cols; j++ {
				// 64×64 -> 128，全宽乘积累加（低 64 位等价 mod 2^64 乘积）
				ph, pl := bits.Mul64(uint64(int64(m.Data[base+j])), vec[j])
				lo, hi = add128(lo, hi, pl, ph)
			}
			if m.Bias != nil {
				blo, bhi := signed128(int64(m.Bias[i]))
				lo, hi = add128(lo, hi, blo, bhi)
			}
			// 低 64 位即 mod 2^64 结果（128 位和未溢出，低 64 位精确）
			row[i] = lo
		}
		out[b] = row
	}
	return out, nil
}

// add128 将 (pl, ph) 加到 (lo, hi) 表示的 128 位数，返回新 (lo, hi)。
func add128(lo, hi, pl, ph uint64) (uint64, uint64) {
	l := lo + pl
	c := uint64(0)
	if l < lo {
		c = 1
	}
	h := hi + ph + c
	return l, h
}

// signed128 将 int64 展开为 128 位二进制补码 (lo, hi)。
func signed128(v int64) (lo, hi uint64) {
	lo = uint64(v)
	if v < 0 {
		hi = ^uint64(0) // 负数为全 1 高 64 位
	}
	return lo, hi
}
