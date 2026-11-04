// masked_linear_fastpath_test.go - linearMod 快速路径 vs math/big 精确实现的逐位对拍
//
// 背景：MaskImage/CipherLinear 原实现对每个内层元素新建 big.Int 做乘法，真实
// Qwen3-0.6B 一次 6-token prefill 的掩码像计算量约 2.6G 次乘加，实测 10 分钟仍未跑完
// （T5 端到端门控直接被拖死）。改为 uint64 回绕的等价实现后，必须证明"逐位相同"，
// 否则就是"提速换正确性"——本项目最不能接受的那类变化。
package maskedinfer

import (
	"math/big"
	"math/rand"
	"testing"
)

// oracleLinear 用 math/big 精确计算 (W·v [+b]) mod R（不依赖被测实现）。
func oracleLinear(m *QuantizedMatrix, v []uint64, addBias bool) []uint64 {
	R := m.bigR()
	acc := big.NewInt(0)
	term := big.NewInt(0)
	out := make([]uint64, m.Rows)
	for i := 0; i < m.Rows; i++ {
		acc.SetInt64(0)
		for j := 0; j < m.Cols; j++ {
			term.SetInt64(int64(m.Data[i*m.Cols+j]))
			term.Mul(term, new(big.Int).SetUint64(v[j]))
			acc.Add(acc, term)
		}
		if addBias && m.Bias != nil {
			acc.Add(acc, big.NewInt(int64(m.Bias[i])))
		}
		out[i] = m.reduce(acc, R)
	}
	return out
}

// edgeVec 取一批"最容易暴露回绕错误"的边界值。
func edgeVec(cols int, r *rand.Rand) []uint64 {
	edge := []uint64{0, 1, 2, ^uint64(0), ^uint64(0) - 1, 1 << 63, (1 << 63) - 1, 1 << 32, 1<<32 - 1}
	v := make([]uint64, cols)
	for j := range v {
		if j < len(edge) {
			v[j] = edge[j]
		} else {
			v[j] = r.Uint64()
		}
	}
	return v
}

// TestLinearModMatchesBigInt Mod64/Mod32 × 有/无偏置 × 含负权重与边界掩码，逐位对拍。
func TestLinearModMatchesBigInt(t *testing.T) {
	r := rand.New(rand.NewSource(20261104))
	for _, modBits := range []MaskModulusBits{Mod64, Mod32} {
		for _, withBias := range []bool{false, true} {
			rows, cols := 7, 33
			m := &QuantizedMatrix{
				Rows:       rows,
				Cols:       cols,
				Scale:      0.01,
				Data:       make([]int32, rows*cols),
				ModBits:    modBits,
				InputScale: 1 << 20,
			}
			// int8 全范围（含 -128/127），覆盖补码负权重的取模行为
			for i := range m.Data {
				m.Data[i] = int32(r.Intn(256) - 128)
			}
			if withBias {
				m.Bias = make([]int32, rows)
				for i := range m.Bias {
					m.Bias[i] = int32(r.Intn(2001) - 1000)
				}
			}

			v := edgeVec(cols, r)
			gotMask := m.linearMod(v, false)
			wantMask := oracleLinear(m, v, false)
			for i := range wantMask {
				if gotMask[i] != wantMask[i] {
					t.Fatalf("mod=%v bias=%v MaskImage 行 %d: got %d want %d", modBits, withBias, i, gotMask[i], wantMask[i])
				}
			}

			// CipherLinear 与 MaskImage 的差别只有偏置一项
			gotCipher, err := m.CipherLinear([][]uint64{v})
			if err != nil {
				t.Fatal(err)
			}
			wantCipher := oracleLinear(m, v, true)
			for i := range wantCipher {
				if gotCipher[0][i] != wantCipher[i] {
					t.Fatalf("mod=%v bias=%v CipherLinear 行 %d: got %d want %d", modBits, withBias, i, gotCipher[0][i], wantCipher[i])
				}
			}
		}
	}
}

// TestMaskImageRejectsWrongWidth 形状护栏不得因提速而丢失。
func TestMaskImageRejectsWrongWidth(t *testing.T) {
	m := &QuantizedMatrix{Rows: 2, Cols: 3, Data: make([]int32, 6), ModBits: Mod64}
	if _, err := m.MaskImage(make([]uint64, 2)); err == nil {
		t.Fatal("掩码长度与列数不符应报错")
	}
	if _, err := m.CipherLinear([][]uint64{{1, 2}}); err == nil {
		t.Fatal("向量长度与列数不符应报错")
	}
}
