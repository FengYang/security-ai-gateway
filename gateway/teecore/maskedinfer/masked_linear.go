// Package maskedinfer 路线 2 的密文线性内核和掩码像计算
package maskedinfer

import (
	"errors"
	"fmt"
	"math"
	"math/big"
)

// MaskModulusBits 选择掩码模 R 的位宽。
// 路线 2 技术方案 §7.7 定案：生产首选 2^64（int128 累加）+ 输入定点 S=1e6；
// 2^32 在 S=1e6 下 headroom 不足（exp2 实测全部崩坏），仅作无 int128 加速器的兜底（须降 S）。
type MaskModulusBits int

const (
	Mod32 MaskModulusBits = 32
	Mod64 MaskModulusBits = 64
)

// DefaultModulusBits 默认 2^32，以保持与既有掩码生成基础设施
// （maskVector / newLayerStream 走 uint64 2^32）兼容，服务侧零改动。
// 生产路径请用 NewQuantizedMatrixMod(..., Mod64) 显式启用 2^64 + int128 累加，
// 并在服务侧把掩码流/掩码生成升级到 2^64（见 §7.7 与 M1 接线任务）。
const DefaultModulusBits = Mod32

// InputScale 输入定点缩放 S（与 ToMaskDomain 一致）。默认 1e6。
const InputScale = 1e6

// QuantizedMatrix 量化权重矩阵，行优先。
type QuantizedMatrix struct {
	Rows       int
	Cols       int
	Scale      float64
	Data       []int32
	Bias       []int32
	ModBits    MaskModulusBits
	InputScale float64
}

// NewQuantizedMatrix 默认 2^32 模（与既有服务兼容）。
func NewQuantizedMatrix(weights [][]float64, bitWidth int) (*QuantizedMatrix, error) {
	return newQuantizedMatrix(weights, bitWidth, DefaultModulusBits)
}

// NewQuantizedMatrixMod 显式指定掩码模位宽；生产路径用 Mod64（int128 累加）。
func NewQuantizedMatrixMod(weights [][]float64, bitWidth int, modBits MaskModulusBits) (*QuantizedMatrix, error) {
	return newQuantizedMatrix(weights, bitWidth, modBits)
}

func newQuantizedMatrix(weights [][]float64, bitWidth int, modBits MaskModulusBits) (*QuantizedMatrix, error) {
	rows := len(weights)
	if rows == 0 {
		return nil, errors.New("maskedinfer: 空权重")
	}
	cols := len(weights[0])
	if cols == 0 {
		return nil, errors.New("maskedinfer: 空权重列")
	}
	maxW := 0.0
	for _, row := range weights {
		if len(row) != cols {
			return nil, errors.New("maskedinfer: 权重矩阵非矩形")
		}
		for _, v := range row {
			if absF(v) > maxW {
				maxW = absF(v)
			}
		}
	}
	if maxW == 0 {
		return nil, errors.New("maskedinfer: 权重全零")
	}
	maxQ := float64((int64(1) << (bitWidth - 1)) - 1) // INT8: 127, INT16: 32767
	scale := maxW / maxQ
	m := &QuantizedMatrix{
		Rows:       rows,
		Cols:       cols,
		Scale:      scale,
		Data:       make([]int32, rows*cols),
		ModBits:    modBits,
		InputScale: InputScale,
	}
	for i, row := range weights {
		for j, v := range row {
			m.Data[i*cols+j] = int32(math.Round(v / scale))
		}
	}
	return m, nil
}

// WithBias 附加量化 bias。
func (m *QuantizedMatrix) WithBias(bias []float64) *QuantizedMatrix {
	m.Bias = make([]int32, len(bias))
	for i, b := range bias {
		m.Bias[i] = int32(math.Round(b / m.Scale))
	}
	return m
}

// bigR 返回 2^ModBits 的 *big.Int。
func (m *QuantizedMatrix) bigR() *big.Int {
	r := big.NewInt(1)
	if m.ModBits == Mod32 {
		r.Lsh(r, 32)
	} else {
		r.Lsh(r, 64)
	}
	return r
}

// reduce 整数域取模（处理负数），返回 [0, R) 的 uint64。
func (m *QuantizedMatrix) reduce(a *big.Int, R *big.Int) uint64 {
	a.Mod(a, R)
	if a.Sign() < 0 {
		a.Add(a, R)
	}
	return a.Uint64()
}

// MaskImage 计算掩码像 W·r（整数域，不先乘 scale），r 是掩码向量。
func (m *QuantizedMatrix) MaskImage(r []uint64) ([]uint64, error) {
	if len(r) != m.Cols {
		return nil, fmt.Errorf("maskedinfer: 掩码长度 %d != 权重列数 %d", len(r), m.Cols)
	}
	R := m.bigR()
	acc := big.NewInt(0)
	term := big.NewInt(0)
	out := make([]uint64, m.Rows)
	for i := 0; i < m.Rows; i++ {
		acc.SetInt64(0)
		for j := 0; j < m.Cols; j++ {
			term.SetInt64(int64(m.Data[i*m.Cols+j]))
			term.Mul(term, big.NewInt(0).SetUint64(r[j]))
			acc.Add(acc, term)
		}
		if m.Bias != nil {
			acc.Add(acc, big.NewInt(int64(m.Bias[i])))
		}
		out[i] = m.reduce(acc, R)
	}
	return out, nil
}

// CipherLinear 密文线性内核：y = W_q·V + b_q (mod R)，整数域（不先乘 scale）。
// 修正（路线 2 技术方案 §7.1/§7.7）：先整数域脱掩码、后缩放；
// 累加器在 Mod64 下需 int128，此处用 math/big 精确模拟，生产 GPU 内核用 Triton/CUTLASS 的 __int128。
func (m *QuantizedMatrix) CipherLinear(V [][]uint64) ([][]uint64, error) {
	out := make([][]uint64, len(V))
	for b, vec := range V {
		if len(vec) != m.Cols {
			return nil, fmt.Errorf("maskedinfer: 向量[%d]长度 %d != 列数 %d", b, len(vec), m.Cols)
		}
		R := m.bigR()
		acc := big.NewInt(0)
		term := big.NewInt(0)
		row := make([]uint64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			acc.SetInt64(0)
			for j := 0; j < m.Cols; j++ {
				term.SetInt64(int64(m.Data[i*m.Cols+j]))
				term.Mul(term, big.NewInt(0).SetUint64(vec[j]))
				acc.Add(acc, term)
			}
			if m.Bias != nil {
				acc.Add(acc, big.NewInt(int64(m.Bias[i])))
			}
			row[i] = m.reduce(acc, R)
		}
		out[b] = row
	}
	return out, nil
}

// PlainLinear 明文对照，用于验收基准（浮点，无掩码）。
func (m *QuantizedMatrix) PlainLinear(x [][]float64) [][]float64 {
	out := make([][]float64, len(x))
	for b, vec := range x {
		row := make([]float64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			var acc float64
			for j := 0; j < m.Cols; j++ {
				acc += float64(m.Data[i*m.Cols+j]) * m.Scale * vec[j]
			}
			if m.Bias != nil {
				acc += float64(m.Bias[i]) * m.Scale
			}
			row[i] = acc
		}
		out[b] = row
	}
	return out
}

// Unmask 脱掩码：y = y_cipher - mask_image (mod R)。整数域先脱掩码，残留项干净归零。
func (m *QuantizedMatrix) Unmask(yCipher, maskImage []uint64) ([]uint64, error) {
	if len(yCipher) != len(maskImage) {
		return nil, errors.New("maskedinfer: 密文与掩码像长度不一致")
	}
	R := m.bigR()
	a := big.NewInt(0)
	b := big.NewInt(0)
	out := make([]uint64, len(yCipher))
	for i := range yCipher {
		a.SetUint64(yCipher[i])
		b.SetUint64(maskImage[i]) // maskImage 已由 MaskImage 规约到 [0,R)
		a.Sub(a, b)
		a.Mod(a, R)
		if a.Sign() < 0 {
			a.Add(a, R)
		}
		out[i] = a.Uint64()
	}
	return out, nil
}

// SignedValue 模域转有符号；负数落在 [R/2, R) 区间。
func (m *QuantizedMatrix) SignedValue(v uint64) int64 {
	R := m.bigR()
	half := new(big.Int).Rsh(new(big.Int).Set(R), 1) // R/2
	if new(big.Int).SetUint64(v).Cmp(half) >= 0 {
		s := new(big.Int).SetUint64(v)
		s.Sub(s, R)
		return s.Int64()
	}
	return int64(v)
}

// SignedVector 整向量符号还原。
func (m *QuantizedMatrix) SignedVector(v []uint64) []int64 {
	out := make([]int64, len(v))
	for i, x := range v {
		out[i] = m.SignedValue(x)
	}
	return out
}

// Remask 重掩码：y_cipher' = f(y) + r_{l+1} (mod R)。
func (m *QuantizedMatrix) Remask(fY, nextMask []uint64) ([]uint64, error) {
	if len(fY) != len(nextMask) {
		return nil, errors.New("maskedinfer: 输出与掩码长度不一致")
	}
	R := m.bigR()
	a := big.NewInt(0)
	out := make([]uint64, len(fY))
	for i := range fY {
		a.SetUint64(fY[i])
		a.Add(a, big.NewInt(0).SetUint64(nextMask[i]))
		a.Mod(a, R)
		out[i] = a.Uint64()
	}
	return out, nil
}

// ToMaskDomain 浮点转掩码域整数，定点缩放 ×S（S 默认 1e6）。
func (m *QuantizedMatrix) ToMaskDomain(v []float64) []uint64 {
	R := m.bigR()
	a := big.NewInt(0)
	out := make([]uint64, len(v))
	for i, x := range v {
		a.SetInt64(int64(x * m.InputScale)) // 截断；负数以补码进入整数取模
		a.Mod(a, R)
		if a.Sign() < 0 {
			a.Add(a, R)
		}
		out[i] = a.Uint64()
	}
	return out
}

// Decode 脱掩码后还原为真值浮点：有符号整数 × scale / 输入定点 S。
// 这是与旧实现（先乘 scale 再取模）相反的正确次序——先整数域脱掩码，最后才缩放。
func (m *QuantizedMatrix) Decode(y []uint64) []float64 {
	out := make([]float64, len(y))
	for i, v := range y {
		out[i] = float64(m.SignedValue(v)) * m.Scale / m.InputScale
	}
	return out
}

// absF 绝对值（量化用）。
func absF(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// 兼容包装：既有服务（recompute.go 等）沿用 2^32 默认模与包级自由函数，做到零改动。
var defaultMod = &QuantizedMatrix{ModBits: Mod32, InputScale: InputScale}

// Unmask 包级兼容：2^32 默认模。
func Unmask(yCipher, maskImage []uint64) ([]uint64, error) { return defaultMod.Unmask(yCipher, maskImage) }

// SignedValue 包级兼容。
func SignedValue(v uint64) int64 { return defaultMod.SignedValue(v) }

// SignedVector 包级兼容。
func SignedVector(v []uint64) []int64 { return defaultMod.SignedVector(v) }

// FloatToMaskDomain 包级兼容：2^32 默认模。
func FloatToMaskDomain(x []float64) []uint64 { return defaultMod.ToMaskDomain(x) }

// ToMaskDomain 包级兼容：2^32 默认模（与同名词方法并存，方法用于显式 Mod 路径）。
func ToMaskDomain(x []float64) []uint64 { return defaultMod.ToMaskDomain(x) }

// Remask 包级兼容：2^32 默认模。
func Remask(fY, nextMask []uint64) ([]uint64, error) { return defaultMod.Remask(fY, nextMask) }
