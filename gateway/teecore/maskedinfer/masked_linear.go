// Package maskedinfer 路线 2 的密文线性内核和掩码像计算
package maskedinfer

import (
	"errors"
	"fmt"
	"math"
)

// 掩码模 R，跟 OTP-Mask 对齐
const maskModulus uint64 = 1 << 32

// QuantizedMatrix 量化权重矩阵，行优先
type QuantizedMatrix struct {
	Rows   int
	Cols   int
	Scale  float64
	Data   []int32
	Bias   []int32
}

func NewQuantizedMatrix(weights [][]float64, bitWidth int) (*QuantizedMatrix, error) {
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
	m := &QuantizedMatrix{Rows: rows, Cols: cols, Scale: scale, Data: make([]int32, rows*cols)}
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

// MaskImage 计算掩码像 W·r，r 是掩码向量
func (m *QuantizedMatrix) MaskImage(r []uint64) ([]uint64, error) {
	if len(r) != m.Cols {
		return nil, fmt.Errorf("maskedinfer: 掩码长度 %d != 权重列数 %d", len(r), m.Cols)
	}
	out := make([]uint64, m.Rows)
	for i := 0; i < m.Rows; i++ {
		var acc int64
		for j := 0; j < m.Cols; j++ {
			acc += int64(m.Data[i*m.Cols+j]) * int64(r[j])
		}
		val := float64(acc) * m.Scale
		out[i] = uint64(int64(val)) % maskModulus
	}
	return out, nil
}

// CipherLinear 密文线性内核：y_cipher = W_q·V_cipher + b_q (mod R)
// 生产 GPU 内核用 Triton/CUTLASS，这里是 CPU 参考实现
func (m *QuantizedMatrix) CipherLinear(V [][]uint64) ([][]uint64, error) {
	out := make([][]uint64, len(V))
	for b, vec := range V {
		if len(vec) != m.Cols {
			return nil, fmt.Errorf("maskedinfer: 向量[%d]长度 %d != 列数 %d", b, len(vec), m.Cols)
		}
		row := make([]uint64, m.Rows)
		for i := 0; i < m.Rows; i++ {
			var acc int64
			for j := 0; j < m.Cols; j++ {
				acc += int64(m.Data[i*m.Cols+j]) * int64(vec[j])
			}
			if m.Bias != nil {
				acc += int64(m.Bias[i])
			}
			val := float64(acc) * m.Scale
			row[i] = uint64(int64(val)) % maskModulus
		}
		out[b] = row
	}
	return out, nil
}

// PlainLinear 明文对照，用于验收基准
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

// Unmask 脱掩码：y = y_cipher - W·r (mod R)
func Unmask(yCipher []uint64, maskImage []uint64) ([]uint64, error) {
	if len(yCipher) != len(maskImage) {
		return nil, errors.New("maskedinfer: 密文与掩码像长度不一致")
	}
	out := make([]uint64, len(yCipher))
	for i := range yCipher {
		out[i] = (yCipher[i] + maskModulus - maskImage[i]%maskModulus) % maskModulus
	}
	return out, nil
}

// SignedValue 模域转有符号，负数落在 [R/2, R) 区间，非线性运算前必须符号还原
func SignedValue(v uint64) int64 {
	if v >= maskModulus/2 {
		return int64(v) - int64(maskModulus)
	}
	return int64(v)
}

// SignedVector 整向量符号还原
func SignedVector(v []uint64) []int64 {
	out := make([]int64, len(v))
	for i, x := range v {
		out[i] = SignedValue(x)
	}
	return out
}

// Remask 重掩码：y_cipher' = f(y) + r_{l+1} (mod R)
func Remask(fY []uint64, nextMask []uint64) ([]uint64, error) {
	if len(fY) != len(nextMask) {
		return nil, errors.New("maskedinfer: 输出与掩码长度不一致")
	}
	out := make([]uint64, len(fY))
	for i := range fY {
		out[i] = (fY[i] + nextMask[i]) % maskModulus
	}
	return out, nil
}

func toFloat(v []uint64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = float64(x)
	}
	return out
}

// FloatToMaskDomain 浮点转掩码域整数，定点缩放 ×1e6
func FloatToMaskDomain(v []float64) []uint64 {
	out := make([]uint64, len(v))
	for i, x := range v {
		out[i] = uint64(int64(x * 1e6)) % maskModulus
	}
	return out
}

func absF(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
