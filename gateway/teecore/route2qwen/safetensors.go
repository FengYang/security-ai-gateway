package route2qwen

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// STTensor 一个 safetensors 张量（引用数据区切片，不立即解码）。
type STTensor struct {
	Name   string
	DType  string // "F32" / "F16" / "BF16"
	Shape  []int
	Offset int // 在数据区内的起始字节（相对数据区）
	Length int // 字节长度
}

// SafeTensors 解析后的 safetensors 文件。
type SafeTensors struct {
	Tensors map[string]STTensor
	Meta    map[string]string
	data    []byte // 完整数据区
}

// LoadSafeTensors 解析 safetensors 文件（仅索引，张量按需解码）。
func LoadSafeTensors(path string) (*SafeTensors, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("route2qwen: 读 safetensors 失败: %w", err)
	}
	if len(raw) < 8 {
		return nil, fmt.Errorf("route2qwen: 文件过短")
	}
	headerLen := binary.LittleEndian.Uint64(raw[0:8])
	if int(8+headerLen) > len(raw) {
		return nil, fmt.Errorf("route2qwen: header 长度越界 %d > %d", 8+headerLen, len(raw))
	}
	// 先解析顶层（含 __metadata__ 与所有张量键）
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw[8:8+headerLen], &top); err != nil {
		return nil, fmt.Errorf("route2qwen: 解析 header JSON 失败: %w", err)
	}
	st := &SafeTensors{Tensors: map[string]STTensor{}, Meta: map[string]string{}}
	if meta, ok := top["__metadata__"]; ok {
		_ = json.Unmarshal(meta, &st.Meta)
	}
	for name, rawMsg := range top {
		if name == "__metadata__" {
			continue
		}
		var t struct {
			DType       string `json:"dtype"`
			Shape       []int  `json:"shape"`
			DataOffsets []int  `json:"data_offsets"`
		}
		if err := json.Unmarshal(rawMsg, &t); err != nil {
			return nil, fmt.Errorf("route2qwen: 解析张量 %q 失败: %w", name, err)
		}
		if len(t.DataOffsets) != 2 {
			return nil, fmt.Errorf("route2qwen: 张量 %q 的 data_offsets 非法", name)
		}
		st.Tensors[name] = STTensor{
			Name:   name,
			DType:  t.DType,
			Shape:  t.Shape,
			Offset: t.DataOffsets[0],
			Length: t.DataOffsets[1] - t.DataOffsets[0],
		}
	}
	st.data = raw[8+headerLen:]
	return st, nil
}

// Bytes 返回该张量在数据区内的原始字节切片。
func (t STTensor) Bytes(st *SafeTensors) []byte {
	return st.data[t.Offset : t.Offset+t.Length]
}

// Float32 把张量解码为 float32 切片（按行优先展平）。
// 支持 F32 / F16 / BF16 三种 Qwen2.5 常见 dtype；其余报错。
func (t STTensor) Float32(st *SafeTensors) ([]float32, error) {
	count := 1
	for _, s := range t.Shape {
		count *= s
	}
	raw := t.Bytes(st)
	switch t.DType {
	case "F32":
		if len(raw) != count*4 {
			return nil, fmt.Errorf("route2qwen: %s F32 长度不符 %d != %d", t.Name, len(raw), count*4)
		}
		out := make([]float32, count)
		for i := 0; i < count; i++ {
			out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
		}
		return out, nil
	case "BF16":
		if len(raw) != count*2 {
			return nil, fmt.Errorf("route2qwen: %s BF16 长度不符 %d != %d", t.Name, len(raw), count*2)
		}
		out := make([]float32, count)
		for i := 0; i < count; i++ {
			u16 := binary.LittleEndian.Uint16(raw[i*2:])
			// BF16 高位 16 位直接作为 float32 的指数+尾数高位，低 16 位补零
			u32 := uint32(u16) << 16
			out[i] = math.Float32frombits(u32)
		}
		return out, nil
	case "F16":
		if len(raw) != count*2 {
			return nil, fmt.Errorf("route2qwen: %s F16 长度不符 %d != %d", t.Name, len(raw), count*2)
		}
		out := make([]float32, count)
		for i := 0; i < count; i++ {
			u16 := binary.LittleEndian.Uint16(raw[i*2:])
			out[i] = float32(halfToFloat32(u16))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("route2qwen: 不支持的 dtype %q（张量 %s）", t.DType, t.Name)
	}
}

// halfToFloat32 把 IEEE 754 半精度（binary16）转单精度（binary32）。
func halfToFloat32(h uint16) float64 {
	sign := uint32(h>>15) << 31
	exp := uint32(h>>10) & 0x1f
	mant := uint32(h) & 0x3ff
	var val uint32
	if exp == 0 {
		if mant == 0 {
			val = sign // ±0
		} else {
			// 非规约数
			for mant&0x400 == 0 {
				mant <<= 1
				exp--
			}
			exp++
			mant &= 0x3ff
			val = sign | ((exp + 112) << 23) | (mant << 13)
		}
	} else if exp == 0x1f {
		val = sign | 0x7f800000 | (mant << 13) // Inf / NaN
	} else {
		val = sign | ((exp + 112) << 23) | (mant << 13)
	}
	return float64(math.Float32frombits(val))
}
