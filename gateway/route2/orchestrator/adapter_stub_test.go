package orchestrator

import (
	"testing"

	"github.com/FengYang/masked-infer/core"
)

// stubAdapter 仅实现 ModelAdapter，用于 L1 复用性冒烟：
// 不依赖任何具体模型（qwen/llama），验证编排器可被任意适配器驱动。
type stubAdapter struct {
	dim int
	em  *maskedinfer.QuantizedMatrix
	lm  *maskedinfer.QuantizedMatrix
}

func newStubAdapter(dim int) *stubAdapter {
	q := func(rows, cols int) *maskedinfer.QuantizedMatrix {
		return &maskedinfer.QuantizedMatrix{
			Rows: rows, Cols: cols, Scale: 1,
			Data:    make([]int32, rows*cols),
			ModBits: maskedinfer.Mod64, InputScale: maskedinfer.InputScale,
		}
	}
	return &stubAdapter{dim: dim, em: q(4, dim), lm: q(4, dim)}
}

func (s *stubAdapter) Dim() int                             { return s.dim }
func (s *stubAdapter) Encode(string) []int                  { return []int{0} }
func (s *stubAdapter) Decode([]int) string                  { return "" }
func (s *stubAdapter) Embed() *maskedinfer.QuantizedMatrix  { return s.em }
func (s *stubAdapter) LMHead() *maskedinfer.QuantizedMatrix { return s.lm }
func (s *stubAdapter) EmbedRows(tokens []int) ([][]float64, error) {
	out := make([][]float64, len(tokens))
	for i := range out {
		out[i] = make([]float64, s.dim)
	}
	return out, nil
}
func (s *stubAdapter) BackendStep(m [][]uint64, _ []uint64) ([][]uint64, error) { return m, nil }

// TestStubAdapterDrivable L1：仅实现 ModelAdapter 的哑适配器即可被同一编排器驱动。
func TestStubAdapterDrivable(t *testing.T) {
	a := newStubAdapter(8)
	rGW := GenOTP(a.Dim(), maskedinfer.Mod64)
	if _, err := ForwardMaskedFormA(a, []int{0}, rGW); err != nil {
		t.Fatalf("ForwardMaskedFormA(stub): %v", err)
	}
}
