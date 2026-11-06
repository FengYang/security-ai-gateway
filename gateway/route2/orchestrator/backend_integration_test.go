// backend_integration_test.go - 阶段 4 验收：网关经 go.work 接回消费新库的 MaskedInferenceBackend。
//
// 这是对方案 §4.2「网关侧定义 MaskedInferenceBackend，经 go.work 接回跑通集成」的端到端证明：
// 主仓库（网关侧）导入 github.com/FengYang/masked-infer/backend，注入一个已加载的 *qwen.Weights，
// 调用 ForwardMasked 并断言 ① 返回形状正确 ② 确定性（同输入/同 rGW 两次结果一致）。
//
// 用合成小权重（Dim=16 / 1 层 / 2 头 GQA）跑通真实掩码像前向（adapters/qwen.ForwardMaskedEmb），
// 无需下载真实模型；数值正确性由 282 步 golden（route2step 包）独立保证。
package orchestrator_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/FengYang/masked-infer/adapters/qwen"
	backend "github.com/FengYang/masked-infer/backend"
	core "github.com/FengYang/masked-infer/core"
)

// synthQwenWeights 构造一个维度自洽的极小 *qwen.Weights，供集成测试免模型跑通前向。
func synthQwenWeights(t *testing.T) *qwen.Weights {
	t.Helper()
	cfg := qwen.QwenConfig{
		Layers: 1, Dim: 16, Heads: 2, KVHeads: 2, HeadDim: 8,
		FFN: 32, Vocab: 32, RopeTheta: 1e6, NormEps: 1e-6, MaxTokens: 8, TiedEmb: true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合成配置非法: %v", err)
	}
	mk := func(rows, cols int) *core.QuantizedMatrix {
		w := make([][]float64, rows)
		for i := range w {
			w[i] = make([]float64, cols)
			for j := range w[i] {
				w[i][j] = 0.1
			}
		}
		m, err := core.NewQuantizedMatrix(w, 8)
		if err != nil {
			t.Fatalf("构造 QuantizedMatrix(%d×%d): %v", rows, cols, err)
		}
		return m
	}
	dim, attnDim, kvd, ffn, vocab := cfg.Dim, cfg.AttnDim(), cfg.KVDim(), cfg.FFN, cfg.Vocab
	embed := mk(vocab, dim)
	ln := make([]float64, dim)
	qn := make([]float64, cfg.HeadDim)
	for i := range ln {
		ln[i] = 1.0
	}
	for i := range qn {
		qn[i] = 1.0
	}
	return &qwen.Weights{
		Cfg:       cfg,
		EmbedMat:  embed,
		LMHeadMat: embed, // tied embeddings
		AttnQ:     [][]*core.QuantizedMatrix{{mk(attnDim, dim)}},
		AttnK:     [][]*core.QuantizedMatrix{{mk(kvd, dim)}},
		AttnV:     [][]*core.QuantizedMatrix{{mk(kvd, dim)}},
		AttnO:     [][]*core.QuantizedMatrix{{mk(dim, attnDim)}},
		Gate:      [][]*core.QuantizedMatrix{{mk(ffn, dim)}},
		Up:        [][]*core.QuantizedMatrix{{mk(ffn, dim)}},
		Down:      [][]*core.QuantizedMatrix{{mk(dim, ffn)}},
		LNIn:      [][]float64{ln},
		LNPost:    [][]float64{ln},
		LNFinal:   ln,
		QNorm:     [][]float64{qn},
		KNorm:     [][]float64{qn},
	}
}

// TestGatewayConsumesBackendViaGoWork 证明：主仓库（网关侧）经 go.work 解析新库 backend 包，
// 注入已加载权重后 ForwardMasked 可端到端跑通掩码域前向，且结果确定。
func TestGatewayConsumesBackendViaGoWork(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过集成前向（合成权重前向为 CPU 轻量，但仍属集成面）")
	}
	b := backend.NewBackendWithWeights(synthQwenWeights(t))
	defer b.Close()

	spec := b.Config()
	if spec.Dim != 16 || spec.Layers != 1 || spec.Heads != 2 {
		t.Fatalf("Config 规格不符: %+v", spec)
	}
	dim := spec.Dim

	// rGW 长度须 = Dim（与掩码嵌入同宽）。
	rGW := make(backend.MaskedVec, dim)
	for i := range rGW {
		rGW[i] = uint64(i + 1)
	}

	// 合成掩码嵌入：每行 Dim 个 uint64（仅验证形状/确定性，不要求数值 golden）。
	const batch = 2
	in := make([]backend.MaskedVec, batch)
	for s := range in {
		in[s] = make(backend.MaskedVec, dim)
		for j := range in[s] {
			in[s][j] = uint64(j+1)*7 + uint64(s)
		}
	}

	out, err := b.ForwardMasked(context.Background(), in, rGW)
	if err != nil {
		t.Fatalf("ForwardMasked 失败: %v", err)
	}
	if len(out) != batch {
		t.Fatalf("输出 batch 数 = %d，期望 %d", len(out), batch)
	}
	for i, row := range out {
		if len(row) != dim {
			t.Fatalf("输出第 %d 行长度 = %d，期望 %d", i, len(row), dim)
		}
	}

	// 确定性：同输入 + 同 rGW 两次结果须逐位一致。
	out2, err := b.ForwardMasked(context.Background(), in, rGW)
	if err != nil {
		t.Fatalf("ForwardMasked(2) 失败: %v", err)
	}
	if !reflect.DeepEqual(out, out2) {
		t.Fatal("ForwardMasked 非确定性（同输入/同 rGW 两次结果不一致）")
	}
}
