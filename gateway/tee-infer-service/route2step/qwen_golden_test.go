// route2step_golden_test.go - T5：真实 Qwen3 权重经**生产 step 引擎**端到端对拍 golden
//
// 与 realweights_test.go 的分工：
//   - realweights_test.go 验的是 adapters/qwen 自己的前向实现（ForwardRef / ForwardMasked）；
//   - 本文件验的是**生产链路** route2plan→route2step（plan 驱动、逐步脱掩码/算子/重掩码）
//     在真实权重下能否跑完整轮并给出与 transformers fp32 参考一致的 top-1。
//
// 这两件事不能互相替代：前者证明"模型结构实现对"，后者证明"计划机把同一结构按步拆开
// 执行后仍然对"（GQA 的 KV 宽度、attnDim≠Dim 的 Wo 回映、SwiGLU 的 gate/up 次序、
// QK-norm 落在 RoPE 之前——任一处错位，前者全绿而后者必错）。
//
// 【门槛】权重不在本机时 Skip 并写明「D2 未执行」，不伪造 PASS。
// 显式执行：
//
//	ROUTE2_QWEN_DIR=.tools/models/Qwen3Guard-Gen-0.6B go test ./gateway/tee-infer-service/route2step -run TestRoute2StepRealQwenGolden -v
package route2step_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FengYang/masked-infer/adapters/qwen"
	"github.com/FengYang/masked-infer/masklite"
	"github.com/FengYang/masked-infer/plan"
	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/tee-infer-service/route2step"
)

// defaultRoute2QwenDir 与 realweights_test.go 的默认路径保持一致（本文件是外部测试包，
// 不能引用其未导出常量，故在此声明同一默认值；两处漂移只会让 Skip 消息里的路径不准）。
const defaultRoute2QwenDir = "../../../.tools/models/Qwen3Guard-Gen-0.6B"

// route2GoldenFile 与 scripts/gen-qwen3-golden.py 的输出一一对应（只取本用例需要的字段）。
type route2GoldenFile struct {
	Model    string    `json:"model"`
	TokenIDs []int     `json:"token_ids"`
	Indices  []int     `json:"indices"`
	Logits   []float64 `json:"logits"`
}

func loadRoute2Golden(t *testing.T) route2GoldenFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/qwen3-06b-golden.json")
	if err != nil {
		t.Fatalf("读取 golden 失败: %v", err)
	}
	var g route2GoldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("解析 golden 失败: %v", err)
	}
	if len(g.TokenIDs) == 0 || len(g.Indices) == 0 {
		t.Fatal("golden 结构不完整（缺 token_ids / indices）")
	}
	return g
}

// realQwenDir 真实权重目录（与 realweights_test.go 同款环境变量约定）。
func realQwenDir() string {
	if d := os.Getenv("ROUTE2_QWEN_DIR"); d != "" {
		return d
	}
	return defaultRoute2QwenDir
}

// TestRoute2StepRealQwenGolden 真实权重 × 生产 step 引擎 × golden 对拍（D2 门控的生产链路侧）。
func TestRoute2StepRealQwenGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过真实权重端到端（28 层掩码计划机耗时数分钟以上）")
	}
	dir := realQwenDir()
	path := filepath.Join(dir, "model.safetensors")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("真实权重不存在（%s）：**D2 门控未执行**，不得据此宣称生产链路支持真实模型。设置 ROUTE2_QWEN_DIR 后重跑", path)
	}
	g := loadRoute2Golden(t)

	preset := qwen.Qwen3_06B()
	w, err := qwen.LoadWeights(path, preset)
	if err != nil {
		t.Fatalf("加载真实权重失败: %v", err)
	}
	cfg := preset.ToModelConfig(true)
	cfg.ModelID = "qwen3-0.6b"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("真实 Qwen3 映射出的 ModelConfig 应合法: %v", err)
	}
	// 前提校验：本用例的意义就在于覆盖 GQA / SwiGLU / QK-norm / attnDim≠Dim 四个结构，
	// 任一退化都会让用例变成"又测了一遍 demo"，故在此显式断言。
	if cfg.KVHeads == cfg.Heads || cfg.FFNType != route2plan.FFNTypeSwiGLU || !cfg.QKNorm || cfg.AttnDim() == cfg.Dim {
		t.Fatalf("前提失效：真实 Qwen3 应具备 GQA/SwiGLU/QK-norm/attnDim≠Dim，实际 %+v", cfg)
	}

	plan, err := route2plan.BuildTurn(cfg, route2plan.StagePrefill, 0)
	if err != nil {
		t.Fatalf("BuildTurn(prefill): %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan 自校验失败: %v", err)
	}
	kv, err := route2step.NewKVCache(cfg)
	if err != nil {
		t.Fatalf("NewKVCache: %v", err)
	}

	tokens := g.TokenIDs
	seed := []byte("route2step-golden-seed-0000000001")
	ctx := &route2step.StepContext{
		Cfg:      cfg,
		Weights:  w,
		Plan:     plan,
		Stage:    route2plan.StagePrefill,
		Turn:     0,
		TurnBase: 0,
		KV:       kv,
		Seed:     seed,
		NewStream: func(s []byte, modulus uint64, domain []byte) (masklite.MaskStream, error) {
			return mask.NewStreamDomain(s, modulus, domain)
		},
	}

	injected, err := route2StepInject(t, w, plan, tokens, seed)
	if err != nil {
		t.Fatalf("客户端注入行构造失败: %v", err)
	}

	outs := make(map[int][][]uint64, len(plan))
	token := -1
	for seq := 0; seq < len(plan); seq++ {
		spec := plan[seq]
		ctx.Seq, ctx.Spec = seq, spec
		// 进度日志：28 层 × 10 步 ≈ 282 步，且每步的 MaskImage 是 big.Int 逐元素乘法，
		// 整轮耗时以十分钟计。无进度输出时无法区分"慢"与"卡死"。
		if spec.Coord.Branch == route2plan.BranchMain && seq%10 == 0 {
			t.Logf("进度 seq=%d/%d block=%d step=%d", seq, len(plan), spec.Coord.Block, spec.Coord.Step)
		}

		lines := make([][][]uint64, len(spec.InSrc))
		for r, src := range spec.InSrc {
			var rows [][]uint64
			if src == route2plan.SrcInject {
				rows = injected
			} else {
				rows = outs[src]
				if rows == nil {
					t.Fatalf("seq=%d op=%s 行 %d 引用了尚未产出的步 %d（计划顺序有环或跳步）", seq, spec.Op, r, src)
				}
			}
			if spec.InWeight[r].Applied {
				m, merr := w.Matrix(spec.InWeight[r].Key)
				if merr != nil {
					t.Fatalf("seq=%d 权重 %s 加载失败: %v", seq, spec.InWeight[r].Key.String(), merr)
				}
				rows, merr = m.CipherLinear(rows)
				if merr != nil {
					t.Fatalf("seq=%d 不可信加速器线性失败: %v", seq, merr)
				}
			}
			lines[r] = rows
		}
		// line-major：batch[line*T + pos]
		batch := make([][]uint64, 0, len(spec.InSrc)*len(tokens))
		for r := range lines {
			if len(lines[r]) != len(tokens) {
				t.Fatalf("seq=%d op=%s 行 %d 行数=%d，应为位置数 %d", seq, spec.Op, r, len(lines[r]), len(tokens))
			}
			batch = append(batch, lines[r]...)
		}

		// ⚠ Batch 必须写回上下文：ExecStep 只读 ctx.Batch，漏赋值会让 nPos=0、
		// 静默返回空结果且不报错（本用例首跑即栽在这里，症状正是"产出行数=0"）。
		ctx.Batch = batch

		res, tok, serr := route2step.ExecStep(ctx)
		if serr != nil {
			t.Fatalf("seq=%d op=%s 执行失败: %v", seq, spec.Op, serr)
		}
		if spec.Terminal {
			token = tok
			continue
		}
		// kv_append_* 按契约**不产出** result（§7.2：没有下游消费者，返回重掩码身份值
		// 只会让客户端误接）。此处显式断言这一契约，避免把"空结果"当成漏算。
		if spec.Op == route2plan.OpKVAppendK || spec.Op == route2plan.OpKVAppendV {
			if len(res) != 0 {
				t.Fatalf("seq=%d op=%s 应返回空 result（契约），实际 %d 行", seq, spec.Op, len(res))
			}
			continue
		}
		if len(res) != len(tokens) {
			t.Fatalf("seq=%d op=%s 产出行数=%d，应为 %d", seq, spec.Op, len(res), len(tokens))
		}
		outs[seq] = res
	}

	if token < 0 {
		t.Fatal("整轮执行完毕却没有产出 token（plan 缺少 terminal 步？）")
	}
	if want := g.Indices[0]; token != want {
		t.Fatalf("生产链路 top-1 = %d，golden(transformers fp32) = %d：D2 门控**未通过**\n"+
			"（该偏差不是量化噪声级别，指示 plan 步序/掩码域/维度映射有实质错误）", token, want)
	}
	t.Logf("生产链路 × 真实权重 top-1 = %d，与 transformers fp32 golden 一致（golden top-2=%d, Δlogit=%.4f）",
		token, g.Indices[1], g.Logits[0]-g.Logits[1])
}

// route2StepInject 构造客户端注入行：V = ToMaskDomain(x) + ρ_inject(pos)（mod 2^64）。
//
// 注入域来自 plan 的 SrcMaskDomain(0,0)；多位置时掩码流**逐段推进**（与服务端逐行
// nextMaskVec 的消费次序一致）。行 j 若各自取流首段，服务端脱掩码即错位且不报错。
func route2StepInject(t *testing.T, w *qwen.Weights, plan route2plan.Plan, tokens []int, seed []byte) ([][]uint64, error) {
	t.Helper()
	xs, err := w.EmbedRows(tokens)
	if err != nil {
		return nil, err
	}
	ref, err := w.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		return nil, err
	}
	domain, err := plan.SrcMaskDomain(0, 0)
	if err != nil {
		return nil, err
	}
	stream, err := mask.NewStreamDomain(seed, route2step.Route2MaskModulus, []byte(domain))
	if err != nil {
		return nil, err
	}
	out := make([][]uint64, len(xs))
	for j, x := range xs {
		rho := make([]uint64, len(x))
		for i := range rho {
			rho[i] = stream.Next() % route2step.Route2MaskModulus
		}
		xm := ref.ToMaskDomain(x)
		row := make([]uint64, len(x))
		for i := range row {
			row[i] = xm[i] + rho[i]
		}
		out[j] = row
	}
	return out, nil
}
