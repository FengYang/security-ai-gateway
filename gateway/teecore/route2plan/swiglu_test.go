package route2plan

import "testing"

// TestSwiGLUPlanLayout SwiGLU（FFNType=swiglu）布局的 plan 形态断言（T2 验收）。
//
// 关键点：SwiGLU 在前 6 条（attn_norm→ffn_norm）与 GELU 完全共用，仅在 FFN 尾段
// 改为 up→gate→swiglu_mul→down 四步（block 内条目数 10，而非 GELU 的 8）；
// 坐标 Wire 严格递增由 Validate 兜底。本测试只断言「形态正确、可自校验、可被 Blocks 反推」。
func TestSwiGLUPlanLayout(t *testing.T) {
	cfg := DemoTinyConfig()
	cfg.FFNType = FFNTypeSwiGLU
	blocks := cfg.Blocks

	p, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build(SwiGLU) 报错: %v", err)
	}
	// 长度必须 == Blocks*10 + 2（TailSteps）
	wantLen := blocks*StepsPerBlockSwiGLU + TailSteps
	if len(p) != wantLen {
		t.Fatalf("SwiGLU plan 长度 = %d, want %d（Blocks=%d）", len(p), wantLen, blocks)
	}
	// 自校验必须通过（含 Wire 严格递增、arity、op 白名单等）
	if err := p.Validate(); err != nil {
		t.Fatalf("SwiGLU plan 自校验失败: %v", err)
	}
	// Blocks() 必须能反推回原 block 数
	gotBlocks, err := p.Blocks()
	if err != nil {
		t.Fatalf("SwiGLU plan Blocks() 报错: %v", err)
	}
	if gotBlocks != blocks {
		t.Fatalf("Blocks() = %d, want %d", gotBlocks, blocks)
	}

	// 逐 block 断言 FFN 尾段四步的 op 与分支序列（up=OpLinear / gate=OpLinear /
	// swiglu_mul=OpSwiGLUMul / down=OpResidualAdd）。前 6 条与 GELU 共用，此处不重复断言。
	for b := 0; b < blocks; b++ {
		base := BlockBase(b, cfg)
		up := p[base+offFFNUp]
		gate := p[base+offSwiGLUGate]
		mul := p[base+offSwiGLUMul]
		down := p[base+offSwiGLUResidual]

		if up.Op != OpLinear || up.Coord.Branch != BranchMain {
			t.Fatalf("block %d up 步异常: op=%q branch=%d", b, up.Op, up.Coord.Branch)
		}
		if gate.Op != OpLinear || gate.Coord.Branch != BranchV {
			t.Fatalf("block %d gate 步异常: op=%q branch=%d", b, gate.Op, gate.Coord.Branch)
		}
		if mul.Op != OpSwiGLUMul {
			t.Fatalf("block %d swiglu_mul 步异常: op=%q（应为 %q）", b, mul.Op, OpSwiGLUMul)
		}
		if mul.Coord.Branch != BranchV || mul.OutDim != cfg.FFNDim {
			t.Fatalf("block %d swiglu_mul 步异常: branch=%d out=%d", b, mul.Coord.Branch, mul.OutDim)
		}
		if down.Op != OpResidualAdd || down.Coord.Branch != BranchQ {
			t.Fatalf("block %d down 步异常: op=%q branch=%d", b, down.Op, down.Coord.Branch)
		}
		// gate 与 up 必须共享同一输入（ffn_norm 输出）
		if len(gate.InSrc) != 1 || gate.InSrc[0] != base+offFFNNorm {
			t.Fatalf("block %d gate 输入异常: %v", b, gate.InSrc)
		}
		if len(up.InSrc) != 1 || up.InSrc[0] != base+offFFNNorm {
			t.Fatalf("block %d up 输入异常: %v", b, up.InSrc)
		}
		// swiglu_mul 两行必须分别来自 up 与 gate
		if len(mul.InSrc) != 2 || mul.InSrc[0] != base+offFFNUp || mul.InSrc[1] != base+offSwiGLUGate {
			t.Fatalf("block %d swiglu_mul 输入异常: %v", b, mul.InSrc)
		}
		// down 的两行必须来自 swiglu_mul 与 attn_residual（扇入两行掩码不同）
		if len(down.InSrc) != 2 || down.InSrc[0] != base+offSwiGLUMul || down.InSrc[1] != base+offAttnRes {
			t.Fatalf("block %d down 输入异常: %v", b, down.InSrc)
		}
	}

	// 末步必须是 argmax（terminal）
	if !p[len(p)-1].Terminal || p[len(p)-1].Op != OpArgMax {
		t.Fatal("SwiGLU plan 末步必须是 terminal argmax")
	}
}

// TestSwiGLUPlanIsDistinctFromGELU 同一 cfg 仅 FFNType 不同，plan 必须不同（防掩码错配）。
func TestSwiGLUPlanIsDistinctFromGELU(t *testing.T) {
	g := DemoTinyConfig() // FFNType 默认 "" → GELU
	s := DemoTinyConfig()
	s.FFNType = FFNTypeSwiGLU
	pg, err := Build(g)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg) == len(ps) {
		t.Fatalf("GELU 与 SwiGLU plan 长度不应相等: 均为 %d", len(pg))
	}
	// 首步坐标相同（同 stage/turn/block/step），但长度不同即代表结构不同，已足够。
	if pg[0].Coord == ps[0].Coord && len(pg) == len(ps) {
		t.Fatal("FFNType 未改变 plan 结构")
	}
}
