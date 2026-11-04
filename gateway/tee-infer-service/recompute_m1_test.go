package main

// M1 验收：路线2 服务侧 Mod64 接线端到端正确性（proto=2 迁移版）。
//
// 旧版用 proto=1 请求（layer/mask_version 语义），已被版本门禁拒绝
//（400 recompute_proto_v1_unsupported，见 recompute.go 版本门禁）。本版走 proto=2
// 的 plan 步：选 block 0 的 ffn_up（gelu）步，测试侧等价模拟「不可信加速器」算出
// yCipher = W·V + b (mod R)，服务端脱掩码 → Decode → GELU → 重掩码（产出步自己的域）；
// 测试侧用同一批权重与掩码流独立重算期望结果，逐位比对。
//
// 这是最强断言：任一环节若仍走 Mod32 兼容垫片（旧 bug），掩码流将为 mod 2^32、
// Unmask/Remask 将 mod 2^32，与本测试基于 route2MaskModulus 的独立重算结果不一致，
// 从而精准暴露 M1 接线是否真的生效。

import (
	"testing"

	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2plan"
	"security-ai-gateway/gateway/teecore/trustedops"
)

// TestM1RecomputeMod64 路线2 服务侧 Mod64 接线端到端验收（M1，proto=2）。
func TestM1RecomputeMod64(t *testing.T) {
	h := newV2Harness(t)

	// block 0 的 ffn_up 步（seq=6，op=gelu，加权通路：InWeight=W_up）。
	// 该步不依赖前面任何步的运行结果（掩码域由 plan 坐标纯函数派生），
	// 故可独立单步构造输入，专门对拍 Mod64 数值通路。
	const seq = 6
	spec, err := h.plan.At(seq)
	if err != nil {
		t.Fatalf("plan.At(%d): %v", seq, err)
	}
	if spec.Op != route2plan.OpGELU {
		t.Fatalf("seq=%d 应为 ffn_up(gelu), got %s", seq, spec.Op)
	}
	wup, err := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorFFNUp})
	if err != nil {
		t.Fatalf("W_up: %v", err)
	}
	if wup.ModBits != maskedinfer.Mod64 {
		t.Fatalf("M1 期望 Mod64 权重，实际 %v", wup.ModBits)
	}

	// 直接把状态机推进到该步（与 TestV2ArgMaxUsesTokenField 同款）：
	// 该步不依赖前面步的运行结果（掩码域由 plan 坐标纯函数派生），可独立单步对拍。
	st := h.state()
	st.mu.Lock()
	if err := st.initLocked(route2plan.DemoModelID); err != nil {
		st.mu.Unlock()
		t.Fatalf("initLocked: %v", err)
	}
	if err := st.ensurePlanLocked(); err != nil {
		st.mu.Unlock()
		t.Fatalf("ensurePlanLocked: %v", err)
	}
	st.pos = seq
	st.mu.Unlock()
	h.pos = seq
	h.nextCoord = spec.Coord.Wire()

	// 小输入 x（float），使定点化不溢出 R/2，避免符号还原误判
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = (float64(i) - float64(h.cfg.Dim)/2) * 0.05
	}

	// 密态输入：V = ToMaskDomain(x) + ρ_src(seq,0)
	vin := h.maskForStep(seq, 0, x)

	// 「不可信加速器」：yCipher = W·V + b (mod R)
	yc, err := wup.CipherLinear([][]uint64{vin})
	if err != nil {
		t.Fatalf("CipherLinear: %v", err)
	}

	// 发步（proto=2；coord/seq/model_id 均进签名）
	rc := h.step(yc)
	if len(rc.Result) != 1 || len(rc.Result[0]) != h.cfg.FFNDim {
		t.Fatalf("结果形状错误: %d x %d（want 1 x %d）",
			len(rc.Result), len(rc.Result[0]), h.cfg.FFNDim)
	}

	// ---- 独立重算期望（整数精确，应与服务端逐位相等）----
	// 1) 重放服务端脱掩码：img = W·ρ；y = yCipher - img = W·ToMaskDomain(x) + b
	rho := h.srcRho(seq, 0, len(x))
	img, err := wup.MaskImage(rho)
	if err != nil {
		t.Fatalf("MaskImage: %v", err)
	}
	y, err := wup.Unmask(yc[0], img)
	if err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	// 2) Decode 还原线性真值 → GELU → 定点化（ref 的 InputScale 是全局常量，
	//    与服务端 refMatrix 的 ToMaskDomain 同款）
	ref, err := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatalf("基准矩阵: %v", err)
	}
	xLin := wup.Decode(y)
	geluOut := make([]float64, len(xLin))
	for i := range xLin {
		geluOut[i] = trustedops.GELU(xLin[i])
	}
	fY := ref.ToMaskDomain(geluOut)
	// 3) 重掩码（产出步自己的域，与服务端 outStream 同款派生）
	rhoOut := h.outRho(seq, len(fY))
	expected := make([]uint64, len(fY))
	for i := range expected {
		expected[i] = fY[i] + rhoOut[i] // uint64 自然回绕 = mod 2^64（Mod64）
	}

	for i := range rc.Result[0] {
		if rc.Result[0][i] != expected[i] {
			t.Fatalf("ffn_dim %d: 服务端结果 %d != 期望 %d（Mod64 路径不一致，可能 M1 未生效）",
				i, rc.Result[0][i], expected[i])
		}
	}
}
