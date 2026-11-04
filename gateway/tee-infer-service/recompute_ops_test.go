// recompute_ops_test.go - 补算服务扩展算子验收（rmsnorm / argmax / 边界，proto=2 迁移版）
//
// 旧版用 proto=1 请求（layer/mask_version 语义），已被版本门禁拒绝
// （400 recompute_proto_v1_unsupported）。本版走 proto=2 plan 步：
//   - rmsnorm：注入已知 x，服务端归一化后**逐位**对拍独立重算（掩码算术精确相等）；
//   - argmax：构造已知 logits 掩码行，对拍服务端返回的 token；
//   - 未知算子 / batch 超上限：走同一 proto=2 端点的 fail-closed 边界。
package main

import (
	"net/http"
	"testing"

	"security-ai-gateway/gateway/teecore/route2plan"
	"security-ai-gateway/gateway/teecore/trustedops"
)

// TestRecomputeRMSNorm 覆盖 rmsnorm 算子的数值正确性（proto=2，逐位对拍）。
//
// seq0（block0 attn_norm）是直通行（InWeight=NoWeight）：服务端用注入掩码 ρ 脱掩码、
// 按 InputScale 还原浮点，再以服务端权威 gamma/eps 做 RMSNorm，最后按产出步自己的域
// 重掩码。测试侧用同一批权重与掩码流独立重算，整数精确相等。
func TestRecomputeRMSNorm(t *testing.T) {
	h := newV2Harness(t)
	const seq = 0
	spec, err := h.plan.At(seq)
	if err != nil {
		t.Fatalf("plan.At(%d): %v", seq, err)
	}
	if spec.Op != route2plan.OpRMSNorm {
		t.Fatalf("seq=%d 应为 attn_norm(rmsnorm), got %s", seq, spec.Op)
	}
	ref, err := h.weights.Matrix(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorAttnQ})
	if err != nil {
		t.Fatalf("基准矩阵: %v", err)
	}
	// 服务端权威归一化参数（normTensorKey(StepAttnNorm) → ln_in）
	gamma, eps, err := h.weights.Affine(route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorLNIn})
	if err != nil {
		t.Fatalf("Affine(ln_in): %v", err)
	}

	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = (float64(i) - float64(h.cfg.Dim)/2) * 0.05
	}
	v := h.maskForStep(seq, 0, x)

	rc := h.step([][]uint64{v})
	if len(rc.Result) != 1 || len(rc.Result[0]) != h.cfg.Dim {
		t.Fatalf("rmsnorm 结果形状错误: %d x %d", len(rc.Result), len(rc.Result[0]))
	}
	if rc.MaskNext == "" {
		t.Fatal("rmsnorm 应返回 mask_next 指纹")
	}
	if rc.Token != -1 {
		t.Fatalf("非 argmax 步 token 应为哨兵 -1, got %d", rc.Token)
	}

	// ---- 独立重算期望（整数精确）----
	// 1) 直通脱掩码：y = v - ρ = ToMaskDomain(x)；按 InputScale 还原（与服务端
	//    decodePassthrough 同款：SignedValue/InputScale，scale=1）
	rho := h.srcRho(seq, 0, len(x))
	y := make([]uint64, len(v))
	for i := range y {
		y[i] = v[i] - rho[i] // uint64 回绕 = mod 2^64
	}
	xq := make([]float64, len(y))
	for i := range y {
		xq[i] = float64(ref.SignedValue(y[i])) / ref.InputScale
	}
	// 2) RMSNorm（服务端权威 gamma/eps）→ 定点化 → 重掩码（产出步自己的域）
	normed := trustedops.RMSNorm(xq, gamma, eps)
	fY := ref.ToMaskDomain(normed)
	rhoOut := h.outRho(seq, len(fY))
	expected := make([]uint64, len(fY))
	for i := range expected {
		expected[i] = fY[i] + rhoOut[i]
	}
	for i := range rc.Result[0] {
		if rc.Result[0][i] != expected[i] {
			t.Fatalf("dim %d: 服务端 rmsnorm 结果 %d != 期望 %d", i, rc.Result[0][i], expected[i])
		}
	}
}

// TestRecomputeArgMax 覆盖 argmax 算子的数值正确性（proto=2，对拍 token）。
//
// 直接把状态推到本轮末步（argmax），构造 logits 掩码行
// V = W_lm·(ToMaskDomain(x)+ρ) + b，服务端脱掩码 → Decode → ArgMax；
// 测试侧独立重算期望 token 并比对。
func TestRecomputeArgMax(t *testing.T) {
	h := newV2Harness(t)
	last := len(h.plan) - 1
	spec := h.plan[last]
	if spec.Op != route2plan.OpArgMax {
		t.Fatalf("plan 末步应为 argmax, got %s", spec.Op)
	}
	// 与 TestV2ArgMaxUsesTokenField 同款：直接把状态推到末步
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
	st.pos = last
	st.mu.Unlock()

	wlm, err := h.weights.Matrix(route2plan.TensorKey{Block: h.cfg.Blocks, Tensor: route2plan.TensorLMHead})
	if err != nil {
		t.Fatalf("W_lm: %v", err)
	}

	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = 0.01 * float64(i+1)
	}
	v := h.maskForStep(last, 0, x)
	logits, err := wlm.CipherLinear([][]uint64{v})
	if err != nil {
		t.Fatalf("CipherLinear(lm): %v", err)
	}

	req := h.mkReq(route2plan.OpArgMax, last, spec.Coord.Wire(), logits)
	resp, rc := h.post(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("argmax 应 200, got %d", resp.StatusCode)
	}
	if rc.Token < 0 || rc.Token >= h.cfg.Vocab {
		t.Fatalf("token=%d 越界（Vocab=%d）", rc.Token, h.cfg.Vocab)
	}
	if len(rc.Result) != 0 {
		t.Fatalf("argmax 的 result 应为空, got %d 行", len(rc.Result))
	}

	// 独立重算期望 token：img = W_lm·ρ；y = logits - img；Decode → ArgMax
	rho := h.srcRho(last, 0, len(x))
	img, err := wlm.MaskImage(rho)
	if err != nil {
		t.Fatalf("MaskImage: %v", err)
	}
	y, err := wlm.Unmask(logits[0], img)
	if err != nil {
		t.Fatalf("Unmask: %v", err)
	}
	want := trustedops.ArgMax(wlm.Decode(y))
	if rc.Token != want {
		t.Fatalf("argmax token=%d != 期望 %d", rc.Token, want)
	}
}

// TestRecomputeOpAndBatchBoundaries 未知算子与 batch 超上限的 fail-closed 边界（proto=2）。
func TestRecomputeOpAndBatchBoundaries(t *testing.T) {
	h := newV2Harness(t)

	// 未知算子 → 400（op 白名单在状态推进前拦截，独立审计码 recompute_unknown_op）
	bad := h.mkReq("foo", 0, h.nextCoord, [][]uint64{{1, 2, 3, 4}})
	resp, _ := h.post(bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知算子应 400, got %d", resp.StatusCode)
	}

	// batch 超上限（recomputeBatchLimit+1 行）→ 400（在签名之后、步执行之前拦截）
	bigBatch := make([][]uint64, recomputeBatchLimit+1)
	for i := range bigBatch {
		bigBatch[i] = []uint64{1, 2, 3, 4}
	}
	big := h.mkReq(route2plan.OpRMSNorm, 0, h.nextCoord, bigBatch)
	resp2, _ := h.post(big)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("batch 超限应 400, got %d", resp2.StatusCode)
	}

	// 边界被拒后会话状态不得被推进：合法首步照常成功
	x := make([]float64, h.cfg.Dim)
	for i := range x {
		x[i] = 0.01 * float64(i+1)
	}
	rc := h.step([][]uint64{h.inject(x)})
	if len(rc.Result) != 1 || len(rc.Result[0]) != h.cfg.Dim {
		t.Fatalf("边界拒绝后合法步应照常成功，结果形状: %d x %d", len(rc.Result), len(rc.Result[0]))
	}
}
