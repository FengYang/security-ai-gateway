package main

// M1 验收：路线2 服务侧 Mod64 接线端到端正确性。
// 复用与 handler 完全一致的掩码流派生（同会话 seed + route2MaskModulus + 同 domain），
// 独立构造 yCipher = W·(xMask + r) mod 2^64 经 /v1/recompute(gelu) 后，
// 用 handler 同款 nextStream 还原 rNext 并独立重算期望结果，逐位比对。
//
// 这是最强断言：任一环节若仍走 Mod32 兼容垫片（旧 bug），掩码流 r/rNext 将为 mod 2^32、
// Unmask/Remask 将 mod 2^32，与本测试基于 route2MaskModulus(=2^64-1) 的独立重算结果不一致，
// 从而精准暴露 M1 接线是否真的生效。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/gateway/teecore/maskedinfer"
)

// TestM1RecomputeMod64 路线2 服务侧 Mod64 接线端到端验收（M1）。
func TestM1RecomputeMod64(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, _ := setupTestSession(t, ts)

	dim := 8
	layer := 0

	// 取 Mod64 权重矩阵（mockWeightProvider 已改为 NewQuantizedMatrixMod(..., Mod64)）
	weights, err := srv.weightProvider.LayerWeight(layer)
	if err != nil {
		t.Fatalf("LayerWeight: %v", err)
	}
	if weights.ModBits != maskedinfer.Mod64 {
		t.Fatalf("M1 期望 Mod64 权重，实际 %v", weights.ModBits)
	}

	// 小输入 x（float），使 xMask 不溢出 R/2，避免符号还原误判
	x := make([]float64, dim)
	for i := range x {
		x[i] = (float64(i) - float64(dim)/2) * 0.05
	}

	// 复现 handler 的掩码流 seed（同会话、同 route2MaskModulus）
	seedReq, _ := http.NewRequest("GET", "/", nil)
	seedReq.Header.Set("X-Session-ID", sessionID)
	seed, serr := srv.sessionSeed(seedReq)
	if serr != nil {
		t.Fatalf("sessionSeed: %v", serr)
	}
	defer wipe(seed)

	layerDomain := fmt.Sprintf("otpmask/layer/%d/v1", layer)
	stream, err := newLayerStream(seed, route2MaskModulus, []byte(layerDomain))
	if err != nil {
		t.Fatalf("newLayerStream(layer): %v", err)
	}
	r := make([]uint64, dim)
	for i := range r {
		r[i] = stream.Next() % route2MaskModulus
	}

	// 构造 yCipher = W·(xMask + r) mod 2^64（无 TEE 加速器时由测试侧等价模拟）
	xMask := weights.ToMaskDomain(x) // round(x*S) mod R
	V := make([]uint64, dim)
	for i := range V {
		V[i] = xMask[i] + r[i] // uint64 自然回绕 = mod 2^64（Mod64）
	}
	ycOut, err := weights.CipherLinear([][]uint64{V})
	if err != nil {
		t.Fatalf("CipherLinear: %v", err)
	}
	yCipher := ycOut[0]

	// 发请求
	req := &recomputeRequest{
		RequestID:   "m1-mod64-1",
		Layer:       layer,
		Op:          "gelu",
		Batch:       [][]uint64{yCipher},
		MaskVersion: 0,
	}
	hr := buildRecomputeReq(ts.URL+"/v1/recompute", sessionID, ksig, req)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatalf("recompute 请求: %v", err)
	}
	var rc recomputeResponse
	if err := json.NewDecoder(resp.Body).Decode(&rc); err != nil {
		t.Fatalf("响应解析: %v", err)
	}
	resp.Body.Close()
	if rc.RequestID != req.RequestID || len(rc.Result) != 1 || len(rc.Result[0]) != dim {
		t.Fatalf("响应异常: %+v", rc)
	}

	// 复现 handler 的 rNext（同 nextStream，单 batch 首段消费顺序）
	nextDomain := fmt.Sprintf("otpmask/layer/%d/v1", layer+1)
	nextStream, err := newLayerStream(seed, route2MaskModulus, []byte(nextDomain))
	if err != nil {
		t.Fatalf("newLayerStream(next): %v", err)
	}
	rNext := make([]uint64, dim)
	for i := range rNext {
		rNext[i] = nextStream.Next() % route2MaskModulus
	}

	// 独立以 handler 等价方式计算期望结果（整数精确，应与服务端逐位相等）
	// 1) W·xMask（精确整数累加），再按 Decode 语义还原为线性真值浮点
	xmSigned := weights.SignedVector(xMask)
	yLinear := make([]float64, dim)
	for i := 0; i < dim; i++ {
		var acc int64
		for j := 0; j < dim; j++ {
			acc += int64(weights.Data[i*dim+j]) * xmSigned[j]
		}
		yLinear[i] = float64(acc) * weights.Scale / weights.InputScale
	}
	// 2) GELU 非线性 + 定点化（ToMaskDomain 尊重 Mod64 + InputScale=1e6）
	expectedFY := make([]uint64, dim)
	for i := range yLinear {
		yLinear[i] = teecore.GELU(yLinear[i])
		expectedFY[i] = weights.ToMaskDomain([]float64{yLinear[i]})[0]
	}
	// 3) 重掩码（同 rNext，Mod64）
	expectedResult, err := weights.Remask(expectedFY, rNext)
	if err != nil {
		t.Fatalf("Remask(expected): %v", err)
	}

	for i := range rc.Result[0] {
		if rc.Result[0][i] != expectedResult[i] {
			t.Fatalf("dim %d: 服务端结果 %d != 期望 %d（Mod64 路径不一致，可能 M1 未生效）",
				i, rc.Result[0][i], expectedResult[i])
		}
	}
	t.Logf("M1 Mod64 端到端逐位一致通过：result=%v", rc.Result[0])
}
