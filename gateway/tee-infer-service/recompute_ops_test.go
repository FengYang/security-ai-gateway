// recompute_ops_test.go - 补算服务扩展算子测试（rmsnorm / argmax / 边界）
package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestRecomputeRMSNormArgMax 覆盖新增算子 rmsnorm / argmax 与边界校验
func TestRecomputeRMSNormArgMax(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, _ := setupTestSession(t, ts)

	// rmsnorm（layer 0，Gamma 全 1 → 输出为归一化值）
	reqRMS := &recomputeRequest{
		RequestID: "rc-rms-1", Layer: 0, Op: "rmsnorm",
		Batch:       [][]uint64{{100, 200, 300, 400, 500, 600, 700, 800}},
		MaskVersion: 0,
		Gamma:       []float64{1, 1, 1, 1, 1, 1, 1, 1},
	}
	hr := buildRecomputeReq(ts.URL+"/v1/recompute", sessionID, ksig, reqRMS)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("rmsnorm 应 200, got %d", resp.StatusCode)
	}
	var rcRMS recomputeResponse
	if err := json.NewDecoder(resp.Body).Decode(&rcRMS); err != nil {
		t.Fatalf("rmsnorm 解析失败: %v", err)
	}
	if len(rcRMS.Result) != 1 || len(rcRMS.Result[0]) != 8 {
		t.Fatalf("rmsnorm 结果形状错误: %d x %d", len(rcRMS.Result), len(rcRMS.Result[0]))
	}
	if rcRMS.MaskNext == "" {
		t.Fatal("rmsnorm 应返回 mask_next 指纹")
	}

	// argmax（layer 1，P4 采样确认：返回单元素 token 向量）
	reqAM := &recomputeRequest{
		RequestID: "rc-am-1", Layer: 1, Op: "argmax",
		Batch:       [][]uint64{{100, 200, 300, 400, 500, 600, 700, 800}},
		MaskVersion: 0,
	}
	ha := buildRecomputeReq(ts.URL+"/v1/recompute", sessionID, ksig, reqAM)
	respA, err := http.DefaultClient.Do(ha)
	if err != nil {
		t.Fatal(err)
	}
	defer respA.Body.Close()
	if respA.StatusCode != 200 {
		t.Fatalf("argmax 应 200, got %d", respA.StatusCode)
	}
	var rcAM recomputeResponse
	if err := json.NewDecoder(respA.Body).Decode(&rcAM); err != nil {
		t.Fatalf("argmax 解析失败: %v", err)
	}
	if len(rcAM.Result) != 1 || len(rcAM.Result[0]) != 1 {
		t.Fatalf("argmax 结果应为单 token 向量, got %v", rcAM.Result)
	}

	// 未知算子 → 400
	reqBad := &recomputeRequest{
		RequestID: "rc-bad-1", Layer: 2, Op: "foo",
		Batch: [][]uint64{{1, 2, 3, 4, 5, 6, 7, 8}}, MaskVersion: 0,
	}
	hb := buildRecomputeReq(ts.URL+"/v1/recompute", sessionID, ksig, reqBad)
	respB, err := http.DefaultClient.Do(hb)
	if err != nil {
		t.Fatal(err)
	}
	respB.Body.Close()
	if respB.StatusCode != 400 {
		t.Fatalf("未知算子应 400, got %d", respB.StatusCode)
	}

	// batch 超上限 → 400（4097 行）
	bigBatch := make([][]uint64, recomputeBatchLimit+1)
	for i := range bigBatch {
		bigBatch[i] = []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	}
	reqBig := &recomputeRequest{
		RequestID: "rc-big-1", Layer: 3, Op: "gelu",
		Batch: bigBatch, MaskVersion: 0,
	}
	hg := buildRecomputeReq(ts.URL+"/v1/recompute", sessionID, ksig, reqBig)
	respG, err := http.DefaultClient.Do(hg)
	if err != nil {
		t.Fatal(err)
	}
	respG.Body.Close()
	if respG.StatusCode != 400 {
		t.Fatalf("batch 超限应 400, got %d", respG.StatusCode)
	}

	_ = srv
}
