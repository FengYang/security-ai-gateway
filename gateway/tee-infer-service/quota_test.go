package main

// P1 token 配额管控测试：
// - 默认（配额 0 = 不限）正常推理
// - 设置配额后超限 → 429 + 审计 quota_exceeded
// - 解除配额（max_tokens<=0）恢复
// - /usage 响应含配额视图（quota / used_tokens）

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-ai-gateway/protocol/go"
)

// setQuota 经 admin 接口设置租户配额。
func setQuota(t *testing.T, ts *httptest.Server, tenant string, maxTokens int64) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"tenant": tenant, "max_tokens": maxTokens})
	req, _ := http.NewRequest("POST", ts.URL+"/usage/quota", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("设置配额失败: %d", resp.StatusCode)
	}
}

// quotaInfer 发起一次 text 推理请求，返回状态码。
func quotaInfer(t *testing.T, ts *httptest.Server, sessionID string, ksig, kenc []byte, text string, counter uint64) int {
	t.Helper()
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, text, protocol.EngineTypeTEEGPU, false, counter)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestQuotaDefaultUnlimited 默认配额（0）不限。
func TestQuotaDefaultUnlimited(t *testing.T) {
	_, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusOK {
		t.Fatalf("默认无配额应放行，got %d", code)
	}
}

// TestQuotaExceeded 设置配额后超限 → 429 + 审计 quota_exceeded；解除后恢复。
func TestQuotaExceeded(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)

	// 配额上限很小：1 个 token（"hello" 估算 = (5+3)/4 = 2 > 1 → 首请求即超限）
	setQuota(t, ts, "default", 1)
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusTooManyRequests {
		t.Fatalf("超配额应 429，got %d", code)
	}
	// 审计记录 quota_exceeded
	found := false
	for _, e := range srv.audit.query("") {
		if e.Action == "deny" && e.Result == "quota_exceeded" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("审计未记录 quota_exceeded")
	}
	// 解除配额 → 恢复
	setQuota(t, ts, "default", 0)
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 2); code != http.StatusOK {
		t.Fatalf("解除配额后应恢复，got %d", code)
	}
}

// TestQuotaWithin 配额内正常（估算口径：4 字符 ≈ 1 token）。
func TestQuotaWithin(t *testing.T) {
	_, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	setQuota(t, ts, "default", 10)
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusOK {
		t.Fatalf("配额内应放行，got %d", code)
	}
}

// TestUsageQuotaView /usage 响应含配额视图。
func TestUsageQuotaView(t *testing.T) {
	_, ts := newM9Server(t)
	setQuota(t, ts, "acme", 1000)
	resp, err := http.Get(ts.URL + "/usage?tenant=acme")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]struct {
		Quota      int64 `json:"quota"`
		UsedTokens int64 `json:"used_tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	v, ok := out["acme"]
	if !ok {
		t.Fatal("usage 响应缺租户")
	}
	if v.Quota != 1000 {
		t.Fatalf("quota 视图异常: %+v", v)
	}
}

// TestQuotaConcurrent 并发推理不超卖配额（配额 8；每请求消耗 in=1 + out=1 = 2，4 并发全过）。
func TestQuotaConcurrent(t *testing.T) {
	_, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	setQuota(t, ts, "default", 8) // 4 请求 × (in 1 + out 1) = 8
	done := make(chan int, 4)
	for i := 0; i < 4; i++ {
		i := i // 循环变量捕获
		go func() {
			hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "ab", protocol.EngineTypeTEEGPU, false, uint64(i+1))
			resp, err := http.DefaultClient.Do(hr)
			if err != nil {
				done <- -1
				return
			}
			code := resp.StatusCode
			resp.Body.Close()
			done <- code
		}()
	}
	time.Sleep(200 * time.Millisecond) // 等待并发完成（httptest 同步处理）
	for i := 0; i < 4; i++ {
		if code := <-done; code != http.StatusOK {
			t.Fatalf("配额内并发应全部放行，got %d", code)
		}
	}
}
