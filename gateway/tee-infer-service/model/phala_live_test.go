package model

// Phala Cloud 密态推理真连测试（环境变量门控，默认 skip）。
// 运行：PHALA_API_KEY=<key> go test ./model -run TestPhalaLiveGenerate -v
// key 只经环境变量传入，绝不写入文件或提交。

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPhalaLiveGenerate 真连 Phala 密态网关：流式生成 + 证明回执捕获与验证。
// 验证点：① Bearer 鉴权与 OpenAI 兼容路径 ② X-Receipt-Id 响应头捕获
// ③ GET /v1/aci/receipts/{id} 回执验证落 LastAttestation。
func TestPhalaLiveGenerate(t *testing.T) {
	key := os.Getenv("PHALA_API_KEY")
	if key == "" {
		t.Skip("PHALA_API_KEY 未设置，跳过真连测试")
	}
	// 引擎契约只取 delta.content（reasoning_content 为模型内部思考流，不透传）。
	// 真连模型用非推理 instruct 模型；qwen3.5-27b 在 Phala 为深思考形态，
	// 内容全走 reasoning_content 且预算易耗尽，不适合作为 content 路径验证。
	eng := NewCmaasEngine("https://inference.phala.com", key, "meta-llama/llama-3.3-70b-instruct")
	var got string
	done := make(chan error, 1)
	go func() {
		done <- eng.Generate(GenerateRequest{
			Messages:  []ChatMessage{{Role: "user", Content: "用一句话说明机密计算"}},
			MaxTokens: 128,
		}, func(delta string) error {
			got += delta
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("真连 Generate 失败: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("真连 Generate 超时（90s）")
	}
	t.Logf("生成内容（前 120 字）: %s", got)
	if strings.TrimSpace(got) == "" {
		t.Fatal("流式输出为空")
	}

	ref := eng.LastAttestation()
	t.Logf("证明回执引用: %q", ref)
	if ref == "" {
		t.Fatal("未捕获 Phala 证明回执（X-Receipt-Id 缺失）")
	}
	if !strings.HasPrefix(ref, "phala-receipt:") {
		t.Fatalf("回执引用格式不符: %q", ref)
	}
	// 回执验证结果记录（verified=true 为预期；false/fetch-error 时打印供排查）
	if !strings.HasSuffix(ref, ":verified=true") {
		t.Logf("注意：回执未达 verified=true，引用 = %q（审计链已如实记录）", ref)
	}
}

// TestPhalaLiveRawDump 诊断用：打印原始 SSE 帧前若干行（确认分片结构与 X-Receipt-Id）。
func TestPhalaLiveRawDump(t *testing.T) {
	key := os.Getenv("PHALA_API_KEY")
	if key == "" {
		t.Skip("PHALA_API_KEY 未设置，跳过真连测试")
	}
	_ = NewCmaasEngine("https://inference.phala.com", key, "meta-llama/llama-3.3-70b-instruct") // 构造可用性自检
	client := &http.Client{Timeout: 60 * time.Second}
	body := `{"model":"meta-llama/llama-3.3-70b-instruct","messages":[{"role":"user","content":"hi"}],"max_tokens":32,"stream":true}`
	req, _ := http.NewRequest(http.MethodPost, "https://inference.phala.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("HTTP %d; X-Receipt-Id=%q; X-ACI-Identity=%q; Content-Type=%q",
		resp.StatusCode, resp.Header.Get("X-Receipt-Id"), resp.Header.Get("X-ACI-Identity"), resp.Header.Get("Content-Type"))
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<21))
	var nReason, nContent int
	var contentSample []string
	var lines []string
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "data:") {
			continue
		}
		lines = append(lines, ln)
		if ln == "data: [DONE]" {
			continue
		}
		var probe struct {
			Choices []struct {
				Delta struct {
					ReasoningContent *string `json:"reasoning_content"`
					Content          string  `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(ln, "data: ")), &probe) != nil || len(probe.Choices) == 0 {
			continue
		}
		d := probe.Choices[0].Delta
		if d.ReasoningContent != nil && *d.ReasoningContent != "" {
			nReason++
		}
		if d.Content != "" {
			nContent++
			if len(contentSample) < 3 {
				contentSample = append(contentSample, d.Content)
			}
		}
	}
	t.Logf("data 帧总数=%d; reasoning_content 帧=%d; content 帧=%d; content 样本=%q",
		len(lines), nReason, nContent, contentSample)
	for i, ln := range lines {
		if i < 3 || i >= len(lines)-5 {
			if len(ln) > 300 {
				ln = ln[:300] + "...(截断)"
			}
			t.Logf("RAW[%02d] %s", i, ln)
		}
	}
}
