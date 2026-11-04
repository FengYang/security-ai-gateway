// Package model — 推理引擎抽象（M12 vLLM 对接层；P2 升级：text 载荷流式生成）。
//
// Engine 接口把"TEE 内推理引擎"从 tee-infer 的本地确定性模型解耦为可插拔：
//   - LocalEngine（默认）：tee-infer 进程内的确定性演示模型（M7 既有行为）
//   - RemoteEngine：text 载荷下直连 vLLM OpenAI 兼容接口流式推理（P2，D1）；
//     vectors 载荷仍经 vLLM 适配器（gateway/vllm-adapter，路线 2 保留路径）
//   - CmaasEngine：百炼 Confidential MaaS（P5，engine_cmaas.go）
//
// 明文边界不变：向量/文本仅在 TEE 内明文域出现，Engine 是明文域内的推理后端。
package model

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"security-ai-gateway/gateway/modelengine"
)

// ---- 明文引擎契约（别名转发；权威定义在 gateway/modelengine）----
//
// 为什么用别名而不是各定义一份：`gateway/vllm-adapter` 是独立进程、不得 import 宿主包
// （方案 §8.2④），故契约必须落在两侧都能依赖的独立平面上；宿主侧保留同名别名，
// 既让既有 36 处 `model.Engine`/`model.ChatMessage` 调用点零改动，也保证两边是**同一类型**
// （不会出现"两套 Engine 靠断言互转"的隐性耦合）。

// Engine 明文域推理引擎（契约见 modelengine.Engine）。
type Engine = modelengine.Engine

// GenerateRequest text 载荷生成请求（明文域）。
type GenerateRequest = modelengine.GenerateRequest

// ChatMessage OpenAI 兼容消息（text 载荷，D1）；字段语义见 modelengine.ChatMessage。
type ChatMessage = modelengine.ChatMessage

// ToolCall 模型发起的工具调用（OpenAI 兼容 function 形态；M8-1）。
type ToolCall = modelengine.ToolCall

// ToolCallFunc 工具调用函数体：name + JSON 字符串形态的 arguments。
type ToolCallFunc = modelengine.ToolCallFunc

// upstreamHTTPTransport 上游模型出站 HTTP 传输。
// 默认 http.DefaultTransport（行为与现网逐字节一致）；tee-infer 在 tracing
// 初始化后经 SetUpstreamTransport 注入剥离追踪头的传输（§6.4 安全约束：
// traceparent/tracestate/x-request-id 不外泄至上游模型厂商）。
var upstreamHTTPTransport http.RoundTripper = http.DefaultTransport

// SetUpstreamTransport 设置上游模型出站传输（tee-infer 启动期调用一次；
// nil 时忽略，退回默认传输）。
func SetUpstreamTransport(t http.RoundTripper) {
	if t != nil {
		upstreamHTTPTransport = t
	}
}

// ensure *Model（= modelengine.Demo）implements Engine。
var _ Engine = (*Model)(nil)

// generateRequest / generateResponse vLLM 适配器明文接口（TEE 内部协议）。
type generateRequest struct {
	Vectors [][]float64 `json:"vectors,omitempty"`
	Text    string      `json:"text,omitempty"`
}

type generateResponse struct {
	Tokens []uint64 `json:"tokens"`
}

// RemoteEngine 远程推理（TEE 内，明文域）：
// - Predict（vectors，路线 2 保留）：经 vLLM 适配器 /generate
// - Generate（text，P2）：直连 vLLM OpenAI 兼容 /v1/chat/completions 流式
type RemoteEngine struct {
	baseURL string
	client  *http.Client
}

// NewRemoteEngine 构造远程引擎；baseURL 形如 http://vllm:8000（vLLM OpenAI 兼容服务）。
func NewRemoteEngine(baseURL string) *RemoteEngine {
	return &RemoteEngine{
		baseURL: baseURL,
		// 流式整体超时：单请求完整生成窗口（含逐块读，非空闲超时）
		// Transport：剥离追踪头的上游传输（§6.4；默认 http.DefaultTransport）。
		client: &http.Client{Timeout: 120 * time.Second, Transport: upstreamHTTPTransport},
	}
}

// Predict 远程推理：单向量 → token ID（适配器 batch 生成后取首个）。
func (r *RemoteEngine) Predict(x []float64) int {
	body, _ := json.Marshal(generateRequest{Vectors: [][]float64{x}})
	resp, err := r.client.Post(r.baseURL+"/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return -1 // 调用失败由上层 fail-closed 处理（不可信引擎不产生明文）
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	raw, _ := io.ReadAll(resp.Body)
	var gr generateResponse
	if err := json.Unmarshal(raw, &gr); err != nil || len(gr.Tokens) == 0 {
		return -1
	}
	return int(gr.Tokens[0])
}

// Generate vLLM OpenAI 兼容流式生成（/v1/chat/completions，SSE）。
func (r *RemoteEngine) Generate(req GenerateRequest, onDelta func(delta string) error) error {
	return StreamChat(r.client, r.baseURL+"/v1/chat/completions", nil, req, onDelta, nil)
}

// Close 预留（远程引擎无本地资源；真实 vLLM 场景可扩展会话管理）。
func (r *RemoteEngine) Close() error { return nil }

// ---------- OpenAI 兼容流式客户端（RemoteEngine / CmaasEngine 共享） ----------

// chatCompletionRequest OpenAI Chat Completions 请求体。
type chatCompletionRequest struct {
	Model     string        `json:"model"`
	Messages  []ChatMessage `json:"messages"`
	MaxTokens uint32        `json:"max_tokens,omitempty"`
	Stream    bool          `json:"stream"`
}

// chatStreamChunk OpenAI 流式分片（仅取 delta.content）。
type chatStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

// StreamChat OpenAI 兼容流式 Chat 调用（SSE 增量解析）。
// 任一失败（连接/超时/非 200/JSON 解析/流中断/[DONE] 缺失）→ error，
// 已回调的增量不回滚，由调用方 fail-closed 丢弃（不产出半截明文）。
// extraHeaders 为引擎特定请求头（如 CmaasEngine 的 Authorization）。
// onRespHeader 在确认 200 后、流消费前回调一次（可 nil）：CmaasEngine 据此捕获
// Phala 密态网关的证明回执头（x-receipt-id 等，流式响应体消费后无法回读）。
func StreamChat(client *http.Client, url string, extraHeaders [][2]string,
	req GenerateRequest, onDelta func(delta string) error,
	onRespHeader func(http.Header)) error {
	body, err := json.Marshal(chatCompletionRequest{
		Model: req.Model, Messages: req.Messages,
		MaxTokens: req.MaxTokens, Stream: true,
	})
	if err != nil {
		return fmt.Errorf("engine: 编码请求失败: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("engine: 构造请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	for _, h := range extraHeaders {
		httpReq.Header.Set(h[0], h[1])
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("engine: 引擎不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("engine: 引擎返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if onRespHeader != nil {
		onRespHeader(resp.Header)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	sawDone := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue // 空行/SSE 注释
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			sawDone = true
			break
		}
		var chunk chatStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			return fmt.Errorf("engine: 流分片 JSON 无效: %w", err)
		}
		if len(chunk.Choices) == 0 {
			continue // usage 等辅助帧
		}
		if d := chunk.Choices[0].Delta.Content; d != "" {
			if err := onDelta(d); err != nil {
				return err // 调用方中止（如客户端断连）
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("engine: 流读取中断: %w", err)
	}
	if !sawDone {
		return errors.New("engine: 流未正常终止（缺 [DONE]，fail-closed）")
	}
	return nil
}
