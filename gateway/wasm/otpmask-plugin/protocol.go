package main

import (
	"encoding/json"
	"fmt"
)

// mock 加解密协议（M4 版本，技术方案 南向协议的前身）。
//
// 请求路径（客户端 → 网关 → mock vLLM）：
//
//	文本请求：  {"text": "hello world"}                    （Agent 原始输入，M4）
//	向量请求：  {"vectors": [[1,2,3], ...]}                （M2/M3 兼容输入）
//	密文请求：  {"cipher_vectors": [[...]], "nonce": "hex", "model": "mock"}
//
// 响应路径（mock vLLM → 网关 → 客户端）：
//
//	密文响应：  {"cipher_output": [...], "nonce": "hex"}
//	明文响应：  {"output": [...], "tokens": [...], "text": "..."}   （M4 含文本还原）
//
// embedding-service 响应：
//
//	{"tokens": [...], "vectors": [[...]]}

// plainRequest 明文请求（向量输入，M2/M3 兼容）。
type plainRequest struct {
	Vectors [][]uint64 `json:"vectors"`
}

// chatMsg 消息项（统一 text 载荷 = OpenAI messages；与 tee-infer-service/model.ChatMessage JSON 同构，
// 见 tee-infer-service/main.go handleTextInfer json.Unmarshal 消费）。不改 import，避免 wasm 膨胀/耦合。
// P1-1 G-8 / M8-1：扩展 tool_calls/tool_call_id（承载模型发起的工具调用与工具结果）。
// 向后兼容：缺省无这些字段时序列化逐字节不变（omitempty）。
type chatMsg struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

// chatToolCall 模型发起的工具调用（与 tee-infer-service/model.ToolCall 同构；M8-1）。
type chatToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function chatToolCallFunc `json:"function"`
}

// chatToolCallFunc 工具调用函数体：name + JSON 字符串形态的 arguments。
type chatToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// textRequest 明文请求（文本输入，M4；P2 扩展可选 stream/engine_type）。
// 统一 text 载荷（对齐1）：Messages 为优先形态（OpenAI messages），Text 为既有单 text 兼容回退。
type textRequest struct {
	Text string `json:"text"`
	// Messages 统一 text 载荷（OpenAI messages 数组，GF3.2 对齐1）。
	Messages []chatMsg `json:"messages,omitempty"`
	// Stream 流式响应（缺省 true：SSE 逐块；false = 聚合单响应）。
	Stream *bool `json:"stream,omitempty"`
	// EngineType 引擎类型（缺省 tee_gpu；cmaas = 百炼 C-MaaS，P5）。
	EngineType string `json:"engine_type,omitempty"`
}

// embedResponse embedding-service 响应。
type embedResponse struct {
	Tokens  []uint32   `json:"tokens"`
	Vectors [][]uint64 `json:"vectors"`
}

// cipherRequest 网关发往 mock vLLM 的密文请求。
type cipherRequest struct {
	CipherVectors [][]uint64 `json:"cipher_vectors"`
	Nonce         string     `json:"nonce"`
	Model         string     `json:"model"`
}

// cipherResponse mock vLLM 返回的密文响应。
type cipherResponse struct {
	CipherOutput []uint64 `json:"cipher_output"`
	Nonce        string   `json:"nonce"`
}

// plainResponse 网关返回客户端的明文响应。
type plainResponse struct {
	Output []uint64 `json:"output"`
	Tokens []uint32 `json:"tokens,omitempty"`
	Text   string   `json:"text,omitempty"`
}

// parsePlainRequest 解析向量明文请求（M2/M3 兼容）。
func parsePlainRequest(body []byte) (*plainRequest, error) {
	var req plainRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("otpmask: 解析明文请求失败: %w", err)
	}
	if len(req.Vectors) == 0 {
		return nil, fmt.Errorf("otpmask: 明文请求无 vectors")
	}
	for i, v := range req.Vectors {
		if len(v) == 0 {
			return nil, fmt.Errorf("otpmask: vectors[%d] 为空", i)
		}
	}
	return &req, nil
}

// validRole 角色白名单：system/user/assistant/tool；未知角色 fail-closed（M8-1 放开 tool）。
func validRole(r string) bool {
	return r == "system" || r == "user" || r == "assistant" || r == "tool"
}

// parseTextRequest 解析文本明文请求（双形态，统一 text 载荷 = OpenAI messages）：
//   - messages 优先：非空则逐项校验角色（未知角色 fail-closed），原样作为统一载荷；
//     M8-1：`tool` 角色已放开（承载工具结果），但须携带非空 `tool_call_id`（否则 fail-closed，
//     防无主结果注入）；`assistant.tool_calls` 随消息原样透传（由 TEE 内裁决）。
//   - 否则回退 text：兼容既有单 text 调用。
func parseTextRequest(body []byte) (*textRequest, error) {
	var req textRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("otpmask: 解析文本请求失败: %w", err)
	}
	if len(req.Messages) > 0 {
		for _, m := range req.Messages {
			if !validRole(m.Role) {
				return nil, fmt.Errorf("otpmask: 未知消息角色 %q（fail-closed）", m.Role)
			}
			if m.Role == "tool" && m.ToolCallID == "" {
				return nil, fmt.Errorf("otpmask: tool 角色缺 tool_call_id（fail-closed）")
			}
		}
		return &req, nil
	}
	if req.Text == "" {
		return nil, fmt.Errorf("otpmask: 文本请求既无 text 也无 messages")
	}
	return &req, nil
}

// marshalMessages 按双形态构造段① 内层 TextPayload（OpenAI messages，对齐1）：
// messages 优先整体透传；否则单 text 回退为单条 user（既有行为不变）。
func marshalMessages(req *textRequest) ([]byte, error) {
	if len(req.Messages) > 0 {
		return json.Marshal(req.Messages)
	}
	return json.Marshal([]chatMsg{{Role: "user", Content: req.Text}})
}

// parseEmbedResponse 解析 embedding-service 响应。
func parseEmbedResponse(body []byte) (*embedResponse, error) {
	var resp embedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("otpmask: 解析 embedding 响应失败: %w", err)
	}
	if len(resp.Vectors) == 0 {
		return nil, fmt.Errorf("otpmask: embedding 响应无 vectors")
	}
	return &resp, nil
}

// encodeCipherRequest 编码密文请求体。
func encodeCipherRequest(req *cipherRequest) ([]byte, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("otpmask: 编码密文请求失败: %w", err)
	}
	return data, nil
}

// parseCipherResponse 解析密文响应体。
func parseCipherResponse(body []byte) (*cipherResponse, error) {
	var resp cipherResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("otpmask: 解析密文响应失败: %w", err)
	}
	if resp.Nonce == "" || len(resp.CipherOutput) == 0 {
		return nil, fmt.Errorf("otpmask: 密文响应字段缺失（nonce/cipher_output）")
	}
	return &resp, nil
}

// encodePlainResponse 编码明文响应体。
func encodePlainResponse(out []uint64, tokens []uint32, text string) ([]byte, error) {
	data, err := json.Marshal(&plainResponse{Output: out, Tokens: tokens, Text: text})
	if err != nil {
		return nil, fmt.Errorf("otpmask: 编码明文响应失败: %w", err)
	}
	return data, nil
}
