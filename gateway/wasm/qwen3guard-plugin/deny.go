package main

import (
	"encoding/json"
	"fmt"
	"time"
)

type chatCompletionBody struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Usage   usageBody    `json:"usage"`
	// B1 强标标识（GB 45438-2025）顶层 chunk 注解；标准客户端忽略未知键。
	Label *labelMeta `json:"content_label,omitempty"`
}

// labelMeta B1 强标标识 chunk 注解（与 tee-infer chunkLabelMeta / otpmask chunkLabel 同构）。
// 不含文案（与 delta 冗余防漂移）、不含用户内容。
type labelMeta struct {
	Std      string `json:"std"`      // 标准号（默认 GB45438-2025）
	Position string `json:"position"` // head | repeat | tail
}

// B1 标识位置（qwen3guard 注入点恒为 head——流首注入，不重复）。
const labelPositionHead = "head"

type chatChoice struct {
	Index        int          `json:"index"`
	Message      *messageBody `json:"message,omitempty"`
	Delta        interface{}  `json:"delta,omitempty"`
	Logprobs     interface{}  `json:"logprobs"`
	FinishReason interface{}  `json:"finish_reason"`
}

type messageBody struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type usageBody struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func buildChatDenyBody(message string) []byte {
	body := chatCompletionBody{
		ID:      newDenyID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "from-security-guard",
		Choices: []chatChoice{
			{
				Index: 0,
				Message: &messageBody{
					Role:    "assistant",
					Content: message,
				},
				Logprobs:     nil,
				FinishReason: "stop",
			},
		},
		Usage: usageBody{},
	}
	data, _ := json.Marshal(body)
	return data
}

func buildStreamDenyBody(message string) []byte {
	return buildStreamDenyBodyWithLabel(message, nil)
}

// buildStreamDenyBodyWithLabel B1 on_deny 变体：拒答首帧携带强标标识 meta（label 非 nil 时）。
// 拒答文案是网关固定文本而非 AI 生成物，是否带标识属法务口径（D-LLM-6 未定），默认不带。
func buildStreamDenyBodyWithLabel(message string, label *labelMeta) []byte {
	id := newDenyID()
	created := time.Now().Unix()
	chunk := chatCompletionBody{
		ID:      id,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   "from-security-guard",
		Choices: []chatChoice{
			{
				Index: 0,
				Delta: map[string]string{
					"role":    "assistant",
					"content": message,
				},
				Logprobs:     nil,
				FinishReason: nil,
			},
		},
		Label: label,
	}
	end := chatCompletionBody{
		ID:      id,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   "from-security-guard",
		Choices: []chatChoice{
			{
				Index:        0,
				Delta:        map[string]string{},
				Logprobs:     nil,
				FinishReason: "stop",
			},
		},
		Usage: usageBody{},
	}

	chunkData, _ := json.Marshal(chunk)
	endData, _ := json.Marshal(end)
	return []byte(fmt.Sprintf("data: %s\n\ndata: %s\n\ndata: [DONE]\n\n", chunkData, endData))
}

// buildStreamLabelBody B1 流首标识帧：单 delta 帧（delta.content = 标识文案 + 顶层 label 注解），
// 无 [DONE]——流由后续内容帧继续，标识帧先行下发。仿 buildStreamDenyBody 帧形态。
// 标识文本是网关固定文本，不进入 ctxStreamPending/uncheckedText，天然不参与送检。
func buildStreamLabelBody(text string) []byte {
	chunk := chatCompletionBody{
		ID:      newDenyID(),
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   "from-security-guard",
		Choices: []chatChoice{
			{
				Index: 0,
				Delta: map[string]string{
					"role":    "assistant",
					"content": text,
				},
				Logprobs:     nil,
				FinishReason: nil,
			},
		},
		Label: &labelMeta{Std: defaultContentLabelStd, Position: labelPositionHead},
	}
	chunkData, _ := json.Marshal(chunk)
	return []byte(fmt.Sprintf("data: %s\n\n", chunkData))
}

func newDenyID() string {
	return fmt.Sprintf("chatcmpl-qwen3guard-%d", time.Now().UnixNano())
}
