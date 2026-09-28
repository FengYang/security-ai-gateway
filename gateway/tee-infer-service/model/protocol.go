// Package model — 多模型协议适配（GF.3.2）
//
// 入站协议统一：Anthropic Messages API / Gemini generateContent → 网关内部 text 载荷
// （OpenAI 兼容 ChatMessage）。转换在网关边缘完成，产出统一 text 载荷进入段① 加密链，
// 引擎路由不变（tee_gpu / cmaas）。协议映射表见 docs/GF3-多模型协议映射表.md。
//
// fail-closed：转换失败（缺 role / 缺 content / 空 messages）返回 error，上层拒绝，
// 绝不产出半结构化明文。
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 角色归一化：Anthropic/Gemini 角色 → OpenAI 角色。
// 未知角色保守拒绝（fail-closed），避免静默丢语义。
func normalizeRole(role string) (string, error) {
	switch role {
	case "user", "human":
		return "user", nil
	case "assistant", "model", "bot":
		return "assistant", nil
	case "system", "developer":
		return "system", nil
	default:
		return "", fmt.Errorf("protocol: 未知消息角色 %q", role)
	}
}

// ---------- Anthropic Messages API ----------

type anthropicRequest struct {
	System   string `json:"system"` // 可选：系统提示词（顶层字段）
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"` // string 或 [{type:"text",text:"..."}]
	} `json:"messages"`
	// X-2 / T6：工具定义（tool spec）——输入侧 guardrail 需审查工具描述中的文本
	Tools json.RawMessage `json:"tools,omitempty"`
}

// anthropicText 从 content（string 或 text block 数组）提取纯文本。
func anthropicText(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", errors.New("protocol: Anthropic content 既非字符串亦非文本块数组")
	}
	var out string
	for _, b := range blocks {
		if b.Type == "text" {
			out += b.Text
		}
		// 非文本块（image/tool_use 等）跳过；多模态由文本与工具调用另行处理
	}
	return out, nil
}

// AnthropicToolFields 从 Anthropic Messages 请求中提取需输入侧审查的工具相关文本字段。
// 含 tool_spec（工具定义描述）和 tool_result（用户侧工具调用结果内容）。
// 所有字段拼接成纯文本，供 guardrail 统一检查。
// 返回 map[field]text：field = tool_spec | tool_result。
func AnthropicToolFields(raw []byte) (map[string]string, error) {
	var req anthropicRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("protocol: Anthropic 请求解析失败: %w", err)
	}
	fields := make(map[string]string)

	// tool_spec：从 tools 数组提取 name + description + input_schema 描述
	if len(req.Tools) > 0 {
		var tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			InputSchema struct {
				Properties map[string]struct {
					Description string `json:"description"`
					Type        string `json:"type"`
				} `json:"properties"`
			} `json:"input_schema"`
		}
		if err := json.Unmarshal(req.Tools, &tools); err == nil {
			var sb strings.Builder
			for _, t := range tools {
				sb.WriteString(t.Name)
				sb.WriteString(": ")
				sb.WriteString(t.Description)
				sb.WriteString("\n")
				for _, p := range t.InputSchema.Properties {
					sb.WriteString("  - ")
					sb.WriteString(p.Description)
					sb.WriteString("\n")
				}
			}
			fields["tool_spec"] = sb.String()
		}
	}

	// tool_result：从 messages 的 user 消息中提取 type=tool_result 块的内容
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		var blocks []struct {
			Type      string          `json:"type"`
			Content   json.RawMessage `json:"content"` // string 或 [{type:text,text:...}]
			ToolUseID string          `json:"tool_use_id,omitempty"`
		}
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			continue // 不是块数组（纯文本），跳过
		}
		var sb strings.Builder
		for _, b := range blocks {
			if b.Type != "tool_result" {
				continue
			}
			// content 可能是 string 或 text block 数组
			if s, err := anthropicText(b.Content); err == nil {
				sb.WriteString(s)
				sb.WriteString("\n")
			}
		}
		if sb.Len() > 0 {
			if existing, ok := fields["tool_result"]; ok {
				fields["tool_result"] = existing + sb.String()
			} else {
				fields["tool_result"] = sb.String()
			}
		}
	}

	return fields, nil
}

// ConvertAnthropicMessages 将 Anthropic Messages API 请求体转为网关内部 text 载荷。
// system 顶层字段 → 首条 system 消息；messages 逐条归一化 role/content。
func ConvertAnthropicMessages(raw []byte) ([]ChatMessage, error) {
	var req anthropicRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("protocol: Anthropic 请求解析失败: %w", err)
	}
	if len(req.Messages) == 0 {
		return nil, errors.New("protocol: Anthropic messages 为空（fail-closed）")
	}
	msgs := make([]ChatMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, ChatMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		role, err := normalizeRole(m.Role)
		if err != nil {
			return nil, err
		}
		text, err := anthropicText(m.Content)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, ChatMessage{Role: role, Content: text})
	}
	return msgs, nil
}

// ---------- Gemini generateContent ----------

type geminiRequest struct {
	SystemInstruction *struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"systemInstruction"`
	Contents []struct {
		Role  string `json:"role"`
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"contents"`
}

// ConvertGeminiMessages 将 Gemini generateContent 请求体转为网关内部 text 载荷。
// role: user→user, model→assistant；systemInstruction → 首条 system 消息。
func ConvertGeminiMessages(raw []byte) ([]ChatMessage, error) {
	var req geminiRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("protocol: Gemini 请求解析失败: %w", err)
	}
	if len(req.Contents) == 0 {
		return nil, errors.New("protocol: Gemini contents 为空（fail-closed）")
	}
	msgs := make([]ChatMessage, 0, len(req.Contents)+1)
	if req.SystemInstruction != nil {
		var sys string
		for _, p := range req.SystemInstruction.Parts {
			sys += p.Text
		}
		if sys != "" {
			msgs = append(msgs, ChatMessage{Role: "system", Content: sys})
		}
	}
	for _, c := range req.Contents {
		role, err := normalizeRole(c.Role)
		if err != nil {
			return nil, err
		}
		var text string
		for _, p := range c.Parts {
			text += p.Text
		}
		msgs = append(msgs, ChatMessage{Role: role, Content: text})
	}
	return msgs, nil
}
