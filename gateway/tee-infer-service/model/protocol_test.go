package model

import "testing"

// TestConvertAnthropicMessages 覆盖 string/content 块数组/system 顶层字段。
func TestConvertAnthropicMessages(t *testing.T) {
	raw := []byte(`{
		"model": "claude-3-5-sonnet",
		"max_tokens": 1024,
		"system": "你是企业助手",
		"messages": [
			{"role": "user", "content": "你好"},
			{"role": "assistant", "content": [{"type": "text", "text": "你好，请问"}]},
			{"role": "user", "content": [{"type": "text", "text": "帮我"}, {"type": "image", "source": {}}]}
		]
	}`)
	msgs, err := ConvertAnthropicMessages(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("应 4 条（system+3 消息），got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "你是企业助手" {
		t.Fatalf("system 映射失败: %+v", msgs[0])
	}
	if msgs[1].Role != "user" || msgs[1].Content != "你好" {
		t.Fatalf("string content 映射失败: %+v", msgs[1])
	}
	if msgs[2].Role != "assistant" || msgs[2].Content != "你好，请问" {
		t.Fatalf("text block 映射失败: %+v", msgs[2])
	}
	// 第 3 条：image block 应被跳过，仅保留 text "帮我"
	if msgs[3].Content != "帮我" {
		t.Fatalf("多 block 文本拼接失败: %+v", msgs[3])
	}
}

// TestConvertAnthropicEmpty 空 messages fail-closed。
func TestConvertAnthropicEmpty(t *testing.T) {
	if _, err := ConvertAnthropicMessages([]byte(`{"messages":[]}`)); err == nil {
		t.Fatal("空 messages 应报错")
	}
}

// TestConvertAnthropicUnknownRole 未知角色 fail-closed。
func TestConvertAnthropicUnknownRole(t *testing.T) {
	raw := []byte(`{"messages":[{"role":"weird","content":"x"}]}`)
	if _, err := ConvertAnthropicMessages(raw); err == nil {
		t.Fatal("未知角色应报错")
	}
}

// TestConvertGeminiMessages 覆盖 systemInstruction / user / model 角色。
func TestConvertGeminiMessages(t *testing.T) {
	raw := []byte(`{
		"contents": [
			{"role": "user", "parts": [{"text": "问题"}]},
			{"role": "model", "parts": [{"text": "回答"}]}
		],
		"systemInstruction": {"parts": [{"text": "你是助手"}]}
	}`)
	msgs, err := ConvertGeminiMessages(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("应 3 条，got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "你是助手" {
		t.Fatalf("systemInstruction 映射失败: %+v", msgs[0])
	}
	if msgs[1].Role != "user" || msgs[1].Content != "问题" {
		t.Fatalf("user 映射失败: %+v", msgs[1])
	}
	if msgs[2].Role != "assistant" || msgs[2].Content != "回答" {
		t.Fatalf("model→assistant 映射失败: %+v", msgs[2])
	}
}

// TestConvertGeminiEmpty 空 contents fail-closed。
func TestConvertGeminiEmpty(t *testing.T) {
	if _, err := ConvertGeminiMessages([]byte(`{"contents":[]}`)); err == nil {
		t.Fatal("空 contents 应报错")
	}
}
