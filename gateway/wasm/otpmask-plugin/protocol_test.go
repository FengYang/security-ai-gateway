package main

// GF3.2 对齐1：文本请求双形态（messages 优先 / text 回退）与 fail-closed 解析测试。

import (
	"encoding/json"
	"testing"
)

func TestParseTextRequestMessages(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"}],"stream":true,"engine_type":"tee_gpu"}`)
	req, err := parseTextRequest(body)
	if err != nil {
		t.Fatalf("parseTextRequest messages 应成功: %v", err)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("Messages 长度应为 2，got %d", len(req.Messages))
	}
	if req.Messages[0].Role != "system" || req.Messages[1].Content != "hi" {
		t.Fatalf("Messages 内容不符: %+v", req.Messages)
	}
	if req.EngineType != "tee_gpu" {
		t.Fatalf("EngineType 未透传: %q", req.EngineType)
	}
}

func TestParseTextRequestTextFallback(t *testing.T) {
	req, err := parseTextRequest([]byte(`{"text":"hello"}`))
	if err != nil {
		t.Fatalf("text 回退应成功: %v", err)
	}
	if req.Text != "hello" {
		t.Fatalf("Text 不符: %q", req.Text)
	}
	if len(req.Messages) != 0 {
		t.Fatalf("text 形态 Messages 应为空: %+v", req.Messages)
	}
}

func TestParseTextRequestUnknownRole(t *testing.T) {
	body := []byte(`{"messages":[{"role":"tool","content":"x"}]}`)
	if _, err := parseTextRequest(body); err == nil {
		t.Fatal("未知角色应 fail-closed（拒绝）")
	}
}

func TestParseTextRequestBothEmpty(t *testing.T) {
	if _, err := parseTextRequest([]byte(`{}`)); err == nil {
		t.Fatal("既无 text 也无 messages 应失败")
	}
}

// TestMarshalMessagesMessages marshalMessages 在 messages 模式下原样透传。
func TestMarshalMessagesMessages(t *testing.T) {
	req := &textRequest{Messages: []chatMsg{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "hi"},
	}}
	b, err := marshalMessages(req)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []chatMsg
	if err := json.Unmarshal(b, &msgs); err != nil {
		t.Fatalf("输出不是合法 messages JSON: %v", err)
	}
	if len(msgs) != 2 || msgs[0].Role != "system" || msgs[1].Content != "hi" {
		t.Fatalf("messages 透传不符: %+v", msgs)
	}
}

// TestMarshalMessagesTextFallback marshalMessages 在 text 模式下回退为单 user。
func TestMarshalMessagesTextFallback(t *testing.T) {
	req := &textRequest{Text: "hello"}
	b, err := marshalMessages(req)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []chatMsg
	if err := json.Unmarshal(b, &msgs); err != nil {
		t.Fatalf("输出不是合法 messages JSON: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Role != "user" || msgs[0].Content != "hello" {
		t.Fatalf("text 回退不符: %+v", msgs)
	}
}