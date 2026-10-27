package confllm

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConfigRejectsLiteralKey P0-4③：字面量 key 必须被拦截（fail-closed）。
//
// 断言三件事：
//  1. 含字面量 key → ValidateConfig 返回 invalid_secret_literal（拒绝启动）；
//  2. 错误信息**不回显** key 原文（§7.2：凭据绝不进日志/错误报文）；
//  3. 走 SecretRef 的正常配置必须通过（不得误伤）。
func TestConfigRejectsLiteralKey(t *testing.T) {
	const literal = "sk-SECRET_CANARY_9f3a"

	// 1) 字面量 key → 拒绝，且错误码为 invalid_secret_literal。
	err := ValidateConfig(ProviderConfig{ID: "p-literal", LiteralKey: literal})
	if err == nil {
		t.Fatal("期望 ValidateConfig 拒绝字面量 key（fail-closed），实际返回 nil")
	}
	if pe := ParseError(err); pe.Code != CodeInvalidSecretLiteral {
		t.Fatalf("期望错误码 %s，实际 %s（%v）", CodeInvalidSecretLiteral, pe.Code, err)
	}
	// 2) 错误信息不得回显凭据原文。
	if strings.Contains(err.Error(), literal) {
		t.Fatalf("错误报文不得回显 key 原文（§7.2）：%v", err)
	}
	// 脱敏 body 同样不得含原文。
	raw, merr := json.Marshal(ParseError(err).SanitizedBody())
	if merr != nil {
		t.Fatalf("序列化 SanitizedBody 失败：%v", merr)
	}
	if strings.Contains(string(raw), literal) {
		t.Fatalf("SanitizedBody 不得含 key 原文：%s", string(raw))
	}

	// 3) 正常配置（走 SecretRef，无字面量）必须通过。
	if err := ValidateConfig(ProviderConfig{
		ID:        "p-secretref",
		SecretRef: SecretRef{Name: "broker.env:KEY"},
	}); err != nil {
		t.Fatalf("无字面量 key 的配置应通过，实际被拒：%v", err)
	}

	// 4) 空白/空白字符也应视为「无字面量」（TrimSpace 语义）。
	if err := ValidateConfig(ProviderConfig{ID: "p-blank", LiteralKey: "   "}); err != nil {
		t.Fatalf("纯空白 LiteralKey 应视为空并通过，实际被拒：%v", err)
	}
}
