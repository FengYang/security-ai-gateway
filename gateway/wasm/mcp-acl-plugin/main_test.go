package main

import (
	"encoding/json"
	"testing"
)

// TestDecideMethodClassification 决策分类矩阵（无 hostcall 的纯逻辑路径）。
func TestDecideMethodClassification(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		wantAllow  bool
		wantReason string
	}{
		{"tools/call 且缓存未装配 → fail-closed", "tools/call", false, "policy_unavailable"},
		{"tools/list 放行", "tools/list", true, ""},
		{"initialize 放行", "initialize", true, ""},
		{"notifications/initialized 放行", "notifications/initialized", true, ""},
		{"server/discover 放行", "server/discover", true, ""},
		{"resources/read 放行", "resources/read", true, ""},
		{"缺 Mcp-Method 拒绝", "", false, "missing_method"},
		{"大小写变体拒绝（非规范方法名）", "Tools/Call", false, "method_not_allowed"},
		{"未知方法拒绝", "tools/delete", false, "method_not_allowed"},
	}
	for _, tc := range cases {
		allow, reason := decide(tc.method, "t-a", "list_tables", nil)
		if allow != tc.wantAllow || reason != tc.wantReason {
			t.Fatalf("%s: got(allow=%v,reason=%q) want(allow=%v,reason=%q)",
				tc.name, allow, reason, tc.wantAllow, tc.wantReason)
		}
	}
}

// TestDenyBodyContract 拒绝响应契约（C-MCP-2 §5.7.3 分层 + 统一码防 oracle）。
func TestDenyBodyContract(t *testing.T) {
	var body struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(denyBody), &body); err != nil {
		t.Fatalf("denyBody 非法 JSON: %v", err)
	}
	if body.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc=%q（want 2.0）", body.JSONRPC)
	}
	if string(body.ID) != "null" {
		t.Fatalf("id=%s（want null：插件不读 body，无法回显请求 id）", body.ID)
	}
	if body.Error.Code != -32602 {
		t.Fatalf("error.code=%d（want -32602：统一码，避免 oracle 区分 ACL 与 schema）", body.Error.Code)
	}
}

// TestNonCallMethodsAreExplicit 白名单为显式枚举：核心方法必须在列（防手误删）。
func TestNonCallMethodsAreExplicit(t *testing.T) {
	for _, m := range []string{
		"initialize", "ping", "tools/list", "resources/list", "prompts/list",
		"server/discover", "notifications/initialized",
	} {
		if _, ok := nonCallMethods[m]; !ok {
			t.Fatalf("非调用方法白名单缺 %s", m)
		}
	}
	if _, ok := nonCallMethods[methodToolsCall]; ok {
		t.Fatalf("%s 不得进入非调用白名单", methodToolsCall)
	}
}
