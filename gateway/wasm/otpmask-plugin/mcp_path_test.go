package main

import "testing"

// TestIsSecureMCPPathStr 校验 MCP 敏感轨路径判定（T-2：按路径分流，禁止内容嗅探）。
func TestIsSecureMCPPathStr(t *testing.T) {
	yes := []string{
		"/mcp-servers/secure-tools",
		"/mcp-servers/secure-tools/sse",
		"/mcp-servers/secure-tools/anything?x=1",
	}
	for _, p := range yes {
		if !isSecureMCPPathStr(p) {
			t.Errorf("期望 %q 属敏感轨 → true", p)
		}
	}
	no := []string{
		"",
		"/v1/infer",
		"/provider/openai",
		"/mcp-servers/public-tools",
		"/mcp-servers/secure-tool", // 前缀不完整
	}
	for _, p := range no {
		if isSecureMCPPathStr(p) {
			t.Errorf("期望 %q 非敏感轨 → false", p)
		}
	}
}

// TestSecureMCPPathPrefixMatchesIngress 固化前缀与 deploy/higress/ingress-mcp.yaml 的约定一致。
func TestSecureMCPPathPrefixMatchesIngress(t *testing.T) {
	if secureMCPPathPrefix != "/mcp-servers/secure-tools" {
		t.Fatalf("前缀漂移：%q（须与 ingress-mcp.yaml 的 mcp-secure-tools 路径一致）", secureMCPPathPrefix)
	}
}
