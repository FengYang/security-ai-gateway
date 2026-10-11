package main

// T-9：MCP 敏感轨（T-2）可测性抽取后的单测 + 红线 V-5 单元断言。

import (
	"bytes"
	"testing"

	"security-ai-gateway/protocol/go"
)

// TestDecideOpaqueMCP MCP 敏感轨动作判定（纯逻辑）：token 模式 fail-closed；
// quote 未握手 → 先握手；quote 会话就绪 → 直接密封。
func TestDecideOpaqueMCP(t *testing.T) {
	cases := []struct {
		mode  string
		valid bool
		want  opaqueMCPAction
	}{
		{"token", true, opaqueMCPReject},  // token 模式：不支持不透明载荷 → 拒
		{"token", false, opaqueMCPReject}, // 同上（无会话亦拒）
		{"", false, opaqueMCPReject},      // 缺省/空 → 非 quote → 拒（fail-closed）
		{"quote", false, opaqueMCPHandshake},
		{"quote", true, opaqueMCPSeal},
	}
	for _, c := range cases {
		if got := decideOpaqueMCP(c.mode, c.valid); got != c.want {
			t.Fatalf("decideOpaqueMCP(%q,%v)=%d，期望 %d", c.mode, c.valid, got, c.want)
		}
	}
}

// TestResponseEnvelopeEndpointMCP 响应阶段 endpoint 选择（2026-10-11 真机定位）：
// MCP 敏感轨响应必须以 **EndpointMCP** 解封（与请求侧一致）；用 EndpointInfer 解 MCP 响应
// 必失败（AAD 绑定 endpoint）——这正是本修复针对的缺陷。
func TestResponseEnvelopeEndpointMCP(t *testing.T) {
	if got := responseEnvelopeEndpoint(true); got != protocol.EndpointMCP {
		t.Fatalf("MCP 敏感轨响应 endpoint 应为 %q，得 %q", protocol.EndpointMCP, got)
	}
	if got := responseEnvelopeEndpoint(false); got != protocol.EndpointInfer {
		t.Fatalf("文本/向量轨响应 endpoint 应为 %q，得 %q", protocol.EndpointInfer, got)
	}

	newSessionForTest(t)
	defer Session.clear()
	w1 := sealS2CForTest(t, protocol.EndpointMCP, 1, []byte(`{"jsonrpc":"2.0","id":1}`))
	w2 := sealS2CForTest(t, protocol.EndpointMCP, 2, []byte(`{"jsonrpc":"2.0","id":2}`))

	// 正确：用 MCP endpoint 解封（counter=1）
	var pt []byte
	var oerr error
	Session.openPayload(responseEnvelopeEndpoint(true), w1, func(p []byte, err error) { pt, oerr = p, err })
	if oerr != nil {
		t.Fatalf("MCP 响应按 EndpointMCP 解封失败: %v", oerr)
	}
	if string(pt) != `{"jsonrpc":"2.0","id":1}` {
		t.Fatalf("明文不符: %s", pt)
	}

	// 修复前行为：用 EndpointInfer 解 MCP 响应（counter=2，避开窗口因素）→ 必须失败
	var badErr error
	Session.openPayload(protocol.EndpointInfer, w2, func(_ []byte, err error) { badErr = err })
	if badErr == nil {
		t.Fatal("MCP 响应按 EndpointInfer 解封竟成功（AAD 端点绑定失效）")
	}
}

// TestRedlineV5OpaqueBodyNotParsed V-5：敏感轨请求体**不被结构化解析**——
// 不透明字节既非 text 亦非 vectors，但敏感轨按路径直入密封分支（禁止内容嗅探）。
func TestRedlineV5OpaqueBodyNotParsed(t *testing.T) {
	opaque := []byte("\x00\x01\x02 not-json \xff\xfe")
	if _, err := parseTextRequest(opaque); err == nil {
		t.Fatal("不透明字节不应被文本解析接受")
	}
	if _, err := parsePlainRequest(opaque); err == nil {
		t.Fatal("不透明字节不应被向量解析接受")
	}
	if !isSecureMCPPathStr(secureMCPPathPrefix + "/sse") {
		t.Fatal("敏感轨路径判定失效")
	}
	if decideOpaqueMCP("quote", true) != opaqueMCPSeal {
		t.Fatal("quote 会话就绪时敏感轨应直接密封（不进入解析分支）")
	}
}

// TestRedlineV5SealedWireHasNoPlaintext V-5：段① 密封后 wire 不含明文（明文不随密文外泄），
// 且信封绑定端点 /v1/mcp（AAD 防跨端点搬运）。
func TestRedlineV5SealedWireHasNoPlaintext(t *testing.T) {
	newSessionForTest(t)
	defer Session.clear()
	secret := []byte("S3CRET-PARAM-VALUE-42")
	var wire []byte
	var serr error
	Session.sealPayload(protocol.EndpointMCP, secret, func(w []byte, err error) { wire, serr = w, err })
	if serr != nil {
		t.Fatalf("密封失败: %v", serr)
	}
	if len(wire) == 0 {
		t.Fatal("wire 为空")
	}
	if bytes.Contains(wire, secret) {
		t.Fatal("段① 信封 wire 含明文（V-5 违例）")
	}
	env, err := protocol.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if env.Counter != 1 || env.Direction != protocol.DirectionC2S {
		t.Fatalf("首信封 counter/direction 异常: counter=%d direction=%d", env.Counter, env.Direction)
	}
}
