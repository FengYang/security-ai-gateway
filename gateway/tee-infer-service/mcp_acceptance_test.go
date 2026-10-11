package main

// T-9 A 组补测（本体 §12.3.3 整体验收判据）：
//   V-6 敏感轨 tools/call 审计（唯一生产者＝tee-infer；仅 hash 无明文）
//   V-7 就绪门控 → 503（不降级）
//   V-8 MCP 门控不影响既有 /infer 输出（无 tool_calls 时逐字节一致）

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
	"security-ai-gateway/gateway/tee-infer-service/mcpproto"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// TestAcceptanceV6MCPToolCallAudited V-6：放行与拒绝各产一条 `action=mcp_tool_call` 审计，
// 仅含参数 hash 与决策元数据，无明文参数。
func TestAcceptanceV6MCPToolCallAudited(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", []string{"sql"}, kenc, "sess-a")
	secret := "S3CRET-PARAM-VALUE-42"

	// 放行：参数不含 deny_params 命中键
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, penSeal(t, kenc, "sess-a", 1,
		penToolCall("secure_ok", `{"q":"`+secret+`"}`), "ta"))
	if rec.Code != http.StatusOK {
		t.Fatalf("放行调用应 200，实得 %d", rec.Code)
	}
	// 拒绝：命中 deny_params
	rec2 := httptest.NewRecorder()
	s.handleMCPRequest(rec2, penSeal(t, kenc, "sess-a", 2,
		penToolCall("secure_ok", `{"sql":"SELECT 1"}`), "ta"))

	var allow, deny int
	for _, e := range s.audit.query("") {
		if e.Action != "mcp_tool_call" {
			continue
		}
		if e.MCPTool != "secure_ok" || len(e.PayloadSHA) == 0 {
			t.Fatalf("审计字段不符（应含工具名与参数 hash）: %+v", e)
		}
		if strings.Contains(e.PayloadSHA, secret) || strings.Contains(e.MCPReason, secret) {
			t.Fatalf("审计含明文（V-6 违例）: %+v", e)
		}
		switch e.Result {
		case "allow":
			allow++
		case "deny":
			deny++
		}
	}
	if allow != 1 || deny != 1 {
		t.Fatalf("应各 1 条 allow/deny 审计，实得 allow=%d deny=%d", allow, deny)
	}
}

// TestAcceptanceV7SecureTrackNotReady503 V-7：敏感轨入口治理未就绪 → **503**（fail-closed，不降级）。
func TestAcceptanceV7SecureTrackNotReady503(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	key := bytes.Repeat([]byte{0x44}, 32)
	mc, err := mcpguard.NewCache(key) // 未装载目录/策略 → Ready()==false
	if err != nil {
		t.Fatal(err)
	}
	s := &teeServer{
		adminToken: "tok", mcpKey: key, mcpCache: mc, mcpEngine: mcpguard.NewEngine(mc),
		sessions: map[string]*teeSession{}, audit: newAuditChain(),
		usage: make(map[string]*usageRecord), metrics: newMetrics(),
	}
	s.mcpHandler = mcpproto.NewHandler(mcpproto.Deps{Guard: s.mcpEngine, Cache: mc, Audit: s.mcpCallAudit})

	sealed, err := cryptoops.SealEnvelope(kenc, "sess-x", protocol.EndpointMCP, protocol.DirectionC2S, 1,
		penToolCall("secure_ok", `{}`))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp-servers/secure-tools", bytes.NewReader(sealed))
	req.Header.Set("X-Session-ID", "sess-x")
	req.Header.Set("X-Tenant-ID", "ta")
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("治理未就绪应 503，实得 %d", rec.Code)
	}
	if got := lastDenyReason(s); got != "mcp_guard_not_ready" {
		t.Fatalf("审计 result 应为 mcp_guard_not_ready，实得 %q", got)
	}
}

// TestAcceptanceV8InferOutputUnchangedByMCPGate V-8：MCP 门控存在与否，`/infer` 文本路径的
// **解密后输出逐字节一致**（载荷无 tool_calls ⇒ 零行为变化）。
func TestAcceptanceV8InferOutputUnchangedByMCPGate(t *testing.T) {
	run := func(srv *teeServer, ts *httptest.Server) (string, string) {
		t.Helper()
		sid, ksig, kenc := setupTestSession(t, ts)
		hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sid, ksig, kenc, "你好", protocol.EngineTypeTEEGPU, true, 1)
		resp, err := http.DefaultClient.Do(hr)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("应 200，实得 %d", resp.StatusCode)
		}
		return decodeTextSSE(t, mustReadAll(t, resp.Body), sid, kenc)
	}

	// 基线：治理未启用
	srvA, tsA := newM9Server(t)
	textA, finA := run(srvA, tsA)

	// 对照：治理就绪（缓存已装载目录/策略），载荷仍无 tool_calls
	srvB, tsB := newM9Server(t)
	srvB.mcpCache = testMCPCache(t, "ta")
	srvB.mcpEngine = mcpguard.NewEngine(srvB.mcpCache)
	textB, finB := run(srvB, tsB)

	if textA != textB || finA != finB {
		t.Fatalf("V-8 违例：MCP 门控改变了 /infer 输出（基线 %q/%q vs 对照 %q/%q）",
			textA, finA, textB, finB)
	}
}
