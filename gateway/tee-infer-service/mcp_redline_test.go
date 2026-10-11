package main

// T-9 红线 V-4/V-5 单元判据（§10.1 组合判据第 ③ 项：单元级断言）。
//   V-4 敏感轨 tools/call 参数值「网关/TEE 侧仅以 hash 承载，无明文外泄」
//   V-5 敏感轨请求体「不被结构化解析，且明文不随段① 密文外泄」

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

const redlineSecret = "S3CRET-PARAM-VALUE-42"

// TestRedlineV4DecisionCarriesOnlyHash V-4：mcpguard 入参为**解密后明文**，
// 决策仅以 ParamsHash（不可逆、无明文）承载。
func TestRedlineV4DecisionCarriesOnlyHash(t *testing.T) {
	mc := testMCPCache(t, "ta")
	eng := mcpguard.NewEngine(mc)
	d := eng.Evaluate("ta", "req-v4", "secure_ok", map[string]any{"q": redlineSecret})
	if !d.Allow {
		t.Fatalf("应放行，实得 reason=%s", d.Reason)
	}
	if d.ParamsHash == "" || strings.Contains(d.ParamsHash, redlineSecret) {
		t.Fatalf("ParamsHash 应非空且不含明文：%q", d.ParamsHash)
	}
}

// TestRedlineV4ResponseHasNoParamPlaintext V-4：经敏感轨的**响应**（s2c 解密后）与审计
// 均不含请求参数明文。
func TestRedlineV4ResponseHasNoParamPlaintext(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", nil, kenc, "sess-a")
	pt := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secure_ok","arguments":{"q":"` + redlineSecret + `"}}}`)
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, penSeal(t, kenc, "sess-a", 1, pt, "ta"))

	out := penOpenS2C(t, kenc, "sess-a", rec.Body.Bytes())
	if bytes.Contains(out, []byte(redlineSecret)) {
		t.Fatalf("响应含参数明文（V-4 违例）：%s", out)
	}
	for _, e := range s.audit.query("") {
		if strings.Contains(e.Result, redlineSecret) || strings.Contains(e.PayloadSHA, redlineSecret) {
			t.Fatalf("审计含明文（V-4 违例）：%+v", e)
		}
	}
}

// TestRedlineV5WireHasNoPlaintext V-5：敏感轨请求体以段① 信封搬运——密文 wire 不含明文
// （明文不出飞地/网关内存，仅密文出网）。
func TestRedlineV5WireHasNoPlaintext(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	wrapped := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secure_ok","arguments":{"q":"` + redlineSecret + `"}}}`)
	sealed, err := cryptoops.SealEnvelope(kenc, "sess-a", protocol.EndpointMCP, protocol.DirectionC2S, 1, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(redlineSecret)) {
		t.Fatal("段① 信封 wire 含参数明文（V-5 违例）")
	}
}
