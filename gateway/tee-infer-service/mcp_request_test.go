package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-ai-gateway/gateway/mcpsec"
	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
	"security-ai-gateway/gateway/tee-infer-service/mcpproto"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// mcpRequestServer 构造仅含成功路径所需依赖的服务端（tenant=ta → secure_ok）。
func mcpRequestServer(t *testing.T, kenc []byte, sid string) *teeServer {
	t.Helper()
	key := bytes.Repeat([]byte{0x44}, 32)
	sig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	mc, err := mcpguard.NewCache(key)
	if err != nil {
		t.Fatal(err)
	}
	cat := mcpsec.NewToolCatalog(1, 1)
	cat.Tools = []mcpsec.TableTool{{Name: "secure_ok", Track: mcpsec.TrackSecure}}
	if err := sig.SignCatalog(cat); err != nil {
		t.Fatal(err)
	}
	mc.UpdateCatalog(cat)
	pol := mcpsec.NewRBACPolicy(1, 1)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{"ta": {"secure_ok": {}}}
	if err := sig.SignPolicy(pol); err != nil {
		t.Fatal(err)
	}
	mc.UpdatePolicy(pol)
	eng := mcpguard.NewEngine(mc)

	sess := &teeSession{ID: sid, K_enc: kenc, Completed: true, CreatedAt: time.Now()}
	sess.sendCounter = 1
	return &teeServer{
		adminToken: "tok", mcpKey: key, mcpCache: mc, mcpEngine: eng,
		mcpHandler: mcpproto.NewHandler(mcpproto.Deps{Guard: eng, Cache: mc}),
		sessions:   map[string]*teeSession{sid: sess},
	}
}

func TestMCPRequestDecryptRouteSeal(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	sid := "sess-1"
	s := mcpRequestServer(t, kenc, sid)

	pt := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	sealed, err := cryptoops.SealEnvelope(kenc, sid, protocol.EndpointMCP, protocol.DirectionC2S, 1, pt)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp-servers/secure-tools", bytes.NewReader(sealed))
	req.Header.Set("X-Session-ID", sid)
	req.Header.Set("X-Tenant-ID", "ta")
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d（%s）", rec.Code, rec.Body.String())
	}
	respPT, _, err := cryptoops.OpenEnvelope(kenc, sid, protocol.EndpointMCP, protocol.DirectionS2C, rec.Body.Bytes())
	if err != nil {
		t.Fatalf("响应应为 s2c 信封且可解: %v", err)
	}
	if !bytes.Contains(respPT, []byte("secure_ok")) {
		t.Fatalf("响应应含 secure_ok（tools/list 过滤结果），实得 %s", respPT)
	}
}

func TestMCPRequestMethodNotAllowed(t *testing.T) {
	s := mcpRequestServer(t, bytes.Repeat([]byte{0x77}, 32), "sess-1")
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, httptest.NewRequest(http.MethodGet, "/mcp-servers/secure-tools", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 POST 应 405，实得 %d", rec.Code)
	}
}
