package mcpproto

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"security-ai-gateway/gateway/mcpsec"
	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
)

func testSigner(t *testing.T) *mcpsec.Signer {
	t.Helper()
	s, err := mcpsec.NewSigner(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// readyDeps 构造"已就绪"的 Deps：目录含 secure(授权)/public/secure(未授权) 三工具。
func readyDeps(t *testing.T, tenant string) Deps {
	t.Helper()
	key := bytes.Repeat([]byte{0x5A}, 32)
	sig := testSigner(t)
	cache, err := mcpguard.NewCache(key)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	cat := mcpsec.NewToolCatalog(1, 1000)
	cat.Tools = []mcpsec.TableTool{
		{Name: "secure_ok", CatalogOwner: "o", Track: mcpsec.TrackSecure},
		{Name: "public_x", CatalogOwner: "o", Track: mcpsec.TrackPublic},
		{Name: "secure_no", CatalogOwner: "o", Track: mcpsec.TrackSecure},
	}
	if err := sig.SignCatalog(cat); err != nil {
		t.Fatalf("SignCatalog: %v", err)
	}
	if !cache.UpdateCatalog(cat) {
		t.Fatal("UpdateCatalog 应成功")
	}
	pol := mcpsec.NewRBACPolicy(1, 1000)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{
		tenant: {"secure_ok": {}, "public_x": {}},
	}
	if err := sig.SignPolicy(pol); err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	if !cache.UpdatePolicy(pol) {
		t.Fatal("UpdatePolicy 应成功")
	}
	return Deps{Guard: mcpguard.NewEngine(cache), Cache: cache}
}

func TestSelectToolsFiltersTrackAndRBAC(t *testing.T) {
	d := readyDeps(t, "ta")
	got := selectTools(d.Cache.Catalog(), d.Cache.Policy(), "ta")
	if len(got) != 1 || got[0].Name != "secure_ok" {
		t.Fatalf("应仅含 secure_ok（敏感轨+授权），实得 %+v", got)
	}
	// 未授权租户 → 空
	if out := selectTools(d.Cache.Catalog(), d.Cache.Policy(), "tb"); len(out) != 0 {
		t.Fatalf("未授权租户应为空，实得 %+v", out)
	}
}

func TestSelectToolsDeterministicOrder(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	sig := testSigner(t)
	cache, _ := mcpguard.NewCache(key)
	cat := mcpsec.NewToolCatalog(1, 1)
	cat.Tools = []mcpsec.TableTool{
		{Name: "b_tool", Track: mcpsec.TrackSecure},
		{Name: "a_tool", Track: mcpsec.TrackSecure},
	}
	_ = sig.SignCatalog(cat)
	cache.UpdateCatalog(cat)
	pol := mcpsec.NewRBACPolicy(1, 1)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{"t": {"a_tool": {}, "b_tool": {}}}
	_ = sig.SignPolicy(pol)
	cache.UpdatePolicy(pol)
	got := selectTools(cache.Catalog(), cache.Policy(), "t")
	if len(got) != 2 || got[0].Name != "a_tool" || got[1].Name != "b_tool" {
		t.Fatalf("应为字典序 [a_tool b_tool]，实得 %+v", got)
	}
}

func TestInputSchema(t *testing.T) {
	tl := &mcpsec.TableTool{
		Name:     "t",
		Schema:   map[string]*mcpsec.FieldConstraint{"q": {Type: "string", Pattern: "^[a-z]+$", Whitelist: []string{"x", "y"}}},
		Required: []string{"q"},
	}
	sch := inputSchema(tl)
	if sch["type"] != "object" {
		t.Fatalf("type 应为 object: %v", sch["type"])
	}
	props := sch["properties"].(map[string]any)
	q := props["q"].(map[string]any)
	if q["type"] != "string" || q["pattern"] != "^[a-z]+$" {
		t.Fatalf("q 约束不符: %v", q)
	}
	if req, ok := sch["required"].([]string); !ok || len(req) != 1 || req[0] != "q" {
		t.Fatalf("required 不符: %v", sch["required"])
	}
}

func TestTransportConsistency(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t1","arguments":{}}}`
	mk := func(method, name, body string, httpMethod string) *http.Request {
		r, _ := http.NewRequest(httpMethod, "/", bytes.NewBufferString(body))
		if method != "" {
			r.Header.Set(hdrMcpMethod, method)
		}
		if name != "" {
			r.Header.Set(hdrMcpName, name)
		}
		return r
	}
	cases := []struct {
		desc string
		req  *http.Request
		bad  bool
		want int
	}{
		{"无头放行", mk("", "", body, http.MethodPost), false, 0},
		{"GET 放行", mk("tools/call", "t1", body, http.MethodGet), false, 0},
		{"一致放行", mk("tools/call", "t1", body, http.MethodPost), false, 0},
		{"名称不符", mk("tools/call", "t2", body, http.MethodPost), true, CodeInconsistent},
		{"方法不符", mk("tools/list", "", body, http.MethodPost), true, CodeInconsistent},
		{"未知方法", mk("tools/evil", "", body, http.MethodPost), true, CodeInconsistent},
		{"非法 body", mk("tools/call", "t1", "not-json", http.MethodPost), true, CodeInconsistent},
	}
	for _, c := range cases {
		code, _, bad := transportConsistency(c.req)
		if bad != c.bad || code != c.want {
			t.Errorf("%s: got (bad=%v,code=%d) want (bad=%v,code=%d)", c.desc, bad, code, c.bad, c.want)
		}
		if !bad { // 放行时 body 必须可再读（透传给 SDK）
			buf := make([]byte, len(body))
			n, _ := c.req.Body.Read(buf)
			if n == 0 {
				t.Errorf("%s: body 未透传", c.desc)
			}
		}
	}
}

func TestCallToolAllowDeny(t *testing.T) {
	d := readyDeps(t, "ta")
	call := func(name string) *mcp.CallToolResult {
		res, err := callTool(d, "ta", &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{Name: name, Arguments: json.RawMessage(`{"q":"x"}`)},
		})
		if err != nil {
			t.Fatalf("callTool %s: %v", name, err)
		}
		return res
	}
	if res := call("secure_ok"); res.IsError {
		t.Fatalf("授权工具应放行，实得 IsError=true")
	} else if _, ok := res.Meta["params_hash"]; !ok {
		t.Fatalf("放行结果应带 params_hash（审计关联）")
	}
	if res := call("secure_no"); !res.IsError {
		t.Fatalf("未授权工具应拒绝")
	}
	// 未就绪引擎 → 拒绝（fail-closed）
	empty, _ := mcpguard.NewCache(bytes.Repeat([]byte{0x11}, 32))
	d2 := Deps{Guard: mcpguard.NewEngine(empty), Cache: empty}
	if res, _ := callTool(d2, "ta", &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "secure_ok"}}); !res.IsError {
		t.Fatalf("未就绪应 fail-closed 拒绝")
	}
}

func TestServerNotReadyHasNoTools(t *testing.T) {
	empty, _ := mcpguard.NewCache(bytes.Repeat([]byte{0x11}, 32))
	if s := buildServer(Deps{Guard: mcpguard.NewEngine(empty), Cache: empty}, "ta"); s == nil {
		t.Fatal("未就绪也应返回非 nil Server（空工具表）")
	}
	_ = context.Background()
}

func TestBuildServerWithReadyDeps(t *testing.T) {
	d := readyDeps(t, "ta")
	if s := buildServer(d, "ta"); s == nil {
		t.Fatal("就绪时应返回非 nil Server（已注册敏感轨授权工具）")
	}
}

func TestNewHandlerRejectsInconsistentHeaders(t *testing.T) {
	d := readyDeps(t, "ta")
	h := NewHandler(d)
	req, _ := http.NewRequest(http.MethodPost, "/mcp",
		bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t1"}}`))
	req.Header.Set(hdrMcpMethod, "tools/call")
	req.Header.Set(hdrMcpName, "t2") // 与 body.params.name 不符
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON-RPC 错误应按 HTTP 200 返回，实得 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "-32020") {
		t.Fatalf("应含 -32020，实得 %s", rec.Body.String())
	}
}

// tenantRT 为集成测试客户端注入租户头（生产由段① 会话/网关注入）。
type tenantRT struct{ tenant string }

func (t tenantRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set(tenantHeader, t.tenant)
	return http.DefaultTransport.RoundTrip(r2)
}

// TestIntegrationDiscoverListCall 端到端：SDK 客户端 ↔ 本 handler（§12.3.2 T-4 集成）。
func TestIntegrationDiscoverListCall(t *testing.T) {
	d := readyDeps(t, "ta")
	srv := httptest.NewServer(NewHandler(d))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "it-client", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             srv.URL,
		DisableStandaloneSSE: true,
		HTTPClient:           &http.Client{Transport: tenantRT{tenant: "ta"}},
	}, nil)
	if err != nil {
		t.Fatalf("Connect（含 server/discover 协商）失败: %v", err)
	}
	defer cs.Close()

	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := map[string]bool{}
	for _, tl := range lt.Tools {
		names[tl.Name] = true
	}
	if !names["secure_ok"] || names["public_x"] || names["secure_no"] {
		t.Fatalf("tools/list 应仅含 secure_ok（敏感轨+授权），实得 %v", names)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "secure_ok", Arguments: map[string]any{"q": "x"}})
	if err != nil {
		t.Fatalf("tools/call(授权): %v", err)
	}
	if res.IsError {
		t.Fatal("授权工具应放行")
	}

	if r2, err2 := cs.CallTool(ctx, &mcp.CallToolParams{Name: "secure_no"}); err2 == nil && r2 != nil && !r2.IsError {
		t.Fatal("未暴露/未授权工具应被拒绝")
	}
}
