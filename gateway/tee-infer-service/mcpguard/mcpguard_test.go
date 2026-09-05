package mcpguard

import (
	"bytes"
	"testing"

	"security-ai-gateway/gateway/mcpsec"
)

func testKey() []byte { return bytes.Repeat([]byte{0x77}, 32) }

func signedCache(t *testing.T) *PolicyCache {
	t.Helper()
	sig := mustSigner(t)
	// 目录：db_query（table 白名单 + token 敏感 strip）、search（free text）
	cat := mcpsec.NewToolCatalog(1, 1000)
	cat.Tools = []mcpsec.TableTool{
		{Name: "db_query", CatalogOwner: "tenant-a", Schema: map[string]*mcpsec.FieldConstraint{
			"table": {Type: "string", Whitelist: []string{"users", "orders"}},
			"sql":   {Type: "string", InjectionGuard: true},
			"token": {Type: "string", Sensitive: mcpsec.SensStrip},
			"pw":    {Type: "string", Sensitive: mcpsec.SensBlock},
			"name":  {Type: "string", Sensitive: mcpsec.SensMask},
		}, Required: []string{"table"}},
		{Name: "email_search", CatalogOwner: "tenant-a"},
	}
	if err := sig.SignCatalog(cat); err != nil {
		t.Fatal(err)
	}
	// 策略：tenant-a 可用 db_query（禁 sql 直传）；tenant-x 无 db_query；全租户允许 email_search
	pol := mcpsec.NewRBACPolicy(1, 1000)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{
		"tenant-a": {"db_query": {DenyParams: []string{"sql"}}, "email_search": {}, "ghost_tool": {}},
		"tenant-x": {"email_search": {}},
	}
	if err := sig.SignPolicy(pol); err != nil {
		t.Fatal(err)
	}
	c, err := NewCache(testKey())
	if err != nil {
		t.Fatal(err)
	}
	if !c.UpdateCatalog(cat) || !c.UpdatePolicy(pol) {
		t.Fatal("种子装载失败")
	}
	if !c.Ready() {
		t.Fatal("种子后应就绪")
	}
	return c
}

func mustSigner(t *testing.T) *mcpsec.Signer {
	t.Helper()
	s, err := mcpsec.NewSigner(testKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCacheRejectsTamperAndRollback(t *testing.T) {
	sig := mustSigner(t)
	c := signedCache(t)

	// 篡改：拷贝后改内容、保留旧签名 → 验签失败应拒新
	tampered := *c.Catalog()
	tampered.Tools = append([]mcpsec.TableTool{}, c.Catalog().Tools...)
	tampered.Tools[0].Name = "hacked"
	if c.UpdateCatalog(&tampered) {
		t.Fatal("篡改目录不应更新")
	}
	// 回滚：低于当前版本
	low := mcpsec.NewToolCatalog(0, 0)
	if err := sig.SignCatalog(low); err != nil {
		t.Fatal(err)
	}
	if c.UpdateCatalog(low) {
		t.Fatal("低版本目录不应更新（防回滚）")
	}
	// 高版本合法更新
	hi := mcpsec.NewToolCatalog(2, 1001)
	hi.Tools = c.Catalog().Tools
	if err := sig.SignCatalog(hi); err != nil {
		t.Fatal(err)
	}
	if !c.UpdateCatalog(hi) {
		t.Fatal("高版本合法签名应更新")
	}
	catV, polV := c.Version()
	if catV != 2 || polV != 1 {
		t.Fatalf("版本错误: cat=%d pol=%d", catV, polV)
	}
}

func TestEngineColdStartFailClosed(t *testing.T) {
	c, err := NewCache(testKey())
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(c)
	d := e.Evaluate("tenant-a", "req-1", "db_query", map[string]any{"table": "users"})
	if d.Allow || d.Reason != ReasonNotReady {
		t.Fatalf("未就绪应 fail-closed not_ready，got allow=%v reason=%s", d.Allow, d.Reason)
	}
}

func TestEnginePermissionAndDenyParam(t *testing.T) {
	c := signedCache(t)
	e := NewEngine(c)

	// 未授权租户
	d := e.Evaluate("tenant-x", "r1", "db_query", map[string]any{"table": "users"})
	if d.Allow || d.Reason != ReasonPermission {
		t.Fatalf("越权应拒绝 permission，got %v/%s", d.Allow, d.Reason)
	}
	// deny_params：租户 A 禁直传 sql
	d2 := e.Evaluate("tenant-a", "r2", "db_query", map[string]any{"table": "users", "sql": "SELECT * FROM users"})
	if d2.Allow || d2.Reason != ReasonDenyParam {
		t.Fatalf("deny_params 应拒绝 deny_param，got %v/%s", d2.Allow, d2.Reason)
	}
}

func TestEngineSchemaReject(t *testing.T) {
	c := signedCache(t)
	e := NewEngine(c)
	// 缺必填 table
	d := e.Evaluate("tenant-a", "r3", "db_query", map[string]any{})
	if d.Allow || d.Reason != ReasonSchema {
		t.Fatalf("缺必填应 schema_reject，got %v/%s", d.Allow, d.Reason)
	}
	// table 不在白名单
	d2 := e.Evaluate("tenant-a", "r4", "db_query", map[string]any{"table": "admin"})
	if d2.Allow || d2.Reason != ReasonSchema {
		t.Fatalf("白名单外应 schema_reject，got %v/%s", d2.Allow, d2.Reason)
	}
	// 授权通过但目录缺失该工具 → tool_unknown（tenant-a 对 ghost_tool 有授权）
	d3 := e.Evaluate("tenant-a", "r5", "ghost_tool", nil)
	if d3.Allow || d3.Reason != ReasonToolUnknown {
		t.Fatalf("目录缺失应 tool_unknown，got %v/%s", d3.Allow, d3.Reason)
	}
}

func TestEngineSensitiveThreeState(t *testing.T) {
	c := signedCache(t)
	e := NewEngine(c)
	// block：pw 非空 → sensitive 拒绝
	d := e.Evaluate("tenant-a", "r6", "db_query", map[string]any{"table": "users", "pw": "secret"})
	if d.Allow || d.Reason != ReasonSensitive {
		t.Fatalf("block 敏感应拒绝 sensitive，got %v/%s", d.Allow, d.Reason)
	}
	// strip：token 被移除，后续看不到明文；mask：name 被替换
	d2 := e.Evaluate("tenant-a", "r7", "db_query",
		map[string]any{"table": "users", "token": "t0k3n", "name": "张三"})
	if !d2.Allow {
		t.Fatalf("允许调用被拒: %s", d2.Reason)
	}
	if _, hasTok := d2.Params["token"]; hasTok {
		t.Fatal("strip 后不应残留 token 明文")
	}
	if d2.Params["name"] != "[已脱敏]" {
		t.Fatalf("mask 应为 [已脱敏]，got %v", d2.Params["name"])
	}
	if d2.Params["table"] != "users" {
		t.Fatal("非敏感字段应保留")
	}
}

func TestParamsHashBindsTenantAndReq(t *testing.T) {
	p := map[string]any{"table": "users"}
	if ParamsHash("a", "r1", p) == ParamsHash("a", "r2", p) {
		t.Fatal("不同 reqID 不应产生相同 hash")
	}
	if ParamsHash("a", "r1", p) == ParamsHash("b", "r1", p) {
		t.Fatal("不同 tenant 不应产生相同 hash")
	}
	if ParamsHash("a", "r1", map[string]any{"b": "y", "a": "x"}) != ParamsHash("a", "r1", map[string]any{"a": "x", "b": "y"}) {
		t.Fatal("map 键序不应影响规范化 hash")
	}
}

func TestInjectionHook(t *testing.T) {
	// 独立构造无 deny_params 的缓存，使 sql 可流过 RBAC 直达注入钩子。
	sig := mustSigner(t)
	cat := mcpsec.NewToolCatalog(1, 1000)
	cat.Tools = []mcpsec.TableTool{
		{Name: "db_query", CatalogOwner: "tenant-a", Schema: map[string]*mcpsec.FieldConstraint{
			"sql": {Type: "string", InjectionGuard: true},
		}},
	}
	if err := sig.SignCatalog(cat); err != nil {
		t.Fatal(err)
	}
	pol := mcpsec.NewRBACPolicy(1, 1000)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{"tenant-a": {"db_query": {}}}
	if err := sig.SignPolicy(pol); err != nil {
		t.Fatal(err)
	}
	c, err := NewCache(testKey())
	if err != nil {
		t.Fatal(err)
	}
	if !c.UpdateCatalog(cat) || !c.UpdatePolicy(pol) {
		t.Fatal("装载失败")
	}
	e := NewEngine(c)
	e.PreInject = func(tool string, sanitized map[string]any) bool {
		s, _ := sanitized["sql"].(string)
		return tool == "db_query" && containsSQL(s)
	}
	d := e.Evaluate("tenant-a", "r8", "db_query", map[string]any{"sql": "SELECT * FROM users"})
	if d.Allow || d.Reason != ReasonInjection {
		t.Fatalf("命中注入钩子应拒绝 injection，got allow=%v reason=%s", d.Allow, d.Reason)
	}
	d2 := e.Evaluate("tenant-a", "r9", "db_query", map[string]any{"sql": "select 1"})
	if !d2.Allow {
		t.Fatalf("无注入应放行，got %s", d2.Reason)
	}
}

func containsSQL(s string) bool {
	return bytes.Contains([]byte(s), []byte("SELECT"))
}