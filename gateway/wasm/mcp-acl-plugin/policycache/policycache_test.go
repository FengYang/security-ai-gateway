package policycache

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/mcpsec"
)

// 本文件为 T-4 渗透用例（本地段）与单一事实源断言：
//   - canonical 字节与 gateway/mcpsec 逐字节一致（防镜像漂移）；
//   - 验签/版本/大小矩阵（防篡改、防回滚、防 DoS）；
//   - Decide 授权矩阵（越权、跨租户、secure 轨、缺头、default deny、fail-closed）。
//
// 测试专属 import（crypto/hmac 等）不进插件源码依赖闭包（wasm-guard 以 go list
// Imports 判源码，_test.go 天然排除）。

// testKey 32 字节测试密钥（K_rx 句柄对应的字节值；仅单测进程内使用）。
func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// stubVerifier 同步 HMAC-SHA256 验签（生产＝cryptop sidecar /v1/hmac；
// intl 档 HMAC-SHA256 与本实现逐字节等价，model.go 注释锚点）。
type stubVerifier struct {
	key  []byte
	down bool
}

func (v *stubVerifier) VerifySym(_ string, data, sig []byte, cb func(ok bool, err error)) {
	if v.down {
		cb(false, errors.New("cps unavailable"))
		return
	}
	m := hmac.New(sha256.New, v.key)
	m.Write(data)
	cb(hmac.Equal(m.Sum(nil), sig), nil)
}

func newSigner(t *testing.T) *mcpsec.Signer {
	t.Helper()
	s, err := mcpsec.NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// mirrorCatalog 签发后走「服务端对象 → JSON → 插件镜像」的字节路径（与运行时拉取一致）。
func mirrorCatalog(t *testing.T, s *mcpsec.Signer, c *mcpsec.ToolCatalog) *ToolCatalog {
	t.Helper()
	if err := s.SignCatalog(c); err != nil {
		t.Fatalf("SignCatalog: %v", err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	var m ToolCatalog
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	return &m
}

func mirrorPolicy(t *testing.T, s *mcpsec.Signer, p *mcpsec.RBACPolicy) *RBACPolicy {
	t.Helper()
	if err := s.SignPolicy(p); err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	var m RBACPolicy
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return &m
}

// catalogFixture 富字段目录夹具（覆盖命名空间/分轨/约束/后端摘要等 canonical 面）。
func catalogFixture(version int) *mcpsec.ToolCatalog {
	c := mcpsec.NewToolCatalog(version, 1750000000)
	c.Tools = []mcpsec.TableTool{
		{
			Name: "read_file", CatalogOwner: "ops", Track: mcpsec.TrackPublic,
			Transport: "higress-mcp", Server: "mcp-fs", Namespace: "fs",
			Schema: map[string]*mcpsec.FieldConstraint{
				"path": {Type: "string", Pattern: "^/data/.*$", Whitelist: []string{"/data/a"}, InjectionGuard: true, Sensitive: mcpsec.SensMask},
			},
			Required: []string{"path"}, ResponseSensitive: []string{"secret"},
		},
		{Name: "list_tables", CatalogOwner: "ops", Track: mcpsec.TrackPublic},
		{Name: "exec_sql", CatalogOwner: "ops", Track: mcpsec.TrackSecure},
		{Name: "fmt_disk", CatalogOwner: "ops"}, // Track 空值 ⇒ 有效轨 secure（fail-closed）
	}
	c.Servers = []mcpsec.CatalogServer{
		{ID: "mcp-fs", BaseURL: "http://mcp-fs.higress-system:80", Track: mcpsec.TrackPublic, Prefix: "/mcp-servers/mcp-fs"},
	}
	return c
}

// policyFixture 授权策略夹具：t-a 全域规则，t-b 仅裸名规则。
func policyFixture(version int) *mcpsec.RBACPolicy {
	p := mcpsec.NewRBACPolicy(version, 1750000000)
	p.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{
		"t-a": {"fs__read_file": {}, "list_tables": nil, "exec_sql": {}, "fmt_disk": {}},
		"t-b": {"list_tables": {}},
	}
	return p
}

func acceptCatalog(c *Cache, t *ToolCatalog) bool {
	var ok bool
	c.UpdateCatalog(t, func(a bool) { ok = a })
	return ok
}

func acceptPolicy(c *Cache, p *RBACPolicy) bool {
	var ok bool
	c.UpdatePolicy(p, func(a bool) { ok = a })
	return ok
}

type reasonRec struct{ list []string }

func (r *reasonRec) cb(source, reason string, _ int) {
	r.list = append(r.list, source+":"+reason)
}

// TestCanonicalBytesMatchMcpsec 断言镜像 canonical 与 mcpsec 逐字节一致（单一事实源）。
func TestCanonicalBytesMatchMcpsec(t *testing.T) {
	s := newSigner(t)

	c := catalogFixture(7)
	wantC, err := c.CanonicalBytes()
	if err != nil {
		t.Fatalf("mcpsec catalog canonical: %v", err)
	}
	mc := mirrorCatalog(t, s, c)
	gotC, err := mc.CanonicalBytes()
	if err != nil {
		t.Fatalf("mirror catalog canonical: %v", err)
	}
	if !bytes.Equal(wantC, gotC) {
		t.Fatalf("目录 canonical 漂移（单一事实源硬约束）:\n want=%s\n got =%s", wantC, gotC)
	}

	p := policyFixture(3)
	wantP, err := p.CanonicalBytes()
	if err != nil {
		t.Fatalf("mcpsec policy canonical: %v", err)
	}
	mp := mirrorPolicy(t, s, p)
	gotP, err := mp.CanonicalBytes()
	if err != nil {
		t.Fatalf("mirror policy canonical: %v", err)
	}
	if !bytes.Equal(wantP, gotP) {
		t.Fatalf("策略 canonical 漂移（单一事实源硬约束）:\n want=%s\n got =%s", wantP, gotP)
	}

	// 镜像路径签名可被 intl 档等价实现验证（生产即 sidecar HMAC + 常量时间比较）。
	ver := &stubVerifier{key: testKey()}
	ver.VerifySym("ref", gotC, mc.Signature, func(ok bool, err error) {
		if err != nil || !ok {
			t.Fatalf("镜像目录签名应可验证: ok=%v err=%v", ok, err)
		}
	})
	ver.VerifySym("ref", gotP, mp.Signature, func(ok bool, err error) {
		if err != nil || !ok {
			t.Fatalf("镜像策略签名应可验证: ok=%v err=%v", ok, err)
		}
	})
}

// TestCacheUpdateAcceptReject 验签/版本/大小矩阵（失败一律保留旧对象）。
func TestCacheUpdateAcceptReject(t *testing.T) {
	s := newSigner(t)
	rec := &reasonRec{}
	c := NewWithOptions(&stubVerifier{key: testKey()}, "otpmask/route-verify/v1", Options{OnReject: rec.cb})

	// 1) 验签通过 → 接受；单源未加载仍 fail-closed（Loaded=false，Decide 拒绝）。
	if !acceptCatalog(c, mirrorCatalog(t, s, catalogFixture(1))) {
		t.Fatal("有效目录应被接受")
	}
	if c.CatalogVersion() != 1 || c.Loaded() {
		t.Fatalf("加载状态错误: cat=%d loaded=%v", c.CatalogVersion(), c.Loaded())
	}
	if d := c.Decide("t-a", "list_tables"); d.Allow || d.Reason != "policy_unavailable" {
		t.Fatalf("单源加载应判 policy_unavailable，got=%+v", d)
	}

	// 2) 篡改签名 → 拒绝；保留旧对象。
	tampered := mirrorCatalog(t, s, catalogFixture(2))
	tampered.Signature[0] ^= 0xFF
	if acceptCatalog(c, tampered) {
		t.Fatal("篡改签名不得被接受")
	}
	if c.CatalogVersion() != 1 {
		t.Fatalf("拒绝后应保留旧对象，got v%d", c.CatalogVersion())
	}

	// 3) 版本回退 → 拒绝（防回滚）。
	if acceptCatalog(c, mirrorCatalog(t, s, catalogFixture(0))) {
		t.Fatal("版本回退不得被接受")
	}
	if c.CatalogVersion() != 1 {
		t.Fatal("回退拒绝后应保留旧对象")
	}

	// 4) 同版本重放 → 接受（语义＝重认最新已签对象）。
	if !acceptCatalog(c, mirrorCatalog(t, s, catalogFixture(1))) {
		t.Fatal("同版本重放应被接受")
	}

	// 5) 更高版本 → 接受。
	if !acceptCatalog(c, mirrorCatalog(t, s, catalogFixture(2))) || c.CatalogVersion() != 2 {
		t.Fatal("更高版本应被接受")
	}

	// 6) 策略链路：有效接受、篡改拒绝、回退拒绝；双源齐 → Loaded。
	if !acceptPolicy(c, mirrorPolicy(t, s, policyFixture(1))) {
		t.Fatal("有效策略应被接受")
	}
	if !c.Loaded() {
		t.Fatal("双源加载后应 Loaded")
	}
	badPol := mirrorPolicy(t, s, policyFixture(2))
	badPol.Signature[0] ^= 0xFF
	if acceptPolicy(c, badPol) {
		t.Fatal("篡改策略签名不得被接受")
	}
	if c.PolicyVersion() != 1 {
		t.Fatal("策略拒绝后应保留旧对象")
	}
	if acceptPolicy(c, mirrorPolicy(t, s, policyFixture(0))) {
		t.Fatal("策略版本回退不得被接受")
	}

	// 7) 大小超限 → 拒绝（保留旧对象）。
	cSmall := NewWithOptions(&stubVerifier{key: testKey()}, "ref", Options{MaxSize: 8, OnReject: rec.cb})
	if acceptCatalog(cSmall, mirrorCatalog(t, s, catalogFixture(1))) {
		t.Fatal("超限目录不得被接受")
	}
	if acceptPolicy(cSmall, mirrorPolicy(t, s, policyFixture(1))) {
		t.Fatal("超限策略不得被接受")
	}

	// 8) 验签不可用（sidecar 故障）→ 拒绝（fail-closed）。
	cDown := NewWithOptions(&stubVerifier{key: testKey(), down: true}, "ref", Options{OnReject: rec.cb})
	if acceptPolicy(cDown, mirrorPolicy(t, s, policyFixture(1))) {
		t.Fatal("验签不可用时不得接受")
	}

	// 9) verifier 缺失（装配错误）→ 拒绝（fail-closed 双保险）。
	cNil := NewWithOptions(nil, "ref", Options{})
	if acceptPolicy(cNil, mirrorPolicy(t, s, policyFixture(1))) {
		t.Fatal("verifier 缺失不得接受")
	}

	// 拒绝原因矩阵（指标/日志证据口径）。
	joined := strings.Join(rec.list, ",")
	for _, want := range []string{
		"catalog:bad_signature", "catalog:replay", "catalog:too_large",
		"policy:bad_signature", "policy:replay", "policy:too_large",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺拒绝原因 %s（got=%s）", want, joined)
		}
	}
}

// TestDecideMatrix 授权判定矩阵（越权/跨租户/secure 轨/缺头/default deny）。
func TestDecideMatrix(t *testing.T) {
	s := newSigner(t)
	c := NewWithOptions(&stubVerifier{key: testKey()}, "ref", Options{})
	if !acceptCatalog(c, mirrorCatalog(t, s, catalogFixture(1))) ||
		!acceptPolicy(c, mirrorPolicy(t, s, policyFixture(1))) {
		t.Fatal("夹具加载失败")
	}

	cases := []struct {
		name   string
		tenant string
		tool   string
		allow  bool
		reason string
	}{
		{"命名空间名命中放行", "t-a", "fs__read_file", true, ""},
		{"命名空间工具以裸名请求（命中后回退命名空间键）", "t-a", "read_file", true, ""},
		{"裸名规则命中放行", "t-a", "list_tables", true, ""},
		{"跨租户越权拒绝", "t-b", "fs__read_file", false, "not_granted"},
		{"无规则租户拒绝（default deny）", "t-z", "list_tables", false, "not_granted"},
		{"secure 轨工具拒绝（即便策略含规则）", "t-a", "exec_sql", false, "track_denied"},
		{"Track 空值视同 secure 拒绝", "t-a", "fmt_disk", false, "track_denied"},
		{"目录未收录拒绝", "t-a", "ghost_tool", false, "not_in_catalog"},
		{"缺租户拒绝", "", "list_tables", false, "missing_tenant"},
		{"缺工具名拒绝", "t-a", "", false, "missing_name"},
	}
	for _, tc := range cases {
		d := c.Decide(tc.tenant, tc.tool)
		if d.Allow != tc.allow || d.Reason != tc.reason {
			t.Fatalf("%s: got(allow=%v,reason=%q) want(allow=%v,reason=%q)",
				tc.name, d.Allow, d.Reason, tc.allow, tc.reason)
		}
	}

	// 空缓存（从未拉到）→ policy_unavailable（fail-closed）。
	empty := New(&stubVerifier{key: testKey()}, "ref")
	if d := empty.Decide("t-a", "list_tables"); d.Allow || d.Reason != "policy_unavailable" {
		t.Fatalf("空缓存应判 policy_unavailable，got=%+v", d)
	}
}

// TestFindToolAmbiguity 裸名多重命中（发行端 U-5 应拒绝冲突；此处防御性保守）。
func TestFindToolAmbiguity(t *testing.T) {
	m := &ToolCatalog{Tools: []TableTool{
		{Name: "dup", CatalogOwner: "ops", Track: TrackPublic},
		{Name: "dup", CatalogOwner: "ops2", Track: TrackPublic},
	}}
	if findTool(m, "dup") != nil {
		t.Fatal("裸名多重命中应返回 nil（歧义 => not_in_catalog 拒绝）")
	}
}

// TestDecideStaleGate 过期门（MaxStale>0）：过期即拒（fail-closed）；阈值内放行。
func TestDecideStaleGate(t *testing.T) {
	s := newSigner(t)

	cat := catalogFixture(1)
	cat.UpdatedAt = 1000
	pol := policyFixture(1)
	pol.UpdatedAt = 1000
	c := NewWithOptions(&stubVerifier{key: testKey()}, "ref", Options{
		MaxStale: time.Hour,
		Now:      func() time.Time { return time.Unix(2_000_000_000, 0) },
	})
	if !acceptCatalog(c, mirrorCatalog(t, s, cat)) || !acceptPolicy(c, mirrorPolicy(t, s, pol)) {
		t.Fatal("夹具加载失败")
	}
	if d := c.Decide("t-a", "list_tables"); d.Allow || d.Reason != "policy_stale" {
		t.Fatalf("过期对象应判 policy_stale，got=%+v", d)
	}

	// 对照：阈值内不判过期。
	c2 := NewWithOptions(&stubVerifier{key: testKey()}, "ref", Options{
		MaxStale: time.Hour,
		Now:      func() time.Time { return time.Unix(1750000000+60, 0) },
	})
	if !acceptCatalog(c2, mirrorCatalog(t, s, catalogFixture(1))) ||
		!acceptPolicy(c2, mirrorPolicy(t, s, policyFixture(1))) {
		t.Fatal("夹具加载失败（对照）")
	}
	if d := c2.Decide("t-a", "list_tables"); !d.Allow {
		t.Fatalf("未过期应放行，got=%+v", d)
	}
}
