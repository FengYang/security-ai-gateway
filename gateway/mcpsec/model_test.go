package mcpsec

import (
	"bytes"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestNewSignerRejectsShortKey(t *testing.T) {
	if _, err := NewSigner([]byte("short")); err == nil {
		t.Fatal("期望短密钥被拒绝")
	}
	if _, err := NewSigner(bytes.Repeat([]byte{0x01}, 32)); err != nil {
		t.Fatalf("32 字节密钥应通过: %v", err)
	}
}

func TestToolCatalogCanonicalStable(t *testing.T) {
	c1 := NewToolCatalog(3, 1000)
	c1.Tools = []TableTool{
		{Name: "db_query", CatalogOwner: "tenant-a", Schema: map[string]*FieldConstraint{"table": {Type: "string", Whitelist: []string{"u", "o"}}}},
	}
	c2 := &ToolCatalog{Version: c1.Version, UpdatedAt: c1.UpdatedAt, Tools: append([]TableTool{}, c1.Tools...)}
	b1, err := c1.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := c2.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("canonical 不稳定: %s != %s", b1, b2)
	}
}

func TestCatalogSignVerifyAndTamper(t *testing.T) {
	s := testSigner(t)
	c := NewToolCatalog(1, 1000)
	c.Tools = []TableTool{{Name: "db_query", CatalogOwner: "tenant-a"}}
	if err := s.SignCatalog(c); err != nil {
		t.Fatalf("SignCatalog: %v", err)
	}
	if !s.ValidCatalog(c) {
		t.Fatal("合法签名应通过验证")
	}
	c.Tools[0].CatalogOwner = "tenant-b" // 篡改
	if s.ValidCatalog(c) {
		t.Fatal("篡改后应验签失败")
	}
}

func TestRBACPolicySignVerifyAndTamper(t *testing.T) {
	s := testSigner(t)
	p := NewRBACPolicy(2, 2000)
	p.TenantRules = map[string]map[string]*PolicyBinding{
		"tenant-a": {"db_query": {}},
	}
	if err := s.SignPolicy(p); err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	if !s.ValidPolicy(p) {
		t.Fatal("合法策略应通过验证")
	}
	p.TenantRules["tenant-a"]["db_query"] = &PolicyBinding{DenyParams: []string{"sql"}} // 篡改
	if s.ValidPolicy(p) {
		t.Fatal("篡改后应验签失败")
	}
}

func TestCanonicalStableAcrossLiteralRebuild(t *testing.T) {
	// 逐字重建（相同字段值、不同构造路径）→ canonical 必须一致，模拟两侧同实现一致性。
	s := testSigner(t)
	orig := NewRBACPolicy(5, 3000)
	orig.TenantRules = map[string]map[string]*PolicyBinding{
		"t1": {"tool_x": {DenyParams: []string{"a", "b"}}},
	}
	if err := s.SignPolicy(orig); err != nil {
		t.Fatal(err)
	}
	rebuilt := &RBACPolicy{Version: 5, UpdatedAt: 3000, Signature: orig.Signature, TenantRules: map[string]map[string]*PolicyBinding{"t1": {"tool_x": &PolicyBinding{DenyParams: []string{"a", "b"}}}}}
	if !s.ValidPolicy(rebuilt) {
		t.Fatal("逐字重建应验签通过（canonical 确定性）")
	}
}

func TestToolTrackDefaultSecure(t *testing.T) {
	cases := map[string]string{
		"":          TrackSecure, // 缺省 ⇒ secure（fail-closed）
		TrackPublic: TrackPublic,
		TrackSecure: TrackSecure,
	}
	for in, want := range cases {
		if got := (TableTool{Name: "t", Track: in}).ToolTrack(); got != want {
			t.Fatalf("ToolTrack(Track=%q) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestValidCatalogRejectsInvalidTrack(t *testing.T) {
	s := testSigner(t)

	// 非法分轨：即便签名正确也必须被拒。
	bad := NewToolCatalog(1, 1000)
	bad.Tools = []TableTool{{Name: "db_query", CatalogOwner: "tenant-a", Track: "internal"}}
	if err := s.SignCatalog(bad); err != nil {
		t.Fatal(err)
	}
	if s.ValidCatalog(bad) {
		t.Fatal("非法 Track 应被 ValidCatalog 拒绝（即便签名有效）")
	}

	// 合法分轨：空 / public / secure 均应通过。
	for _, tr := range []string{"", TrackPublic, TrackSecure} {
		ok := NewToolCatalog(1, 1000)
		ok.Tools = []TableTool{{Name: "db_query", CatalogOwner: "tenant-a", Track: tr}}
		if err := s.SignCatalog(ok); err != nil {
			t.Fatal(err)
		}
		if !s.ValidCatalog(ok) {
			t.Fatalf("合法 Track=%q 应通过校验", tr)
		}
	}
}
