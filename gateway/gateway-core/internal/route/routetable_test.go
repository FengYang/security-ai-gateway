package route

import "testing"

func TestSignVerifyTable(t *testing.T) {
	s, _ := NewSigner(testKey())
	tbl := NewRouteTable(1, 1725500000)
	tbl.Routes = []TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", FallbackEngine: "vllm"},
		{Tenant: "tenant-b", Model: "deepseek-r1", DefaultEngine: "vllm"},
	}
	if err := s.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if len(tbl.Signature) == 0 {
		t.Fatal("签名应为非空")
	}
	if !s.VerifyTable(tbl) {
		t.Fatal("有效签名应通过")
	}
}

func TestVerifyTableTampered(t *testing.T) {
	s, _ := NewSigner(testKey())
	tbl := NewRouteTable(1, 1725500000)
	tbl.Routes = []TableRoute{{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas"}}
	_ = s.SignTable(tbl)
	// 篡改一条记录的 engine
	tbl.Routes[0].DefaultEngine = "evil-engine"
	if s.VerifyTable(tbl) {
		t.Fatal("篡改后的路由表应验签失败")
	}
}

func TestVerifyTableWrongKey(t *testing.T) {
	s1, _ := NewSigner(testKey())
	tbl := NewRouteTable(1, 1725500000)
	tbl.Routes = []TableRoute{{Tenant: "a", Model: "m", DefaultEngine: "e"}}
	_ = s1.SignTable(tbl)
	s2, _ := NewSigner([]byte("fedcba9876543210fedcba9876543210"))
	if s2.VerifyTable(tbl) {
		t.Fatal("错误密钥应验签失败")
	}
}

func TestLookup(t *testing.T) {
	tbl := NewRouteTable(1, 1725500000)
	tbl.Routes = []TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas"},
		{Tenant: "tenant-a", Model: "deepseek-r1", DefaultEngine: "vllm"},
	}
	r := tbl.Lookup("tenant-a", "deepseek-r1")
	if r == nil || r.DefaultEngine != "vllm" {
		t.Fatalf("应命中 deepseek 表项，got %+v", r)
	}
	if r := tbl.Lookup("tenant-a", "unknown-model"); r != nil {
		t.Fatalf("未知 model 应返回 nil，got %+v", r)
	}
	if r := tbl.Lookup("unknown-tenant", "qwen-plus"); r != nil {
		t.Fatalf("未知 tenant 应返回 nil，got %+v", r)
	}
}