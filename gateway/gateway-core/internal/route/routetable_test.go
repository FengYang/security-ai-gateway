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

// P0-1 新增：多端点配置签名与验签
func TestSignVerifyMultiEndpoint(t *testing.T) {
	s, _ := NewSigner(testKey())
	tbl := NewRouteTable(2, 1725500000)
	tbl.Routes = []TableRoute{
		{
			Tenant:        "tenant-a",
			Model:         "gpt-4",
			DefaultEngine: "cmaas",
			Endpoints: []TableEndpoint{
				{Name: "openai-gpt4-main", URL: "https://api.openai.com/v1", Weight: 0.6, Priority: 1, Enabled: true},
				{Name: "azure-gpt4-backup", URL: "https://azure.openai.com/v1", Weight: 0.4, Priority: 1, Enabled: true},
				{Name: "fallback-ep", Weight: 1.0, Priority: 2, Enabled: true},
			},
		},
	}
	if err := s.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyTable(tbl) {
		t.Fatal("多端点配置签名应通过")
	}
	if len(tbl.Routes[0].Endpoints) != 3 {
		t.Fatalf("端点数量应为 3，got %d", len(tbl.Routes[0].Endpoints))
	}
	if tbl.Routes[0].Endpoints[0].Weight != 0.6 {
		t.Fatalf("权重不匹配: %f", tbl.Routes[0].Endpoints[0].Weight)
	}
}

// P0-1 新增：篡改 Endpoints 字段应验签失败（防篡改）
func TestTamperEndpointsFailsVerify(t *testing.T) {
	s, _ := NewSigner(testKey())
	tbl := NewRouteTable(1, 1725500000)
	tbl.Routes = []TableRoute{
		{
			Tenant:        "tenant-a",
			Model:         "gpt-4",
			DefaultEngine: "cmaas",
			Endpoints: []TableEndpoint{
				{Name: "legit-ep", Weight: 1.0, Priority: 1},
			},
		},
	}
	_ = s.SignTable(tbl)
	// 篡改端点名称
	tbl.Routes[0].Endpoints[0].Name = "evil-ep"
	if s.VerifyTable(tbl) {
		t.Fatal("篡改 Endpoints 应验签失败")
	}
}

// P0-1 新增：v1 旧格式（无 Endpoints）在新代码中仍能正确签名验签（向后兼容）
func TestV1FormatStillWorks(t *testing.T) {
	s, _ := NewSigner(testKey())
	tbl := NewRouteTable(1, 1725500000)
	// 只有 v1 字段，无 Endpoints
	tbl.Routes = []TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", FallbackEngine: "vllm"},
	}
	if err := s.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyTable(tbl) {
		t.Fatal("v1 格式（无 Endpoints）应仍正常工作")
	}
	if len(tbl.Routes[0].Endpoints) != 0 {
		t.Fatal("v1 格式 Endpoints 应为空")
	}
}