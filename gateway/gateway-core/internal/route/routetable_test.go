package route

import (
	"encoding/json"
	"strings"
	"testing"
)

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

// ============================================================
// P1-6 M4.1：latency 段 Schema（C-5 旧表逐字节不变 / 显式零值存在性 / 签名 / Diff latency.*）
// ============================================================

// TestCanonicalBytesOldTableUnchanged（C-5/V-7）：无 latency 段的旧表规范字节逐字节不变。
// 基线向量与 routecache 外部签发 fixture 同源（146 字节）。
func TestCanonicalBytesOldTableUnchanged(t *testing.T) {
	tbl := &RouteTable{
		Version:   1,
		UpdatedAt: 1725500000,
		Routes: []TableRoute{
			{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", Target: "https://cmaas.local"},
		},
	}
	got, err := tbl.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"updated_at":1725500000,"routes":[{"tenant":"tenant-a","model":"qwen-plus","default_engine":"cmaas","target":"https://cmaas.local"}]}`
	if string(got) != want {
		t.Fatalf("旧表规范字节变化（C-5 违约）:\n got = %s\nwant = %s", got, want)
	}
	// 旧表签名/验签零回归
	s, _ := NewSigner(testKey())
	if err := s.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyTable(tbl) {
		t.Fatal("旧表（无 latency）应验签通过")
	}
}

// TestRouteLatencyCanonicalAndPresence：latency 段落入规范字节；显式零值经序列化/往返保留
// （指针存在性）；未配置字段不序列化（omitempty）。
func TestRouteLatencyCanonicalAndPresence(t *testing.T) {
	gamma := 0.0
	explore := 1.0
	partition := false
	tbl := &RouteTable{Version: 2, UpdatedAt: 1725500000, Routes: []TableRoute{
		{
			Tenant: "t-001", Model: "qwen-max", DefaultEngine: "cmaas", Strategy: "latency-aware",
			Endpoints: []TableEndpoint{{Name: "a", URL: "https://a.internal/v1", Weight: 0.5, Priority: 1, Enabled: true}},
			Latency: &RouteLatency{
				Quantile:       "p95",
				Gamma:          &gamma,
				ExploreRatio:   &explore,
				CachePartition: &partition,
			},
		},
	}}
	b, err := tbl.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// 与 routecache 侧（routecache_latency_test.go）**同一字面量**共同锁定（C-5）：
	// 显式零值 gamma=0 / explore_ratio=1 / cache_partition=false 保留；未配置字段不序列化。
	const want = `{"version":2,"updated_at":1725500000,"routes":[{"tenant":"t-001","model":"qwen-max","default_engine":"cmaas","endpoints":[{"name":"a","url":"https://a.internal/v1","weight":0.5,"priority":1,"enabled":true,"auth":{}}],"strategy":"latency-aware","latency":{"quantile":"p95","gamma":0,"explore_ratio":1,"cache_partition":false}}]}`
	if s != want {
		t.Fatalf("含 latency 表的规范字节不符（C-5，基线应与 routecache 侧一致）:\n got = %s\nwant = %s", s, want)
	}
	// 往返：显式零值保留（指针存在性），且规范字节逐字节稳定
	var back RouteTable
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	l := back.Routes[0].Latency
	if l == nil {
		t.Fatal("往返后 latency 段丢失")
	}
	if l.Gamma == nil || *l.Gamma != 0 || l.ExploreRatio == nil || *l.ExploreRatio != 1 ||
		l.CachePartition == nil || *l.CachePartition != false {
		t.Fatalf("显式零值往返丢失：%+v", l)
	}
	if b2, err := back.CanonicalBytes(); err != nil || string(b2) != s {
		t.Errorf("往返后规范字节不一致（C-5）:\n b2 = %s\n b1 = %s", b2, s)
	}
	// 含 latency 的新表签名/验签；篡改 latency 应验签失败
	signer, _ := NewSigner(testKey())
	if err := signer.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if !signer.VerifyTable(tbl) {
		t.Fatal("含 latency 的表应验签通过")
	}
	tbl.Routes[0].Latency.ExploreRatio = nil
	if signer.VerifyTable(tbl) {
		t.Fatal("篡改 latency 应验签失败")
	}
}

// TestDiffRoutesLatency：latency.* 子字段级变更记录（含添加/移除/显式零值）。
func TestDiffRoutesLatency(t *testing.T) {
	base := &RouteTable{Routes: []TableRoute{{Tenant: "t", Model: "m", DefaultEngine: "cmaas"}}}
	gamma := 2.0
	withLat := &RouteTable{Routes: []TableRoute{{Tenant: "t", Model: "m", DefaultEngine: "cmaas",
		Latency: &RouteLatency{WindowSec: 600, Gamma: &gamma}}}}

	// 添加 latency 段 → 记录 2 条子字段变更
	changes := DiffRoutes(base, withLat)
	got := map[string][2]string{}
	for _, c := range changes {
		if strings.HasPrefix(c.Field, "latency.") {
			got[c.Field] = [2]string{c.Old, c.New}
		}
	}
	if len(got) != 2 {
		t.Fatalf("应记录 2 条 latency 子字段变更，got %v（全部变更 %+v）", got, changes)
	}
	if got["latency.window_sec"] != [2]string{"(缺省)", "600"} {
		t.Errorf("latency.window_sec = %v", got["latency.window_sec"])
	}
	if got["latency.gamma"] != [2]string{"(缺省)", "2"} {
		t.Errorf("latency.gamma = %v", got["latency.gamma"])
	}

	// 移除 latency 段 → 反向记录
	changes2 := DiffRoutes(withLat, base)
	got2 := map[string][2]string{}
	for _, c := range changes2 {
		if strings.HasPrefix(c.Field, "latency.") {
			got2[c.Field] = [2]string{c.Old, c.New}
		}
	}
	if got2["latency.window_sec"] != [2]string{"600", "(缺省)"} || got2["latency.gamma"] != [2]string{"2", "(缺省)"} {
		t.Errorf("移除 latency 段记录错误：%v", got2)
	}

	// nil 段 ≡ 空段（{}/未配置语义等价）：无变更
	empty := &RouteTable{Routes: []TableRoute{{Tenant: "t", Model: "m", DefaultEngine: "cmaas", Latency: &RouteLatency{}}}}
	if ch := DiffRoutes(base, empty); len(ch) != 0 {
		t.Fatalf("空段应等价于 nil 段（无变更），got %+v", ch)
	}

	// 显式零值可见：gamma=0 与缺省（nil）不同 → 记录一条
	g0 := 0.0
	zeroSeg := &RouteTable{Routes: []TableRoute{{Tenant: "t", Model: "m", DefaultEngine: "cmaas", Latency: &RouteLatency{Gamma: &g0}}}}
	ch := DiffRoutes(base, zeroSeg)
	if len(ch) != 1 || ch[0].Field != "latency.gamma" || ch[0].Old != "(缺省)" || ch[0].New != "0" {
		t.Fatalf("显式 gamma=0 应记录一条变更，got %+v", ch)
	}
}

// ============================================================
// P1-6 M4.3：Validate 策略枚举 × latency 段范围 × 一致性（400 invalid_route 的校验源）
// ============================================================

// TestValidateStrategyLatencyCombos：合法组合通过；非法枚举/缺段/越界拒绝。
func TestValidateStrategyLatencyCombos(t *testing.T) {
	eps := []TableEndpoint{{Name: "a", URL: "https://a/v1", Weight: 1, Priority: 1, Enabled: true}}
	routeWith := func(mut func(*TableRoute)) TableRoute {
		r := TableRoute{Tenant: "t", Model: "m", DefaultEngine: "cmaas", Endpoints: eps}
		mut(&r)
		return r
	}
	ok := []struct {
		name string
		r    TableRoute
	}{
		{"latency-aware+空段", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{} })},
		{"latency-fastest+段", routeWith(func(r *TableRoute) { r.Strategy = "latency-fastest"; r.Latency = &RouteLatency{WindowSec: 300} })},
		{"hybrid+显式零值", routeWith(func(r *TableRoute) {
			r.Strategy = "hybrid"
			r.Latency = &RouteLatency{Gamma: new(float64), CachePartition: new(bool)}
		})},
		{"旧策略无段", routeWith(func(r *TableRoute) { r.Strategy = "failure-rate-aware" })},
		{"边缘合法值", routeWith(func(r *TableRoute) {
			r.Strategy = "latency-aware"
			r.Latency = &RouteLatency{WindowSec: 60, Quantile: "p50", MinSamples: 1, StaleSec: 25, MaxTTFTMs: 1000}
		})},
		{"上界合法值", routeWith(func(r *TableRoute) {
			g5, mw05, er1 := 5.0, 0.5, 1.0
			r.Strategy = "latency-aware"
			r.Latency = &RouteLatency{WindowSec: 3600, Gamma: &g5, MinWeight: &mw05, ExploreRatio: &er1}
		})},
	}
	for _, tc := range ok {
		tbl := &RouteTable{Routes: []TableRoute{tc.r}}
		if err := tbl.Validate(); err != nil {
			t.Errorf("%s：应合法，got %v", tc.name, err)
		}
	}

	g6, mw06, er15 := 6.0, 0.6, 1.5
	bad := []struct {
		name string
		r    TableRoute
	}{
		{"未知策略", routeWith(func(r *TableRoute) { r.Strategy = "latency-smart" })},
		{"latency 策略缺段", routeWith(func(r *TableRoute) { r.Strategy = "hybrid" })},
		{"非 latency 策略带段", routeWith(func(r *TableRoute) { r.Strategy = "weighted"; r.Latency = &RouteLatency{} })},
		{"缺省策略带段", routeWith(func(r *TableRoute) { r.Latency = &RouteLatency{} })},
		{"window_sec 过小", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{WindowSec: 59} })},
		{"window_sec 过大", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{WindowSec: 3601} })},
		{"quantile 非法", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{Quantile: "p99"} })},
		{"gamma 越界", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{Gamma: &g6} })},
		{"min_weight 越界", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{MinWeight: &mw06} })},
		{"explore_ratio 越界", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{ExploreRatio: &er15} })},
		{"min_samples 为负", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{MinSamples: -1} })},
		{"stale_sec 过小", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{StaleSec: 24} })},
		{"max_ttft_ms 过小", routeWith(func(r *TableRoute) { r.Strategy = "latency-aware"; r.Latency = &RouteLatency{MaxTTFTMs: 999} })},
	}
	for _, tc := range bad {
		tbl := &RouteTable{Routes: []TableRoute{tc.r}}
		if err := tbl.Validate(); err == nil {
			t.Errorf("%s：应校验失败（400 invalid_route 的校验源）", tc.name)
		}
	}
}
