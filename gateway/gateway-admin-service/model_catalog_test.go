// Package main — 模型目录只读端点单测（M2 A-1'）。
//
// 覆盖（重排计划 §3 A-1' 完成定义③）：
//   - CR providers 行扫描解析（含明文 token / broker 形态 / 空列表 / managedFields 干扰）
//   - ai-route ConfigMap 目录装载（label 过滤 / 单文件损坏跳过 / 目录缺失空态）
//   - 端点行为（鉴权 401 / auditor 可读 / 405 / 端到端字段核对 / 无 CR 空列表）
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testAIProxyCR 与 higress-standalone/wasmplugins/ai-proxy.internal.yaml 同构的测试夹具
// （含 managedFields 的 "f:providers: {}" 干扰行，验证正则不误匹配）。
const testAIProxyCR = `apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  managedFields:
  - apiVersion: extensions.higress.io/v1alpha1
    fieldsV1:
      f:spec:
        f:defaultConfig:
          f:providers: {}
    manager: Kubernetes Java Client
  name: ai-proxy.internal
  namespace: higress-system
spec:
  defaultConfig:
    providers:
    - apiTokens:
      - sk-rp-plaintext-token-value
      id: phala
      openaiCustomUrl: https://inference.phala.com/v1/chat/completions
      protocol: openai
      type: openai
    - apiTokens: []
      id: empty-tokens
      openaiCustomUrl: https://inference.example.com/v1/chat/completions
      protocol: openai
      type: openai
    - id: phala-broker
      openaiCustomUrl: http://host.docker.internal:19095/llm-broker/phala/v1/chat/completions
      protocol: openai
      type: openai
  defaultConfigDisable: false
  matchRules:
  - config:
      activeProviderId: phala-broker
    service:
    - llm-phala-broker.internal.dns
  priority: 100
`

func TestParseAIProxyProviders(t *testing.T) {
	t.Run("解析明文/broker/空 token 三形态", func(t *testing.T) {
		got := parseAIProxyProviders(testAIProxyCR)
		if len(got) != 3 {
			t.Fatalf("期望 3 个 provider，实际 %d：%v", len(got), got)
		}
		p := got["phala"]
		if p == nil {
			t.Fatal("缺少 provider phala")
		}
		if !p.HasTokens {
			t.Fatal("phala 应检出明文 apiTokens")
		}
		if p.Type != "openai" || p.Protocol != "openai" {
			t.Fatalf("phala type/protocol 解析不符：%+v", p)
		}
		if !strings.Contains(p.OpenaiCustomURL, "inference.phala.com") {
			t.Fatalf("phala openaiCustomUrl 解析不符：%q", p.OpenaiCustomURL)
		}

		e := got["empty-tokens"]
		if e == nil {
			t.Fatal("缺少 provider empty-tokens")
		}
		if e.HasTokens {
			t.Fatal("apiTokens: [] 行内空列表不应判定为有 token")
		}

		b := got["phala-broker"]
		if b == nil {
			t.Fatal("缺少 provider phala-broker")
		}
		if b.HasTokens {
			t.Fatal("phala-broker 无 apiTokens，不应判定为有 token")
		}
		if !strings.Contains(b.OpenaiCustomURL, brokerPathPrefix) {
			t.Fatalf("phala-broker openaiCustomUrl 应指向 broker：%q", b.OpenaiCustomURL)
		}
	})

	t.Run("无 providers 键 → 空", func(t *testing.T) {
		got := parseAIProxyProviders("spec:\n  defaultConfig: {}\n")
		if len(got) != 0 {
			t.Fatalf("期望空，实际 %v", got)
		}
	})

	t.Run("providers 行内空列表 → 空", func(t *testing.T) {
		got := parseAIProxyProviders("spec:\n  defaultConfig:\n    providers: []\n")
		if len(got) != 0 {
			t.Fatalf("期望空，实际 %v", got)
		}
	})

	t.Run("块列表空 apiTokens（无条目行）→ 无 token", func(t *testing.T) {
		raw := "spec:\n  defaultConfig:\n    providers:\n" +
			"    - apiTokens:\n      id: no-token\n      type: openai\n"
		got := parseAIProxyProviders(raw)
		if len(got) != 1 {
			t.Fatalf("期望 1 个 provider，实际 %d", len(got))
		}
		if got["no-token"].HasTokens {
			t.Fatal("块列表后无条目行 = 空 apiTokens，不应判定为有 token")
		}
	})
}

// writeAIRouteFile 生成与 higress-standalone/configmaps/ai-route-*.yaml 同构的文件。
func writeAIRouteFile(t *testing.T, dir, name, dataJSON string) {
	t.Helper()
	content := "apiVersion: v1\ndata:\n  data: '" + dataJSON + "'\nkind: ConfigMap\nmetadata:\n" +
		"  labels:\n    higress.io/config-map-type: ai-route\n  name: " + name + "\n"
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAIRoutes(t *testing.T) {
	dir := t.TempDir()
	writeAIRouteFile(t, dir, "ai-route-b-demo",
		`{"name":"route-b","pathPredicate":{"matchType":"PRE","matchValue":"/b"},"upstreams":[{"provider":"pb","weight":100}]}`)
	writeAIRouteFile(t, dir, "ai-route-a-demo",
		`{"name":"route-a","pathPredicate":{"matchType":"PRE","matchValue":"/a"},"modelPredicates":[{"matchType":"EQUAL","matchValue":"qwen-max"}],"upstreams":[{"provider":"pa","weight":80,"modelMapping":{"gpt-4o":"model-x"}},{"provider":"pb","weight":20}]}`)
	// 非 ai-route 的 yaml（无 label）应被忽略
	if err := os.WriteFile(filepath.Join(dir, "higress-console.yaml"),
		[]byte("apiVersion: v1\ndata:\n  data: '{\"foo\":1}'\nkind: ConfigMap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 损坏 JSON 的 ai-route：跳过不整体失败
	writeAIRouteFile(t, dir, "ai-route-c-corrupt", `{"name":broken`)
	// 非 yaml 文件忽略
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("label 过滤 + 文件名序 + 损坏跳过", func(t *testing.T) {
		routes := loadAIRoutes(dir)
		if len(routes) != 2 {
			t.Fatalf("期望 2 条 route，实际 %d", len(routes))
		}
		if routes[0].Name != "route-a" || routes[1].Name != "route-b" {
			t.Fatalf("文件名排序不符：%v", routes)
		}
		a := routes[0]
		if a.PathPredicate == nil || a.PathPredicate.MatchValue != "/a" || a.PathPredicate.MatchType != "PRE" {
			t.Fatalf("pathPredicate 解析不符：%+v", a.PathPredicate)
		}
		if len(a.ModelPredicates) != 1 || a.ModelPredicates[0].MatchValue != "qwen-max" {
			t.Fatalf("modelPredicates 解析不符：%+v", a.ModelPredicates)
		}
		if len(a.Upstreams) != 2 || a.Upstreams[0].Provider != "pa" || a.Upstreams[0].Weight != 80 {
			t.Fatalf("upstreams 解析不符：%+v", a.Upstreams)
		}
		if a.Upstreams[0].ModelMapping["gpt-4o"] != "model-x" {
			t.Fatalf("modelMapping 解析不符：%+v", a.Upstreams[0].ModelMapping)
		}
	})

	t.Run("目录不存在 → 空列表", func(t *testing.T) {
		if routes := loadAIRoutes(filepath.Join(dir, "no-such-dir")); len(routes) != 0 {
			t.Fatalf("期望空列表，实际 %v", routes)
		}
	})
}

// newTestModelsMux 组装带模型目录端点的管理面路由（与 main 同构）。
func newTestModelsMux(t *testing.T, s *modelCatalogSettings) *http.ServeMux {
	t.Helper()
	return buildAdminMux(testCfg(), nil, nil, newModelCatalogHandler(s), nil, nil, nil, nil, nil, false)
}

// testModelCatalogSettings 生成指向临时 CR 文件 + ai-route 目录的配置并落盘夹具。
func testModelCatalogSettings(t *testing.T) *modelCatalogSettings {
	t.Helper()
	s := &modelCatalogSettings{
		crFile:    filepath.Join(t.TempDir(), "ai-proxy.internal.yaml"),
		routesDir: t.TempDir(),
	}
	if err := os.WriteFile(s.crFile, []byte(testAIProxyCR), 0o600); err != nil {
		t.Fatal(err)
	}
	writeAIRouteFile(t, s.routesDir, "ai-route-phala-demo",
		`{"name":"phala-demo","pathPredicate":{"matchType":"PRE","matchValue":"/phala"},"upstreams":[{"provider":"phala","weight":100}]}`)
	writeAIRouteFile(t, s.routesDir, "ai-route-phala-broker-demo",
		`{"name":"phala-broker-demo","pathPredicate":{"matchType":"PRE","matchValue":"/phala-broker"},"upstreams":[{"provider":"phala-broker","weight":100}]}`)
	return s
}

func TestModelsEndpoint(t *testing.T) {
	srv := httptest.NewServer(newTestModelsMux(t, testModelCatalogSettings(t)))
	defer srv.Close()

	t.Run("无令牌 401", func(t *testing.T) {
		resp, err := http.Get(srv.URL + modelsAPIBase)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("期望 401，实际 %d", resp.StatusCode)
		}
	})

	t.Run("auditor 只读可访问", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+modelsAPIBase, nil)
		req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
			Sub: "auditor-user", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience,
		}))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("auditor 只读期望 200，实际 %d", resp.StatusCode)
		}
	})

	t.Run("非 GET 405", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+modelsAPIBase, nil)
		req.Header.Set("Authorization", bearerToken(t))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST 期望 405，实际 %d", resp.StatusCode)
		}
	})

	t.Run("端到端：目录字段与数据源一致", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+modelsAPIBase, nil)
		req.Header.Set("Authorization", bearerToken(t))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", resp.StatusCode)
		}
		var got modelCatalogResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if len(got.Routes) != 2 {
			t.Fatalf("期望 2 行目录，实际 %d：%v", len(got.Routes), got.Routes)
		}
		// 文件名序：ai-route-phala-broker-demo 在前
		row := got.Routes[0]
		if row.Route != "phala-broker-demo" || row.Path != "/phala-broker" {
			t.Fatalf("broker 路由行不符：%+v", row)
		}
		if row.Provider != "phala-broker" || !row.ViaBroker || row.HasPlaintextToken {
			t.Fatalf("broker 路由的 provider 归属不符：%+v", row)
		}
		if row.ProviderType != "openai" || row.ProviderProtocol != "openai" || row.Weight != 100 {
			t.Fatalf("broker 路由的 provider 元数据不符：%+v", row)
		}
		if row.Models == nil || len(row.Models) != 0 {
			t.Fatalf("无限定模型的路由 models 应为空数组：%+v", row.Models)
		}
		plain := got.Routes[1]
		if plain.Route != "phala-demo" || plain.Path != "/phala" || plain.Provider != "phala" {
			t.Fatalf("明文路由行不符：%+v", plain)
		}
		if plain.ViaBroker || !plain.HasPlaintextToken {
			t.Fatalf("明文路由的形态判定不符：%+v", plain)
		}
	})

	t.Run("无 CR 且目录缺失 → 200 空列表", func(t *testing.T) {
		empty := &modelCatalogSettings{
			crFile:    filepath.Join(t.TempDir(), "no-such-cr.yaml"),
			routesDir: filepath.Join(t.TempDir(), "no-such-dir"),
		}
		srv2 := httptest.NewServer(newTestModelsMux(t, empty))
		defer srv2.Close()

		req, _ := http.NewRequest(http.MethodGet, srv2.URL+modelsAPIBase, nil)
		req.Header.Set("Authorization", bearerToken(t))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("无 CR 期望 200，实际 %d", resp.StatusCode)
		}
		var got modelCatalogResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Routes == nil || len(got.Routes) != 0 {
			t.Fatalf("无 CR 期望空列表（非 null），实际：%v", got.Routes)
		}
	})
}
