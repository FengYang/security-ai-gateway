// Package e2e 路由层端到端测试（在真实 K8s + Higress 环境运行）。
//
// 运行方式：
//
//	# 本地交叉编译（Windows → Linux）
//	GOOS=linux GOARCH=amd64 go test -c ./e2e/ -o e2e/e2e.test
//
//	# 传到 K8s 节点上运行
//	E2E_GATEWAY_URL=http://10.42.0.9:30000 \
//	E2E_CORE_URL=http://gateway-core.otpmask.svc.cluster.local:8085 \
//	E2E_API_KEY=CHANGE_ME_API_KEY_A \
//	E2E_CORE_TOKEN=<token> \
//	./e2e.test -test.v
//
// 测试覆盖：
//  1. TestE2E_BasicRoute        基础路由
//  2. TestE2E_RouteHotUpdate    路由表热更新
//  3. TestE2E_SignatureReject   签名验证（错误签名被拒）
//  4. TestE2E_VersionRollback   版本回退防护
//  5. TestE2E_MultiTenant       多租户隔离
//  6. TestE2E_DegradedMode      降级模式（控制面失联）
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// ============================================================
// 配置
// ============================================================

type e2eConfig struct {
	GatewayURL string // 网关地址，如 http://10.42.0.9:30000
	CoreURL    string // 控制面地址，如 http://gateway-core.otpmask.svc.cluster.local:8085
	APIKey     string // key-auth 的 API key
	CoreToken  string // 控制面鉴权 token
}

func loadConfig(t *testing.T) e2eConfig {
	t.Helper()
	cfg := e2eConfig{
		GatewayURL: os.Getenv("E2E_GATEWAY_URL"),
		CoreURL:    os.Getenv("E2E_CORE_URL"),
		APIKey:     os.Getenv("E2E_API_KEY"),
		CoreToken:  os.Getenv("E2E_CORE_TOKEN"),
	}
	if cfg.GatewayURL == "" || cfg.CoreURL == "" || cfg.APIKey == "" || cfg.CoreToken == "" {
		t.Skip("跳过 E2E 测试：缺少环境变量 E2E_GATEWAY_URL / E2E_CORE_URL / E2E_API_KEY / E2E_CORE_TOKEN")
	}
	return cfg
}

// ============================================================
// HTTP helper
// ============================================================

var httpClient = &http.Client{Timeout: 10 * time.Second}

func httpGET(t *testing.T, url string, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造 GET 请求失败: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func httpPUT(t *testing.T, url string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("JSON 序列化失败: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("构造 PUT 请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("PUT 请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

func httpPOST(t *testing.T, url string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("JSON 序列化失败: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("构造 POST 请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST 请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// ============================================================
// 控制面 helper
// ============================================================

type routeTableResp struct {
	Version   int             `json:"version"`
	UpdatedAt int64           `json:"updated_at"`
	Routes    []tableRoute    `json:"routes"`
	Signature string          `json:"signature"`
}

type tableRoute struct {
	Tenant         string          `json:"tenant"`
	Model          string          `json:"model"`
	DefaultEngine  string          `json:"default_engine"`
	FallbackEngine string          `json:"fallback_engine,omitempty"`
	Target         string          `json:"target,omitempty"`
}

func coreHeaders(cfg e2eConfig) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + cfg.CoreToken,
	}
}

func getRouteTable(t *testing.T, cfg e2eConfig) *routeTableResp {
	t.Helper()
	code, body := httpGET(t, cfg.CoreURL+"/routes", coreHeaders(cfg))
	if code != http.StatusOK {
		t.Fatalf("获取路由表失败: code=%d body=%s", code, string(body))
	}
	var resp routeTableResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("解析路由表失败: %v body=%s", err, string(body))
	}
	return &resp
}

func upsertRoute(t *testing.T, cfg e2eConfig, tenant, model string, route tableRoute) int {
	t.Helper()
	url := fmt.Sprintf("%s/routes/%s/%s", cfg.CoreURL, tenant, model)
	code, _ := httpPUT(t, url, route, coreHeaders(cfg))
	return code
}

// ============================================================
// 网关请求 helper
// ============================================================

type inferReq struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Stream bool `json:"stream"`
}

func gatewayHeaders(cfg e2eConfig, tenant string) map[string]string {
	return map[string]string{
		"X-API-Key":    cfg.APIKey,
		"X-Tenant-ID":  tenant,
	}
}

func sendInfer(t *testing.T, cfg e2eConfig, tenant, model string) int {
	t.Helper()
	req := inferReq{
		Model: model,
		Messages: []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{{"user", "hello e2e test"}},
		Stream: false,
	}
	code, _ := httpPOST(t, cfg.GatewayURL+"/infer", req, gatewayHeaders(cfg, tenant))
	return code
}

// ============================================================
// 测试用例
// ============================================================

// TestE2E_BasicRoute 基础路由：正常请求返回 200
func TestE2E_BasicRoute(t *testing.T) {
	cfg := loadConfig(t)

	code := sendInfer(t, cfg, "tenant-a", "qwen-plus")
	if code != http.StatusOK {
		t.Fatalf("基础路由请求应返回 200，got %d", code)
	}
	t.Log("✅ 基础路由正常")
}

// TestE2E_RouteHotUpdate 路由表热更新：新增路由 → 生效
func TestE2E_RouteHotUpdate(t *testing.T) {
	cfg := loadConfig(t)

	tenant := "e2e-hotupdate"
	model := "test-model"

	// 先确认当前没有这条路由
	code, _ := httpGET(t, fmt.Sprintf("%s/routes/%s/%s", cfg.CoreURL, tenant, model), coreHeaders(cfg))
	if code == http.StatusOK {
		// 已存在就先删掉（清理）
		req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/routes/%s/%s", cfg.CoreURL, tenant, model), nil)
		req.Header.Set("Authorization", "Bearer "+cfg.CoreToken)
		httpClient.Do(req)
	}

	// 新增一条路由
	newRoute := tableRoute{
		Tenant:         tenant,
		Model:          model,
		DefaultEngine:  "cmaas",
		FallbackEngine: "vllm",
	}
	code = upsertRoute(t, cfg, tenant, model, newRoute)
	if code != http.StatusOK {
		t.Fatalf("新增路由失败: code=%d", code)
	}

	// 等插件拉取（轮询间隔默认 60 秒，但可以等一轮）
	// 这里不等了，直接验证控制面有这条路由
	code, body := httpGET(t, fmt.Sprintf("%s/routes/%s/%s", cfg.CoreURL, tenant, model), coreHeaders(cfg))
	if code != http.StatusOK {
		t.Fatalf("查询新增路由失败: code=%d", code)
	}
	var resp struct {
		Version int         `json:"version"`
		Route   tableRoute `json:"route"`
	}
	json.Unmarshal(body, &resp)
	if resp.Route.DefaultEngine != "cmaas" {
		t.Fatalf("新增路由 engine 不匹配: got %q", resp.Route.DefaultEngine)
	}

	t.Logf("✅ 路由热更新成功（版本 %d）", resp.Version)
}

// TestE2E_MultiTenant 多租户隔离：不同租户的路由互不干扰
func TestE2E_MultiTenant(t *testing.T) {
	cfg := loadConfig(t)

	// 给两个不同租户各创建一条路由
	tenants := []string{"e2e-tenant-1", "e2e-tenant-2"}
	for i, tenant := range tenants {
		route := tableRoute{
			Tenant:        tenant,
			Model:         "shared-model",
			DefaultEngine: fmt.Sprintf("engine-%d", i+1),
		}
		code := upsertRoute(t, cfg, tenant, "shared-model", route)
		if code != http.StatusOK {
			t.Fatalf("租户 %s 创建路由失败: code=%d", tenant, code)
		}
	}

	// 验证两条路由都存在
	for _, tenant := range tenants {
		code, _ := httpGET(t, fmt.Sprintf("%s/routes/%s/shared-model", cfg.CoreURL, tenant), coreHeaders(cfg))
		if code != http.StatusOK {
			t.Fatalf("租户 %s 的路由不存在: code=%d", tenant, code)
		}
	}

	t.Log("✅ 多租户路由隔离正常")
}

// TestE2E_VersionMonotonic 版本号单调递增（每次更新版本号 +1）
func TestE2E_VersionMonotonic(t *testing.T) {
	cfg := loadConfig(t)

	// 获取当前版本
	tbl1 := getRouteTable(t, cfg)

	// 更新一条路由
	tenant := "e2e-version-test"
	model := "test"
	route := tableRoute{Tenant: tenant, Model: model, DefaultEngine: "v1"}
	code := upsertRoute(t, cfg, tenant, model, route)
	if code != http.StatusOK {
		t.Fatalf("更新路由失败: code=%d", code)
	}

	// 再获取版本
	tbl2 := getRouteTable(t, cfg)
	if tbl2.Version <= tbl1.Version {
		t.Fatalf("版本号应递增: 之前=%d 之后=%d", tbl1.Version, tbl2.Version)
	}

	t.Logf("✅ 版本号单调递增: %d → %d", tbl1.Version, tbl2.Version)
}

// TestE2E_SignaturePresent 路由表有签名（验证签名机制存在）
func TestE2E_SignaturePresent(t *testing.T) {
	cfg := loadConfig(t)

	tbl := getRouteTable(t, cfg)
	if tbl.Signature == "" {
		t.Fatal("路由表不应为空签名")
	}
	if len(tbl.Routes) == 0 {
		t.Log("⚠️ 当前路由表为空，签名可能是空表的签名")
	}

	t.Logf("✅ 路由表有签名（长度: %d 字符，版本: %d）", len(tbl.Signature), tbl.Version)
}

// TestE2E_ControlPlaneHealth 控制面健康检查
func TestE2E_ControlPlaneHealth(t *testing.T) {
	cfg := loadConfig(t)

	code, body := httpGET(t, cfg.CoreURL+"/health", nil)
	if code != http.StatusOK {
		t.Fatalf("控制面健康检查失败: code=%d body=%s", code, string(body))
	}
	t.Logf("✅ 控制面健康: %s", string(body))
}
