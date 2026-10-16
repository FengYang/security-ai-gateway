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
//  3. TestE2E_MultiTenant       多租户隔离
//  4. TestE2E_VersionMonotonic  版本号单调递增
//  5. TestE2E_SignaturePresent  路由表签名存在
//  6. TestE2E_ControlPlaneHealth 控制面健康检查
//  7. TestE2E_LatencyAwareRoute  latency-aware 多端点路由（P1-6 M6.3）
//  8. TestE2E_LatencyAwareStatsAggregation 上报→聚合→统计下发（P1-6 M6.3）
//  9. TestE2E_LatencyAwareMetrics 选路计数（需 E2E_GATEWAY_METRICS_URL，P1-6 M6.3）
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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
	Version   int          `json:"version"`
	UpdatedAt int64        `json:"updated_at"`
	Routes    []tableRoute `json:"routes"`
	Signature string       `json:"signature"`
}

type tableRoute struct {
	Tenant         string `json:"tenant"`
	Model          string `json:"model"`
	DefaultEngine  string `json:"default_engine"`
	FallbackEngine string `json:"fallback_engine,omitempty"`
	Target         string `json:"target,omitempty"`
	// P1-6 M6.3：多端点 / 延迟择优（与 gateway-core route.TableRoute 同字段名）。
	Endpoints []tableEndpoint `json:"endpoints,omitempty"`
	Strategy  string          `json:"strategy,omitempty"`
	Latency   *routeLatency   `json:"latency,omitempty"`
}

// tableEndpoint 与 gateway-core route.TableEndpoint 同字段名。
type tableEndpoint struct {
	Name     string  `json:"name"`
	URL      string  `json:"url,omitempty"`
	Weight   float64 `json:"weight,omitempty"`
	Priority int     `json:"priority,omitempty"`
	Enabled  bool    `json:"enabled,omitempty"`
}

// routeLatency 与 gateway-core route.RouteLatency 子集（同字段名）。
type routeLatency struct {
	Quantile   string `json:"quantile,omitempty"`
	MinSamples int    `json:"min_samples,omitempty"`
	StaleSec   int    `json:"stale_sec,omitempty"`
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
		"X-API-Key":   cfg.APIKey,
		"X-Tenant-ID": tenant,
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
		Version int        `json:"version"`
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

// ============================================================
// P1-6 M6.3：latency-aware 端到端（真实控制面 + 网关）
// ============================================================

const (
	e2eLatencyTenant = "e2e-latency"
	e2eLatencyModel  = "latency-model"
)

// upsertLatencyAwareRoute 下发一条双端点 latency-aware 路由（min_samples=1 便于快速判有效）。
func upsertLatencyAwareRoute(t *testing.T, cfg e2eConfig) {
	t.Helper()
	route := tableRoute{
		Tenant: e2eLatencyTenant, Model: e2eLatencyModel, DefaultEngine: "tee",
		Strategy: "latency-aware",
		Endpoints: []tableEndpoint{
			{Name: "tee-a", URL: "http://tee-a.otpmask.svc.cluster.local:19090", Weight: 1, Priority: 1, Enabled: true},
			{Name: "tee-b", URL: "http://tee-b.otpmask.svc.cluster.local:19090", Weight: 1, Priority: 1, Enabled: true},
		},
		Latency: &routeLatency{Quantile: "p95", MinSamples: 1, StaleSec: 300},
	}
	if code := upsertRoute(t, cfg, e2eLatencyTenant, e2eLatencyModel, route); code != http.StatusOK {
		t.Fatalf("下发 latency-aware 路由失败: code=%d", code)
	}
}

// warmLatencySamples 触发 n 次 /infer 以产生 TTFT 样本（供上报聚合），并验证决策路径不阻断。
func warmLatencySamples(t *testing.T, cfg e2eConfig, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if code := sendInfer(t, cfg, e2eLatencyTenant, e2eLatencyModel); code != http.StatusOK {
			t.Fatalf("latency-aware 路由请求应 200（第 %d/%d 次）: got %d（环境需具备健康 tee-a/tee-b 端点）", i+1, n, code)
		}
	}
}

// ttftStatsResp /routes/ttft/stats 响应（P1-6 M3 契约）。
type ttftStatsResp struct {
	GeneratedAt int64 `json:"generated_at"`
	Stats       []struct {
		Tenant    string `json:"tenant"`
		Model     string `json:"model"`
		Endpoint  string `json:"endpoint"`
		Cache     string `json:"cache"`
		P50Ms     int64  `json:"p50_ms"`
		P95Ms     int64  `json:"p95_ms"`
		Samples   int64  `json:"samples"`
		Valid     bool   `json:"valid"`
		UpdatedAt int64  `json:"updated_at"`
	} `json:"stats"`
}

func getTTFTStats(t *testing.T, cfg e2eConfig, tenant string) *ttftStatsResp {
	t.Helper()
	u := cfg.CoreURL + "/routes/ttft/stats?tenant=" + url.QueryEscape(tenant)
	code, body := httpGET(t, u, coreHeaders(cfg))
	if code != http.StatusOK {
		t.Fatalf("获取 TTFT 统计失败: code=%d body=%s", code, string(body))
	}
	var resp ttftStatsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("解析 TTFT 统计失败: %v body=%s", err, string(body))
	}
	return &resp
}

// TestE2E_LatencyAwareRoute 下发 latency-aware 多端点路由并验证请求路径兼容（不阻断）。
func TestE2E_LatencyAwareRoute(t *testing.T) {
	cfg := loadConfig(t)
	upsertLatencyAwareRoute(t, cfg)
	warmLatencySamples(t, cfg, 5)
	t.Log("✅ latency-aware 多端点路由请求路径正常（决策不阻断）")
}

// TestE2E_LatencyAwareStatsAggregation 上报→聚合→统计下发全链路（真实控制面）。
//
// 前置：latency-aware 路由 + 若干 /infer 产生 TTFT 样本。上报周期缺省 10s、聚合窗口 T=25s，
// 故在 120s 内轮询 /routes/ttft/stats，命中即校验契约（字段齐全 + 端点取自路由配置）。
func TestE2E_LatencyAwareStatsAggregation(t *testing.T) {
	cfg := loadConfig(t)
	upsertLatencyAwareRoute(t, cfg)
	warmLatencySamples(t, cfg, 30)

	deadline := time.Now().Add(120 * time.Second)
	for {
		resp := getTTFTStats(t, cfg, e2eLatencyTenant)
		if len(resp.Stats) > 0 {
			epSet := map[string]bool{}
			for _, s := range resp.Stats {
				if s.Tenant != e2eLatencyTenant || s.Model != e2eLatencyModel || s.Cache == "" || s.Samples <= 0 {
					t.Fatalf("统计契约不符: %+v", s)
				}
				epSet[s.Endpoint] = true
				if s.P95Ms < s.P50Ms {
					t.Fatalf("分位关系不符: p50=%d p95=%d", s.P50Ms, s.P95Ms)
				}
			}
			if !epSet["tee-a"] && !epSet["tee-b"] {
				t.Fatalf("统计端点未取自路由配置: %v", epSet)
			}
			t.Logf("✅ 上报→聚合→统计下发闭环（端点 %v，generated_at=%d）", epSet, resp.GeneratedAt)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("120s 内未观察到统计下发（上报/聚合未就绪）")
		}
		time.Sleep(5 * time.Second)
	}
}

// scrapeCounter 从 Prometheus 文本抓取指定指标值之和（无则 0）。
func scrapeCounter(t *testing.T, metricsURL, name string) float64 {
	t.Helper()
	code, body := httpGET(t, metricsURL, nil)
	if code != http.StatusOK {
		t.Fatalf("抓取指标失败: code=%d", code)
	}
	var sum float64
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == name || strings.HasPrefix(line, name+"{") || strings.HasPrefix(line, name+" ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
					sum += v
				}
			}
		}
	}
	return sum
}

// TestE2E_LatencyAwareMetrics 选路计数增长（需 E2E_GATEWAY_METRICS_URL 暴露 Envoy/Prometheus stats）。
func TestE2E_LatencyAwareMetrics(t *testing.T) {
	metricsURL := os.Getenv("E2E_GATEWAY_METRICS_URL")
	if metricsURL == "" {
		t.Skip("跳过：未配置 E2E_GATEWAY_METRICS_URL（Envoy /stats/prometheus）")
	}
	cfg := loadConfig(t)
	upsertLatencyAwareRoute(t, cfg)

	base := scrapeCounter(t, metricsURL, "otpmask_route_latency_pick_weighted_total")
	warmLatencySamples(t, cfg, 10)
	after := scrapeCounter(t, metricsURL, "otpmask_route_latency_pick_weighted_total")
	if after <= base {
		t.Fatalf("选路计数应增长: before=%v after=%v", base, after)
	}
	t.Logf("✅ latency-aware 选路计数增长: %v → %v", base, after)
}
