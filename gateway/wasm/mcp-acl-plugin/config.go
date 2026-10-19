package main

import (
	"fmt"
	"strings"
	"time"

	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/tidwall/gjson"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
)

// PluginConfig mcp-acl 插件配置（WasmPlugin config JSON；控制台 YAML 自动转 JSON 下发）。
//
// 本体 §6.3 契约四键：policy_version / policy_ref / catalog_ref / fail_strategy；
// 其余键为拉取通道与判定参数（与 otpmask 拉取框架同口径，UI 可缺省）。
type PluginConfig struct {
	// ---- 本体 §6.3 契约四键 ----
	PolicyVersion int64  `json:"policy_version"` // >0：策略版本下限（低于即拒收，保留旧策略）
	PolicyRef     string `json:"policy_ref"`     // 授权策略拉取路径（缺省 /tools/policy?kind=policy）
	CatalogRef    string `json:"catalog_ref"`    // 工具目录拉取路径（缺省 /tools/policy?kind=catalog）
	FailStrategy  string `json:"fail_strategy"`  // 仅 FAIL_CLOSED（其余值配置解析即失败）

	// ---- 拉取通道（gateway-core；K_rx 验签、版本单调、失败保留旧策略）----
	GatewayCoreService  string `json:"gateway_core_service"`
	GatewayCorePort     int64  `json:"gateway_core_port"`
	GatewayCoreToken    string `json:"gateway_core_token"`   // 内网 Bearer（生产经部署流水线注入）
	RouteVerifyKeyRef   string `json:"route_verify_key_ref"` // K_rx 句柄（cryptop 静态密钥登记名）
	PollIntervalSeconds int64  `json:"poll_interval"`
	MaxStaleSeconds     int64  `json:"max_stale_seconds"`
	PolicyMaxSizeBytes  int64  `json:"policy_max_size_bytes"`

	// ---- 判定参数 ----
	TenantHeader string `json:"tenant_header"` // 租户载体头（缺省 x-tenant-id，与限流同口径）

	// ---- cryptop sidecar（验签唯一出站；插件零密码 R-4）----
	CryptoService           string `json:"crypto_service"`
	CryptoServicePort       int64  `json:"crypto_service_port"`
	CryptoProfile           string `json:"crypto_profile"`
	CryptoCallTimeoutMS     int64  `json:"crypto_call_timeout_ms"`
	CryptoCircuitThreshold  int64  `json:"crypto_circuit_threshold"`
	CryptoCircuitCooldownMS int64  `json:"crypto_circuit_cooldown_ms"`
}

// parseConfig 解析并校验插件配置；返回错误 = 配置不可用（WasmPlugin failStrategy
// FAIL_CLOSE ⇒ 匹配路由请求一律拒绝，不降级放行）。
func parseConfig(json gjson.Result, config *PluginConfig, log logs.Log) error {
	config.PolicyVersion = json.Get("policy_version").Int()
	config.PolicyRef = json.Get("policy_ref").String()
	config.CatalogRef = json.Get("catalog_ref").String()
	config.FailStrategy = json.Get("fail_strategy").String()
	config.GatewayCoreService = json.Get("gateway_core_service").String()
	config.GatewayCorePort = json.Get("gateway_core_port").Int()
	config.GatewayCoreToken = json.Get("gateway_core_token").String()
	config.RouteVerifyKeyRef = json.Get("route_verify_key_ref").String()
	config.PollIntervalSeconds = json.Get("poll_interval").Int()
	config.MaxStaleSeconds = json.Get("max_stale_seconds").Int()
	config.PolicyMaxSizeBytes = json.Get("policy_max_size_bytes").Int()
	config.TenantHeader = json.Get("tenant_header").String()
	config.CryptoService = json.Get("crypto_service").String()
	config.CryptoServicePort = json.Get("crypto_service_port").Int()
	config.CryptoProfile = json.Get("crypto_profile").String()
	config.CryptoCallTimeoutMS = json.Get("crypto_call_timeout_ms").Int()
	config.CryptoCircuitThreshold = json.Get("crypto_circuit_threshold").Int()
	config.CryptoCircuitCooldownMS = json.Get("crypto_circuit_cooldown_ms").Int()

	// 硬校验：fail_strategy 仅支持 FAIL_CLOSED（fail-closed 为硬约束 R-2，不得配置成放行）。
	if config.FailStrategy == "" {
		config.FailStrategy = "FAIL_CLOSED"
	}
	if !strings.EqualFold(config.FailStrategy, "FAIL_CLOSED") {
		return fmt.Errorf("mcp-acl: fail_strategy=%q 不支持（仅 FAIL_CLOSED；fail-closed 为硬约束）", config.FailStrategy)
	}

	// 缺省补齐（与 otpmask 拉取框架同口径）。
	if config.PolicyRef == "" {
		config.PolicyRef = "/tools/policy?kind=policy"
	}
	if config.CatalogRef == "" {
		config.CatalogRef = "/tools/policy?kind=catalog"
	}
	if config.GatewayCoreService == "" {
		config.GatewayCoreService = "gateway-core.dns" // McpBridge dns registry（不得填跨命名空间 FQDN）
	}
	if config.GatewayCorePort == 0 {
		config.GatewayCorePort = 8085
	}
	if config.PollIntervalSeconds <= 0 {
		config.PollIntervalSeconds = 60
	}
	if config.PolicyMaxSizeBytes <= 0 {
		config.PolicyMaxSizeBytes = 1 << 20 // 1MiB 估算上限（约 5K 工具条目）
	}
	if config.TenantHeader == "" {
		config.TenantHeader = "x-tenant-id"
	}
	if config.CryptoService == "" {
		config.CryptoService = "cryptop-svc.static"
	}
	if config.CryptoServicePort == 0 {
		config.CryptoServicePort = 19097
	}
	if config.CryptoProfile == "" {
		config.CryptoProfile = "intl"
	}
	if config.CryptoCallTimeoutMS <= 0 {
		config.CryptoCallTimeoutMS = int64(cryptoclient.DefaultTimeoutMS)
	}
	if config.CryptoCircuitThreshold <= 0 {
		config.CryptoCircuitThreshold = int64(cryptoclient.DefaultThreshold)
	}
	if config.CryptoCircuitCooldownMS <= 0 {
		config.CryptoCircuitCooldownMS = int64(cryptoclient.DefaultCooldown / time.Millisecond)
	}
	if config.RouteVerifyKeyRef == "" {
		config.RouteVerifyKeyRef = keyRefPolicyVerify
	}

	initCryptoRuntime(*config, log)
	initACLRuntime(*config, log)
	return nil
}
