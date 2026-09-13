// Package main — Higress Wasm 插件：rpm-shadow-plugin（Phase 1 门禁 #7 边界 A）
//
// 目的：为**明文 Provider 路由**（17 条 `/provider/*`，ingress `ai-*`）补齐 RPM **影子**执行器
// （判据 4：只计数不拒绝 + 命中落审计）——此前影子只在 tee-infer 覆盖密态链路（`/infer`、`/v1/infer`）。
//
// 边界（如实）：
//   - 只处理 `action=shadow && enabled && kind=rate && rpm>0`；enforce 规则仍由
//     `cluster-key-rate-limit` 执行（本插件**不拒绝任何请求**，不新增限流执行器）；
//   - 只做分钟窗口（rpm）；token/预算影子不在本插件内（明文链路无 tokenizer，避免假精度）；
//   - 维度：`scope=tenant`（`x-tenant-id`）/ `scope=api_key`（key-auth 2.0.0 注入的 `X-Mse-Consumer`，
//     2026-09-13 standalone 实链取证）；缺头 → 跳过并计数，**不猜测**；
//   - 限流表未拉到（或验签失败）→ 该请求不计数（`otpmask_shadow_table_fetch_reject_total` 告警）；
//   - 上报为**窗口级汇总**（非逐请求）：窗口翻转后由 tick 批量 POST tee-infer `/audit/shadow`；
//     失败重投（有界队列、溢出丢弃 + 计数）⇒ 审计对明文影子是**窗口级最终一致**（可能缺报，不静默）；
//   - 默认关闭（`shadow_enabled=false`）＝行为不变；生产 `failStrategy: FAIL_OPEN`（影子非安全边界）。
//
// 编译（仓库根执行）：
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o gateway/wasm/rpm-shadow-plugin/main.wasm ./gateway/wasm/rpm-shadow-plugin
package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

const (
	pluginName            = "rpm-shadow-plugin"
	defaultCredentialName = "core-channel"
	defaultQueueMax       = 32
	defaultFlushSeconds   = 5
	reportTimeoutMs       = 5000
)

// 维度头名（可由配置覆盖；缺省＝实链取证值：消费者头来自 key-auth 2.0.0 插件 wasm 字面量 + 上游观测）。
var (
	tenantHeaderName   = "x-tenant-id"
	consumerHeaderName = "x-mse-consumer"
)

// vmTag 本 VM（worker）标识：wasm VM **每 worker 一份**，故窗口计数是 per-worker 的
// （全局 RPM 由上报链条在 tee-infer/看板侧汇总）。report_id 必须带该标识，否则多 worker 的
// 同窗同维度汇总会因幂等键相同被 tee-infer 去重而**丢计数**——本插件实链已踩到：
// accepted=2/deduped=8（16 worker 上报同一 report_id）。
var vmTag = fmt.Sprintf("%x", time.Now().UnixNano())

// PluginConfig 插件配置（CR 内 config JSON；字段名与 deploy/higress/rpm-shadow-plugin.yaml 对齐）。
type PluginConfig struct {
	Enabled             bool   `json:"shadow_enabled"`       // 总开关（默认 false = 行为不变）
	GatewayCoreService  string `json:"gateway_core_service"` // 限流表源（如 gateway-core.dns / <svc>.svc.cluster.local）
	GatewayCorePort     int64  `json:"gateway_core_port"`
	GatewayCoreToken    string `json:"gateway_core_token"` // 兼容/联调；配了凭据通道时以运行态令牌为准
	CredentialService   string `json:"credential_service"` // 管理面凭据端点地址（与 otpmask 同一通道）
	CredentialPort      int64  `json:"credential_port"`
	CredentialName      string `json:"gateway_core_credential_name"`  // 凭据集名（缺省 core-channel；与 otpmask 通道集命名一致）
	CredentialToken     string `json:"gateway_core_credential_token"` // 该集合的受限读令牌
	RouteVerifyKeyHex   string `json:"route_verify_key"`              // K_rx（与 gateway-core 一致）
	PollIntervalSeconds int64  `json:"poll_interval"`                 // 拉取周期，缺省 60s
	TeeService          string `json:"tee_service"`                   // 上报目标（POST /audit/shadow）
	TeePort             int64  `json:"tee_port"`
	AdminToken          string `json:"admin_token"`     // X-Admin-Token（空 = tee-infer 开发模式）
	FlushSeconds        int64  `json:"flush_seconds"`   // 结算/上报周期，缺省 5s
	QueueMax            int64  `json:"queue_max"`       // 上报队列上限，缺省 32
	TenantHeader        string `json:"tenant_header"`   // 缺省 x-tenant-id
	ConsumerHeader      string `json:"consumer_header"` // 缺省 x-mse-consumer
}

var (
	// shadowEngineInstance 计数引擎（进程内单例；每 worker 一份 VM）。
	shadowEngineInstance = newShadowEngine()
	// reportQ 上报队列（容量由配置决定，parseConfig 时重建）。
	reportQ = newReportQueue(defaultQueueMax)
	// currentConfig 最近一次 parseConfig 的配置（tick 回调无配置参数，故留副本）。
	currentConfig PluginConfig
	flushOnce     sync.Once
)

func main() {}

func init() {
	wrapper.SetCtx(
		pluginName,
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

// parseConfig 解析插件配置并接线（拉取 tick / 结算 tick）。
func parseConfig(json gjson.Result, config *PluginConfig, log logs.Log) error {
	config.Enabled = json.Get("shadow_enabled").Bool()
	config.GatewayCoreService = json.Get("gateway_core_service").String()
	config.GatewayCorePort = json.Get("gateway_core_port").Int()
	config.GatewayCoreToken = json.Get("gateway_core_token").String()
	config.CredentialService = json.Get("credential_service").String()
	config.CredentialPort = json.Get("credential_port").Int()
	config.CredentialName = json.Get("gateway_core_credential_name").String()
	config.CredentialToken = json.Get("gateway_core_credential_token").String()
	config.RouteVerifyKeyHex = json.Get("route_verify_key").String()
	config.PollIntervalSeconds = json.Get("poll_interval").Int()
	config.TeeService = json.Get("tee_service").String()
	config.TeePort = json.Get("tee_port").Int()
	config.AdminToken = json.Get("admin_token").String()
	config.FlushSeconds = json.Get("flush_seconds").Int()
	config.QueueMax = json.Get("queue_max").Int()
	config.TenantHeader = json.Get("tenant_header").String()
	config.ConsumerHeader = json.Get("consumer_header").String()
	if config.TenantHeader != "" {
		tenantHeaderName = config.TenantHeader
	}
	if config.ConsumerHeader != "" {
		consumerHeaderName = config.ConsumerHeader
	}
	// 缺省值
	if config.PollIntervalSeconds <= 0 {
		config.PollIntervalSeconds = 60
	}
	if config.GatewayCorePort == 0 {
		config.GatewayCorePort = 8085
	}
	if config.TeePort == 0 {
		config.TeePort = 19090
	}
	if config.TeeService == "" {
		// 与 otpmask 一致：standalone 用完整服务域名（FQDNCluster 需完整域名，短名不会物化）
		config.TeeService = "tee-infer.higress-system.svc.cluster.local"
	}
	if config.FlushSeconds <= 0 {
		config.FlushSeconds = defaultFlushSeconds
	}
	if config.QueueMax <= 0 {
		config.QueueMax = defaultQueueMax
	}
	currentConfig = *config

	if !config.Enabled {
		log.Info("rpm-shadow-plugin: shadow_enabled=false（默认关闭，行为不变）")
		return nil
	}
	if config.GatewayCoreService == "" || config.RouteVerifyKeyHex == "" {
		return fmt.Errorf("rpm-shadow-plugin: 配置不完整（gateway_core_service / route_verify_key 必填）")
	}
	reportQ = newReportQueue(int(config.QueueMax))
	initTableFetch(*config)
	initCredentialRuntime(*config)
	ensureFetchTick(config.PollIntervalSeconds * 1000)
	ensureFlushTick(config.FlushSeconds * 1000)
	fetchTableOnce() // 冷启动立即拉一次（失败由 tick 兜底）
	log.Infof("rpm-shadow-plugin: 影子执行器已启用 table=%s:%d tenant_header=%s consumer_header=%s",
		config.GatewayCoreService, config.GatewayCorePort, tenantHeaderName, consumerHeaderName)
	return nil
}

// onHttpRequestHeaders 请求头阶段：读维度头 → 计数（**只读、不拒绝、不改请求**）。
func onHttpRequestHeaders(_ wrapper.HttpContext, cfg PluginConfig, _ logs.Log) types.Action {
	if !cfg.Enabled {
		return types.ActionContinue
	}
	tenant, _ := proxywasm.GetHttpRequestHeader(tenantHeaderName)
	consumer, _ := proxywasm.GetHttpRequestHeader(consumerHeaderName)
	requestID, _ := proxywasm.GetHttpRequestHeader("x-request-id")
	res := shadowEngineInstance.observe(tenant, consumer, requestID, tableRules())
	if res.Hits > 0 {
		metricWouldReject.add(int64(res.Hits))
	}
	if len(res.MissingHeads) > 0 {
		metricHeadMissing.add(int64(len(res.MissingHeads)))
	}
	if res.Evicted > 0 {
		metricReportDropped.add(int64(res.Evicted))
	}
	reportQ.push(res.Reports) // 纯内存入队；HTTP 投递只在 tick（不拖慢请求路径）
	return types.ActionContinue
}

// ensureFlushTick 注册"窗口结算 + 上报"tick（幂等）。
func ensureFlushTick(intervalMs int64) {
	if intervalMs < 1000 {
		intervalMs = 1000
	}
	flushOnce.Do(func() {
		wrapper.RegisterTickFunc(intervalMs, onFlushTick)
		logInfof("rpm-shadow-plugin: 结算/上报 tick 已注册 period_ms=%d", intervalMs)
	})
}

// onFlushTick 结算已翻转窗口并批量投递（**不在请求路径发 HTTP**；失败由队列重试）。
func onFlushTick() {
	if !currentConfig.Enabled {
		return
	}
	reportQ.push(shadowEngineInstance.collectExpired())
	sendReports(currentConfig, reportQ, reportQ.takeAll())
}
