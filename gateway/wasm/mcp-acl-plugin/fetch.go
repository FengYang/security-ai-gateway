package main

// fetch.go —— 双源策略拉取（gateway-core，复用 otpmask 拉取框架：周期 tick +
// FQDNCluster 出站 + Bearer + K_rx 验签 + 版本单调 + 失败保留旧对象）。
//
// 与 otpmask 的差异（trap，勿踩）：
//   - 语义为 **fail-closed**：任一源从未拉到 → Decide 保守拒绝（不学限流表的
//     "从未拉到 → 放行 + degraded"——ACL 不允许无策略放行）；
//   - 拉取仍只由周期 tick 驱动（请求路径不发起即发即弃请求，见 otpmask routefetch.go
//     文件头：SendHttpResponse 后挂起的回调会被丢弃）。
//
// ⚠️ tick 注册不可用 sync.Once 去重：wasm-go v1.1.2 的 OnPluginStart（含配置热更新
// 产生的新插件上下文）会先清空全局 tick 注册表，须由 parseConfig 每次重新登记
// （与 otpmask 集群实测结论一致）。

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/mcp-acl-plugin/policycache"
)

// 拉取源标识（日志/指标维度）。
const (
	sourcePolicy  = "policy"
	sourceCatalog = "catalog"
)

// aclRuntimeState 运行时状态（parseConfig 初始化；wasm 单线程：配置期写、请求期读）。
type aclRuntimeState struct {
	cache            *policycache.Cache
	service          string // gateway-core（McpBridge dns registry 名，如 gateway-core.dns）
	port             int64
	token            string // 内网 Bearer（空 = 控制面未启用鉴权）
	pollIntervalMs   int64
	policyPath       string
	catalogPath      string
	minPolicyVersion int64 // policy_version 配置下限（0 = 不设限）
}

var aclRuntime aclRuntimeState

// initACLRuntime 按配置初始化/刷新运行时并注册周期拉取。
func initACLRuntime(config PluginConfig, log logs.Log) {
	aclRuntime = aclRuntimeState{
		service:          config.GatewayCoreService,
		port:             config.GatewayCorePort,
		token:            config.GatewayCoreToken,
		pollIntervalMs:   config.PollIntervalSeconds * 1000,
		policyPath:       config.PolicyRef,
		catalogPath:      config.CatalogRef,
		minPolicyVersion: config.PolicyVersion,
	}
	aclRuntime.cache = policycache.NewWithOptions(
		sidecarVerifier{},
		config.RouteVerifyKeyRef,
		policycache.Options{
			MaxStale: time.Duration(config.MaxStaleSeconds) * time.Second,
			MaxSize:  int(config.PolicyMaxSizeBytes),
			OnReject: func(source, reason string, newVersion int) {
				// 唯一拒绝计数点（Update 内部拒绝：bad_signature|replay|too_large）。
				metricFetchReject.incr()
				proxywasm.LogWarnf("mcp-acl: %s 源更新被拒 reason=%s version=%d（保留旧对象；fail-closed）",
					source, reason, newVersion)
			},
		},
	)
	ensureACLFetchLoop()
	log.Infof("mcp-acl: 双源策略拉取已启用 gateway-core=%s:%d poll=%ds policy_ref=%s catalog_ref=%s",
		aclRuntime.service, aclRuntime.port, config.PollIntervalSeconds, aclRuntime.policyPath, aclRuntime.catalogPath)
}

// ensureACLFetchLoop 注册周期拉取任务（每次 parseConfig 调用重新登记，见文件头）。
func ensureACLFetchLoop() {
	interval := aclRuntime.pollIntervalMs
	if interval < 100 {
		interval = 100
	}
	wrapper.RegisterTickFunc(interval, fetchOnce)
	proxywasm.LogInfof("mcp-acl: 双源拉取已注册 period_ms=%d（每次插件启动/热更新重新注册）", interval)
}

// fetchOnce 单次 tick：触发两源拉取（异步回调各自入缓存；任一失败保留旧对象）。
func fetchOnce() {
	if aclRuntime.service == "" || aclRuntime.cache == nil {
		return
	}
	fetchSource(sourcePolicy, aclRuntime.policyPath)
	fetchSource(sourceCatalog, aclRuntime.catalogPath)
}

// fetchSource 拉取单源并写缓存；失败路径一律保留旧对象（网络/非 200/解析/验签/回滚/超限）。
func fetchSource(source, path string) {
	reject := func(format string, args ...interface{}) {
		metricFetchReject.incr()
		proxywasm.LogWarnf("mcp-acl: "+format, args...)
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: aclRuntime.service, Port: aclRuntime.port})
	headers := [][2]string{{"Accept", "application/json"}}
	if aclRuntime.token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + aclRuntime.token})
	}
	err := cli.Get(path,
		headers,
		func(statusCode int, _ http.Header, respBody []byte) {
			// 诊断计数：cb 恒未注册 ⇒ 回调从未执行（异步回调被丢弃）。
			metricFetchCb.incr()
			if statusCode != 200 {
				reject("拉取 %s 返回 %d（保留旧对象）", path, statusCode)
				return
			}
			switch source {
			case sourcePolicy:
				var p policycache.RBACPolicy
				if err := json.Unmarshal(respBody, &p); err != nil {
					reject("解析策略失败: %v（保留旧对象）", err)
					return
				}
				if aclRuntime.minPolicyVersion > 0 && int64(p.Version) < aclRuntime.minPolicyVersion {
					reject("策略版本 %d 低于配置下限 %d，拒绝（保留旧对象）", p.Version, aclRuntime.minPolicyVersion)
					return
				}
				// 版本判定：同版本 = 常态（无变更，不计数不告警）；回退 = 异常（拒绝并计数）。
				if cur := aclRuntime.cache.PolicyVersion(); p.Version == cur {
					return
				} else if p.Version < cur {
					reject("策略版本回退 version=%d < 当前 %d，拒绝（保留旧对象）", p.Version, cur)
					return
				}
				// §5.4.5：验签经 cryptop sidecar（唯一 HTTP 面）→ 通过后入缓存。
				aclRuntime.cache.UpdatePolicy(&p, func(accepted bool) {
					if !accepted {
						// 指标/原因已在 cache.OnReject 落账（bad_signature|replay|too_large）。
						return
					}
					metricFetchOK.incr()
					proxywasm.LogInfof("mcp-acl: 策略验签通过并已入缓存 version=%d tenants=%d",
						p.Version, len(p.TenantRules))
				})
			case sourceCatalog:
				var ct policycache.ToolCatalog
				if err := json.Unmarshal(respBody, &ct); err != nil {
					reject("解析目录失败: %v（保留旧对象）", err)
					return
				}
				if cur := aclRuntime.cache.CatalogVersion(); ct.Version == cur {
					return
				} else if ct.Version < cur {
					reject("目录版本回退 version=%d < 当前 %d，拒绝（保留旧对象）", ct.Version, cur)
					return
				}
				aclRuntime.cache.UpdateCatalog(&ct, func(accepted bool) {
					if !accepted {
						return
					}
					metricFetchOK.incr()
					proxywasm.LogInfof("mcp-acl: 目录验签通过并已入缓存 version=%d tools=%d servers=%d",
						ct.Version, len(ct.Tools), len(ct.Servers))
				})
			}
		})
	if err != nil {
		reject("触发 %s 拉取失败: %v", source, err)
	}
}
