package main

// routefetch.go — 默认路由表拉取（拉路径 B / L3 冷启动 + 周期刷新）。
//
// 实现要点（2026-09-12 门禁 #5 实证后的修正）：
//   - 拉取由 **周期 tick 任务**驱动（设计 §3.3 poll_interval），**不再**在请求路径里
//     "即发即弃"：请求路径若先 fail-closed（SendHttpResponse 结束流上下文），挂起的
//     异步回调会被丢弃——实测表现为 HTTP 请求已发出、stub 返回 200，但回调从未执行
//     （fetch_cb 计数恒未注册）→ 缓存永不写入 → 降级永不发生。
//   - 出站客户端统一用 wrapper.FQDNCluster（与 tee/embedding/attest 一致）；此前用
//     DnsCluster（插件内唯一孤例）实测无法发出请求。故 gateway_core_service 须配置为
//     FQDN 形式（<svc>.<ns>.svc.cluster.local）。
//   - 仅当启用路由（gateway_core_enabled + 有效 route_verify_key）时注册与拉取。

import (
	"encoding/json"
	"net/http"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

// ensureRouteFetchLoop 注册周期拉取任务。
//
// ⚠️ **不可用 sync.Once 去重**（wasm-go v1.1.2 生命周期，2026-10-12 集群实测 + SDK 源码取证）：
// OnPluginStart 每次执行（含 ECDS 配置热更新产生的新插件上下文）都会先把 SDK 的
// globalOnTickFuncs 清空（plugin_wrapper.go OnPluginStart: `globalOnTickFuncs = nil`），
// 随后由 parseConfig 重新登记并把 tick 绑到新上下文。Once 在 VM 内只执行一次，
// 热更新后会跳过重注册 ⇒ 新上下文零 tick ⇒ 路由表周期拉取永久停止、内存缓存不再回填
// （实测：热更新后持续 fail-closed「无可用路由」）。
//
// 不会重复登记：defaultConfigDisable + 单条 matchRule ⇒ parseConfig 每次 OnPluginStart 仅调用一次。
// 同范式见 gateway/wasm/rpm-shadow-plugin/fetch.go 的 ensureFetchTick。
func ensureRouteFetchLoop() {
	interval := routeRuntime.pollIntervalMs
	if interval < 100 {
		interval = 100
	}
	wrapper.RegisterTickFunc(interval, fetchRouteTableOnce)
	proxywasm.LogInfof("otpmask-plugin: 路由表周期拉取已注册 period_ms=%d（每次插件启动/热更新重新注册）", interval)
}

// fetchRouteTableOnce 拉取一次路由表并写入运行时缓存（tick 触发；同时覆盖冷启动场景）。
func fetchRouteTableOnce() {
	_, service, port, ok := routeRuntime.fetchParams()
	if !ok {
		return
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: service, Port: port})
	headers := [][2]string{{"Accept", "application/json"}}
	if routeRuntime.token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + routeRuntime.token})
	}
	err := cli.Get("/routes",
		headers,
		func(statusCode int, _ http.Header, respBody []byte) {
			// 诊断计数（门禁 #5）：cb 恒未注册 ⇒ 回调从未执行（异步回调被丢弃）。
			metricRouteFetchCb.incr()
			if statusCode != 200 {
				metricRouteFetchReject.incr()
				proxywasm.LogWarnf("otpmask-plugin: 拉取 /routes 返回 %d", statusCode)
				return
			}
			rt, err := parseRouteTable(respBody)
			if err != nil {
				metricRouteFetchReject.incr()
				proxywasm.LogWarnf("otpmask-plugin: 解析路由表失败: %v", err)
				return
			}
			// §5.4.5：表签名校验经 cryptop sidecar（CPS，唯一 HTTP 面）→ 通过后再入缓存。
			if routeRuntime.cache == nil {
				metricRouteFetchReject.incr()
				return
			}
			routeRuntime.cache.Update(rt, func(accepted bool) {
				if accepted {
					metricRouteFetchOK.incr()
					proxywasm.LogInfof("otpmask-plugin: 路由表验签通过并已入缓存 version=%d routes=%d", rt.Version, len(rt.Routes))
					return
				}
				metricRouteFetchReject.incr()
				proxywasm.LogWarnf("otpmask-plugin: 路由表未入缓存（验签失败，或重复/回滚版本）version=%d", rt.Version)
			})
		})
	if err != nil {
		proxywasm.LogWarnf("otpmask-plugin: 触发路由拉取失败: %v", err)
	}
}

// parseRouteTable 将 gateway-core /routes JSON 响应解析为插件路由表类型。
func parseRouteTable(body []byte) (*routecache.RouteTable, error) {
	var rt routecache.RouteTable
	if err := json.Unmarshal(body, &rt); err != nil {
		return nil, err
	}
	return &rt, nil
}
