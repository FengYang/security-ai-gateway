package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/higress-group/wasm-go/pkg/wrapper"
	logs "github.com/higress-group/wasm-go/pkg/log"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

// routeFetch 冷启动拉取（拉路径 B / L3）：从 gateway-core 拉取并验签默认路由表写入缓存。
//
// 仅在 config.GatewayCoreEnabled=true 时启用。使用 wrapper 异步 cluster client，
// 与既有 embedding/tee 调用一致。回调内完成验签（防篡改）与版本推进（防回滚）。
//
// 说明：wasm 异步拉取依赖 Envoy 事件循环，需在真实运行环境验证；本函数为能力封装，
// 调用入口（如 onHttpRequestHeaders 头部缓存空判定）在官方接入真机时接通。
func maybeFetchRoutes(cfg PluginConfig, log logs.Log) {
	if !cfg.GatewayCoreEnabled || cfg.RouteVerifyKeyHex == "" {
		return
	}
	key, err := hex.DecodeString(cfg.RouteVerifyKeyHex)
	if err != nil || len(key) < 32 {
		log.Warnf("otpmask-plugin: route_verify_key 无效（须≥32字节hex），跳过路由拉取")
		return
	}
	// 注意（2026-09-12 演练实证）：此处原用 wrapper.DnsCluster —— 它与插件其余出站调用
	// （tee/embedding/attest 全用 FQDNCluster）不一致，且实测**容器从未发起请求**
	// （宿主 stub 零请求日志）→ 冷启动拉取形同虚设。改为 FQDNCluster 并统一按 FQDN 配置
	// （gateway_core_service 须写 <svc>.<ns>.svc.cluster.local，与 tee_service 同理）。
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: cfg.GatewayCoreService,
		Port: cfg.GatewayCorePort,
	})
	err = cli.Get("/routes",
		[][2]string{{"Accept", "application/json"}},
		func(statusCode int, _ http.Header, respBody []byte) {
			if statusCode != 200 {
				log.Warnf("otpmask-plugin: 拉取 /routes 返回 %d", statusCode)
				return
			}
			rt, err := parseRouteTable(respBody)
			if err != nil {
				log.Warnf("otpmask-plugin: 解析路由表失败: %v", err)
				return
			}
			if routecache.Verify(key, rt) {
				// 写入路由运行时单例（route.go 持有）；Update 内部再做一次验签 + 防回滚判定。
				if routeEnabled() && routeRuntime.cache.Update(rt) {
					log.Infof("otpmask-plugin: 路由表验签通过并已入缓存 version=%d routes=%d", rt.Version, len(rt.Routes))
				} else {
					log.Warnf("otpmask-plugin: 路由表未入缓存（重复/回滚版本，或路由未启用）version=%d", rt.Version)
				}
			} else {
				log.Warnf("otpmask-plugin: 路由表验签失败，拒绝")
			}
		})
	if err != nil {
		log.Warnf("otpmask-plugin: 触发路由拉取失败: %v", err)
	}
}

// parseRouteTable 将 gateway-core /routes JSON 响应解析为插件路由表类型。
func parseRouteTable(body []byte) (*routecache.RouteTable, error) {
	var rt routecache.RouteTable
	if err := json.Unmarshal(body, &rt); err != nil {
		return nil, fmt.Errorf("路由表 JSON 解析失败: %w", err)
	}
	return &rt, nil
}