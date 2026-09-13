// fetch.go — 限流表拉取（与 otpmask 插件的判据 5 同款语义：K_rx 验签 + 版本单调 + **失败保留旧表**）。
//
// 复用 otpmask 插件已交付的 `ratelimitcache` 包（**同一实现，不复制**；同一 Go module 内可直接 import）。
// 仅读取 `action=shadow && kind=rate` 规则用于影子计数——enforce 规则不在本插件执行。
package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/ratelimitcache"
)

var (
	ruleCache   *ratelimitcache.Cache
	tableKey    []byte
	tableOnce   sync.Once
	tableParams struct {
		service string
		port    int64
		token   string // 兼容写法（静态通道令牌；配了凭据通道时以运行态为准）
	}
)

// initTableFetch 初始化限流表拉取（K_rx 有效且配了控制面地址才启用）。
func initTableFetch(c PluginConfig) {
	ruleCache, tableKey = nil, nil
	if !c.Enabled || c.RouteVerifyKeyHex == "" || c.GatewayCoreService == "" {
		return
	}
	key, err := hex.DecodeString(c.RouteVerifyKeyHex)
	if err != nil || len(key) < rxroute.MinKeyLen {
		logWarnf("rpm-shadow-plugin: 限流表拉取未启用（route_verify_key 无效）")
		return
	}
	ruleCache = ratelimitcache.New(key)
	tableKey = key
	tableParams.service = c.GatewayCoreService
	tableParams.port = c.GatewayCorePort
	tableParams.token = c.GatewayCoreToken
	logInfof("rpm-shadow-plugin: 限流表拉取已启用 gateway-core=%s:%d", tableParams.service, tableParams.port)
}

// tableRules 当前已验签表的规则（未拉到 → nil：不计数）。
func tableRules() []ratelimitcache.Rule {
	if ruleCache == nil {
		return nil
	}
	return ruleCache.Rules()
}

// fetchTableOnce 拉取一次限流表并验签入缓存（失败保留旧表；版本回退/验签失败一律拒收）。
func fetchTableOnce() {
	if ruleCache == nil {
		return
	}
	token := tableParams.token
	if v := runtimeCoreToken(); v != "" {
		token = v // 运行态（凭据通道）优先
	}
	headers := [][2]string{{"Accept", "application/json"}}
	if token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + token})
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: tableParams.service, Port: tableParams.port})
	err := cli.Get("/ratelimits", headers, func(statusCode int, _ http.Header, respBody []byte) {
		if statusCode != 200 {
			metricTableFetchRej.incr()
			logWarnf("rpm-shadow-plugin: 拉取 /ratelimits 返回 %d（保留旧表）", statusCode)
			return
		}
		tbl := ratelimitcache.Table{}
		if err := json.Unmarshal(respBody, &tbl); err != nil {
			metricTableFetchRej.incr()
			logWarnf("rpm-shadow-plugin: 解析限流表失败: %v（保留旧表）", err)
			return
		}
		if !ratelimitcache.Verify(tableKey, &tbl) {
			metricTableFetchRej.incr()
			logWarnf("rpm-shadow-plugin: 限流表验签失败，拒绝（保留旧表）")
			return
		}
		if cur := ruleCache.Version(); tbl.Version == cur {
			return // 同版本＝无变更（常态，不计 ok）
		} else if tbl.Version < cur {
			metricTableFetchRej.incr()
			logWarnf("rpm-shadow-plugin: 限流表版本回退 %d < %d，拒绝（保留旧表）", tbl.Version, cur)
			return
		}
		if !ruleCache.Update(&tbl) {
			metricTableFetchRej.incr()
			logWarnf("rpm-shadow-plugin: 限流表未入缓存（版本未递增）version=%d", tbl.Version)
			return
		}
		metricTableFetchOK.incr()
		logInfof("rpm-shadow-plugin: 限流表验签通过并入缓存 version=%d rules=%d", tbl.Version, len(tbl.Rules))
	})
	if err != nil {
		metricTableFetchRej.incr()
		logWarnf("rpm-shadow-plugin: 触发限流表拉取失败: %v", err)
	}
}

// ensureFetchTick 注册拉取 tick（幂等；凭据未启用时也要拉表，故两条路径都调用）。
func ensureFetchTick(intervalMs int64) {
	if intervalMs < 1000 {
		intervalMs = 1000
	}
	tableOnce.Do(func() {
		wrapper.RegisterTickFunc(intervalMs, onFetchTick)
		logInfof("rpm-shadow-plugin: 拉取 tick 已注册 period_ms=%d（限流表）", intervalMs)
	})
}

// onFetchTick 拉取 tick：凭据（若启用）+ 限流表。**失败各自保留旧值**。
func onFetchTick() {
	fetchCredentialOnce()
	fetchTableOnce()
}
