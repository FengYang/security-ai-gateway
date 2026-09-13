package main

// ratelimitfetch.go — 限流表拉取（Phase 1 门禁 #7 / 判据 5：拉取失败保留旧表；从未拉到 → 放行 + 告警）。
//
// 与 routefetch.go 同机制（同一 K_rx、同一 FQDNCluster 出站、周期 tick 驱动）：
//   - 拉取 gateway-core `GET /ratelimits`（已签名表）→ 验签 → 版本不倒退 → 入缓存；
//   - **失败保留旧表**（可用性优先，与路由表/凭据同策略）；版本回退/验签失败一律拒收；
//   - **从未拉到**（无任何可用表）→ 按设计 §6 放行（不限流）并计数 `otpmask_ratelimit_degraded_total`（告警源）。
//
// 范围（如实）：本文件交付**拉取与失败语义**（判据 5）。数据面限流执行仍走控制面编译产物
// （cluster-key-rate-limit 配置，见 S2/S4）；缓存规则供影子计数与后续下发适配器消费。

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/ratelimitcache"
)

// rateLimitRuntime 限流表运行时状态（由 parseConfig 初始化）。
type rateLimitRuntimeState struct {
	key            []byte
	cache          *ratelimitcache.Cache
	service        string
	token          string // gateway-core 拉取通道令牌（Authorization: Bearer；空 = 控制面未启用鉴权）
	port           int64
	pollIntervalMs int64
}

var rateLimitRuntime rateLimitRuntimeState

// fetchParams 返回拉取所需参数；未启用返回 ok=false。
func (r *rateLimitRuntimeState) fetchParams() (key []byte, service string, port int64, ok bool) {
	if r.key == nil || r.cache == nil || r.service == "" {
		return nil, "", 0, false
	}
	return r.key, r.service, r.port, true
}

// initRateLimitRuntime 按配置初始化/刷新限流表运行时；未启用则置空（不拉取、不介入）。
// 默认关闭＝行为不变（与段① 凭据拉取同一纪律）。
// 注意：**不依赖** gateway_core_enabled（路由决策开关）——限流表拉取有独立开关，
// 避免"为一个拉取通道打开路由决策"这种耦合（实链踩过：开路由决策 → 路由表拉取缺令牌
// → 空表 → 数据面 fail-closed）。
func initRateLimitRuntime(config PluginConfig, log logs.Log) {
	rateLimitRuntime.key = nil
	rateLimitRuntime.cache = nil
	rateLimitRuntime.service = ""
	rateLimitRuntime.token = ""
	rateLimitRuntime.port = 0
	rateLimitRuntime.pollIntervalMs = 0
	if !config.RateLimitEnabled || config.RouteVerifyKeyHex == "" || config.GatewayCoreService == "" {
		return
	}
	key, err := hex.DecodeString(config.RouteVerifyKeyHex) // 与路由表共用 K_rx
	if err != nil || len(key) < rxroute.MinKeyLen {
		log.Warnf("otpmask-plugin: 限流表拉取未启用（route_verify_key 无效）")
		return
	}
	rateLimitRuntime.key = key
	rateLimitRuntime.cache = ratelimitcache.New(key)
	rateLimitRuntime.service = config.GatewayCoreService
	rateLimitRuntime.token = config.GatewayCoreToken
	rateLimitRuntime.port = config.GatewayCorePort
	rateLimitRuntime.pollIntervalMs = config.PollIntervalSeconds * 1000
	ensureRateLimitFetchLoop()
	log.Infof("otpmask-plugin: 限流表拉取已启用 gateway-core=%s:%d poll=%ds",
		config.GatewayCoreService, config.GatewayCorePort, config.PollIntervalSeconds)
}

// rateLimitFetchLoopOnce 保证 tick 仅注册一次（parseConfig 可能因热更新重复调用）。
var rateLimitFetchLoopOnce sync.Once

// ensureRateLimitFetchLoop 注册周期拉取任务（幂等）。
func ensureRateLimitFetchLoop() {
	rateLimitFetchLoopOnce.Do(func() {
		interval := rateLimitRuntime.pollIntervalMs
		if interval < 100 {
			interval = 100
		}
		wrapper.RegisterTickFunc(interval, fetchRateLimitOnce)
		proxywasm.LogInfof("otpmask-plugin: 限流表周期拉取已注册 period_ms=%d", interval)
	})
}

// fetchRateLimitOnce 拉取一次限流表（tick 触发，同时覆盖冷启动）。
// 失败路径一律**保留旧表**；若本地无任何已验签表（从未拉到）→ 计数 degraded（告警源）。
func fetchRateLimitOnce() {
	key, service, port, ok := rateLimitRuntime.fetchParams()
	if !ok {
		return
	}
	reject := func(format string, args ...interface{}) {
		metricRateLimitFetchReject.incr()
		if !rateLimitRuntime.cache.Loaded() {
			// 从未拉到可用表：按设计 §6 放行 + 告警可见
			metricRateLimitDegraded.incr()
		}
		proxywasm.LogWarnf("otpmask-plugin: "+format, args...)
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: service, Port: port})
	headers := [][2]string{{"Accept", "application/json"}}
	if rateLimitRuntime.token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + rateLimitRuntime.token})
	}
	err := cli.Get("/ratelimits",
		headers,
		func(statusCode int, _ http.Header, respBody []byte) {
			metricRateLimitFetchCb.incr()
			if statusCode != 200 {
				reject("拉取 /ratelimits 返回 %d（保留旧表）", statusCode)
				return
			}
			var tbl ratelimitcache.Table
			if err := json.Unmarshal(respBody, &tbl); err != nil {
				reject("解析限流表失败: %v（保留旧表）", err)
				return
			}
			if !ratelimitcache.Verify(key, &tbl) {
				reject("限流表验签失败，拒绝（保留旧表）")
				return
			}
			// 版本判定：同版本 = 设计内常态（无变更，不计数不告警）；回退 = 异常（拒绝并计数）。
			if cur := rateLimitRuntime.cache.Version(); tbl.Version == cur {
				return
			} else if tbl.Version < cur {
				reject("限流表版本回退 version=%d < 当前 %d，拒绝（保留旧表）", tbl.Version, cur)
				return
			}
			if !rateLimitRuntime.cache.Update(&tbl) {
				reject("限流表未入缓存（版本未递增/回退）version=%d（保留旧表）", tbl.Version)
				return
			}
			metricRateLimitFetchOK.incr()
			proxywasm.LogInfof("otpmask-plugin: 限流表验签通过并已入缓存 version=%d rules=%d",
				tbl.Version, len(tbl.Rules))
		})
	if err != nil {
		reject("触发限流表拉取失败: %v", err)
	}
}
