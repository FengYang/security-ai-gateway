// fetch.go — 限流表拉取（与 otpmask 插件的判据 5 同款语义：K_rx 验签 + 版本单调 + **失败保留旧表**）。
//
// 复用 otpmask 插件已交付的 `ratelimitcache` 包（**同一实现，不复制**；同一 Go module 内可直接 import）。
// 仅读取 `action=shadow && kind=rate` 规则用于影子计数——enforce 规则不在本插件执行。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/ratelimitcache"
)

var (
	ruleCache   *ratelimitcache.Cache
	tableParams struct {
		service string
		port    int64
		token   string // 兼容写法（静态通道令牌；配了凭据通道时以运行态为准）
	}
)

// rmHMACVerifier 实现 ratelimitcache.Verifier：本插件**自带** K_rx 字节（不经 cryptop sidecar，
// 本插件不属 §9.1 门禁作用域），故直接以 HMAC-SHA256 同步校验。
type rmHMACVerifier struct{ key []byte }

func (v rmHMACVerifier) VerifySym(_ string, data, sig []byte, cb func(ok bool, err error)) {
	m := hmac.New(sha256.New, v.key)
	_, _ = m.Write(data)
	cb(hmac.Equal(sig, m.Sum(nil)), nil)
}

// initTableFetch 初始化限流表拉取（K_rx 有效且配了控制面地址才启用）。
func initTableFetch(c PluginConfig) {
	ruleCache = nil
	if !c.Enabled || c.RouteVerifyKeyHex == "" || c.GatewayCoreService == "" {
		return
	}
	key, err := hex.DecodeString(c.RouteVerifyKeyHex)
	if err != nil || len(key) < rxroute.MinKeyLen {
		logWarnf("rpm-shadow-plugin: 限流表拉取未启用（route_verify_key 无效）")
		return
	}
	ruleCache = ratelimitcache.New(rmHMACVerifier{key: key}, "")
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
		// 版本判定（同版本=常态；回退=异常）——签名校验在 Update 内经 verifier 完成。
		if cur := ruleCache.Version(); tbl.Version == cur {
			return // 同版本＝无变更（常态，不计 ok）
		} else if tbl.Version < cur {
			metricTableFetchRej.incr()
			logWarnf("rpm-shadow-plugin: 限流表版本回退 %d < %d，拒绝（保留旧表）", tbl.Version, cur)
			return
		}
		ruleCache.Update(&tbl, func(accepted bool) {
			if !accepted {
				metricTableFetchRej.incr()
				logWarnf("rpm-shadow-plugin: 限流表未入缓存（验签失败/版本未递增）version=%d", tbl.Version)
				return
			}
			metricTableFetchOK.incr()
			logInfof("rpm-shadow-plugin: 限流表验签通过并入缓存 version=%d rules=%d", tbl.Version, len(tbl.Rules))
		})
	})
	if err != nil {
		metricTableFetchRej.incr()
		logWarnf("rpm-shadow-plugin: 触发限流表拉取失败: %v", err)
	}
}

// ensureFetchTick 注册拉取 tick（每个插件上下文一次）。
//
// 关键（wasm-go v1.1.2 生命周期，2026-09-14 kind 集群实测 + SDK 源码取证）：
// OnPluginStart 每次执行（含 ECDS 配置热更新产生的**新插件上下文**）都会先把 SDK 的
// globalOnTickFuncs 清空（plugin_wrapper.go OnPluginStart：`globalOnTickFuncs = nil`），
// 随后由 parseConfig 重新登记，并把 tick 绑到**新**上下文；旧上下文随热更新销毁。
// 因此这里**绝不能用 sync.Once 去重**：Once 在 VM 内只执行一次，热更新后 parseConfig 再执行时
// 跳过重注册 ⇒ 新上下文零 tick（本机实测：第二次 CR apply 后拉表/凭据 tick 全灭，
// 各 worker 永久停留旧版本表，table_fetch_* 计数冻结）。
//
// 不会重复登记：本插件 defaultConfigDisable + 单条 matchRule，parseConfig 在每次
// OnPluginStart 中只被调用一次（matcher.ParseRuleConfig：无全局键时仅对唯一 rule 解析一次），
// 且 SDK 每次 OnPluginStart 也会重置登记表。
func ensureFetchTick(intervalMs int64) {
	if intervalMs < 1000 {
		intervalMs = 1000
	}
	wrapper.RegisterTickFunc(intervalMs, onFetchTick)
	logInfof("rpm-shadow-plugin: 拉取 tick 已注册 period_ms=%d（限流表+凭据；每次插件启动/热更新重新注册）", intervalMs)
}

// onFetchTick 拉取 tick：凭据（若启用）+ 限流表。**失败各自保留旧值**。
func onFetchTick() {
	fetchCredentialOnce()
	fetchTableOnce()
}
