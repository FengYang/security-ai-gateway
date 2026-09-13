// credential.go — gateway-core 通道令牌的**运行态拉取**（轻量版，复用门禁 #7 边界 C 的凭据通道）。
//
// 与 otpmask 的完整凭据运行态（sig_key/attest/多集合/共用 tick）不同：本插件只需
// `core-channel` 集合的 `token` 一个字段，故为最小实现；失败**保留旧令牌**（可用性优先）。
// 因此本插件的 CR 内**同样不落通道令牌明文**（与 C 项一致），生产由管理面凭据端点投递。
//
// 契约（deploy/higress/README.md §6.1）：
//
//	GET {credential_service}:{credential_port}/v1/adminext/credentials/core-channel
//	header X-Credential-Token: <该集合的受限读令牌>
//	→ {"name":"core-channel","token":"<64 hex>"}
package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// minChannelTokenLen 通道令牌最小长度（与管理面 core-channel 校验一致：短令牌易被碰撞）。
const minChannelTokenLen = 32

// credentialRuntimeState 凭据运行态（进程内单例）。
type credentialRuntimeState struct {
	enabled    bool
	service    string
	port       int64
	name       string
	token      string // 该集合的受限读令牌
	intervalMs int64
	mu         sync.Mutex
	value      string // 运行态通道令牌
}

var credRuntime credentialRuntimeState

// initCredentialRuntime 按配置启用凭据运行态拉取；未配置 → 使用静态 gateway_core_token（兼容/联调）。
// **不注册 tick**：与限流表拉取共用 fetch.go 的 ensureFetchTick（同一通道，避免重复 tick）。
func initCredentialRuntime(c PluginConfig) {
	credRuntime.enabled = false
	credRuntime.service = c.CredentialService
	credRuntime.port = c.CredentialPort
	credRuntime.name = c.CredentialName
	credRuntime.token = c.CredentialToken
	credRuntime.intervalMs = c.PollIntervalSeconds * 1000
	if credRuntime.name == "" {
		credRuntime.name = defaultCredentialName
	}
	if credRuntime.intervalMs < 1000 {
		credRuntime.intervalMs = 1000 // 防御性下限：防热点轮询
	}
	if !c.Enabled || credRuntime.service == "" || credRuntime.token == "" {
		metricCredDisabled.incr()
		logInfof("rpm-shadow-plugin: 通道令牌运行态拉取未启用（使用静态 gateway_core_token）")
		return
	}
	credRuntime.enabled = true
	fetchCredentialOnce() // 冷启动立即拉一次（失败由 tick 兜底）
}

// fetchCredentialOnce 拉取通道令牌并写入运行态（失败保留旧令牌）。
func fetchCredentialOnce() {
	if !credRuntime.enabled {
		return
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: credRuntime.service, Port: credRuntime.port})
	err := cli.Get("/v1/adminext/credentials/"+credRuntime.name,
		[][2]string{
			{"Accept", "application/json"},
			{"X-Credential-Token", credRuntime.token},
		},
		func(statusCode int, _ http.Header, respBody []byte) {
			metricCredFetchCb.incr() // 诊断：恒为 0 ⇒ 回调从未执行（异步回调被丢弃）
			if statusCode != 200 {
				metricCredFetchRej.incr()
				logWarnf("rpm-shadow-plugin: 拉取通道令牌返回 %d（保留旧令牌）", statusCode)
				return
			}
			var resp struct {
				Name  string `json:"name"`
				Token string `json:"token"`
			}
			if err := json.Unmarshal(respBody, &resp); err != nil || len(resp.Token) < minChannelTokenLen {
				metricCredFetchRej.incr()
				logWarnf("rpm-shadow-plugin: 通道令牌载荷非法或过短（保留旧令牌）")
				return
			}
			credRuntime.mu.Lock()
			changed := credRuntime.value != resp.Token
			credRuntime.value = resp.Token
			credRuntime.mu.Unlock()
			metricCredFetchOK.incr()
			if changed {
				logInfof("rpm-shadow-plugin: 通道令牌已更新（立即触发一次限流表拉取）")
				fetchTableOnce() // 令牌轮换即时生效（与 otpmask 同语义）
			}
		})
	if err != nil {
		metricCredFetchRej.incr()
		logWarnf("rpm-shadow-plugin: 触发通道令牌拉取失败（保留旧令牌）: %v", err)
	}
}

// runtimeCoreToken 当前生效的通道令牌（运行态优先）。
func runtimeCoreToken() string {
	credRuntime.mu.Lock()
	defer credRuntime.mu.Unlock()
	return credRuntime.value
}
