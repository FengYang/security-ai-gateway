package main

// credential.go — 段① 凭据（K_sig / attest token）**运行时周期拉取**（Phase 1 门禁 #8 / GF.2.5）。
//
// 动机：WasmPlugin config 为静态 JSON（不支持 secretKeyRef），若由部署流水线把真实密钥
// 替换进 CR，则 CR 内仍是明文。本模块让插件改为周期从管理面**只读**端点拉取：CR 内只保留
// 服务地址与一个受限读取令牌（明文通道＝内网 + 令牌，已评审选定）。
//
// 实现要点（与 routefetch.go 同构，踩坑勿重犯）：
//   - 拉取由**周期 tick 任务**驱动，不在请求路径里"即发即弃"：请求路径若先 fail-closed
//     （SendHttpResponse 结束流上下文），挂起的异步回调会被丢弃 → 回调永不执行；
//   - 出站统一 wrapper.FQDNCluster（DnsCluster 在插件内实测无法发出请求）；
//   - 失败**保留旧值**（不像路由表那样拒绝入缓存）：密钥被清空/降级会导致全量请求 401，
//     可用性优先；连续失败以日志与指标暴露，不做静默；
//   - **默认关闭**（credential_enabled 未置位 = 行为与接线前完全一致）。

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// credentialRuntime 段① 凭据运行态（tick 写入、请求路径只读）。
type credentialRuntime struct {
	enabled    bool
	service    string
	port       int64
	token      string
	name       string
	intervalMs int64

	mu          sync.RWMutex
	sigKeyHex   string // 运行态 K_sig（64 位 hex）；空 = 尚未拉到
	attestToken string // 运行态 attest token；空 = 尚未拉到
}

// credRuntime 全局凭据运行态（与 routeRuntime 同风格）。
var credRuntime credentialRuntime

// credFetchLoopOnce 保证 tick 仅注册一次（parseConfig 可能因配置热更新重复调用）。
var credFetchLoopOnce sync.Once

// initCredentialRuntime 装配凭据运行态并注册周期拉取（幂等；未启用则零影响）。
func initCredentialRuntime(c PluginConfig) {
	credRuntime.enabled = c.CredentialEnabled
	credRuntime.service = c.CredentialService
	credRuntime.port = c.CredentialPort
	credRuntime.token = c.CredentialToken
	credRuntime.name = c.CredentialName
	credRuntime.intervalMs = c.CredentialIntervalSeconds * 1000
	if credRuntime.intervalMs < 1000 {
		credRuntime.intervalMs = 1000 // 最小 1s（防御性下限：防热点轮询）
	}
	if !credRuntime.enabled {
		proxywasm.LogInfof("otpmask-plugin: 段① 凭据运行态拉取未启用（使用静态 config）")
		return
	}
	credFetchLoopOnce.Do(func() {
		wrapper.RegisterTickFunc(credRuntime.intervalMs, fetchCredentialOnce)
		proxywasm.LogInfof("otpmask-plugin: 段① 凭据周期拉取已注册 period_ms=%d name=%s",
			credRuntime.intervalMs, credRuntime.name)
	})
	// 冷启动：tick 首个回调要等一个周期，配置加载期先立即拉一次（失败由后续 tick 兜底）。
	fetchCredentialOnce()
}

// credentialResponse 端点响应（字段名与 plugin config 的 sig_key/attest_token 对齐）。
type credentialResponse struct {
	Name        string `json:"name"`
	SigKeyHex   string `json:"sig_key"`
	AttestToken string `json:"attest_token"`
}

// fetchCredentialOnce 拉取一次凭据并写入运行态（tick 触发；失败保留旧值）。
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
			// 诊断计数（与 routefetch 同思路）：cb 恒为 0 ⇒ 回调从未执行。
			metricCredFetchCb.incr()
			if statusCode != 200 {
				metricCredFetchReject.incr()
				proxywasm.LogWarnf("otpmask-plugin: 拉取段① 凭据返回 %d（保留旧值）", statusCode)
				return
			}
			var resp credentialResponse
			if err := json.Unmarshal(respBody, &resp); err != nil {
				metricCredFetchReject.incr()
				proxywasm.LogWarnf("otpmask-plugin: 解析段① 凭据失败（保留旧值）: %v", err)
				return
			}
			if err := validateCredentialPayload(resp); err != nil {
				metricCredFetchReject.incr()
				proxywasm.LogWarnf("otpmask-plugin: 段① 凭据非法（保留旧值）: %v", err)
				return
			}
			credRuntime.mu.Lock()
			credRuntime.sigKeyHex = resp.SigKeyHex
			credRuntime.attestToken = resp.AttestToken
			credRuntime.mu.Unlock()
			metricCredFetchOK.incr()
			// 只记录长度，绝不打印密钥内容。
			proxywasm.LogInfof("otpmask-plugin: 段① 凭据已更新 sig_key_len=%d attest_token_len=%d",
				len(resp.SigKeyHex), len(resp.AttestToken))
		})
	if err != nil {
		proxywasm.LogWarnf("otpmask-plugin: 触发段① 凭据拉取失败: %v", err)
	}
}

// validateCredentialPayload 校验拉取到的凭据（非法即拒绝覆盖 → 保留旧值）。
func validateCredentialPayload(r credentialResponse) error {
	if len(r.SigKeyHex) != 64 {
		return fmt.Errorf("sig_key 长度非法（%d，要求 64 位 hex）", len(r.SigKeyHex))
	}
	if _, err := hex.DecodeString(r.SigKeyHex); err != nil {
		return fmt.Errorf("sig_key 非法 hex: %w", err)
	}
	if len(r.AttestToken) < 8 {
		return fmt.Errorf("attest_token 过短（%d）", len(r.AttestToken))
	}
	return nil
}

// runtimeSigKeyHex 运行态 K_sig（尚未拉取到则为空串）。
func runtimeSigKeyHex() string {
	credRuntime.mu.RLock()
	defer credRuntime.mu.RUnlock()
	return credRuntime.sigKeyHex
}

// runtimeAttestToken 运行态 attest token（尚未拉取到则为空串）。
func runtimeAttestToken() string {
	credRuntime.mu.RLock()
	defer credRuntime.mu.RUnlock()
	return credRuntime.attestToken
}

// currentAttestToken 生效的 attest token：运行态拉取优先，回退静态注入。
func currentAttestToken(c PluginConfig) string {
	if v := runtimeAttestToken(); v != "" {
		return v
	}
	return c.AttestToken
}
