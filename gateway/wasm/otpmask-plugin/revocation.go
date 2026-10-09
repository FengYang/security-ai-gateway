// revocation.go — 租户 API Key 吊销集拉取（§8 依赖 3，M3）。
//
// 数据面从管理面 `GET /v1/adminext/key-revocations?since=<unix秒>` 周期**增量**拉取已吊销
// jti，维护本地集合；插件校验租户 Key JWT（jwt.go）通过后若 jti 命中 → 拒绝（fail-closed）。
//
// 可用性语义（与限流表/凭据同纪律）：拉取失败**保留旧集合**；**未启用 = 行为与接线前完全一致**。
// 未成功拉到过 → 不拦截（以 Key TTL 作兜底窗口，§8）。
// proxy-wasm 单线程事件循环：集合访问无并发（保留轻量互斥以便测试与演进）。
package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// keyRevocationRuntimeState 吊销集运行时状态。
type keyRevocationRuntimeState struct {
	service    string
	port       int64
	token      string
	intervalMs int64

	mu      sync.Mutex
	revoked map[string]struct{} // 已吊销 jti 集合
	since   int64               // 已拉取水位（最大 revoked_at，unix 秒）
	loaded  bool                // 是否成功拉到过（未拉到 → 不拦截，TTL 兜底）
}

var keyRevocationRuntime = keyRevocationRuntimeState{revoked: map[string]struct{}{}}

// initKeyRevocationRuntime 按配置初始化/刷新吊销拉取；未启用则置空（不拉取、不介入）。
func initKeyRevocationRuntime(config PluginConfig, log logs.Log) {
	keyRevocationRuntime.mu.Lock()
	keyRevocationRuntime.service = ""
	keyRevocationRuntime.port = 0
	keyRevocationRuntime.token = ""
	keyRevocationRuntime.intervalMs = 0
	keyRevocationRuntime.mu.Unlock()

	if !config.KeyRevocationEnabled || config.KeyRevocationService == "" {
		return
	}
	intervalSec := config.KeyRevocationIntervalSeconds
	if intervalSec <= 0 {
		intervalSec = 60 // §8：轮询间隔 ≤60s
	}
	keyRevocationRuntime.service = config.KeyRevocationService
	keyRevocationRuntime.port = config.KeyRevocationPort
	keyRevocationRuntime.token = config.KeyRevocationToken
	keyRevocationRuntime.intervalMs = intervalSec * 1000
	ensureKeyRevocationLoop(intervalSec)
	log.Infof("otpmask-plugin: 租户 Key 吊销拉取已启用 admin=%s:%d poll=%ds",
		config.KeyRevocationService, config.KeyRevocationPort, intervalSec)
}

// keyRevocationLoopOnce 保证 tick 仅注册一次（parseConfig 可能因热更新重复调用）。
var keyRevocationLoopOnce sync.Once

// ensureKeyRevocationLoop 注册周期拉取任务（幂等）。
func ensureKeyRevocationLoop(intervalSec int64) {
	keyRevocationLoopOnce.Do(func() {
		interval := intervalSec * 1000
		if interval < 100 {
			interval = 100
		}
		wrapper.RegisterTickFunc(interval, fetchKeyRevocationsOnce)
		proxywasm.LogInfof("otpmask-plugin: 租户 Key 吊销周期拉取已注册 period_ms=%d", interval)
	})
}

// fetchKeyRevocationsOnce 增量拉取一次（tick 触发，覆盖冷启动）。
func fetchKeyRevocationsOnce() {
	service := keyRevocationRuntime.service
	if service == "" {
		return
	}
	keyRevocationRuntime.mu.Lock()
	since := keyRevocationRuntime.since
	keyRevocationRuntime.mu.Unlock()

	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: service, Port: keyRevocationRuntime.port})
	headers := [][2]string{{"Accept", "application/json"}}
	if keyRevocationRuntime.token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + keyRevocationRuntime.token})
	}
	path := "/v1/adminext/key-revocations?since=" + revocationItoa(since)
	_ = cli.Get(path, headers, func(statusCode int, _ http.Header, respBody []byte) {
		if statusCode != 200 {
			proxywasm.LogWarnf("otpmask-plugin: 吊销拉取返回 %d（保留旧集合）", statusCode)
			return
		}
		var resp struct {
			Revoked []struct {
				JTI       string `json:"jti"`
				RevokedAt int64  `json:"revoked_at"`
			} `json:"revoked"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			proxywasm.LogWarnf("otpmask-plugin: 吊销响应解析失败: %v（保留旧集合）", err)
			return
		}
		keyRevocationRuntime.mu.Lock()
		for _, r := range resp.Revoked {
			if r.JTI != "" {
				keyRevocationRuntime.revoked[r.JTI] = struct{}{}
			}
			if r.RevokedAt > keyRevocationRuntime.since {
				keyRevocationRuntime.since = r.RevokedAt
			}
		}
		keyRevocationRuntime.loaded = true
		keyRevocationRuntime.mu.Unlock()
	})
}

// isKeyRevoked jti 是否已吊销（空 jti → 不判定；未拉到过 → 不拦截，TTL 兜底）。
func isKeyRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	keyRevocationRuntime.mu.Lock()
	defer keyRevocationRuntime.mu.Unlock()
	if !keyRevocationRuntime.loaded {
		return false
	}
	_, ok := keyRevocationRuntime.revoked[jti]
	return ok
}

// revocationItoa int64 → 十进制字符串（自包含，不依赖 strconv；与测试辅助 itoa 区分命名）。
func revocationItoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
