// 输入侧语义分类器侧车健康探活。
//
// 背景：侧车不可用时按 fail-closed 拒答（见 model/http_classifier.go）。若同时不摘流，
// 流量会持续打到"无审核能力"的实例上，形成 403 风暴。故可用性保障方式是
// **侧车健康进 readiness**（实例摘流 ＋ 容量保障），而不是"回退关键词、静默放行"。
//
// 健康端点契约：分类器 URL **同目录**下的 /healthz（GET，2xx 视为健康）；
// 与既有侧车实现一致（scripts/qwen3guard-l2-sidecar.py、g4-mock-sidecar.py 均提供 GET /healthz）。
//
// 状态语义：未探活过 = 不健康（避免"未确认侧车可用即接流量"）；启动即探一次，随后周期探活。
package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"sync/atomic"
	"time"
)

const (
	// guardProbeInterval 探活周期（轻量 GET，不含推理调用）。
	guardProbeInterval = 5 * time.Second
	// guardProbeTimeout 单次探活超时（不得拖慢启动与 readiness 判定）。
	guardProbeTimeout = 2 * time.Second
)

// guardClassifierProbe 侧车健康状态。
type guardClassifierProbe struct {
	healthURL string
	client    *http.Client
	healthy   atomic.Bool
	probed    atomic.Bool   // 是否已完成首次探活（区分"首探结果"与"状态翻转"日志）
	onState   func(ok bool) // 状态回调（指标上报；摘流状态须可被指标观测）；可为 nil
}

// deriveHealthURL 由分类器 URL 派生健康端点：同目录下的 /healthz。
// 例：http://127.0.0.1:19091/classify → http://127.0.0.1:19091/healthz。
func deriveHealthURL(classifyURL string) (string, error) {
	u, err := url.Parse(classifyURL)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(path.Dir(u.Path), "/healthz")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// newGuardClassifierProbe 构造探活器（URL 非法 → 返回错误，由启动期拒绝启动，fail-closed）。
// onState 每次探活后回调当前健康状态（用于 gauge 上报）；可为 nil。
func newGuardClassifierProbe(classifyURL string, onState func(ok bool)) (*guardClassifierProbe, error) {
	healthURL, err := deriveHealthURL(classifyURL)
	if err != nil {
		return nil, err
	}
	return &guardClassifierProbe{
		healthURL: healthURL,
		client:    &http.Client{Timeout: guardProbeTimeout},
		onState:   onState,
	}, nil
}

// Healthy 当前健康状态（未探活过 = false）。
func (p *guardClassifierProbe) Healthy() bool { return p.healthy.Load() }

// probe 探活一次并更新状态；首探与状态翻转各打一行日志（告警口径，不逐周期刷屏）。
func (p *guardClassifierProbe) probe() bool {
	prev := p.healthy.Load()
	first := !p.probed.Swap(true)
	ok := p.probeOnce()
	p.healthy.Store(ok)
	if p.onState != nil {
		p.onState(ok)
	}
	if first {
		log.Printf("[guardrail] 侧车首次健康探活：%s healthy=%t（不健康时 readiness 503、请求按 fail-closed 拒答）", p.healthURL, ok)
		return ok
	}
	if ok != prev {
		if ok {
			log.Printf("[guardrail] 侧车健康探活恢复：%s（readiness 恢复可服务）", p.healthURL)
		} else {
			log.Printf("[guardrail] 侧车健康探活失败：%s（readiness 置为不可服务；期间请求按 fail-closed 拒答）", p.healthURL)
		}
	}
	return ok
}

// probeOnce 单次探活：GET healthURL，2xx 视为健康。
func (p *guardClassifierProbe) probeOnce() bool {
	resp, err := p.client.Get(p.healthURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// run 启动即探一次（首探完成前 Healthy() 恒为 false），随后周期探活；进程生命周期内常驻。
func (p *guardClassifierProbe) run() {
	p.probe()
	ticker := time.NewTicker(guardProbeInterval)
	defer ticker.Stop()
	for range ticker.C {
		p.probe()
	}
}
