package main

// shadow.go — RPM 影子计数引擎（纯逻辑，可宿主单测）。
//
// 语义（判据 4）：**只计数不拒绝**；窗口＝分钟（Unix 秒 / 60）；窗口翻转即结算（产出窗口级汇总）。
// 仅处理 `action=shadow && enabled && kind=rate && rpm>0` 的规则——enforce 规则仍由
// cluster-key-rate-limit 执行（数据面零新增**限流**代码，本插件不拒绝任何请求）。
//
// 维度：`scope=tenant`（target=租户，取 x-tenant-id）与 `scope=api_key`（target=key-auth 消费者名，
// 取 X-Mse-Consumer）；`scope=model/global` 不在本插件内实施（设计 §10⑤）。缺头 → 跳过该维度并计数，
// **不猜测**（不回落其它头，避免把租户错记成消费者）。

import (
	"fmt"
	"sync"
	"time"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/ratelimitcache"
)

const (
	// shadowWindowMinute 当前仅支持分钟窗口（rpm）；token/预算维度不在本插件内（明文链路无 tokenizer）。
	shadowWindowMinute = "minute"
	// maxSamples 每条汇总携带的样本请求 ID 上限（逐笔核对用）。
	maxSamples = 5
	// maxShadowDims 维度条目上限：防"活跃租户/消费者数"无界增长导致 wasm 内存膨胀；
	// 超限按**最旧窗口**淘汰（其计数随淘汰丢弃并计入 dropped 指标，不静默）。
	maxShadowDims = 1024
)

// dimKey 影子维度键（scope|target|ruleID）。
type dimKey struct {
	Scope  string
	Target string
	RuleID string
}

// windowCount 某维度当前窗口的计数。
type windowCount struct {
	WindowStart int64 // 窗口起点（Unix 秒，= unix/60*60）
	Threshold   int64 // 规则阈值（rpm；随表版本更新）
	Observed    int64
	WouldReject int64
	Samples     []string
}

// observeResult 一次观测的结果。
type observeResult struct {
	Hits         int             // 命中（would_reject）的维度数
	MissingHeads []string        // 缺失的维度头名（去重后）
	Reports      []pendingReport // 窗口翻转结算出的待上报汇总
	Evicted      int             // 因维度上限被淘汰且**含计数**的条目数（调用方计 dropped）
}

// shadowEngine RPM 影子计数引擎。
type shadowEngine struct {
	mu   sync.Mutex
	dims map[dimKey]*windowCount
	now  func() time.Time // 便于单测注入时钟
	// tag 本 VM（worker）标识，计入 report_id：计数是 per-worker 的，多 worker 的同窗同维度汇总
	// 必须各自落链（否则会被 tee-infer 幂等去重而丢计数）。
	tag string
}

// newShadowEngine 构造引擎。
func newShadowEngine() *shadowEngine {
	return &shadowEngine{dims: make(map[dimKey]*windowCount, 32), now: time.Now, tag: vmTag}
}

// windowStartOf 窗口起点（Unix 秒对齐到分钟）。
func windowStartOf(t time.Time) int64 { return t.Unix() / 60 * 60 }

// observe 观测一次请求：按维度累加计数并判定命中；窗口翻转时结算旧窗口（产出上报）。
// **不拒绝请求、不改动请求**（调用方仅读头）。
func (e *shadowEngine) observe(tenant, consumer, requestID string, rules []ratelimitcache.Rule) observeResult {
	now := e.now()
	ws := windowStartOf(now)
	var res observeResult
	missSeen := map[string]bool{}

	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range rules {
		r := rules[i]
		if !r.Enabled || r.Action != "shadow" || r.Kind != "rate" || r.RPM <= 0 {
			continue // enforce / 非 rate / 非影子 一律不由本插件处理
		}
		var target, head, present string
		switch r.Scope {
		case "tenant":
			target, head, present = r.Target, tenantHeaderName, tenant
		case "api_key":
			target, head, present = r.Target, consumerHeaderName, consumer
		default:
			continue // model/global 维度不实施
		}
		if present == "" {
			if !missSeen[head] {
				missSeen[head] = true
				res.MissingHeads = append(res.MissingHeads, head)
			}
			continue
		}
		if present != target {
			continue // 该请求的身份不属于本规则的目标（维度隔离：只统计 rule.Target 对应流量）
		}

		k := dimKey{Scope: r.Scope, Target: target, RuleID: r.ID}
		wc := e.dims[k]
		if wc == nil {
			if len(e.dims) >= maxShadowDims {
				// 淘汰最旧窗口；若其**含计数**则该窗口汇总丢失 → 计入 dropped（不静默）
				if _, ok := e.evictOldestLocked(); ok {
					res.Evicted++
				}
			}
			wc = &windowCount{WindowStart: ws, Threshold: r.RPM}
			e.dims[k] = wc
		} else if wc.WindowStart != ws {
			if rep, ok := e.reportOfLocked(k, wc); ok {
				res.Reports = append(res.Reports, rep)
			}
			wc.WindowStart, wc.Observed, wc.WouldReject, wc.Samples = ws, 0, 0, nil
			wc.Threshold = r.RPM
		} else {
			wc.Threshold = r.RPM // 阈值随表版本更新（不改已计数的窗口起点）
		}

		wc.Observed++
		if wc.Observed > wc.Threshold {
			wc.WouldReject++
			res.Hits++
		}
		if len(wc.Samples) < maxSamples && requestID != "" {
			wc.Samples = append(wc.Samples, requestID)
		}
	}
	return res
}

// collectExpired 结算"窗口已翻转但无新请求触发"的维度（tick 调用），令窗口级汇总按时产出。
func (e *shadowEngine) collectExpired() []pendingReport {
	ws := windowStartOf(e.now())
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []pendingReport
	for k, wc := range e.dims {
		if wc.WindowStart >= ws {
			continue
		}
		if rep, ok := e.reportOfLocked(k, wc); ok {
			out = append(out, rep)
		}
		wc.WindowStart, wc.Observed, wc.WouldReject, wc.Samples = ws, 0, 0, nil
	}
	return out
}

// reportOfLocked 由窗口计数构造一条上报；observed==0 的空窗口不产出（无信息量）。
//
// report_id = `rule|scope|target|windowStart|vmTag`：**确定性键 + 每 VM 标识**——
//   - 同一 VM 的同窗同维度重试上报 ⇒ 键相同 ⇒ 由 tee-infer 幂等去重（不重复落链）；
//   - 不同 worker 的同窗同维度 ⇒ 键不同 ⇒ 各自落链（计数不被去重丢失）。
func (e *shadowEngine) reportOfLocked(k dimKey, wc *windowCount) (pendingReport, bool) {
	if wc.Observed <= 0 {
		return pendingReport{}, false
	}
	return pendingReport{
		ReportID:    fmt.Sprintf("%s|%s|%s|%d|%s", k.RuleID, k.Scope, k.Target, wc.WindowStart, e.tag),
		RuleID:      k.RuleID,
		Scope:       k.Scope,
		Target:      k.Target,
		WindowStart: wc.WindowStart,
		Threshold:   wc.Threshold,
		Observed:    wc.Observed,
		WouldReject: wc.WouldReject,
		Samples:     append([]string(nil), wc.Samples...),
	}, true
}

// evictOldestLocked 淘汰窗口起点最旧的维度条目（调用方须持锁）；返回其汇总（含计数时为 true）。
func (e *shadowEngine) evictOldestLocked() (pendingReport, bool) {
	var oldestK dimKey
	var oldest int64
	first := true
	for k, wc := range e.dims {
		if first || wc.WindowStart < oldest {
			oldestK, oldest, first = k, wc.WindowStart, false
		}
	}
	if first {
		return pendingReport{}, false
	}
	rep, hasCount := e.reportOfLocked(oldestK, e.dims[oldestK])
	delete(e.dims, oldestK)
	return rep, hasCount
}

// dimsSnapshot 当前维度计数快照（诊断/测试用）。
func (e *shadowEngine) dimsSnapshot() map[dimKey]windowCount {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[dimKey]windowCount, len(e.dims))
	for k, wc := range e.dims {
		cp := *wc
		cp.Samples = append([]string(nil), wc.Samples...)
		out[k] = cp
	}
	return out
}
