package main

// report.go — 窗口级汇总的上报队列与批量投递（tee-infer `POST /audit/shadow`）。
//
// 设计要点（方案 §A.3）：
//   - **有界队列**（缺省 32）：溢出**丢弃并计数**（otpmask_shadow_report_dropped_total）；
//   - 投递失败 → 重新入队（下个 tick 重试）并计 fail；因为 report_id 是**确定性**键，
//     重试不会在审计链重复落事件（tee-infer 侧幂等去重）；
//   - 于是"明文影子里程碑"对审计链是**窗口级最终一致**：可能缺报（不静默，有指标与日志）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// pendingReport 一条待上报的窗口级汇总。
type pendingReport struct {
	ReportID    string
	RuleID      string
	Scope       string
	Target      string
	WindowStart int64
	Threshold   int64
	Observed    int64
	WouldReject int64
	Samples     []string
}

// reportQueue 有界 FIFO 上报队列。
type reportQueue struct {
	mu    sync.Mutex
	items []pendingReport
	max   int
}

// newReportQueue 构造队列（max<=0 → 缺省 32）。
func newReportQueue(max int) *reportQueue {
	if max <= 0 {
		max = defaultQueueMax
	}
	return &reportQueue{max: max}
}

// push 入队（溢出丢弃并计 dropped）。
func (q *reportQueue) push(reps []pendingReport) {
	if len(reps) == 0 {
		return
	}
	q.mu.Lock()
	dropped := 0
	for _, r := range reps {
		if len(q.items) >= q.max {
			dropped++
			continue
		}
		q.items = append(q.items, r)
	}
	q.mu.Unlock()
	metricReportDropped.add(int64(dropped))
	if dropped > 0 {
		logWarnf("rpm-shadow-plugin: 上报队列溢出，丢弃 %d 条窗口汇总（审计可能缺报）", dropped)
	}
}

// takeAll 取出全部待上报并清空队列。
func (q *reportQueue) takeAll() []pendingReport {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	out := q.items
	q.items = nil
	return out
}

// len 当前队列长度（测试/诊断用）。
func (q *reportQueue) length() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// shadowReportDTO 上报体单条（字段与 tee-infer shadowReport 对齐）。
type shadowReportDTO struct {
	ReportID    string   `json:"report_id"`
	RuleID      string   `json:"rule_id"`
	Scope       string   `json:"scope"`
	Target      string   `json:"target"`
	Window      string   `json:"window"`
	WindowStart int64    `json:"window_start"`
	Threshold   int64    `json:"threshold"`
	Observed    int64    `json:"observed"`
	WouldReject int64    `json:"would_reject"`
	Samples     []string `json:"sample_request_ids,omitempty"`
	Source      string   `json:"source"`
}

// shadowReportPayload 上报请求体。
type shadowReportPayload struct {
	Reports []shadowReportDTO `json:"reports"`
}

// sendReports 批量投递（异步回调判定成败；失败重新入队重试）。**不在请求路径调用**（仅 tick 调用）。
func sendReports(cfg PluginConfig, q *reportQueue, reps []pendingReport) {
	if len(reps) == 0 {
		return
	}
	payload := shadowReportPayload{Reports: make([]shadowReportDTO, 0, len(reps))}
	for _, r := range reps {
		payload.Reports = append(payload.Reports, shadowReportDTO{
			ReportID: r.ReportID, RuleID: r.RuleID, Scope: r.Scope, Target: r.Target,
			Window: shadowWindowMinute, WindowStart: r.WindowStart,
			Threshold: r.Threshold, Observed: r.Observed, WouldReject: r.WouldReject,
			Samples: r.Samples, Source: "data-plane",
		})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		metricReportFail.add(int64(len(reps)))
		q.push(reps)
		logWarnf("rpm-shadow-plugin: 上报体编码失败（重新入队）: %v", err)
		return
	}
	headers := [][2]string{{"Content-Type", "application/json"}}
	if cfg.AdminToken != "" {
		headers = append(headers, [2]string{"X-Admin-Token", cfg.AdminToken})
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: cfg.TeeService, Port: cfg.TeePort})
	err = cli.Post("/audit/shadow", headers, body,
		func(statusCode int, _ http.Header, respBody []byte) {
			if statusCode == 200 {
				metricReportSent.add(int64(len(reps)))
				return
			}
			metricReportFail.add(int64(len(reps)))
			q.push(reps) // 失败重投（report_id 确定性 ⇒ 不会重复落链）
			logWarnf("rpm-shadow-plugin: 影子汇总上报返回 %d（已重新入队，body=%s）",
				statusCode, truncate(string(respBody), 120))
		}, reportTimeoutMs)
	if err != nil {
		metricReportFail.add(int64(len(reps)))
		q.push(reps)
		logWarnf("rpm-shadow-plugin: 触发上报失败（已重新入队）: %v", err)
	}
}

// truncate 截断日志文本（避免超长 body 打爆日志）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s...(len=%d)", s[:n], len(s))
}
