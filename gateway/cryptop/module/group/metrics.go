package group

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// gmetrics 组级可观测性（T-1 验收「指标可见」的最小实现）。
//
// 设计：低基数标签（op / result / member），避免维度爆炸；指标值经 Render 以
// Prometheus 文本格式输出，后续可并入 gateway 既有 /metrics 端点（Wave B 接线）。
type gmetrics struct {
	mu sync.Mutex

	// ops：key = op|result（如 seal|ok、generate_key|no_leader）。
	ops map[string]int64

	// 最近一次采样值（gauge）。
	leaderEpoch    uint64
	membersTotal   int
	membersHealthy int
	leaderHeld     bool
}

func newGmetrics() *gmetrics {
	return &gmetrics{ops: map[string]int64{}}
}

// recordOp 累加一次操作计数。
func (m *gmetrics) recordOp(op, result string) {
	m.mu.Lock()
	m.ops[op+"|"+result]++
	m.mu.Unlock()
}

// snapshot 写入当前 gauge 值。
func (m *gmetrics) snapshot(epoch uint64, total, healthy int, leaderHeld bool) {
	m.mu.Lock()
	m.leaderEpoch = epoch
	m.membersTotal = total
	m.membersHealthy = healthy
	m.leaderHeld = leaderHeld
	m.mu.Unlock()
}

// Render 以 Prometheus 文本格式输出（供 /metrics 接线；Wave A 仅保证可渲染）。
func (m *gmetrics) Render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprintf(w, "# HELP gateway_group_ops_total 组内所有密码操作的累计次数（按 op/result 标签）。\n")
	fmt.Fprintf(w, "# TYPE gateway_group_ops_total counter\n")
	keys := make([]string, 0, len(m.ops))
	for k := range m.ops {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "gateway_group_ops_total{op=%q,result=%q} %d\n", opOf(k), resOf(k), m.ops[k])
	}

	fmt.Fprintf(w, "# HELP gateway_group_leader_epoch 当前感知的组 epoch（非组主时为 0）。\n")
	fmt.Fprintf(w, "# TYPE gateway_group_leader_epoch gauge\n")
	fmt.Fprintf(w, "gateway_group_leader_epoch %d\n", m.leaderEpoch)

	fmt.Fprintf(w, "# HELP gateway_group_members 成员总数 / 健康数 / 是否持有组主。\n")
	fmt.Fprintf(w, "# TYPE gateway_group_members gauge\n")
	fmt.Fprintf(w, "gateway_group_members{state=\"total\"} %d\n", m.membersTotal)
	fmt.Fprintf(w, "gateway_group_members{state=\"healthy\"} %d\n", m.membersHealthy)
	if m.leaderHeld {
		fmt.Fprintf(w, "gateway_group_leader{held=\"true\"} 1\n")
	} else {
		fmt.Fprintf(w, "gateway_group_leader{held=\"false\"} 0\n")
	}
}

func opOf(k string) string {
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return k[:i]
		}
	}
	return k
}

func resOf(k string) string {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == '|' {
			return k[i+1:]
		}
	}
	return ""
}
