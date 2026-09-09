// Package main — 可观测性指标。
//
// 标准库手写 Prometheus 文本格式（零外部依赖，项目规范）。
// 指标族：
// gateway_admin_requests_total     经鉴权放行的请求计数
// gateway_admin_auth_rejected_total 鉴权拒绝计数（缺/坏令牌、未知角色等）
package main

import (
	"fmt"
	"io"
	"sync"
)

type adminMetrics struct {
	mu           sync.Mutex
	requests     int64
	authRejected int64
}

var metrics = newAdminMetrics()

func newAdminMetrics() *adminMetrics { return &adminMetrics{} }

func (m *adminMetrics) request() {
	m.mu.Lock()
	m.requests++
	m.mu.Unlock()
}

func (m *adminMetrics) incAuthRejected() {
	m.mu.Lock()
	m.authRejected++
	m.mu.Unlock()
}

func (m *adminMetrics) render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(w, "# HELP gateway_admin_requests_total 经鉴权放行的管理面请求计数\n# TYPE gateway_admin_requests_total counter\n")
	fmt.Fprintf(w, "gateway_admin_requests_total %d\n", m.requests)
	fmt.Fprintf(w, "# HELP gateway_admin_auth_rejected_total 鉴权拒绝计数（缺/坏令牌、未知角色等）\n# TYPE gateway_admin_auth_rejected_total counter\n")
	fmt.Fprintf(w, "gateway_admin_auth_rejected_total %d\n", m.authRejected)
}
