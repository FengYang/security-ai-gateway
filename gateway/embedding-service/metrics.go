// Package main — 可观测性指标。
//
// 标准库手写 Prometheus 文本格式（零外部依赖）。
// 指标族：
// otpmask_embed_requests_total  嵌入请求计数
// otpmask_embed_tokens_total    分词 token 总数计数
package main

import (
	"fmt"
	"io"
	"sync"
)

type embedMetrics struct {
	mu       sync.Mutex
	requests int64
	tokens   int64
}

func newEmbedMetrics() *embedMetrics { return &embedMetrics{} }

func (m *embedMetrics) inc(tokens int64) {
	m.mu.Lock()
	m.requests++
	m.tokens += tokens
	m.mu.Unlock()
}

func (m *embedMetrics) render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(w, "# HELP otpmask_embed_requests_total 嵌入请求计数\n# TYPE otpmask_embed_requests_total counter\n")
	fmt.Fprintf(w, "otpmask_embed_requests_total %d\n", m.requests)
	fmt.Fprintf(w, "# HELP otpmask_embed_tokens_total 分词 token 总数\n# TYPE otpmask_embed_tokens_total counter\n")
	fmt.Fprintf(w, "otpmask_embed_tokens_total %d\n", m.tokens)
}
