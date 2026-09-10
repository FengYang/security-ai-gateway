// Package main — 内部凭据 broker（apiTokens Secret 化，路线丙）。
//
// 设计：docs/管理门户-apiTokens-Secret化方案设计.md §4（M1，含评审处置 S-1/S-3/O-2/A-3）；
// M2 A-1 追加热切换路由表：docs/管理门户-apiTokens-Secret化-M2细化方案.md §2.1.5。
//
// provider 的 openaiCustomUrl 指向 /llm-broker/{provider}/...，ai-proxy WasmPlugin CR
// 不含任何 token；本 handler 在集群内网边界内完成：
//
//	provider 允许表校验（未知 → 404 provider_unknown，fail-closed）
//	路径白名单校验（S-1：缺省最小集，越界 → 404 path_denied）
//	Key 覆盖注入（入站 Authorization 一律覆盖，客户端/网关侧凭证不透传厂商）
//	request_id 关联（S-3：透传或生成，写入响应头与日志，可与 Envoy 访问日志关联）
//	httputil.ReverseProxy 透传（FlushInterval=-1 逐帧 flush，SSE 兼容，检查表②）
//
// 安全边界（§4.3）：Key 绝不进入日志/错误信息/响应；指标 label 仅用配置内
// provider 名或常量 "_unknown"，防外部输入撑爆基数；失效语义 = broker 不可用
// 即该 provider 推理 fail（非静默降级）。
//
// 热切换（M2 §2.1.5）：路由表存于 atomic.Value，reload 时整表替换（请求要么用旧表
// 要么用新表，不存在半新半旧）；存表后不再原地修改，保证并发安全。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httputil"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// brokerPathPrefix mux 注册前缀（子树匹配）。
const brokerPathPrefix = "/llm-broker/"

// relayStateKey 单次中转运行态的上下文键（不透出包外）。
type relayStateKey struct{}

// relayState 记录一次中转的运行态（ErrorHandler 与外层 handler 共享）。
type relayState struct {
	upstreamErr atomic.Bool // 上游传输层错误（非 HTTP 状态错误）
}

// brokerHandler broker 路由入口（provider → 预建反代，热路径零配置分配）。
//
// routes 为 atomic.Value，存 map[string]*brokerRoute；写入只发生在本 handler
// 内部（swap），读取在 ServeHTTP，二者经原子替换同步。
type brokerHandler struct {
	routes atomic.Value
}

// brokerRoute 单 provider 的运行态路由（配置 + 预建反代）。
type brokerRoute struct {
	p     *brokerProvider
	proxy *httputil.ReverseProxy
}

// buildRoutes 按配置构建路由表（每次构建新 map，绝不复用/原地修改）。
func buildRoutes(cfg *brokerConfig) map[string]*brokerRoute {
	routes := make(map[string]*brokerRoute, len(cfg.providers))
	for name, p := range cfg.providers {
		routes[name] = &brokerRoute{p: p, proxy: buildProxy(p)}
	}
	return routes
}

// newBrokerHandler 装配 broker handler（按 provider 预建 ReverseProxy）。
func newBrokerHandler(cfg *brokerConfig) *brokerHandler {
	h := &brokerHandler{}
	h.routes.Store(buildRoutes(cfg))
	return h
}

// currentRoutes 取当前路由表快照（原子读）。
func (h *brokerHandler) currentRoutes() map[string]*brokerRoute {
	m, _ := h.routes.Load().(map[string]*brokerRoute)
	return m
}

// swap 原子替换路由表（配置热加载入口，M2 §2.1.5）。
func (h *brokerHandler) swap(cfg *brokerConfig) {
	h.routes.Store(buildRoutes(cfg))
}

// providerCount 当前生效的 provider 数（指标/日志用）。
func (h *brokerHandler) providerCount() int {
	return len(h.currentRoutes())
}

// buildProxy 为 provider 构建反代（Director 只做主机/凭证注入，路径由外层改写）。
func buildProxy(p *brokerProvider) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = p.upstream.Scheme
			req.URL.Host = p.upstream.Host
			// 上游 base path 拼接（upstream.Path 通常为空；外层已把 req.URL.Path
			// 改写为规范化后的上游相对路径，query 原样保留）
			if p.upstream.Path != "" && p.upstream.Path != "/" {
				req.URL.Path = strings.TrimSuffix(p.upstream.Path, "/") + req.URL.Path
			}
			req.URL.RawPath = ""
			req.Host = p.upstream.Host
			// Key 覆盖注入：无论入站是否携带 Authorization，一律覆盖——
			// 客户端/网关侧凭证不透传厂商（评审 R-2①②）。
			req.Header.Set("Authorization", "Bearer "+string(p.key))
		},
		FlushInterval: -1, // 流式兼容检查表②：SSE 逐帧 flush，禁止缓冲
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if st, ok := r.Context().Value(relayStateKey{}).(*relayState); ok {
				st.upstreamErr.Store(true)
			}
			// 只记录概要（host + 传输错误），绝不含 Key/Authorization/请求体
			log.Printf("[broker] rid=%s upstream %s 传输错误: %v",
				r.Header.Get("X-Request-ID"), p.upstream.Host, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// ServeHTTP 处理 /llm-broker/{provider}/{path...}。
func (h *brokerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// request_id 关联（S-3）：透传入站值，缺则生成；同步写入转发请求头与响应头。
	rid := r.Header.Get("X-Request-ID")
	if rid == "" {
		rid = newRequestID()
	}
	r.Header.Set("X-Request-ID", rid)
	w.Header().Set("X-Request-ID", rid)

	routes := h.currentRoutes()
	provider, rest, ok := splitBrokerPath(r.URL.Path)
	if !ok || routes[provider] == nil {
		// 指标 label 用常量 _unknown（外部输入不得直接作 label）
		metrics.brokerRequest("_unknown", "404", "provider_unknown")
		log.Printf("[broker] rid=%s %s %s -> 404 provider_unknown", rid, r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	route := routes[provider]

	// 规范化路径 + 白名单校验（S-1，fail-closed）。
	upstreamPath := path.Clean("/" + rest)
	if !allowPath(route.p, upstreamPath) {
		metrics.brokerRequest(provider, "404", "path_denied")
		log.Printf("[broker] rid=%s %s %s -> 404 path_denied", rid, r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}

	origPath := r.URL.Path    // 日志用原始路径
	r.URL.Path = upstreamPath // 改写为上游相对路径（query 保留）

	rec := &statusRecorder{ResponseWriter: w}
	st := &relayState{}
	r = r.WithContext(context.WithValue(r.Context(), relayStateKey{}, st))
	route.proxy.ServeHTTP(rec, r)

	reason := "ok"
	if st.upstreamErr.Load() {
		reason = "upstream_error"
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	metrics.brokerRequest(provider, strconv.Itoa(status), reason)
	log.Printf("[broker] rid=%s %s %s -> %d %s (%s)",
		rid, r.Method, origPath, status, reason, time.Since(start).Round(time.Millisecond))
}

// splitBrokerPath 拆分 /llm-broker/{provider}/{rest...}。
func splitBrokerPath(p string) (provider, rest string, ok bool) {
	if !strings.HasPrefix(p, brokerPathPrefix) {
		return "", "", false
	}
	remainder := strings.TrimPrefix(p, brokerPathPrefix)
	if remainder == "" {
		return "", "", false
	}
	if i := strings.IndexByte(remainder, '/'); i >= 0 {
		return remainder[:i], remainder[i+1:], true
	}
	return remainder, "", true // 无子路径 → 上游路径 "/"，白名单必拒（fail-closed）
}

// allowPath 白名单匹配：前缀命中且止于边界（末尾或下一字符为 /），防 "/v1/chat/completionsX" 误放行。
func allowPath(p *brokerProvider, upstreamPath string) bool {
	for _, pre := range p.allowPathPrefixes {
		if !strings.HasPrefix(upstreamPath, pre) {
			continue
		}
		if len(upstreamPath) == len(pre) || upstreamPath[len(pre)] == '/' {
			return true
		}
	}
	return false
}

// newRequestID 生成短随机 request_id（16 hex）。
func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// statusRecorder 捕获响应状态码；必须透传 Flush（SSE 逐帧下发依赖，检查表②）。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
