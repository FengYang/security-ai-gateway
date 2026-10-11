package main

import (
	"bytes"
	"io"
	"net/http"

	"security-ai-gateway/protocol/go"
)

// handleMCPRequest 敏感轨请求路径（§12.2 T-5 步骤 5）：
// 段① 解密（EndpointMCP）→ TEE 内 MCP 协议层（mcpproto：按租户过滤 + mcpguard 裁决）
// → 响应以 s2c 信封封装回数据面。
//
// fail-closed：无段① 证明会话 / 信封不可解 一律拒绝，绝不降级明文（C-4）。
func (s *teeServer) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "读取请求失败", http.StatusBadRequest)
		return
	}
	tenant := tenantOf(r)
	sess := s.sessionByID(r)
	if sess == nil {
		s.denyAndAudit(tenant, "", "mcp_no_session", payloadHashHex(body))
		http.Error(w, "MCP 敏感轨须段① 证明会话（fail-closed）", http.StatusBadRequest)
		return
	}
	pt, oerr := sess.openPayload(protocol.EndpointMCP, body)
	if oerr != nil {
		s.denyAndAudit(tenant, "", "mcp_envelope_error", payloadHashHex(body))
		http.Error(w, "MCP 请求须为加密信封（fail-closed）", http.StatusBadRequest)
		return
	}

	// 交 T-4 MCP 协议层：body 换为解密后的 JSON-RPC（客户端原头透传，含 X-Tenant-ID）。
	req2 := r.Clone(r.Context())
	req2.Body = io.NopCloser(bytes.NewReader(pt))
	req2.Header.Set("Content-Type", "application/json")              // 解密后载荷为 JSON-RPC
	req2.Header.Set("Accept", "application/json, text/event-stream") // streamable HTTP 协商
	cap := &captureWriter{header: http.Header{}}
	s.mcpHandler.ServeHTTP(cap, req2)

	// 响应沿用段① s2c 封装。
	sealed, serr := sess.sealPayload(protocol.EndpointMCP, cap.body())
	if serr != nil {
		http.Error(w, "响应加密失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(cap.statusCode())
	_, _ = w.Write(sealed)
}

// captureWriter 轻量响应捕获（替代在生产代码中引入 httptest）。
type captureWriter struct {
	header http.Header
	buf    bytes.Buffer
	status int
}

func (c *captureWriter) Header() http.Header { return c.header }

func (c *captureWriter) Write(b []byte) (int, error) { return c.buf.Write(b) }

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}

func (c *captureWriter) statusCode() int {
	if c.status == 0 {
		return http.StatusOK
	}
	return c.status
}

func (c *captureWriter) body() []byte { return c.buf.Bytes() }
