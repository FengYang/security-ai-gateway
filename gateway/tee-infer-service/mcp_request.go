package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"security-ai-gateway/gateway/tee-infer-service/mcpproto"
	"security-ai-gateway/protocol/go"
)

// handleMCPRequest 敏感轨请求路径（§12.2 T-5 步骤 5）：
// 段① 解密（EndpointMCP）→ TEE 内 MCP 协议层（mcpproto：按租户过滤 + mcpguard 裁决）
// → 响应以 s2c 信封封装回数据面。
//
// fail-closed：无段① 证明会话 / 信封不可解 一律拒绝，绝不降级明文（C-4）。
func (s *teeServer) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	// T3a：注入请求路径证据元数据（MCP 敏感轨 path_mode=encrypted）。
	r = r.WithContext(withAuditReqMeta(r.Context(), r.URL.Path, auditPathMode(r.URL.Path)))
	if r.Method != http.MethodPost {
		recordExemptExit("handleMCPRequest", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.denyAndAuditMCP(r, tenantOf(r), "", "", "mcp_read_failed", "", http.StatusBadRequest)
		http.Error(w, "读取请求失败", http.StatusBadRequest)
		return
	}
	tenant := tenantOf(r)
	// V-7 就绪门控：治理未启用 / 策略未就绪 → **503**（fail-closed，不降级放行）。
	if s.mcpCache == nil || !s.mcpCache.Ready() {
		s.denyAndAuditMCP(r, tenant, "", "", "mcp_guard_not_ready", payloadHashHex(body), http.StatusServiceUnavailable)
		http.Error(w, "MCP 策略未就绪（fail-closed 503）", http.StatusServiceUnavailable)
		return
	}
	sess := s.sessionByID(r)
	if sess == nil {
		s.denyAndAuditMCP(r, tenant, "", "", "mcp_no_session", payloadHashHex(body), http.StatusBadRequest)
		http.Error(w, "MCP 敏感轨须段① 证明会话（fail-closed）", http.StatusBadRequest)
		return
	}
	pt, oerr := sess.openPayload(protocol.EndpointMCP, body)
	if oerr != nil {
		// 解密失败：信封 request_id 不可得 → 以会话 ID 作 request_id（A4-05 ②）。
		s.denyAndAuditMCP(r, tenant, sess.ID, sess.ID, "mcp_envelope_error", payloadHashHex(body), http.StatusBadRequest)
		http.Error(w, "MCP 请求须为加密信封（fail-closed）", http.StatusBadRequest)
		return
	}
	// T-7：按 mcp_method 维度计数（口径＝调用计数；解密后 JSON-RPC 明文在手，直接取 method）。
	s.metrics.incMCPMethod(mcpMethodOf(pt))
	// T3b（A4-05）：派生本请求的 request_id（信封优先，回退会话 ID）供后续落链与 MCP 回调使用。
	mcpReqID := mcpRequestIDOf(pt, sess.ID)

	// 交 T-4 MCP 协议层：body 换为解密后的 JSON-RPC（客户端原头透传，含 X-Tenant-ID）。
	req2 := r.Clone(r.Context())
	req2.Body = io.NopCloser(bytes.NewReader(pt))
	req2.Header.Set("Content-Type", "application/json")              // 解密后载荷为 JSON-RPC
	req2.Header.Set("Accept", "application/json, text/event-stream") // streamable HTTP 协商
	// 注入会话 ID：供 mcpproto tools/call 审计回调填充 mcp_session_id（A3-07 回退关联键）。
	req2 = req2.WithContext(mcpproto.WithSessionID(req2.Context(), sess.ID))
	cap := &captureWriter{header: http.Header{}}
	s.mcpHandler.ServeHTTP(cap, req2)

	// 响应沿用段① s2c 封装。
	sealed, serr := sess.sealPayload(protocol.EndpointMCP, cap.body())
	if serr != nil {
		s.denyAndAuditMCP(r, tenant, mcpReqID, sess.ID, "mcp_seal_error", payloadHashHex(pt), http.StatusInternalServerError)
		http.Error(w, "响应加密失败", http.StatusInternalServerError)
		return
	}
	// 自定义 media type：避免 Envoy wasm wrapper 对 octet-stream 的二进制 body 跳过响应回调
	w.Header().Set("Content-Type", "application/x-otpmask")
	// T3b（C 类豁免）：响应终写（通用写出；状态由内层 mcpproto 返回，工具裁决已由 mcpCallAudit 落链）。
	recordExemptExit("handleMCPRequest", "common_writer")
	w.WriteHeader(cap.statusCode())
	_, _ = w.Write(sealed)
}

// mcpRequestIDOf 派生 MCP 敏感轨 request_id（A4-05 唯一口径）。
//
// ① 优先：解密后 JSON-RPC 载荷中的 request_id 字段（客户端提供且格式校验通过）；
// ② 回退：MCP 会话 ID sessID；
// ③ 二者皆无：返回空串（调用方以 mcp_session_id 作回退关联键）。
//
// 兼容两种客户端携带位置：JSON-RPC 顶层 `request_id`，或 `params._meta.request_id`。
func mcpRequestIDOf(payload []byte, sessID string) string {
	if len(payload) > 0 {
		var env struct {
			RequestID string `json:"request_id"`
			Params    struct {
				Meta map[string]any `json:"_meta"`
			} `json:"params"`
		}
		if err := json.Unmarshal(payload, &env); err == nil {
			if validMCPRequestID(env.RequestID) {
				return env.RequestID
			}
			if v, ok := env.Params.Meta["request_id"].(string); ok && validMCPRequestID(v) {
				return v
			}
		}
	}
	return sessID
}

// validMCPRequestID 校验请求方提供的 request_id（A4-05：非空、≤128 字符、仅 [A-Za-z0-9._:-]）。
func validMCPRequestID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
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

// mcpMethodOf 从解密后的 JSON-RPC 报文取 method 字段（T-7：mcp_method 维度计数）。
// 非 JSON 对象 / 无 method → 空串（上层跳过计数，不臆造 label 值）。
func mcpMethodOf(raw []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return ""
	}
	return env.Method
}
