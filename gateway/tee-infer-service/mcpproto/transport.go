package mcpproto

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// JSON-RPC 2.0 保留错误码（MCP 规范保留段 -32020..-32099）。
const (
	// CodeInconsistent 传输层 Mcp-Method/Mcp-Name 与 body 不一致（纵深防御）。
	CodeInconsistent = -32020
	// CodeUnsupportedVersion 协议版本不受支持（由 SDK 协商兜底；本包显式声明保留）。
	CodeUnsupportedVersion = -32022
)

// 已知方法集合（用于 Mcp-Method 头校验）。
var knownMethods = map[string]bool{
	"server/discover": true,
	"tools/list":      true,
	"tools/call":      true,
}

// transportConsistency 校验传输层头与 JSON-RPC body 一致（§12.2 T-4 步 6）。
// 仅对携带 Mcp-Method 头的 JSON-RPC POST 生效；一致/无头则放行（并透传 body）。
func transportConsistency(r *http.Request) (int, string, bool) {
	m := r.Header.Get(hdrMcpMethod)
	if m == "" || r.Method != http.MethodPost {
		return 0, "", false // 无头 → 交由 SDK 正常协商（兼容旧客户端）
	}
	if !knownMethods[m] {
		return CodeInconsistent, "unknown Mcp-Method", true
	}
	name := r.Header.Get(hdrMcpName)

	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB 上限（超限由 Envoy buffer 先拦）
	_ = r.Body.Close()
	if err != nil {
		return CodeInconsistent, "read body", true
	}
	r.Body = io.NopCloser(bytes.NewReader(raw)) // 透传（SDK 仍需读 body）

	var env struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return CodeInconsistent, "malformed json-rpc", true
	}
	if env.Method != m {
		return CodeInconsistent, "Mcp-Method ≠ body.method", true
	}
	if m == "tools/call" && (name == "" || env.Params.Name != name) {
		return CodeInconsistent, "Mcp-Name ≠ body.params.name", true
	}
	return 0, "", false
}

// writeJSONRPCError 以 HTTP 200 + JSON-RPC error 对象返回（§5.7.3：HTTP 状态 vs JSON-RPC error 分层）。
func writeJSONRPCError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error":   map[string]any{"code": code, "message": msg},
	})
}
