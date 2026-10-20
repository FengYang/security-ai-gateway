package mcpproto

// T-11 ②「JSON-RPC fuzz」：安全轨（TEE 内 MCP 协议层）解析面。
//
// 判据（与 §12.3 统一证据形态一致）：
//  1. 任意字节输入**不得 panic**（fuzz 天然捕获）；
//  2. **不得返回 5xx**（协议错误一律 200 + JSON-RPC error 或 4xx 传输错误）；
//  3. 响应**不得泄露内部栈/文件路径**。
//
// 覆盖点：JSON-RPC 版本/字段类型错配、批量数组、空/null、超深嵌套、超大 id、
// 未授权/不存在的工具名、NUL 与 `__proto__` 类键、以及头部一致性校验旁路。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func FuzzMCPHandlerJSONRPC(f *testing.F) {
	d := readyDeps(f, "ta")
	h := NewHandler(d)

	deep := strings.Repeat("[", 256)
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secure_ok","arguments":{"q":"x"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"secure_no"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"public_x"}}`,
		`{"jsonrpc":"1.0","id":6,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":7,"method":"no/such","params":{}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"secure_ok","arguments":{"q":` + deep + `}}}`,
		`[]`,
		`null`,
		``,
		`{"jsonrpc":"2.0","id":1e309,"method":"tools/list"}`,
		"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"secure_ok\\u0000\"}}",
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"secure_ok","arguments":{"__proto__":{"x":1}}}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set(tenantHeader, "ta")
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		if rec.Code >= http.StatusInternalServerError {
			t.Fatalf("JSON-RPC 输入不得触发 5xx：code=%d body=%q", rec.Code, truncateJSON(rec.Body.String(), 300))
		}
		out := rec.Body.String()
		if strings.Contains(out, "goroutine ") || strings.Contains(out, ".go:") {
			t.Fatalf("响应泄露内部栈信息：%q", truncateJSON(out, 300))
		}
	})
}

func truncateJSON(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
