package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestHealthz 探活端点。
func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestDemoToolsE2E 端到端：SDK 客户端 ↔ 本服务 handler（tools/list + 三个工具 tools/call）。
func TestDemoToolsE2E(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-demo-test", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             srv.URL + "/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	defer cs.Close()

	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := map[string]bool{}
	for _, tl := range lt.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"echo", "add", "server_time"} {
		if !names[want] {
			t.Fatalf("tools/list 缺 %s，实得 %v", want, names)
		}
	}

	// echo
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil || res.IsError {
		t.Fatalf("echo 调用失败: err=%v res=%+v", err, res)
	}
	if got := textOf(res); got != "echo: hi" {
		t.Fatalf("echo 结果不符: %q", got)
	}

	// add
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "add", Arguments: map[string]any{"a": 2, "b": 3}})
	if err != nil || res.IsError || textOf(res) != "5" {
		t.Fatalf("add 结果不符: err=%v res=%+v text=%q", err, res, textOf(res))
	}

	// server_time：可解析为 RFC3339
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "server_time"})
	if err != nil || res.IsError {
		t.Fatalf("server_time 调用失败: err=%v res=%+v", err, res)
	}
	if _, perr := time.Parse(time.RFC3339, textOf(res)); perr != nil {
		t.Fatalf("server_time 非 RFC3339: %q", textOf(res))
	}
}

// textOf 提取首个文本块（测试辅助）。
func textOf(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}
