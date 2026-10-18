package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestFsToolsE2E 端到端：SDK 客户端 ↔ 本服务 handler（正常路径 + 三类拒绝）。
func TestFsToolsE2E(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(newMux(root))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-fs-test", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             srv.URL + "/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	defer cs.Close()

	// list_files（.）
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_files", Arguments: map[string]any{"dir": "."}})
	if err != nil || res.IsError {
		t.Fatalf("list_files: err=%v res=%+v", err, res)
	}
	out := textOf(res)
	if !strings.Contains(out, "a.txt") || !strings.Contains(out, "sub/") {
		t.Fatalf("list_files 输出不符: %q", out)
	}

	// read_text 正常
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_text", Arguments: map[string]any{"path": "a.txt"}})
	if err != nil || res.IsError || textOf(res) != "hello" {
		t.Fatalf("read_text: err=%v res=%+v text=%q", err, res, textOf(res))
	}

	// 越界（..）→ 工具级错误
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_text", Arguments: map[string]any{"path": "../secret.txt"}})
	if err != nil {
		t.Fatalf("越界应返回工具级错误而非协议错误: %v", err)
	}
	if !res.IsError {
		t.Fatalf("越界应 IsError，实得 %+v", res)
	}

	// 绝对路径 → 工具级错误
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_text", Arguments: map[string]any{"path": "/etc/passwd"}})
	if err != nil || !res.IsError {
		t.Fatalf("绝对路径应 IsError: err=%v res=%+v", err, res)
	}

	// 目录 → 工具级错误
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "read_text", Arguments: map[string]any{"path": "sub"}})
	if err != nil || !res.IsError {
		t.Fatalf("目录应 IsError: err=%v res=%+v", err, res)
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
