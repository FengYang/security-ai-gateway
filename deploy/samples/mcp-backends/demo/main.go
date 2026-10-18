// Command mcp-demo 是 P2-1 T-2 的样例 MCP 后端之一（联调样例，不进入产品发布物）。
//
// 职责：在 K8s 内暴露 MCP 协议（Streamable HTTP，无状态），供 Higress MCP Server
// 接入（native / public 轨）做 server/discover、tools/list、tools/call 联调。
// 工具：echo / add / server_time（纯计算/回显；无外部依赖、无凭据）。
//
// 本地运行：LISTEN=:8080 go run ./deploy/samples/mcp-backends/demo
// 端点：/mcp（MCP）；/healthz（探活 200 "ok"）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("mcp-demo 启动：listen=%s（MCP=/mcp，healthz=/healthz）", addr)
	srv := &http.Server{Addr: addr, Handler: newMux(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// newMux 组装 HTTP 面：/healthz 探活 + /mcp（无状态 Streamable HTTP）。
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/mcp", newHandler())
	return mux
}

// newHandler 无状态 Streamable HTTP 处理器（单 Server 实例；样例无租户隔离）。
func newHandler() http.Handler {
	s := newServer()
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
}

// newServer 注册三个样例工具。
func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-demo", Version: "0.1.0"}, nil)

	s.AddTool(&mcp.Tool{
		Name:        "echo",
		Description: "回显输入文本（联调连通性用）",
		InputSchema: objectSchema(map[string]any{
			"message": map[string]any{"type": "string", "description": "要回显的文本"},
		}, "message"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Message string `json:"message"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult("入参解析失败：message 应为字符串"), nil
		}
		if args.Message == "" {
			return errResult("message 不能为空"), nil
		}
		return textResult("echo: " + args.Message), nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "add",
		Description: "计算两数之和（联调结构化参数用）",
		InputSchema: objectSchema(map[string]any{
			"a": map[string]any{"type": "number", "description": "加数 a"},
			"b": map[string]any{"type": "number", "description": "加数 b"},
		}, "a", "b"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			A *float64 `json:"a"`
			B *float64 `json:"b"`
		}
		if err := decodeArgs(req, &args); err != nil || args.A == nil || args.B == nil {
			return errResult("入参解析失败：a/b 应为数字"), nil
		}
		return textResult(fmt.Sprintf("%g", *args.A+*args.B)), nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "server_time",
		Description: "返回服务端当前时间（RFC3339，联调用）",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return textResult(time.Now().Format(time.RFC3339)), nil
	})
	return s
}

// decodeArgs 解析 tools/call 入参；无入参时按零值处理。
func decodeArgs(req *mcp.CallToolRequest, v any) error {
	if req == nil || req.Params == nil || len(req.Params.Arguments) == 0 {
		return nil
	}
	return json.Unmarshal(req.Params.Arguments, v)
}

// textResult 成功结果（单个文本块）。
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// errResult 工具级错误结果（IsError=true；粗粒度信息，不含内部细节）。
func errResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

// objectSchema 构造 JSON Schema（type=object）。
func objectSchema(props map[string]any, required ...string) map[string]any {
	sch := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sch["required"] = required
	}
	return sch
}
