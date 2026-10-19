// Command client-smoke 是 P2-1 T-2④ 的第三方客户端联调素材（官方 go-sdk v1.8.0，
// Streamable HTTP，无状态）。用途：对**经 Higress 网关**的 public 轨 MCP 端点做
// initialize + tools/list + tools/call 冒烟（P2-1 §7.1 T-2④ / V-1）。
//
// 用法（模块内）：
//
//	go run ./client-smoke --endpoint http://<gateway>:30000/mcp-servers/mcp-demo \
//	  --api-key <KEY> --tool echo --arg-name message --arg-value hello-gateway
//
// 说明：--api-key 缺省读取环境变量 GW_API_KEY；不带 key 运行应被网关 key-auth 拒绝
// （fail-closed 负例）。本目录为联调样例，不进入产品发布物。
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// keyTransport 在每次请求注入 x-api-key（网关 key-auth 2.0.0 consumer 凭据）。
type keyTransport struct {
	key  string
	base http.RoundTripper
}

func (t *keyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if t.key != "" {
		r.Header.Set("x-api-key", t.key)
	}
	return t.base.RoundTrip(r)
}

func main() {
	var (
		endpoint = flag.String("endpoint", "", "MCP 端点（经网关，如 http://<gw>:30000/mcp-servers/mcp-demo）")
		apiKey   = flag.String("api-key", os.Getenv("GW_API_KEY"), "x-api-key 值（缺省读 GW_API_KEY）")
		tool     = flag.String("tool", "", "tools/call 目标工具（空则仅 tools/list）")
		argName  = flag.String("arg-name", "message", "tools/call 参数名")
		argValue = flag.String("arg-value", "hello-gateway", "tools/call 参数值")
	)
	flag.Parse()
	if *endpoint == "" {
		fmt.Fprintln(os.Stderr, "用法：client-smoke --endpoint http://<gw>:30000/mcp-servers/<name> [--api-key K] [--tool echo --arg-name message --arg-value hello-gateway]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "p2-1-client-smoke", Version: "0.1.0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             *endpoint,
		HTTPClient:           &http.Client{Transport: &keyTransport{key: *apiKey, base: http.DefaultTransport}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connect 失败（initialize 未通过）: %v\n", err)
		os.Exit(1)
	}
	defer cs.Close()
	fmt.Printf("initialize OK（endpoint=%s）\n", *endpoint)

	tl, err := cs.ListTools(ctx, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tools/list 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("tools/list: %d 个工具\n", len(tl.Tools))
	for _, t := range tl.Tools {
		fmt.Printf("  - %s: %s\n", t.Name, t.Description)
	}

	if *tool == "" {
		fmt.Println("CLIENT_SMOKE_OK")
		return
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: map[string]any{*argName: *argValue}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tools/call %s 失败: %v\n", *tool, err)
		os.Exit(1)
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			fmt.Printf("tools/call %s -> %s\n", *tool, tc.Text)
		}
	}
	if res.IsError {
		fmt.Println("(IsError=true)")
		os.Exit(1)
	}
	fmt.Println("CLIENT_SMOKE_OK")
}
