// Command mcp-fs 是 P2-1 T-2 的样例 MCP 后端之二（联调样例，不进入产品发布物）。
//
// 职责：以只读沙箱目录（FS_ROOT，缺省 /data）暴露两个工具：list_files / read_text；
// 用于联调「真实工具后端」经 Higress MCP Server 的 tools/list、tools/call 全链。
//
// 安全口径（样例级）：
//   - 路径必须落在 FS_ROOT 内（拒绝绝对路径与 .. 越界）；
//   - 只读（不提供写/删）；单文件上限 64 KiB；目录列举上限 200 条；
//   - 错误信息粗粒度（不返回系统错误细节）。
//   - 已知限制：不防护符号链接逃逸（生产接入须另行加固，见 README「工具方责任边界」）。
//
// 本地运行：FS_ROOT=./testdata LISTEN=:8080 go run ./deploy/samples/mcp-backends/filesystem
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxReadBytes = 64 << 10
	maxEntries   = 200
)

func main() {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	root := os.Getenv("FS_ROOT")
	if root == "" {
		root = "/data"
	}
	log.Printf("mcp-fs 启动：listen=%s root=%s（MCP=/mcp，healthz=/healthz）", addr, root)
	srv := &http.Server{Addr: addr, Handler: newMux(root), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// newMux 组装 HTTP 面：/healthz 探活 + /mcp（无状态 Streamable HTTP）。
func newMux(root string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/mcp", newHandler(root))
	return mux
}

// newHandler 无状态 Streamable HTTP 处理器。
func newHandler(root string) http.Handler {
	s := newServer(root)
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
}

// newServer 注册 list_files / read_text（只读沙箱 root）。
func newServer(root string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-fs", Version: "0.1.0"}, nil)

	s.AddTool(&mcp.Tool{
		Name:        "list_files",
		Description: "列出沙箱目录下的条目（名称/类型/大小）",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"dir": map[string]any{"type": "string", "description": "相对沙箱根的目录路径（缺省 .）"},
			},
		},
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Dir string `json:"dir"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult("入参解析失败：dir 应为字符串"), nil
		}
		full, err := resolveInRoot(root, args.Dir)
		if err != nil {
			return errResult("非法路径（越界）"), nil
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			return errResult("列目录失败（不存在或不可读）"), nil
		}
		truncated := false
		if len(entries) > maxEntries {
			entries, truncated = entries[:maxEntries], true
		}
		var b strings.Builder
		for _, e := range entries {
			if e.IsDir() {
				fmt.Fprintf(&b, "%s/\n", e.Name())
				continue
			}
			if info, ierr := e.Info(); ierr == nil {
				fmt.Fprintf(&b, "%s\t%d B\n", e.Name(), info.Size())
			} else {
				fmt.Fprintf(&b, "%s\n", e.Name())
			}
		}
		out := strings.TrimRight(b.String(), "\n")
		if out == "" {
			out = "(空目录)"
		}
		if truncated {
			out += fmt.Sprintf("\n（已截断：仅列前 %d 条）", maxEntries)
		}
		return textResult(out), nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "read_text",
		Description: "读取沙箱内文本文件（上限 64 KiB）",
		InputSchema: objectSchema(map[string]any{
			"path": map[string]any{"type": "string", "description": "相对沙箱根的文件路径"},
		}, "path"),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Path string `json:"path"`
		}
		if err := decodeArgs(req, &args); err != nil {
			return errResult("入参解析失败：path 应为字符串"), nil
		}
		full, err := resolveInRoot(root, args.Path)
		if err != nil {
			return errResult("非法路径（越界）"), nil
		}
		info, err := os.Stat(full)
		if err != nil {
			return errResult("读取失败（不存在或不可读）"), nil
		}
		if info.IsDir() {
			return errResult("读取失败（目标是目录）"), nil
		}
		if info.Size() > maxReadBytes {
			return errResult(fmt.Sprintf("读取失败（文件超过 %d B 上限）", maxReadBytes)), nil
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return errResult("读取失败（不可读）"), nil
		}
		return textResult(string(data)), nil
	})
	return s
}

// resolveInRoot 将相对路径解析到沙箱 root 下；拒绝绝对路径与 .. 越界。
func resolveInRoot(root, rel string) (string, error) {
	if rel == "" {
		rel = "."
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("绝对路径不受支持: %q", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("路径越界: %q", rel)
	}
	return filepath.Join(root, clean), nil
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
