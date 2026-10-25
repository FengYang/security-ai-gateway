package main

// T-1 请求体上限单测：Content-Length 超限确定性 413，限额内正常透传。
// P2-4 T-1.7 优雅退出单测（QA P3-新）：SIGTERM/SIGINT → 排空在途请求 →
// 快照收尾补写（合并写窗口内的变更不丢）。

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
)

func TestLimitBodyOversizedRejected(t *testing.T) {
	called := false
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	body := bytes.NewReader(make([]byte, maxRequestBodyBytes+1))
	req := httptest.NewRequest(http.MethodPost, "/prescriptions", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called {
		t.Fatal("超限请求不应到达处理器")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限应返回 413，got %d", rec.Code)
	}
}

func TestLimitBodyWithinLimitPasses(t *testing.T) {
	const payload = `{"tenant":"tenant-a","model":"qwen-plus"}`
	var got []byte
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("限额内 body 读取失败: %v", err)
		}
		got = b
	}))
	req := httptest.NewRequest(http.MethodPost, "/prescriptions", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if string(got) != payload {
		t.Fatalf("限额内 body 应透传，got %q", got)
	}
}

// TestServeWithShutdownGracefulExit **QA P3-新：优雅退出**——收到 SIGTERM 后
// 排空在途请求（服务停止）并执行收尾钩子（快照补写），而非直接终止进程。
func TestServeWithShutdownGracefulExit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	sigCh := make(chan os.Signal, 1)
	hookDone := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveWithShutdown(srv, ln, sigCh, func() { close(hookDone) })
	}()

	base := "http://" + ln.Addr().String()
	waitForHTTPOK(t, base+"/ping")

	// 触发优雅退出。
	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("优雅退出不应返回错误: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("优雅退出超时（未返回）")
	}

	// 收尾钩子必须执行（快照补写入口）。
	select {
	case <-hookDone:
	default:
		t.Fatal("优雅退出后收尾钩子未执行（快照窗口内变更会丢）")
	}

	// 服务已停止：后续请求应失败（连接被关闭）。
	if _, err := http.Get(base + "/ping"); err == nil {
		t.Fatal("优雅退出后服务不应仍可访问")
	}
}

// TestServeWithShutdownReturnsServeError 服务异常（如监听器已关闭）时返回错误，
// 供调用方按致命错误处理（刷盘后退出）。
func TestServeWithShutdownReturnsServeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	// 先关闭监听器 ⇒ Serve 立即报错。
	_ = ln.Close()
	srv := &http.Server{Handler: http.NewServeMux(), ReadHeaderTimeout: time.Second}
	sigCh := make(chan os.Signal, 1)
	if err := serveWithShutdown(srv, ln, sigCh, nil); err == nil {
		t.Fatal("监听器已关闭时应返回错误")
	}
}

// TestGracefulShutdownFlushesPendingSnapshot **优雅退出补写**：合并写窗口内的
// 变更在退出时经由 snapshotShutdown → ss.Close() 落盘（不丢数据）。
func TestGracefulShutdownFlushesPendingSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := store.NewSnapshotStore(store.NewMemory(), path, nil)
	ss.SetFlushInterval(time.Hour) // 窗口极大：只有 Close 能触发写盘
	_ = ss.Save(&route.RoutePrescription{PrescriptionID: "rx-1", Tenant: "tenant-a"})
	if _, err := os.Stat(path); err == nil {
		t.Fatal("合并写窗口内不应立即落盘")
	}

	// 走与 main 相同的收尾入口。
	snapshotShutdown(ss)()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("收尾补写后快照文件应存在: %v", err)
	}
	if !bytes.Contains(b, []byte("rx-1")) {
		t.Fatalf("收尾补写后快照应包含窗口内变更")
	}
	// 幂等：重复调用不报错、不重复写入。
	snapshotShutdown(ss)()
}

// waitForHTTPOK 轮询等待 HTTP 端点可用（测试辅助）。
func waitForHTTPOK(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("端点 %s 未在超时前就绪", url)
}
