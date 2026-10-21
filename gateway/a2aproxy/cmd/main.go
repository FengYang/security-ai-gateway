// Command a2aproxy runs the P2-2 A2A data plane: a thin protocol-aware
// proxy in front of registered agents (frozen F-1..F-5).
//
// The registry snapshot source is either a local file (dev) or the
// control-plane /internal/a2a/snapshot endpoint. Without a governance
// engine the proxy runs fail-closed (DenyAllGovernance): every call is
// rejected until the policy hooks are wired.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
)

func main() {
	cfg, err := a2aproxy.ConfigFromEnv()
	if err != nil {
		log.Fatalf("配置无效: %v", err)
	}
	store := a2aproxy.NewSnapshotStore()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// T-5：tracing（复用 P1-2 栈；TRACING_ENABLED != "true" 时 NoOp，零开销）。
	if err := a2aproxy.InitTracing(); err != nil {
		log.Printf("警告: tracing 初始化失败（降级为不开销上报）: %v", err)
	}
	defer a2aproxy.ShutdownTracing()

	// Snapshot source: file (dev) or control-plane HTTP endpoint.
	if cfg.SnapshotFile != "" {
		snap, err := a2aproxy.LoadFile(cfg.SnapshotFile)
		if err != nil {
			log.Fatalf("加载注册快照失败（fail-closed 拒绝启动）: %v", err)
		}
		if err := store.ForceReplace(snap); err != nil {
			log.Fatalf("安装注册快照失败: %v", err)
		}
		log.Printf("注册快照已加载: file=%s revision=%d agents=%d", cfg.SnapshotFile, snap.Revision(), snap.Len())
		// File mode is static; poll for file changes (dev workflow).
		go watchSnapshotFile(ctx, store, cfg.SnapshotFile, cfg.SnapshotPoll)
	} else {
		etag := ""
		if err := refreshSnapshotHTTP(ctx, store, cfg.SnapshotURL, cfg.SnapshotToken, &etag); err != nil {
			// Startup without a snapshot is legal but the data plane stays
			// fail-closed until the first successful pull (F-5 §5.1).
			log.Printf("警告: 首次快照拉取失败（数据面 fail-closed 直至就绪）: %v", err)
		}
		go pollSnapshotHTTP(ctx, store, cfg.SnapshotURL, cfg.SnapshotToken, &etag, cfg.SnapshotPoll)
	}

	// T-3/T-3a/T-3b/T-4 集成接线：签名 ACL/限流表 + 静态令牌 + 审计落盘。
	// 未配置 ACL 文件时保持 fail-closed（DenyAllGovernance），不会意外放开。
	governance, govCloser, err := a2aproxy.NewGovernanceFromConfig(*cfg)
	if err != nil {
		log.Fatalf("治理配置无效（fail-closed 拒绝启动）: %v", err)
	}
	if govCloser != nil {
		defer func() { _ = govCloser.Close() }()
	}

	proxy, err := a2aproxy.New(*cfg, store, governance)
	if err != nil {
		log.Fatalf("构造数据面失败: %v", err)
	}
	defer proxy.Close()
	if governance == nil {
		log.Printf("治理未接线：ACL 表缺失，数据面 fail-closed（所有调用拒绝）")
	} else {
		log.Printf("治理已接线：acl=%s ratelimit=%s audit=%s", cfg.ACLFile, cfg.RateLimitFile, cfg.AuditSinkFile)
	}

	// T-5：运维面 /metrics 与数据面路由分离挂载。
	// 若配置了 MetricsAddr 则独立监听（推荐：仅内网可达），否则与数据面共用端口。
	mux := http.NewServeMux()
	mux.Handle("/metrics", proxy.MetricsHandler())
	mux.Handle("/", proxy.Handler())

	handler := http.Handler(mux)
	if cfg.MetricsAddr != "" && cfg.MetricsAddr != cfg.ListenAddr {
		metricsSrv := &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           proxy.MetricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics 服务退出: %v", err)
			}
		}()
		log.Printf("a2aproxy metrics 监听: addr=%s", cfg.MetricsAddr)
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.BackendTimeout + 5*time.Second,
		WriteTimeout:      cfg.BackendTimeout + 5*time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("a2aproxy 启动: addr=%s mode=%s governance=%s", cfg.ListenAddr, cfg.PublicMode, governanceMode(governance))
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务退出: %v", err)
	}
}

func governanceMode(g a2aproxy.Governance) string {
	if g == nil {
		return "fail-closed"
	}
	return "wired"
}

func watchSnapshotFile(ctx context.Context, store *a2aproxy.SnapshotStore, path string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap, err := a2aproxy.LoadFile(path)
			if err != nil {
				log.Printf("警告: 快照文件重新加载失败（保留旧快照）: %v", err)
				continue
			}
			if ok, err := store.Replace(snap); err != nil {
				log.Printf("警告: 快照替换失败: %v", err)
			} else if ok {
				log.Printf("注册快照已更新: revision=%d agents=%d", snap.Revision(), snap.Len())
			}
		}
	}
}

func pollSnapshotHTTP(ctx context.Context, store *a2aproxy.SnapshotStore, url, token string, etag *string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := refreshSnapshotHTTP(ctx, store, url, token, etag); err != nil {
				log.Printf("警告: 快照轮询失败（保留旧快照）: %v", err)
			}
		}
	}
}

func refreshSnapshotHTTP(ctx context.Context, store *a2aproxy.SnapshotStore, url, token string, etag *string) error {
	snap, newETag, err := a2aproxy.FetchSnapshot(url, token, *etag)
	if err != nil {
		return err
	}
	if newETag != "" {
		*etag = newETag
	}
	if snap == nil {
		return nil // 304: unchanged
	}
	if err := store.ForceReplace(snap); err != nil {
		return err
	}
	log.Printf("注册快照已更新: revision=%d agents=%d", snap.Revision(), snap.Len())
	return nil
}

var _ = os.Getenv
