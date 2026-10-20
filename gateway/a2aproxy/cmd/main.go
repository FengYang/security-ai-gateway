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

	proxy, err := a2aproxy.New(*cfg, store, nil)
	if err != nil {
		log.Fatalf("构造数据面失败: %v", err)
	}
	defer proxy.Close()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           proxy.Handler(),
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

	log.Printf("a2aproxy 启动: addr=%s mode=%s 治理=fail-closed(未接线)", cfg.ListenAddr, cfg.PublicMode)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务退出: %v", err)
	}
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
