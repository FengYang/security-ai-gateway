// Command a2aguardrail serves the deterministic L1 content check used by the
// A2A proxy. It loads the existing output-guard policy assets and exposes a
// small internal HTTP contract.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"security-ai-gateway/gateway/a2aguardrail"
	"security-ai-gateway/gateway/a2aguardrail/protocol"
)

func main() {
	addr := flag.String("addr", ":8087", "listen address")
	policyDir := flag.String("policy-dir", "/app/policy", "output-guard policy directory")
	maxBytes := flag.Int("max-bytes", a2aguardrail.DefaultMaxBytes, "maximum inspectable content bytes")
	authToken := flag.String("auth-token", os.Getenv("GUARDRAIL_AUTH_TOKEN"), "optional bearer token for /v1/content/check")
	flag.Parse()

	engine, err := a2aguardrail.NewEngine(*policyDir, *maxBytes)
	if err != nil {
		log.Fatalf("加载 Guardrail 策略失败（fail-closed 拒绝启动）: %v", err)
	}
	st := engine.Status()
	log.Printf("a2aguardrail 启动: addr=%s policy=%s files_rules=%d active_rules=%d categories=%d max_bytes=%d",
		*addr, st.PolicyVersion, st.Rules, st.ActiveRules, st.Categories, st.MaxBytes)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newMux(engine, *authToken),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务退出: %v", err)
	}
}

// newMux builds the HTTP surface. It is separated for handler tests.
func newMux(engine *a2aguardrail.Engine, authToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if engine == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("GET /v1/policy", func(w http.ResponseWriter, _ *http.Request) {
		if engine == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, engine.Status())
	})
	mux.HandleFunc("POST /v1/content/check", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, authToken) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if engine == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		maxBody := int64(engine.Status().MaxBytes)*2 + 64*1024
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBody {
			writeJSON(w, http.StatusOK, protocol.Response{
				Action: protocol.ActionDeny,
				Tier:   "limit",
				Reason: "content_too_large",
			})
			return
		}
		var req protocol.Request
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp, err := engine.Check(r.Context(), req)
		if err != nil {
			// Never include request content in the error response or log.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				http.Error(w, "request canceled", http.StatusRequestTimeout)
				return
			}
			http.Error(w, "check failed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	return mux
}

func authorized(r *http.Request, token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	want := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
