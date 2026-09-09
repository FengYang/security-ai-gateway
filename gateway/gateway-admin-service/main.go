// Package main — gateway-admin-service（管理门户业务服务，M1 WP-A 骨架）。
//
// 定位（docs/管理门户-细化方案.md §3/§3.2）：
// 管理面 UI 的自研业务服务（Go，与网关同栈）。请求路径 = 前端 admin-ext 页 →
// 控制台 Java admin-ext controller →（内部令牌认证）→ 本服务 → K8s/Secret/tee-infer。
// 本服务不直接对外暴露（ClusterIP 集群内）。
//
// 本文件 = WP-A 骨架：路由 / 健康检查 / 上下文透传。
// 业务端点（厂商激活/安全中心/用量/复核）与审计链接线在 WP-B 起逐期追加。
//
// API（本阶段）：
//   GET /healthz                    存活探针
//   GET /metrics                    Prometheus 文本指标
//   GET /v1/adminext/echo           受保护示例端点（回显令牌内 sub/role，供 WP-B 联调闭环）
//
// 运行：go run ./gateway/gateway-admin-service
// 配置：环境变量 ADMIN_SVC_*（见 config.go），其中 ADMIN_SVC_JWT_SECRET 必填。
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// claimsCtxKey 上下文中 claims 的键（不透出包外）。
type claimsCtxKey struct{}

// withClaims 把校验通过的令牌声明写入请求上下文。
func withClaims(ctx context.Context, c *claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, c)
}

// claimsFrom 从请求上下文取出令牌声明（仅经 authMiddleware 放行的 handler 可调用）。
func claimsFrom(ctx context.Context) *claims {
	c, _ := ctx.Value(claimsCtxKey{}).(*claims)
	return c
}

// handleHealthz 存活探针。
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// handleMetrics Prometheus 指标端点：GET /metrics。
func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.render(w)
}

// echoResponse 受保护示例端点响应。
type echoResponse struct {
	Sub  string `json:"sub"`  // 操作人登录名
	Role string `json:"role"` // admin / auditor
}

// handleEcho 受保护示例端点：回显令牌内身份，供 WP-B 联调确认 Java→Go 鉴权闭环。
func handleEcho(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(echoResponse{Sub: c.Sub, Role: c.Role})
	log.Printf("[gateway-admin-service] echo sub=%s role=%s", c.Sub, c.Role)
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("配置加载失败（fail-closed）：%v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handleMetrics)
	// 受保护端点挂鉴权中间件；业务端点随 WP 追加同一模式。
	mux.HandleFunc("/v1/adminext/echo", authMiddleware(cfg, handleEcho))

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("gateway-admin-service 就绪（M1 WP-A 骨架）: %s", cfg.listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
