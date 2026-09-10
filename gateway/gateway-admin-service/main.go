// Package main — gateway-admin-service（管理门户业务服务）。
//
// 定位（docs/管理门户-细化方案.md §3/§3.2）：
// 管理面 UI 的自研业务服务（Go，与网关同栈）。请求路径 = 前端 admin-ext 页 →
// 控制台 Java admin-ext controller →（内部令牌认证）→ 本服务 → K8s/Secret/tee-infer。
// 本服务不直接对外暴露（ClusterIP 集群内）。
//
// API：
//
//	GET  /healthz                                存活探针
//	GET  /metrics                                Prometheus 文本指标
//	GET  /v1/adminext/echo                       受保护示例端点（回显令牌内 sub/role）
//	GET  /v1/adminext/broker-providers           托管凭据列表（auditor 可读）
//	GET  /v1/adminext/broker-providers/{name}    托管凭据详情（auditor 可读）
//	POST /v1/adminext/broker-providers/{name}    写入/轮换凭据（**admin**；返回 customUrl）
//	DELETE /v1/adminext/broker-providers/{name}  删除凭据（**admin**；返回 CR 联动告警）
//	ANY  /llm-broker/{provider}/...              内部凭据 broker 中转（可选启用；
//	                                             不走内部 JWT 鉴权——ai-proxy 无法注入服务令牌；
//	                                             信任边界 = 集群内网 + provider/路径双重白名单，
//	                                             详见 docs/管理门户-apiTokens-Secret化方案设计.md §4.3）
//
// 运行：go run ./gateway/gateway-admin-service
// 配置：环境变量 ADMIN_SVC_*（见 config.go），其中 ADMIN_SVC_JWT_SECRET 必填；
// 写权限白名单 ADMIN_SVC_ROLE_ADMINS（未配置 = 无人可写，fail-closed）；
// broker：ADMIN_BROKER_SECRETS_DIR / ADMIN_BROKER_PUBLIC_BASE / ADMIN_BROKER_CR_FILE（同文件）。
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
	Role string `json:"role"` // admin / auditor（由本服务白名单派生）
}

// handleEcho 受保护示例端点：回显令牌内身份，供联调确认 Java→Go 鉴权闭环。
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
	if len(cfg.roleAdmins) == 0 {
		log.Printf("警告：ADMIN_SVC_ROLE_ADMINS 未配置——全部会话按 auditor 处理，凭据写操作将一律 403（fail-closed）")
	}

	// broker 可选启用：凭据目录存在即接管（含空目录 = 0 provider），否则回落环境变量路径；
	// 均无则返回 nil（特性关闭，零影响既有行为）。配置无效 fail-closed 拒绝启动。
	bs := loadBrokerSettings()
	bc, fromDir, err := openBrokerConfig(bs)
	if err != nil {
		log.Fatalf("broker 配置加载失败（fail-closed）：%v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handleMetrics)
	// 受保护端点挂鉴权中间件；角色授权在 handler 内按方法校验（auth.go requireRole）。
	mux.HandleFunc("/v1/adminext/echo", authMiddleware(cfg, handleEcho))
	if bc != nil {
		if bs.publicBase == "" {
			log.Fatalf("配置缺失：ADMIN_BROKER_PUBLIC_BASE 未设置（broker 已启用，无法生成 provider customUrl，fail-closed）")
		}
		bh := newBrokerHandler(bc)
		mux.Handle(brokerPathPrefix, bh)

		sh := newBrokerSecretHandler(bs, bh)
		mux.HandleFunc(brokerAPIBase, authMiddleware(cfg, sh.handleList))
		mux.HandleFunc(brokerAPIBase+"/", authMiddleware(cfg, sh.handleItem))
		if fromDir {
			sh.startReloader()
		}
		src := "env"
		if fromDir {
			src = "dir:" + bs.secretsDir
		}
		log.Printf("broker 已启用：providers=%d source=%s publicBase=%s（中转 %s；凭据端点 %s）",
			bh.providerCount(), src, bs.publicBase, brokerPathPrefix, brokerAPIBase)
	} else {
		log.Printf("broker 未启用（凭据目录不存在且未设置 ADMIN_BROKER_PROVIDERS_JSON）")
	}

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout/WriteTimeout 不设置（流式兼容检查表①）：
		// broker 中转 SSE 长流不得被服务端超时掐断；慢连接防护由 ReadHeaderTimeout
		// 与集群内网边界承担，M2 随 NetworkPolicy 一并复审。
	}
	log.Printf("gateway-admin-service 就绪（M2 A-1）：%s", cfg.listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
