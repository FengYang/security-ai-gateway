// gateway-core 控制面服务入口。
//
// 职责（MVP，Step 1）：提供路由处方（X-Otp-Route）的签发/查询/吊销 HTTP API，
// 作为网关数据面（otpmask 插件）的路由决策事实源。
// Step 1 只做处方签发（推路径 L1）；默认路由表拉取（拉路径 L2）与冷启动（L3）见设计文档后续 Step。
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/a2aregistry"
	"security-ai-gateway/gateway/gateway-core/internal/api"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// maxRequestBodyBytes 请求体上限（4MiB）：控制面载荷极小，取保守上限（T-1 评审项）。
const maxRequestBodyBytes = 4 << 20

// limitBody 请求体限制中间件：Content-Length 超限确定性 413；chunked 越限由
// MaxBytesReader 在读取时拦截（处理器读取失败走既有 400 fail-closed 路径）。
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func main() {
	sigKeyHex := os.Getenv("OTP_CORE_SIG_KEY")
	if sigKeyHex == "" {
		log.Fatal("OTP_CORE_SIG_KEY 未设置（处方签名密钥，32 字节 hex）")
	}
	key, err := hex.DecodeString(sigKeyHex)
	if err != nil || len(key) < 32 {
		log.Fatal("OTP_CORE_SIG_KEY 无效：须为 ≥32 字节的 hex")
	}

	authToken := os.Getenv("OTP_CORE_AUTH_TOKEN") // 内网静态 token；空则禁用鉴权（仅限内部测试）
	addr := os.Getenv("OTP_CORE_ADDR")
	if addr == "" {
		addr = ":8085"
	}

	signer, err := route.NewSigner(key)
	if err != nil {
		log.Fatalf("构造签名器失败: %v", err)
	}
	msigner, err := mcpsec.NewSigner(key) // MCP 工具目录/策略共用同一对称密钥族
	if err != nil {
		log.Fatalf("构造 MCP 签名器失败: %v", err)
	}
	rsigner, err := ratelimit.NewSigner(key) // 限流/预算表与路由表共用同一密钥族（K_rx）
	if err != nil {
		log.Fatalf("构造限流签名器失败: %v", err)
	}
	st := store.NewMemory()
	rt := defaultRouteTable(signer)
	rlt := defaultRateLimitTable(rsigner)
	// TEE 侧配额下发器（S3）：OTP_CORE_TEE_URL 为空 = nil（预算/TPM 不下发，仅在响应 Note 中说明）
	teeQuota := api.NewHTTPTeeQuotaApplier(os.Getenv("OTP_CORE_TEE_URL"), os.Getenv("OTP_CORE_TEE_ADMIN_TOKEN"))
	srv := api.New(signer, msigner, rsigner, teeQuota, st, authToken, rt, rlt)
	// 策略变更审计（判据 7）：OTP_CORE_AUDIT_FILE 非空 → WORM 持久化（文件损坏即拒绝启动，fail-closed）
	auditFile := os.Getenv("OTP_CORE_AUDIT_FILE")
	if err := srv.SetPolicyAuditFile(auditFile); err != nil {
		log.Fatalf("初始化策略变更审计失败（fail-closed 拒绝启动）: %v", err)
	}
	defer func() { _ = srv.ClosePolicyAudit() }()
	auditState := "内存（重启丢失）"
	if auditFile != "" {
		auditState = auditFile
	}

	// P1-2：控制面 tracing（M3，§7.4 `core.route.change` span；默认关闭，C-4）。
	if err := api.InitTracing(); err != nil {
		log.Fatalf("初始化 tracing 失败（fail-closed）: %v", err)
	}
	defer api.ShutdownTracing()

	// P2-2 T-2：A2A 注册中心控制面。
	// 启用条件：A2A_REGISTRY_DB 非空（显式开启，避免未配置时凭空建库）。
	// ⚠️ 认证口径（冻结 §5.4）：生产仅接受 JWT（A2A_JWT_SECRET）；静态 token
	//    仅在 A2A_DEV_MODE=true 时降级为 platform_admin；**生产只配静态 token
	//    而无 JWT 密钥 → 拒绝启动**（否则控制面将无人能通过租户级鉴权）。
	a2aStatus, err := setupA2ARegistry(srv)
	if err != nil {
		log.Fatalf("初始化 A2A 注册中心失败: %v", err)
	}

	log.Printf("gateway-core 启动: addr=%s 鉴权=%v 路由版本=%d 限流版本=%d TEE配额下发=%v 变更审计=%s A2A注册中心=%s",
		addr, authToken != "", rt.Version, rlt.Version, teeQuota != nil, auditState, a2aStatus)
	// 控制面无流式响应，全量超时；body 上限防资源耗尽（T-1 评审项）
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           limitBody(srv.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("HTTP 服务退出: %v", err)
	}
}

// setupA2ARegistry 按环境变量装配并挂载 A2A 注册中心控制面（冻结 §3.3/§5.4/§5.9）。
// 返回启动日志用的状态描述（"未启用" 或 "已启用"）。
//
// 环境变量：
//
//	A2A_REGISTRY_DB        SQLite 路径（非空即启用）；默认 /var/lib/gateway-core/a2a-registry.db
//	A2A_PUBLIC_MODE        host|path（默认 path）
//	A2A_TENANT_DOMAINS     host 模式的 tenant→域名映射，逗号分隔（tenant=domain）
//	A2A_GATEWAY_PUBLIC_BASE path 模式的网关公网基址（如 https://gateway.example.com）
//	A2A_JWT_SECRET         控制面 JWT（HS256）签名密钥
//	A2A_STATIC_TOKEN       静态 token（仅 A2A_DEV_MODE=true 生效）
//	A2A_SNAPSHOT_TOKEN     快照分发内部 token（/internal/a2a/snapshot）
//	A2A_DEV_MODE           true 时允许静态 token 降级；生产不得为 true
//	A2A_JKU_ALLOWLIST      jku 白名单（逗号分隔 https URL；仅校验，不抓取）
func setupA2ARegistry(srv *api.Server) (string, error) {
	dsn := strings.TrimSpace(os.Getenv("A2A_REGISTRY_DB"))
	if dsn == "" {
		return "未启用", nil // 未启用
	}
	devMode := os.Getenv("A2A_DEV_MODE") == "true"
	jwtSecret := os.Getenv("A2A_JWT_SECRET")
	staticToken := os.Getenv("A2A_STATIC_TOKEN")
	if !devMode && jwtSecret == "" {
		// 生产仅静态 token（或无凭据）→ 拒绝启动（冻结 §5.4）。
		return "", fmt.Errorf("生产模式必须配置 A2A_JWT_SECRET（静态 token 仅在 A2A_DEV_MODE=true 时可用）")
	}
	cfg := a2aregistry.Config{
		DSN:            dsn,
		PublicMode:     os.Getenv("A2A_PUBLIC_MODE"),
		GatewayBase:    os.Getenv("A2A_GATEWAY_PUBLIC_BASE"),
		TenantDomains:  parseTenantDomains(os.Getenv("A2A_TENANT_DOMAINS")),
		JWTSecret:      jwtSecret,
		StaticToken:    staticToken,
		SnapshotToken:  os.Getenv("A2A_SNAPSHOT_TOKEN"),
		DevMode:        devMode,
		JKUAllowlist:   splitCSV(os.Getenv("A2A_JKU_ALLOWLIST")),
	}
	reg, err := a2aregistry.New(cfg, srv.PolicyAuditChain())
	if err != nil {
		// 致命（库 schema 新于代码）→ 拒绝启动。
		return "", err
	}
	srv.SetA2ARegistry(reg)
	return "已启用", nil
}

// parseTenantDomains 解析 "tenant=domain,tenant2=domain2" 形式的映射。
func parseTenantDomains(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range splitCSV(raw) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// splitCSV 按逗号切分并去空白。
func splitCSV(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// defaultRouteTable 构造并签发默认路由表（MVP 从固定配置；后续改环境变量/DB 动态加载）。
func defaultRouteTable(signer *route.Signer) *route.RouteTable {
	now := time.Now().Unix()
	tbl := route.NewRouteTable(1, now)
	// MVP 占位：演示用固定 tenant→engine 映射；生产由控制面/DB 注入。
	tbl.Routes = []route.TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", FallbackEngine: "vllm"},
	}
	if err := signer.SignTable(tbl); err != nil {
		log.Fatalf("路由表签名失败: %v", err)
	}
	return tbl
}

// defaultRateLimitTable 构造并签发默认限流表（MVP：**空表＝不限流**，
// 由 PUT /ratelimits 递增版本动态更新；空表已签名，保证插件侧 pull 始终拿到可验签表）。
func defaultRateLimitTable(signer *ratelimit.Signer) *ratelimit.Table {
	tbl := ratelimit.NewTable(1, time.Now())
	if err := signer.SignTable(tbl); err != nil {
		log.Fatalf("限流表签名失败: %v", err)
	}
	return tbl
}
