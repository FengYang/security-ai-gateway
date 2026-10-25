// gateway-core 控制面服务入口。
//
// 职责（MVP，Step 1）：提供路由处方（X-Otp-Route）的签发/查询/吊销 HTTP API，
// 作为网关数据面（otpmask 插件）的路由决策事实源。
// Step 1 只做处方签发（推路径 L1）；默认路由表拉取（拉路径 L2）与冷启动（L3）见设计文档后续 Step。
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/auditexport"
	"security-ai-gateway/gateway/gateway-core/internal/a2aregistry"
	"security-ai-gateway/gateway/gateway-core/internal/api"
	"security-ai-gateway/gateway/gateway-core/internal/heartbeat"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// maxRequestBodyBytes 请求体上限（4MiB）：控制面载荷极小，取保守上限（T-1 评审项）。
const maxRequestBodyBytes = 4 << 20

// shutdownTimeout 优雅退出时排空在途请求的上限（超时后放弃等待，继续收尾）。
const shutdownTimeout = 10 * time.Second

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
	// P2-2 T-3：A2A ACL 表签名器——与限流/路由表共用同一密钥族（K_rx），
	// 但 ACL 是**独立策略域**（R-6）：独立端点前缀、独立表对象、独立签名对象。
	aclsigner, err := a2aproxy.NewACLSigner(key)
	if err != nil {
		log.Fatalf("构造 ACL 签名器失败: %v", err)
	}
	// P2-2 T-3a：A2A 复合限流表签名器——与 ACL 表共用同一密钥族（K_rx）、
	// 同一分发通道，但限流是**独立策略域**（R-6）：独立端点前缀、独立表对象、独立签名对象。
	a2arlsigner, err := a2aproxy.NewRateLimitSigner(key)
	if err != nil {
		log.Fatalf("构造 A2A 限流表签名器失败: %v", err)
	}
	// P2-4 T-1.7：存储持久化（文件快照 + 原子写 + 重启恢复）。
	// 显式开关：GATEWAY_CORE_STORE_SNAPSHOT_PATH 非空才启用；空 = 纯内存，零行为变化。
	// 合并写窗口：GATEWAY_CORE_STORE_SNAPSHOT_FLUSH_MS（默认 200ms；0 = 每次变更同步落盘）。
	mem := store.NewMemory()
	var st store.Store = mem
	snapState := "内存（重启丢失）"
	// snapFlush 收尾刷盘（优雅退出补写窗口内变更）；log.Fatalf 不跑 defer，
	// 故错误退出路径也显式调用（幂等：Close 只生效一次）。
	var snapFlush func()
	defer func() {
		if snapFlush != nil {
			snapFlush()
		}
	}()
	if snapPath := os.Getenv("GATEWAY_CORE_STORE_SNAPSHOT_PATH"); snapPath != "" {
		ss := store.NewSnapshotStore(mem, snapPath, log.Default())
		// 合并写窗口（QA P3-5）：热路径不再"每张处方一次全量快照 + fsync"。
		flushMS := 200
		if raw := strings.TrimSpace(os.Getenv("GATEWAY_CORE_STORE_SNAPSHOT_FLUSH_MS")); raw != "" {
			n, perr := strconv.Atoi(raw)
			if perr != nil || n < 0 {
				log.Fatalf("GATEWAY_CORE_STORE_SNAPSHOT_FLUSH_MS 非法: %q", raw)
			}
			flushMS = n
		}
		ss.SetFlushInterval(time.Duration(flushMS) * time.Millisecond)
		// 启动准备（QA P3-9）：父目录创建 + 可写性实测 + 符号链接/目录路径拒绝。
		// 失败不阻断启动（内存为准 + 显式开关口径）：降级为纯内存并明确告警。
		if err := ss.Prepare(); err != nil {
			log.Printf("错误: gateway-core 快照路径准备失败，降级为纯内存（重启丢失）: %v", err)
			ss.Disable()
			snapState = fmt.Sprintf("内存（快照不可用: %v）", err)
		} else {
			if err := ss.LoadSnapshot(); err != nil {
				// fail-open：损坏快照拒绝加载后回退空内存启动。理由：core 重启可用性
				// 优先，路由/策略配置可由管理面重新下发；若因快照损坏拒绝启动，整个
				// 网关控制面失联，代价远大于短暂回退空态。
				log.Printf("警告: gateway-core 快照加载失败，回退空内存启动（fail-open）: %v", err)
			}
			st = ss
			snapState = fmt.Sprintf("%s（合并写窗口=%dms）", snapPath, flushMS)
			// 优雅退出补写窗口内变更（崩溃窗口 ≤ flushMS 的语义见 snapshot.go 注释）。
			snapFlush = snapshotShutdown(ss)
		}
	}
	rt := defaultRouteTable(signer)
	rlt := defaultRateLimitTable(rsigner)
	// TEE 侧配额下发器（S3）：OTP_CORE_TEE_URL 为空 = nil（预算/TPM 不下发，仅在响应 Note 中说明）
	teeQuota := api.NewHTTPTeeQuotaApplier(os.Getenv("OTP_CORE_TEE_URL"), os.Getenv("OTP_CORE_TEE_ADMIN_TOKEN"))
	srv := api.New(signer, msigner, rsigner, teeQuota, st, authToken, rt, rlt)
	// 启动日志取**生效表**（api.New 仅在 store 无表时写默认表，故此处可能是快照恢复值），
	// 避免日志版本与实服版本不一致（P2-4 T-1.7 / QA P1-1 配套）。
	if eff := st.GetRouteTable(); eff != nil {
		rt = eff
	}
	if eff := st.GetRateLimitTable(); eff != nil {
		rlt = eff
	}
	srv.SetACLSigner(aclsigner)
	srv.SetRateLimitSigner(a2arlsigner)
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

	// P2-4 T-4.2：审计链导出端点（默认关闭）。
	auditExportStatus, err := setupAuditExport(srv)
	if err != nil {
		log.Fatalf("初始化审计链导出端点失败（fail-closed 拒绝启动）: %v", err)
	}

	// P2-4 T-3.4：集群心跳上报（携带 applied_config_version；默认关闭）。
	hbStatus, stopHeartbeat, err := setupHeartbeat(srv)
	if err != nil {
		log.Fatalf("初始化集群心跳上报失败（fail-closed 拒绝启动）: %v", err)
	}
	defer stopHeartbeat()

	log.Printf("gateway-core 启动: addr=%s 鉴权=%v 路由版本=%d 限流版本=%d TEE配额下发=%v 变更审计=%s A2A注册中心=%s 存储快照=%s 审计导出=%s 心跳上报=%s",
		addr, authToken != "", rt.Version, rlt.Version, teeQuota != nil, auditState, a2aStatus, snapState, auditExportStatus, hbStatus)
	// 控制面无流式响应，全量超时；body 上限防资源耗尽（T-1 评审项）
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           limitBody(srv.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// 监听器显式创建：绑定失败快速失败（fail-fast），且可观测真实绑定地址。
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", addr, err)
	}
	// 退出信号接管（QA P3-新）：K8s 滚动更新删 Pod 发 SIGTERM 属**可预期的优雅
	// 退出**，不应按崩溃处理（Go 默认收到 SIGTERM 直接终止，defer 不执行 ⇒
	// 合并写窗口 ≤200ms 内的快照变更丢失）。故显式接管 SIGTERM/SIGINT：
	// 排空在途请求 → 快照收尾补写（ss.Close → Flush）→ 正常退出。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	// snapShutdown 收尾刷盘（幂等：ss.Close 只生效一次）。
	snapShutdown := func() {
		if snapFlush != nil {
			snapFlush()
			snapFlush = nil
		}
	}
	if err := serveWithShutdown(httpSrv, ln, sigCh, snapShutdown); err != nil {
		// log.Fatalf 不执行 defer：此处显式收尾刷盘（快照窗口内变更不丢）。
		snapShutdown()
		log.Fatalf("HTTP 服务退出: %v", err)
	}
}

// serveWithShutdown 在给定监听器上启动 HTTP 服务并阻塞，直到收到退出信号
// （SIGTERM/SIGINT）或服务出错。
//
// **优雅退出语义**（P2-4 T-1.7 / QA P3-新）：
//   - K8s 滚动更新删 Pod 会发 SIGTERM；Go 进程收到 SIGTERM 的默认行为是
//     **直接终止**（defer 不执行）⇒ 合并写窗口（≤200ms）内的快照变更丢失。
//     这属于"可预期的优雅退出"，不应按崩溃处理。
//   - 故显式接管：收到信号 → httpSrv.Shutdown(ctx) 排空在途请求 → 调用
//     onShutdown（快照 ss.Close() → Flush 补写窗口内变更）→ 返回 nil。
//
// 返回值：nil = 正常退出（信号触发的优雅退出，或服务已被外部关闭）；
// 非 nil = 服务错误（调用方按致命错误处理）。
func serveWithShutdown(httpSrv *http.Server, ln net.Listener, sigCh <-chan os.Signal, onShutdown func()) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.Serve(ln)
	}()
	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case sig := <-sigCh:
		log.Printf("收到信号 %v，开始优雅退出（排空在途请求 → 快照收尾补写）", sig)
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("警告: HTTP 服务优雅关闭未完成（可能有长连接未结束）: %v", err)
		}
		// 无论 Shutdown 是否超时，都必须收尾补写（快照窗口内变更不丢）。
		if onShutdown != nil {
			onShutdown()
		}
		return nil
	}
}

// snapshotShutdown 返回快照收尾刷盘函数（优雅退出补写合并写窗口内的变更）。
//
// 幂等：store.SnapshotStore.Close 内部以 closed 标记保证只生效一次；
// 失败只告警不阻断退出（内存为准，快照是旁路）。
func snapshotShutdown(ss *store.SnapshotStore) func() {
	return func() {
		if ss == nil {
			return
		}
		if err := ss.Close(); err != nil {
			log.Printf("警告: gateway-core 快照收尾刷盘失败: %v", err)
		}
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
		DSN:           dsn,
		PublicMode:    os.Getenv("A2A_PUBLIC_MODE"),
		GatewayBase:   os.Getenv("A2A_GATEWAY_PUBLIC_BASE"),
		TenantDomains: parseTenantDomains(os.Getenv("A2A_TENANT_DOMAINS")),
		JWTSecret:     jwtSecret,
		StaticToken:   staticToken,
		SnapshotToken: os.Getenv("A2A_SNAPSHOT_TOKEN"),
		DevMode:       devMode,
		JKUAllowlist:  splitCSV(os.Getenv("A2A_JKU_ALLOWLIST")),
	}
	reg, err := a2aregistry.New(cfg, srv.PolicyAuditChain())
	if err != nil {
		// 致命（库 schema 新于代码）→ 拒绝启动。
		return "", err
	}
	srv.SetA2ARegistry(reg)
	return "已启用", nil
}

// setupAuditExport 按环境变量装配审计链导出端点（P2-4 T-4.2；**默认关闭**）。
// 返回启动日志用的状态描述（"未启用" 或 "已启用(来源=...)"）。
//
// 环境变量：
//
//	GATEWAY_CORE_AUDIT_EXPORT_ENABLED  1|true|yes|on 才启用（其余 = 未启用 → 路由不注册，请求 404）
//	GATEWAY_CORE_AUDIT_EXPORT_CIDRS    来源 IP CIDR 白名单（逗号分隔；**空 = 拒绝所有来源**，
//	                                   启用时为空 → 拒绝启动：配置遗漏不得变成"启用即全开"）
//	GATEWAY_CORE_AUDIT_EXPORT_TOKEN    静态 Bearer 令牌（**临时联调口径**；空 = deny-all 全部 403）
//	GATEWAY_CORE_AUDIT_EXPORT_MAX      单次导出行数上限（可选；默认 auditexport.DefaultMaxLimit）
//
// ⚠️ **T-2.3 接线点**：授权实现应由 T-2.3「集群身份凭证（签发/校验/轮换/吊销）」
// 提供（实现 auditexport.Authorizer 接口），替换下方的 TokenAuthorizer 临时口径：
//
//	cfg.Authorizer = clustercred.NewAuthorizer(...) // T-2.3 落地后替换
//
// 本任务不实现凭证本身；未注入真实实现时，TokenAuthorizer 令牌为空即 deny-all。
func setupAuditExport(srv *api.Server) (string, error) {
	if !envTruthy(os.Getenv("GATEWAY_CORE_AUDIT_EXPORT_ENABLED")) {
		return "未启用", nil
	}
	cidrs := splitCSV(os.Getenv("GATEWAY_CORE_AUDIT_EXPORT_CIDRS"))
	wl, err := auditexport.NewSourceWhitelist(cidrs)
	if err != nil {
		return "", err // CIDR 非法 → 拒绝启动（fail-closed）
	}
	if wl.Empty() {
		return "", errors.New("GATEWAY_CORE_AUDIT_EXPORT_CIDRS 为空：白名单空 = 拒绝所有来源（请显式配置来源 CIDR 或关闭导出端点）")
	}
	maxLimit := auditexport.DefaultMaxLimit
	if raw := strings.TrimSpace(os.Getenv("GATEWAY_CORE_AUDIT_EXPORT_MAX")); raw != "" {
		n, perr := strconv.Atoi(raw)
		if perr != nil || n <= 0 {
			return "", fmt.Errorf("GATEWAY_CORE_AUDIT_EXPORT_MAX 非法: %q", raw)
		}
		maxLimit = n
	}
	cfg := auditexport.Config{
		Enabled:   true,
		Whitelist: wl,
		MaxLimit:  maxLimit,
		// 临时联调口径（T-2.3 前）：令牌为空 → deny-all。
		Authorizer: auditexport.TokenAuthorizer{Token: os.Getenv("GATEWAY_CORE_AUDIT_EXPORT_TOKEN")},
	}
	srv.SetAuditExport(cfg)
	return fmt.Sprintf("已启用（来源=%s 上限=%d 授权=%s）", strings.Join(cidrs, ","), maxLimit, auditExportAuthState(cfg)), nil
}

// auditExportAuthState 启动日志用：区分"已注入静态令牌"与"deny-all（待 T-2.3）"。
func auditExportAuthState(cfg auditexport.Config) string {
	if tk, ok := cfg.Authorizer.(auditexport.TokenAuthorizer); ok && tk.Token != "" {
		return "静态令牌（临时，待 T-2.3 集群凭证替换）"
	}
	return "deny-all（待 T-2.3 集群凭证）"
}

// setupHeartbeat 按环境变量装配集群心跳上报（P2-4 T-3.4；**默认关闭**）。
// 返回启动日志用的状态描述与停止函数（停止函数总是可安全调用）。
//
// 环境变量：
//
//	GATEWAY_CORE_HEARTBEAT_ENABLED  1|true|yes|on 才启用（其余 = 未启用）
//	GATEWAY_CORE_HEARTBEAT_URL      管理面心跳端点完整 URL
//	                                （如 http://gateway-admin-service:8080/v1/adminext/clusters/cluster-a/heartbeat）
//	GATEWAY_CORE_CLUSTER_ID         集群 ID（凭证与集群绑定）
//	GATEWAY_CORE_CLUSTER_CREDENTIAL 集群身份凭证（T-2.3 签发；**仅内存使用，不落盘不打印**）
//	GATEWAY_CORE_HEARTBEAT_INTERVAL 上报周期秒数（可选；默认 heartbeat.DefaultInterval=30s）
//
// 上报内容：{"applied_config_version": "<插件最近上报的版本>"}；未上报时为空串
// ⇒ 管理面标记 unknown（禁止以「未见差异」默认收敛）。
//
// ⚠️ **core 不做收敛判定**：期望 vs 实际的比较属管理面 sync-status（T-3.3）。
func setupHeartbeat(srv *api.Server) (string, func(), error) {
	noop := func() {}
	if !envTruthy(os.Getenv("GATEWAY_CORE_HEARTBEAT_ENABLED")) {
		return "未启用", noop, nil
	}
	cfg := heartbeat.Config{
		Endpoint:   strings.TrimSpace(os.Getenv("GATEWAY_CORE_HEARTBEAT_URL")),
		ClusterID:  strings.TrimSpace(os.Getenv("GATEWAY_CORE_CLUSTER_ID")),
		Credential: strings.TrimSpace(os.Getenv("GATEWAY_CORE_CLUSTER_CREDENTIAL")),
		Logger:     log.Default(),
	}
	if raw := strings.TrimSpace(os.Getenv("GATEWAY_CORE_HEARTBEAT_INTERVAL")); raw != "" {
		secs, perr := strconv.Atoi(raw)
		if perr != nil || secs <= 0 {
			return "", noop, fmt.Errorf("GATEWAY_CORE_HEARTBEAT_INTERVAL 非法: %q", raw)
		}
		cfg.Interval = time.Duration(secs) * time.Second
	}
	rep, err := heartbeat.NewReporter(cfg)
	if err != nil {
		return "", noop, err // 配置不完整 → 拒绝启动（fail-closed，避免"以为在上报"）
	}
	ctx, cancel := context.WithCancel(context.Background())
	// 版本取值：core 侧只如实转述缓存内容（最近一次被采纳的上报；unknown → 空串）。
	go rep.Run(ctx, func() string {
		rec, ok := srv.AppliedConfigVersion()
		if !ok {
			return "" // unknown
		}
		return rec.Version
	})
	return fmt.Sprintf("已启用（集群=%s 周期=%s）", cfg.ClusterID, rep.Interval()), cancel, nil
}

// envTruthy 判定开关型环境变量是否为真（1/true/yes/on，大小写不敏感）。
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
