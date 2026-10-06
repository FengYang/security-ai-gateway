// Package main — gateway-admin-service（管理门户业务服务）。
//
// 定位（docs/管理门户-细化方案.md §3/§3.2）：
// 管理面 UI 的自研业务服务（Go，与网关同栈）。请求路径 = 前端 admin-ext 页 →
// 控制台 Java admin-ext controller →（内部令牌认证）→ 本服务 → K8s/Secret/tee-infer。
// 本服务不直接对外暴露（ClusterIP 集群内）。
//
// 监听形态（M2 A-2：双 listener 网络隔离）：
//
//	管理面（缺省 :19095）  /healthz /readyz /metrics /v1/adminext/*（含凭据托管端点）
//	broker（缺省 :19096）  /llm-broker/{provider}/**（仅数据面可达，见 K8s NetworkPolicy）
//
// 兼容期（三步收口第 1 步，ADMIN_SVC_BROKER_LEGACY_PORT 缺省 true）：管理面端口
// **同时**暴露 broker 中转，保持 M1 既有链路可用；收口期置 false 后仅 :19096 提供服务。
//
// API：
//
//	GET  /healthz                                存活探针
//	GET  /readyz                                 就绪探针（三态，见 handleReadyz）
//	GET  /metrics                                Prometheus 文本指标
//	GET  /v1/adminext/echo                       受保护示例端点（回显令牌内 sub/role）
//	GET  /v1/adminext/models                     模型目录只读列表（M2 A-1'；已认证可读）
//	GET  /v1/adminext/usage                      用量查询（M2 A-2'；auditor 可读；代理 tee-infer）
//	POST /v1/adminext/usage/quota                 配额设置（M2 A-2'；**admin**；落审计链）
//	POST /v1/adminext/audit-events                账号管理审计投递（M3-A；**admin**；落审计链，action 白名单）
//	GET  /v1/adminext/broker-providers           托管凭据列表（已认证可读）
//	GET  /v1/adminext/broker-providers/{name}    托管凭据详情（已认证可读）
//	POST /v1/adminext/broker-providers/{name}    写入/轮换凭据（**admin**；返回 customUrl）
//	DELETE /v1/adminext/broker-providers/{name}  删除凭据（**admin**；返回 CR 联动告警）
//	ANY  /llm-broker/{provider}/...              内部凭据 broker 中转（可选启用；
//	                                             不走内部 JWT 鉴权——ai-proxy 无法注入服务令牌；
//	                                             信任边界 = 集群内网 + provider/路径双重白名单）
//
// 运行：go run ./gateway/gateway-admin-service
// 配置：环境变量 ADMIN_SVC_*（见 config.go），其中 ADMIN_SVC_JWT_SECRET 必填；
// 角色控制（M3-A）：授权依据 = JWT role（Java 控制台账号表派生）；
// ADMIN_SVC_ROLE_ADMINS 仅作运维层强制加成（白名单内恒 admin，未配置 = 不加成）；
// broker：ADMIN_BROKER_SECRETS_DIR / ADMIN_BROKER_PUBLIC_BASE / ADMIN_BROKER_CR_FILE /
// ADMIN_SVC_BROKER_LISTEN / ADMIN_SVC_BROKER_LEGACY_PORT（同文件）；
// 模型目录：ADMIN_BROKER_CR_FILE（与漂移检测同源）/ ADMIN_SVC_AI_ROUTES_DIR（model_catalog.go）；
// 审计链（G1）：ADMIN_AUDIT_FILE（未配置 = 关闭）/ ADMIN_AUDIT_ANCHOR_FILE（audit.go）；
// 用量代理（A-2'）：ADMIN_TEE_INFER_URL（未配置 = 端点 503）/ ADMIN_TEE_INFER_TOKEN（usage.go）。
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
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

// handleReadyz 就绪探针（M2 A-2 三态语义）：
//
//	broker 未启用（brokerHealthy == nil） → ready（可选特性，不阻塞 Deployment）
//	broker 已启用且未连续失败超阈值       → ready
//	broker 已启用但连续重载失败 ≥3 次     → 503（暴露配置漂移）
//
// 要点：**"未启用 broker" 必须判 ready**，否则可选特性会阻塞整个 Deployment（评审 O-1）。
func handleReadyz(brokerHealthy func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if brokerHealthy != nil && !brokerHealthy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("broker config unhealthy"))
			return
		}
		_, _ = w.Write([]byte("ready"))
	}
}

// handleMetrics Prometheus 指标端点：GET /metrics。
func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.render(w)
	// 计费域指标（T10）：billing.enabled=false 时注册表为空 → 渲染 0 字节（输出逐字节不变 R-1/M10）。
	billing.RenderMetrics(w)
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

// buildAdminMux 构造管理面路由。
//
// sh / bh 为 nil 表示 broker 未启用（特性关闭：既不注册凭据端点，也不注册中转路径）。
// mh 为模型目录 handler（M2 A-1'，只读特性，恒注册；数据源缺失返回空列表）。
// uh 为用量代理 handler（M2 A-2'，恒注册；数据源未配置时端点返回 503）。
// ah 为账号管理审计投递 handler（M3-A，恒注册；审计链未启用时端点返回 503）。
// sch 为安全中心数据 handler（M3-B，恒注册；G1 链/tee-infer 数据源缺失时按 503 语义返回）。
// cs 为高敏变更复核 handler（M3-C，nil = 特性关闭；启用后强制 submitter≠reviewer）。
// bih 为计费域 handler（P0-3，nil = 特性关闭；启用后注册 /billing/* 端点）。
// legacyBroker 为兼容期开关：true 时管理面端口同时暴露 broker 中转（三步收口第 1 步）。
func buildAdminMux(cfg *config, sh *brokerSecretHandler, bh *brokerHandler, mh *modelCatalogHandler, uh *usageHandler, ah *auditEventHandler, sch *secCenterHandler, cs *changeStore, bih *billingHandler, legacyBroker bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handleMetrics)
	// 受保护端点挂鉴权中间件；角色授权在 handler 内按方法校验（auth.go requireRole）。
	mux.HandleFunc("/v1/adminext/echo", authMiddleware(cfg, handleEcho))
	if mh != nil {
		mux.HandleFunc(modelsAPIBase, authMiddleware(cfg, mh.handleModels))
	}
	if uh != nil {
		mux.HandleFunc(usageAPIBase, authMiddleware(cfg, uh.handleUsage))
		mux.HandleFunc(usageQuotaPath, authMiddleware(cfg, uh.handleQuota))
		// S5 判据 6：审计-计量对账快照（只读代理；控制台看板数据源）
		mux.HandleFunc(meteringReconcilePath, authMiddleware(cfg, uh.handleMeteringReconcile))
	}
	if ah != nil {
		mux.HandleFunc(auditEventsPath, authMiddleware(cfg, ah.handle))
	}
	if sch != nil {
		mux.HandleFunc(secStatusPath, authMiddleware(cfg, sch.handleSecStatus))
		mux.HandleFunc(auditChainPath, authMiddleware(cfg, sch.handleAuditChain))
		mux.HandleFunc(auditChainVerifyPath, authMiddleware(cfg, sch.handleAuditChainVerify))
		mux.HandleFunc(auditChainExportPath, authMiddleware(cfg, sch.handleAuditChainExport))
		mux.HandleFunc(teeAuditPath, authMiddleware(cfg, sch.handleTeeAudit))
	}
	if cs != nil {
		mux.HandleFunc(changeAPIBase, authMiddleware(cfg, cs.handleList))
		mux.HandleFunc(changeAPIBase+"/", authMiddleware(cfg, cs.handleItem))
	}
	if bih != nil {
		bih.register(mux, cfg)
	}

	var brokerHealthy func() bool
	if sh != nil {
		brokerHealthy = sh.healthy
		mux.HandleFunc(brokerAPIBase, authMiddleware(cfg, sh.handleList))
		mux.HandleFunc(brokerAPIBase+"/", authMiddleware(cfg, sh.handleItem))
	}
	mux.HandleFunc("/readyz", handleReadyz(brokerHealthy))

	if legacyBroker && bh != nil {
		mux.Handle(brokerPathPrefix, bh)
	}
	return mux
}

// buildBrokerMux 构造 broker 专用 listener 路由（仅中转端点；管理面路径一律 404）。
func buildBrokerMux(bh *brokerHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(brokerPathPrefix, bh)
	return mux
}

// serve 启动单个 listener（阻塞；出错即终止进程，避免"半个服务"静默存活）。
func serve(name, addr string, h http.Handler) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		// ReadTimeout/WriteTimeout 不设置（流式兼容检查表①）：
		// broker 中转 SSE 长流不得被服务端超时掐断；慢连接防护由 ReadHeaderTimeout
		// 与集群内网边界（A-2 NetworkPolicy）承担。
	}
	log.Printf("listener[%s] 就绪：%s", name, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listener[%s] 退出: %v", name, err)
	}
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("配置加载失败（fail-closed）：%v", err)
	}
	if len(cfg.roleAdmins) == 0 {
		log.Printf("提示：ADMIN_SVC_ROLE_ADMINS 未配置——角色全按 JWT 声明（M3-A：Java 控制台账号表派生）；该白名单仅作运维层强制加成")
	}
	// P0-4 §5.4.4/§12.3：装配进程级密码 provider（intl 逐字节等价；非法档 = 启动拒）。
	if err := initCryptoRuntime(); err != nil {
		log.Fatalf("%v", err)
	}

	// broker 可选启用：凭据目录存在即接管（含空目录 = 0 provider），否则回落环境变量路径；
	// 均无则返回 nil（特性关闭，零影响既有行为）。配置无效 fail-closed 拒绝启动。
	bs := loadBrokerSettings()
	bc, fromDir, err := openBrokerConfig(bs)
	if err != nil {
		log.Fatalf("broker 配置加载失败（fail-closed）：%v", err)
	}

	// G1 审计链（B-3 §5）：ADMIN_AUDIT_FILE 未配置 = 关闭（写操作不落链，日志明示）；
	// 已配置但打开/恢复失败 = 拒绝启动（fail-closed：宁可不起，不起一条无审计校验的写路径）。
	as := loadAuditSettings()
	auditChain, err := newAdminAuditChain(as.file, as.anchorFile)
	if err != nil {
		log.Fatalf("审计链初始化失败（fail-closed）：%v", err)
	}
	if auditChain == nil {
		log.Printf("审计链未启用（ADMIN_AUDIT_FILE 未配置）：凭据/配额写操作将不落审计链")
	}

	var bh *brokerHandler
	var sh *brokerSecretHandler
	if bc != nil {
		if bs.publicBase == "" {
			log.Fatalf("配置缺失：ADMIN_BROKER_PUBLIC_BASE 未设置（broker 已启用，无法生成 provider customUrl，fail-closed）")
		}
		bh = newBrokerHandler(bc)
		sh = newBrokerSecretHandler(bs, bh, auditChain)
		if fromDir {
			sh.startReloader()
		}
	}

	// 模型目录（M2 A-1'）：只读特性，数据源缺失时返回空列表（不 fail-closed 启动）。
	mh := newModelCatalogHandler(loadModelCatalogSettings())
	// 用量代理（M2 A-2'）：恒注册；数据源未配置时端点返回 503（不静默返回空数据）。
	us := loadUsageSettings()
	uh := newUsageHandler(us, auditChain)
	// 账号管理审计投递（M3-A）：恒注册；审计链未启用时端点返回 503。
	ah := &auditEventHandler{chain: auditChain}
	// 安全中心数据端点（M3-B）：恒注册；G1 链/tee-infer 数据源缺失时按 503 语义返回。
	sch := newSecCenterHandler(auditChain, us)
	// 高敏变更复核（M3-C）：ADMIN_CHANGES_FILE 未配置 = 特性关闭（变更端点不注册）；
	// 启用后强制 submitter≠reviewer，凭据类动作明文走 0600 暂存文件（不入变更单）。
	cs, err := newChangeStore(os.Getenv("ADMIN_CHANGES_FILE"), auditChain, sh, us.url, us.token)
	if err != nil {
		log.Fatalf("变更单存储初始化失败（fail-closed）：%v", err)
	}
	if cs == nil {
		log.Printf("提示：高敏变更复核未启用（ADMIN_CHANGES_FILE 未配置），变更端点不注册")
	}
	// 计费域（P0-3）：BILLING_ENABLED!=true = 特性关闭（不注册 /billing/*，逐字节一致 R-1/M10）。
	bcfg, err := billing.LoadBillingConfig()
	if err != nil {
		log.Fatalf("计费配置加载失败（fail-closed）：%v", err)
	}
	bih, err := newBillingHandler(bcfg, auditChain)
	if err != nil {
		log.Fatalf("计费子系统初始化失败（fail-closed）：%v", err)
	}
	if bih != nil {
		log.Printf("计费域已启用：store=%s price_table=%s sync_mode=%s",
			bcfg.Store.Driver, bcfg.Rating.PriceTable, bcfg.Source.SyncMode)
		// 后台调度（S-8 缺口扫描：启动即执行一次 + 每日一次；补齐漏跑日账并预热月累计缓存）。
		bih.StartSchedulers(context.Background())
		defer bih.Close()                        // 先停调度（LIFO：先于 store.Close）
		defer func() { _ = bih.store.Close() }() // 再关存储
	} else {
		log.Printf("计费域未启用（BILLING_ENABLED!=true），/billing/* 端点不注册")
	}
	adminMux := buildAdminMux(cfg, sh, bh, mh, uh, ah, sch, cs, bih, bs.legacyPort)

	// 段① 凭据只读投递端点（Phase 1 门禁 #8；C 项起支持多集合）：
	// 未配置任何集合 = 不注册（fail-closed：绝不无令牌裸奔投递密钥）。仅供插件内网周期拉取。
	if csh := newCredentialHandler(loadCredentialSettings()); csh != nil {
		adminMux.HandleFunc(credentialAPIBase+"/", csh.handle)
		log.Printf("段① 凭据投递已启用：sets=%s", csh.settings.setNames())
	} else {
		log.Printf("段① 凭据投递未启用（ADMIN_CREDENTIAL_SETS / ADMIN_CREDENTIAL_TOKEN 均未配置）")
	}

	if bh != nil {
		if bs.brokerListen == cfg.listen {
			log.Fatalf("配置错误：broker 监听 %s 与管理面监听相同（A-2 要求端口分离）", bs.brokerListen)
		}
		src := "env"
		if fromDir {
			src = "dir:" + bs.secretsDir
		}
		log.Printf("broker 已启用：providers=%d source=%s publicBase=%s listen=%s legacyPort=%v",
			bh.providerCount(), src, bs.publicBase, bs.brokerListen, bs.legacyPort)
		go serve("broker", bs.brokerListen, buildBrokerMux(bh))
	} else {
		log.Printf("broker 未启用（凭据目录不存在且未设置 ADMIN_BROKER_PROVIDERS_JSON）")
	}

	log.Printf("gateway-admin-service 就绪（M2 A-2 双 listener）：admin=%s", cfg.listen)
	serve("admin", cfg.listen, adminMux)
}
