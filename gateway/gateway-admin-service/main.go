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
// 兼容期（三步收口第 1 步，ADMIN_SVC_BROKER_LEGACY_PORT 缺省 false（fail-closed），须显式 true 才开启）：
// 管理面端口**可选**同时暴露 broker 中转；收口期置 false 后仅 :19096 提供服务。
// 注意：即便开启，该暴露路径亦须套管理面鉴权（见 buildAdminMux），不得裸奔。
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
//	POST /v1/adminext/cryptop/profile             密码 profile/mask_prg 切换（P0-4 §4.3.10；**admin**；落审计链）
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
// ADMIN_SVC_BROKER_LISTEN / ADMIN_SVC_BROKER_LEGACY_PORT（缺省 false（fail-closed），须显式 true 开启；同文件）；
// 模型目录：ADMIN_BROKER_CR_FILE（与漂移检测同源）/ ADMIN_SVC_AI_ROUTES_DIR（model_catalog.go）；
// 审计链（G1）：ADMIN_AUDIT_FILE（未配置 = 关闭）/ ADMIN_AUDIT_ANCHOR_FILE（audit.go）；
// 用量代理（A-2'）：ADMIN_TEE_INFER_URL（未配置 = 端点 503）/ ADMIN_TEE_INFER_TOKEN（usage.go）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
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

// auditJobCounter 是 billing.JobAuditCounter 的薄适配器：把 P2-5 job 计量对账计数
// 委托给 adminAuditChain —— 按 tenant / action=confllm_graph_submit / 时间窗统计 graph
// 提交事件数，与账本 job 入账数做零容差比对。审计链未启用时不应构造此适配器
// （main 中已用 auditChain != nil 守卫，避免把对账错误地判定为 0 提交）。
type auditJobCounter struct {
	chain *adminAuditChain
}

func (a *auditJobCounter) CountAction(ctx context.Context, tenant, action string, fromNs, toNs int64) (int64, error) {
	return a.chain.CountAction(ctx, tenant, action, fromNs, toNs)
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
		// P1-7 T8/T9（§6.2/§6.4）：温/冷层检索·导出 + 留存声明读写。
		if sch.full != nil {
			mux.HandleFunc(auditFullSearchPath, authMiddleware(cfg, sch.full.handleAuditFullSearch))
			mux.HandleFunc(auditFullExportPath, authMiddleware(cfg, sch.full.handleAuditFullExport))
			mux.HandleFunc(auditRetentionPath, authMiddleware(cfg, sch.full.handleAuditRetention))
		}
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
		mux.Handle(brokerPathPrefix, authMiddleware(cfg, bh.ServeHTTP))
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

// buildConfllmModelGuard 从 ADMIN_CONFLLM_MODEL_ACL_JSON 构造模型级 ACL（tenant×model）。
//
// 语义：allowlist（fail-closed）——租户不在清单 → 拒绝；清单内该模型不在白名单 → 拒绝；
// 白名单含 "*" 表示该租户允许全部模型。env 为空 → 返回 (nil, nil)（不启用 ACL，向后兼容）；
// env 非空但 JSON 解析失败 → 返回 error（调用方 fail-closed 拒绝启动，严禁 fail-open 静默放行）。
func buildConfllmModelGuard(env string) (confllmModelGuard, error) {
	if env == "" {
		return nil, nil
	}
	var m map[string][]string
	if err := json.Unmarshal([]byte(env), &m); err != nil {
		return nil, fmt.Errorf("ADMIN_CONFLLM_MODEL_ACL_JSON 解析失败（ACL 配置错误，fail-closed 拒绝启动）: %w", err)
	}
	return func(tenant, modelKey string) bool {
		allow, ok := m[tenant]
		if !ok {
			return false // 租户不在清单 → 拒绝（fail-closed）
		}
		for _, a := range allow {
			if a == "*" || a == modelKey {
				return true
			}
		}
		return false
	}, nil
}

func main() {
	// P2-4 T-1.6：存储迁移工具（sqlite → 共享库）内建子命令；未调用即零副作用。
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		os.Exit(runMigrate(os.Args[2:]))
	}

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
	// 密态推理数据面（T04）：薄接线（§2 confllm_wire.go）。
	// managed→A override 证明引用（§7.11 B2）与密态上游实例均按 env 可选装配。
	if err := loadConfllmManagedOverrides(); err != nil {
		log.Fatalf("confllm managed→A override 加载失败（fail-closed）：%v", err)
	}
	confllmH := newConfllmHandler(bh)
	if err := loadConfllmProviders(bh); err != nil {
		log.Fatalf("confllm 密态上游装配失败（fail-closed）：%v", err)
	}

	adminMux := buildAdminMux(cfg, sh, bh, mh, uh, ah, sch, cs, bih, bs.legacyPort)

	// 密态推理数据面端点（T04 + D3 parity）：/v1/confllm/* 全部经 confllmPolicy 收口
	//（认证 → 授权 → 配额 → 审计 → 业务 handler，K8 新入口与主链路同策略，见 confllm_policy.go）。
	// 配额查询器 = billing 检测器（QuotaRemaining）；billing 未启用 / 检测器缺失 → nil
	//（策略链内可观测放行 quota_unenforced，绝不静默）。
	var confllmQuota confllmQuotaChecker
	if bih != nil && bih.anomaly != nil {
		confllmQuota = bih.anomaly
	}
	// P2-5 job 计量：复用 billing 服务（IngestJobUsage）。billing 未启用 → nil（策略链跳过
	// 计量，可观测，绝不静默）。
	var confllmJobMeter confllmJobMeterer
	if bih != nil && bih.svc != nil {
		confllmJobMeter = bih.svc
	}
	// P2-5 job 计量对账：审计链计数适配器。
	// 仅当 billing 与审计链**同时**启用时才注入 —— 任一方未启用 → jobAudit 保持 nil，
	// billing.ReconcileJobs 跳过对账（fail-safe，不误判 0 提交）。
	if bih != nil && bih.svc != nil && auditChain != nil {
		bih.svc.SetJobAudit(&auditJobCounter{chain: auditChain})
	}
	// 模型级 ACL（tenant×model）：从环境变量注入允许清单；未配置 → nil（不启用，向后兼容）；
	// 配置非空但解析失败 → fail-closed 拒绝启动（不得 fail-open 静默放行）。
	confllmGuard, loadErr := buildConfllmModelGuard(os.Getenv("ADMIN_CONFLLM_MODEL_ACL_JSON"))
	if loadErr != nil {
		log.Fatalf("confllm 模型级 ACL 配置加载失败（fail-closed）: %v", loadErr)
	}

	// A3（中间件抽离）：将 *adminAuditChain 适配为 confllmAuditChain 接口；auditChain 为 nil 时
	// 得到"真 nil 接口"（防 typed-nil panic），confllmAuditAppend 内 if audit == nil 判空可安全跳过。
	var confllmAudit confllmAuditChain
	if auditChain != nil {
		confllmAudit = auditChain
	}

	// A2（数据面流量隔离）：confllmListen 非空 → 独立 listener 承载 /v1/confllm/*，与管理面端口
	// 分离，缩小管理面爆炸半径；缺省空 = 维持现状挂 adminMux（fail-safe，零行为变化）。
	if cfg.confllmListen != "" {
		if cfg.confllmListen == cfg.listen {
			log.Fatalf("配置错误：confllm 监听 %s 与管理面监听相同（A2 要求端口分离）", cfg.confllmListen)
		}
		confllmMux := http.NewServeMux()
		registerConfllmRoutes(confllmMux, cfg, confllmH, confllmAudit, confllmQuota, confllmJobMeter, confllmGuard)
		go serve("confllm", cfg.confllmListen, confllmMux)
		log.Printf("confllm 数据面独立监听已启用：%s（管理面 %s 隔离，A2）", cfg.confllmListen, cfg.listen)
	} else {
		registerConfllmRoutes(adminMux, cfg, confllmH, confllmAudit, confllmQuota, confllmJobMeter, confllmGuard)
	}

	// P2-4 T-2：集群注册 API（注册/列表/心跳/审批/摘除）。
	// 存储：PG 时与租户库同库（多集群共享），SQLite 时独立文件；两者都未配置 → 不启用（默认零变化）。
	// fail-closed：注册表打开失败即拒启动（集群状态与凭证不可静默丢失）。
	//
	// cstore 提升到外层作用域：T-3.1 的策略作用域校验器（tenant_scope.go）需**复用同一句柄**，
	// 避免对同一 sqlite 文件开第二个连接（多写者与 WAL 锁风险）。
	var cstore ClusterStore
	if cfg.clusterStorePGDSN != "" || cfg.clusterStorePath != "" {
		dialect := sqlutil.SQLite
		dsn := cfg.clusterStorePath
		if cfg.clusterStorePGDSN != "" {
			dialect = sqlutil.Postgres
			dsn = cfg.clusterStorePGDSN
		}
		cs, cerr := OpenClusterStore(dialect, dsn)
		if cerr != nil {
			log.Fatalf("集群注册表初始化失败（fail-closed）：%v", cerr)
		}
		cstore = cs
		defer cstore.Close()
		registerClusterRoutes(adminMux, cfg, newClusterAPI(cstore, newClusterApprovalRegistry(auditChain)))
		log.Printf("集群注册 API 已启用（dialect=%s）", dialect)
	} else {
		log.Printf("集群注册 API 未启用（TENANT_STORE_PG_DSN / ADMIN_CLUSTER_STORE_PATH 均未配置）")
	}

	// P2-4 T-4.1：审计跨集群聚合查询端点注入（安全中心 handler 复用同一集群注册表句柄，
	// 不另开连接）；注册表未启用时 clusterStore 保持 nil ⇒ core/tee 卷如实标 disabled。
	if cstore != nil {
		sch.setClusterStore(cstore)
	}
	sch.setDispatchToken(cfg.gatewayCoreToken)
	sch.registerAuditChainQuery(adminMux, cfg)

	// 租户自助门户（可选启用）：独立 tenantMux 承载 /v1/tenant/* 与 /v1/adminext/tenant/*
	// （双 mux 隔离，C-16）；验证码签发为 Console 内部端点，挂管理面（authMiddleware）。
	var tenantStore TenantStore
	var tenantH *tenantHandler
	if cfg.tenantEnabled {
		// P2-4 T-1.2b：按配置选择方言（TENANT_STORE_PG_DSN 非空 → 共享库 PG；否则 SQLite）。
		// PG 打开失败一律 fail-closed 拒启动（多副本共享语义不可静默丢失）。
		ts, err := openTenantStoreForConfig(cfg)
		if err != nil {
			log.Fatalf("租户存储初始化失败（fail-closed）：%v", err)
		}
		tenantStore = ts
		// billing 域启用时注入免费版绑定器（复用其 store/compiler/applier/回读确认）；
		// 未启用 → binder=nil → verify 返回 503（C-12）
		var binder quotaBinder
		if bih != nil {
			binder = bih
		}
		tenantH = newTenantHandler(ts, cfg, binder, uh, bih, mh, auditChain)
		// P2-4 T-3.1：策略作用域（scope{global|cluster[]}）写入校验器注入集群注册表——
		// 复用同一句柄（不另开连接），未启用注册表时保持 nil（此时只允许 global）。
		if cstore != nil {
			tenantH.setScopeResolver(cstore)
		}
		// P2-4 T-3.3：收敛核对端点取集群注册表 actual 版本（复用同一句柄，不另开连接）。
		tenantH.setClusterStore(cstore)
		// P2-4 T-1.3/T-1.4：安全计数器共享库（captcha 签发限流/答案存储 + 登录失败锁定）。
		// 显式配置 SECURITY_STORE_PG_DSN 才启用；缺省进程内实现（默认行为零变化）。
		// 开库/建表失败 → fail-closed 拒启动（多副本共享语义不可静默丢失）。
		if cfg.securityStorePGDSN != "" {
			sec, err := openSecurityStore(sqlutil.Postgres, cfg.securityStorePGDSN)
			if err != nil {
				log.Fatalf("安全计数器共享库初始化失败（fail-closed）：%v", err)
			}
			defer func() { _ = sec.Close() }()
			tenantH.useSecurityPGStore(sec)
			log.Printf("安全计数器已启用 PG 共享库（多副本原子）：captcha 限流/答案 + 登录失败锁定")
		}
		tenantH.registerCaptcha(adminMux, cfg)
		tenantH.registerKeyRevocations(adminMux, cfg)
		tenantH.registerTenantDirectory(adminMux, cfg)
		// N4 运维批量重签发承诺边界声明（触发③；管理面内部端点，admin）。
		tenantH.registerAdminStatementOps(adminMux, cfg)
		// P2-4 T-3.3：收敛核对端点（GET /v1/adminext/clusters/sync-status，admin-only）。
		tenantH.registerSyncStatus(adminMux, cfg)
		defer func() { _ = ts.Close() }()
		tenantH.startQuotaCompensator(context.Background(),
			time.Duration(cfg.tenantCompensateIntervalMin)*time.Minute)

		// N5 数据面下发通道（§4.3.5，D-12）：经 gateway-core 处方 API；未配置 = 通道未就绪，
		// worker fail-closed（保留旧版并告警），不阻断门户启动。
		var applier dispatchApplier
		if a := newHTTPDispatchApplier(cfg.gatewayCoreURL, cfg.gatewayCoreToken,
			time.Duration(cfg.dispatchTimeoutSec)*time.Second); a != nil {
			applier = a
		} else {
			log.Printf("提示：GATEWAY_CORE_URL 未配置——N5 下发通道未就绪（fail-closed 保留旧版并告警）")
		}
		disp := newDispatcher(ts, applier)
		if bih != nil {
			disp.quotaFn = func(tenantID string) *dispatchQuota {
				plan, err := bih.store.Plans().Resolve(tenantID, time.Now().UnixNano())
				if err != nil || plan == nil {
					return nil
				}
				return &dispatchQuota{
					PlanID: plan.ID, MonthlyTokens: plan.MonthlyTokens,
					Concurrency: plan.Concurrency, CacheTier: plan.CacheTier,
				}
			}
		}
		tenantH.dispatch = disp
		tenantH.effects.bumpDispatchVersion = disp.BumpInTx
		tenantH.effects.enqueueDispatch = disp.Enqueue
		// N4：开通/变更后重签承诺边界声明（supersedes 链；失败不回滚配置，仅告警）。
		tenantH.effects.reissueStatement = tenantH.reissueStatementForTenant
		if n, err := disp.ReplayPending(); err != nil {
			log.Printf("重启重放下发任务失败：%v", err)
		} else if n > 0 {
			log.Printf("重启重放下发任务：%d 个租户（pending/applying）", n)
		}

		// N3 证明状态源（§4.3.3）：未配置 = 未接线 → 看板降级 unknown + 强制未闭环（C-19）。
		if src := newHTTPAttestStatusSource(cfg.attestStatusURL, cfg.attestStatusToken,
			time.Duration(cfg.attestStatusTimeoutSec)*time.Second); src != nil {
			tenantH.attest = src
		} else {
			log.Printf("提示：ATTEST_STATUS_URL 未配置——N3 证明看板降级 unknown 并强制未闭环（C-19）")
		}

		// N10 启动自检（§4.3.10，V-S3）：轴 A=untrusted（任一已开通租户 trust_tier=untrusted）时
		// 强制 attest-verify 度量自检，异常 → fail-closed 拒启动；trusted 档跳过仅记日志。
		if err := n10StartupSelfCheck(ts, tenantH.attest); err != nil {
			log.Fatalf("N10 门户自保护自检失败（fail-closed）：%v", err)
		}

		log.Printf("租户自助门户已启用：store=%s smtp=%v captcha=%v billing=%v dispatch=%v",
			cfg.tenantStorePath, tenantH.mailer != nil, cfg.captchaEnabled, binder != nil, applier != nil)
	} else {
		log.Printf("租户自助门户未启用（TENANT_STORE_PATH 未配置），/v1/tenant/* 端点不注册")
	}
	_ = tenantStore // 暂存引用，后续模块（M3/M5）使用

	// P1-2 排障查询 API（M6，§6.3/§7.7）：恒注册；Tempo 未配置（ADMIN_TEMPO_URL）→ 503。
	// 路由优先级：Go 1.22 ServeMux 下字面量 /trace/search 优先于 /trace/{request_id}。
	th := newTraceHandler(os.Getenv("ADMIN_TEMPO_URL"), us)
	adminMux.HandleFunc(traceSearchPath, authMiddleware(cfg, th.handleTraceSearch))
	adminMux.HandleFunc(traceBasePath+"{request_id}", authMiddleware(cfg, th.handleTraceByID))
	adminMux.HandleFunc(traceBasePath+"{request_id}"+traceReportSuffix, authMiddleware(cfg, th.handleTraceReport))
	// P1-2 SLA 报表端点（M6，§6.3/§7.8）：恒注册；Prometheus 未配置（ADMIN_PROMETHEUS_URL）→ 503。
	slah := newSLAHandler(os.Getenv("ADMIN_PROMETHEUS_URL"))
	adminMux.HandleFunc(slaSummaryPath, authMiddleware(cfg, slah.handleSLASummary))
	// P1-2 SLO 定义与租户 tracing 灰度开关（M7，§6.3/§7.9）：POST 落审计链（fail-closed）。
	sloh := newSLOHandler(os.Getenv("ADMIN_SLO_FILE"), os.Getenv("ADMIN_PROMETHEUS_URL"), auditChain)
	adminMux.HandleFunc(sloPath, authMiddleware(cfg, sloh.handleSLO))
	adminMux.HandleFunc(tracingTenantPath, authMiddleware(cfg, sloh.handleTracingTenant))

	// 段① 凭据只读投递端点（Phase 1 门禁 #8；C 项起支持多集合）：
	// 未配置任何集合 = 不注册（fail-closed：绝不无令牌裸奔投递密钥）。仅供插件内网周期拉取。
	if csh := newCredentialHandler(loadCredentialSettings()); csh != nil {
		adminMux.HandleFunc(credentialAPIBase+"/", csh.handle)
		log.Printf("段① 凭据投递已启用：sets=%s", csh.settings.setNames())
	} else {
		log.Printf("段① 凭据投递未启用（ADMIN_CREDENTIAL_SETS / ADMIN_CREDENTIAL_TOKEN 均未配置）")
	}

	// P0-4 §4.3.10（B5-c）：profile 切换管理端点——不做密码运算，仅校验/一致性/审计/#12。
	// CRYPTOPSVC_URL 未配置时切换前校验无法执行，端点 fail-closed 返回 503。
	cryptopSwitcher := newCryptopProfileSwitcher(auditChain, os.Getenv("CRYPTOPSVC_URL"))
	if cryptopSwitcher.sidecarURL == "" {
		log.Printf("提示：CRYPTOPSVC_URL 未配置——profile 切换端点将 fail-closed 返回 503")
	}
	adminMux.HandleFunc(cryptopProfileSwitchPath, authMiddleware(cfg, cryptopSwitcher.handle))

	// P2-3 T-4：租户分区编排端点（§6.3）。Wave A：协作者以接口注入，单测 mock 覆盖；
	// 生产 MemberRegistry/KeyRefStore/DesiredPublisher 后续由 T-1 组协调器（GroupConfig/
	// 密钥目录/etcd）接入。当前以空注册表 + 静态 KeyRef + 内存 desired 兜底，端点可用、
	// RBAC/审计/幂等/配额/D-11/删除守卫均已落地，不接真实 HSM、不宣称 S3-b/生产合规。
	partitionH := newPartitionHandler(auditChain, newPartitionStore(), nil, nil, nil)
	adminMux.HandleFunc(cryptopPartitionPath, authMiddleware(cfg, partitionH.handle))

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

	// P1-2：管理面 tracing（M3，§7.4 `admin.request` span；默认关闭，C-4）。
	if err := InitTracing(); err != nil {
		log.Fatalf("初始化 tracing 失败（fail-closed）: %v", err)
	}
	defer ShutdownTracing()

	// 双 mux 隔离（C-16）：租户子树（/v1/tenant/* + /v1/adminext/tenant/*）独立 tenantMux，
	// 其余路径走 adminMux；租户端点严禁挂在管理 mux。
	adminHandler := http.Handler(adminMux)
	if tenantH != nil {
		tenantMux := http.NewServeMux()
		tenantH.registerMux(tenantMux)
		root := http.NewServeMux()
		root.Handle(tenantAPIBase+"/", tenantMux)
		root.Handle(tenantSessionBase+"/", tenantMux)
		root.Handle("/", adminMux)
		adminHandler = root
	}

	log.Printf("gateway-admin-service 就绪（M2 A-2 双 listener）：admin=%s", cfg.listen)
	serve("admin", cfg.listen, adminHandler)
}
