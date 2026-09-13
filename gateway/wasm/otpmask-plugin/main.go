// Package main — Higress Wasm 插件：otpmask-plugin（M5 里程碑）
//
// 目标：接入南向私有二进制协议与密态推理路径 A（TEE 服务）。
// 链路：文本输入 → TEE /key/issue 取密钥 → embedding-service 取向量 → 加密 →
// 构造南向协议请求（签名）→ 网关路由 → tee-infer-service（解密推理+加密）
// → 响应解码/验签/解密 → 明文输出。
//
// 复用：cipher/mask、protocol/go（南向协议）、MemKeyStore。
// 生产迁移：M6 接入 TEE KeyService 独立服务 + 远程证明。
//
// 编译（仓库根执行，Go 1.24+ 原生 wasm）：
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"

	"security-ai-gateway/protocol/go"
)

func main() {}

func init() {
	wrapper.SetCtx(
		"otpmask-plugin",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBodyBy(onRequestBody),
		wrapper.ProcessResponseHeadersBy(onHttpResponseHeaders),
		// P1b：流式响应回调（取代整包 ProcessResponseBodyBy）。
		// 逐帧 chunk → SSE 信封流走 SSEStreamDecoder 增量解密外发（解 §4.2 大响应挂起）；
		// 非 SSE（mock JSON/协议/quote 单信封）在回调内缓冲，endOfStream 一次整包处理。
		wrapper.ProcessStreamingResponseBodyBy(onStreamingResponseBody),
		// P1b 待办3：流完成回调——异常中断/fail-closed 截断下兜底删除未消费的请求密钥
		// （MemKeyStore 无 TTL，不做此清理会致 seed 永久残留）。
		wrapper.ProcessStreamDoneBy(onStreamDone),
	)
}

// PluginConfig 插件配置（控制台 YAML 自动转 JSON 下发）。
type PluginConfig struct {
	MaskModulus      uint64 `json:"mask_modulus"`
	Model            string `json:"model"`
	EmbeddingService string `json:"embedding_service"`
	EmbeddingPort    int64  `json:"embedding_port"`
	TEEService       string `json:"tee_service"`
	TEEPort          int64  `json:"tee_port"`
	SigKeyHex        string `json:"sig_key"`           // 协议签名密钥 K_sig（32 字节 hex，M5 静态注入；token 模式用）
	AttestToken      string `json:"attest_token"`      // 远程证明令牌（模拟凭证）
	AttestMode       string `json:"attest_mode"`       // 远程证明模式 "quote"（缺省，挑战-响应，text 载荷必需）| "token"（MVP 兼容，显式配置）
	ExpectedAppHash  string `json:"expected_app_hash"` // quote 模式：期望测量值 app_hash（客户策略，）
	JWTSecretHex     string `json:"jwt_secret"`        // 租户鉴权 JWT 密钥（32 字节 hex，C-6）；空 = 不启用
	RequireAuth      bool   `json:"require_auth"`      // true 时无有效 JWT 拒绝 401（C-6）
	ConfigVersion    string `json:"config_version"`    // 配置版本标识（C-8 热更新观测；发布方维护）
	// gateway-core 推送整合（拉路径 B / 冷启动 L3）：启用后启动/周期拉取默认路由表。
	GatewayCoreEnabled bool   `json:"gateway_core_enabled"`
	GatewayCoreService string `json:"gateway_core_service"`
	GatewayCorePort    int64  `json:"gateway_core_port"`
	RouteVerifyKeyHex  string `json:"route_verify_key"` // 路由表验签密钥 K_rx（32 字节 hex，与 gateway-core 一致）
	// §6 降级接线：默认路由表缓存的最老可接受时长（秒）。缺省 300；显式负数 = 永不过期
	// （对应设计 §6 原文"接受旧版本继续用"，可用性优先）。
	MaxStaleSeconds int64 `json:"max_stale_seconds"`
	// 默认路由表拉取周期（秒，设计 §3.3 poll_interval）。缺省 60；最小按 100ms tick 粒度换算。
	PollIntervalSeconds int64 `json:"poll_interval"`
	// 段① 凭据运行态拉取（Phase 1 门禁 #8 / GF.2.5）：启用后从管理面只读端点周期拉取
	// sig_key/attest_token，CR 内不再出现真实密钥。**未启用 = 行为与接线前完全一致**。
	CredentialEnabled         bool   `json:"credential_enabled"`
	CredentialService         string `json:"credential_service"`
	CredentialPort            int64  `json:"credential_port"`
	CredentialToken           string `json:"credential_token"` // 受限读取令牌（内网通道；非真实厂商密钥）
	CredentialName            string `json:"credential_name"`  // 凭据集名（缺省 otpmask-keys）
	CredentialIntervalSeconds int64  `json:"credential_interval"`
}

func parseConfig(json gjson.Result, config *PluginConfig, log logs.Log) error {
	config.MaskModulus = json.Get("mask_modulus").Uint()
	config.Model = json.Get("model").String()
	config.EmbeddingService = json.Get("embedding_service").String()
	config.EmbeddingPort = json.Get("embedding_port").Int()
	config.TEEService = json.Get("tee_service").String()
	config.TEEPort = json.Get("tee_port").Int()
	config.SigKeyHex = json.Get("sig_key").String()
	config.AttestToken = json.Get("attest_token").String()
	config.AttestMode = json.Get("attest_mode").String()
	config.ExpectedAppHash = json.Get("expected_app_hash").String()
	config.JWTSecretHex = json.Get("jwt_secret").String()
	config.RequireAuth = json.Get("require_auth").Bool()
	config.ConfigVersion = json.Get("config_version").String()
	config.GatewayCoreEnabled = json.Get("gateway_core_enabled").Bool()
	config.GatewayCoreService = json.Get("gateway_core_service").String()
	config.GatewayCorePort = json.Get("gateway_core_port").Int()
	config.RouteVerifyKeyHex = json.Get("route_verify_key").String()
	config.MaxStaleSeconds = json.Get("max_stale_seconds").Int()
	config.PollIntervalSeconds = json.Get("poll_interval").Int()
	config.CredentialEnabled = json.Get("credential_enabled").Bool()
	config.CredentialService = json.Get("credential_service").String()
	config.CredentialPort = json.Get("credential_port").Int()
	config.CredentialToken = json.Get("credential_token").String()
	config.CredentialName = json.Get("credential_name").String()
	config.CredentialIntervalSeconds = json.Get("credential_interval").Int()
	if config.GatewayCoreService == "" {
		// 缺省 FQDN（与 tee_service 同理：FQDNCluster 需完整服务域名，短名不会物化）。
		config.GatewayCoreService = "gateway-core.higress-system.svc.cluster.local"
	}
	if config.GatewayCorePort == 0 {
		config.GatewayCorePort = 8085
	}
	if config.MaskModulus < 2 {
		config.MaskModulus = defaultMaskModulus
	}
	if config.AttestMode == "" {
		config.AttestMode = "quote" // 缺省 quote：text 载荷引擎（tee_gpu/cmaas）必需；token 为显式兼容项
	}
	if config.Model == "" {
		config.Model = "mock"
	}
	if config.EmbeddingService == "" {
		config.EmbeddingService = "embedding.higress-system.svc.cluster.local" // Higress standalone：FQDN 簇（route 引用后由 pilot 物化）
	}
	if config.EmbeddingPort == 0 {
		config.EmbeddingPort = 18080
	}
	if config.TEEService == "" {
		config.TEEService = "tee-infer.higress-system.svc.cluster.local" // Higress standalone：FQDN 簇（route 引用后由 pilot 物化）
	}
	if config.TEEPort == 0 {
		config.TEEPort = 19090
	}
	// §6 降级接线：缺省 max_stale=300s；显式负数 = 永不过期（对应设计 §6 原文"接受旧版本"）。
	if config.MaxStaleSeconds == 0 {
		config.MaxStaleSeconds = 300
	}
	// 拉取周期缺省 60s（设计 §3.3 poll_interval）。
	if config.PollIntervalSeconds <= 0 {
		config.PollIntervalSeconds = 60
	}
	// 段① 凭据拉取缺省（门禁 #8）；无读取令牌 = 不启用（fail-closed：不发半配置请求）。
	if config.CredentialService == "" {
		// 与 deploy/k8s/gateway-admin-service.yaml 的命名空间一致（otpmask）。
		config.CredentialService = "gateway-admin-service.otpmask.svc.cluster.local"
	}
	if config.CredentialPort == 0 {
		config.CredentialPort = 19095
	}
	if config.CredentialName == "" {
		config.CredentialName = "otpmask-keys"
	}
	if config.CredentialIntervalSeconds <= 0 {
		config.CredentialIntervalSeconds = 300
	}
	if config.CredentialToken == "" {
		config.CredentialEnabled = false
	}
	// 按配置初始化/刷新路由运行时（未启用则置空 → 决策不介入请求，行为与接线前一致）。
	initRouteRuntime(*config, log)
	// 段① 凭据运行态（未启用则零影响）。
	initCredentialRuntime(*config)
	log.Infof("otpmask-plugin: 配置已加载 config_version=%q mask_modulus=%d model=%q embedding=%s:%d tee=%s:%d require_auth=%v",
		orStr(config.ConfigVersion, "unset"), config.MaskModulus, config.Model, config.EmbeddingService, config.EmbeddingPort,
		config.TEEService, config.TEEPort, config.RequireAuth)
	return nil
}

// orStr 空串回退（日志辅助）。
func orStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// sigKey 解析后的协议签名密钥（K_sig）：**运行态拉取优先**，非法/缺失时回退静态注入（token 模式）。
func (c *PluginConfig) sigKey() []byte {
	if k := decodeSigKeyHex(runtimeSigKeyHex()); k != nil {
		return k
	}
	return decodeSigKeyHex(c.SigKeyHex)
}

// decodeSigKeyHex 解析 32 字节 K_sig（hex）；非法或长度不符返回 nil。
func decodeSigKeyHex(hexStr string) []byte {
	if hexStr == "" {
		return nil
	}
	k, err := hex.DecodeString(hexStr)
	if err != nil || len(k) != 32 {
		return nil
	}
	return k
}

// requestK_sig 请求签名密钥：quote 模式用会话 K_sig，token 模式用静态注入。
func requestK_sig(config PluginConfig) []byte {
	if config.AttestMode == "quote" {
		if Session.valid() {
			return Session.K_sig
		}
		return nil // 无有效会话 → 不签名（TEE 将拒绝，fail-closed）
	}
	return config.sigKey()
}

// KeyStore 全局密钥存储（插件级共享，跨请求）。
var KeyStore = NewMemKeyStore()

// ctxKeyTenantID 请求上下文中的租户标识键（M9-1）。
// header 阶段读取并保存（body 阶段 proxywasm 读不到原始请求头）。
const ctxKeyTenantID = "otpmask-tenant-id"

// ctxKeyRespStatus 响应状态码缓存键（同因：body 阶段读不到响应伪头 :status）。
const ctxKeyRespStatus = "otpmask-resp-status"

// respStatusCached 取响应状态码：优先头回调缓存；缺失时回退 header 直读
// （缓存缺失 = 非本插件上下文路径，如预判阶段）。
func respStatusCached(ctx wrapper.HttpContext) string {
	if v, ok := ctx.GetContext(ctxKeyRespStatus).(string); ok {
		return v
	}
	return responseStatus()
}

// onHttpRequestHeaders 请求头阶段：移除 Content-Length → chunked 传输密文；
// 读取并保存租户标识 X-Tenant-ID（M9-1，供 /key/issue 与 TEE 侧按租户隔离）；
// C-6：配置 jwt_secret 时校验 Bearer token，以 tenant claim 覆盖自声明头，
// require_auth=true 时无/无效 token → 401。
func onHttpRequestHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	metricRequests.incr() // W-1：请求计数
	if err := proxywasm.RemoveHttpRequestHeader("content-length"); err != nil {
		log.Warnf("otpmask-plugin: 移除 content-length 失败: %v", err)
	}
	// B1：客户端 Accept: text/event-stream → mock 密文响应以 SSE 输出（否则 JSON）
	if a, _ := proxywasm.GetHttpRequestHeader("accept"); a != "" {
		requestWantsSSE = strings.Contains(strings.ToLower(a), "text/event-stream")
	} else {
		requestWantsSSE = false
	}
	if config.JWTSecretHex != "" {
		secret, err := hex.DecodeString(config.JWTSecretHex)
		if err != nil || len(secret) != 32 {
			return failClosed(log, "jwt_secret 配置错误（须 32 字节 hex）")
		}
		tok := bearerToken()
		if tok == "" {
			if config.RequireAuth {
				return authReject(log, "缺少 Bearer token")
			}
		} else if claims, err := verifyJWT(secret, tok); err != nil {
			if config.RequireAuth {
				return authReject(log, fmt.Sprintf("token 无效: %v", err))
			}
			log.Warnf("otpmask-plugin: JWT 校验失败（非强制）: %v", err)
		} else if claims.Tenant != "" {
			// 有效 JWT：以 tenant claim 覆盖客户端自声明（防租户伪造）
			ctx.SetContext(ctxKeyTenantID, claims.Tenant)
			_ = proxywasm.ReplaceHttpRequestHeader("X-Tenant-ID", claims.Tenant)
		}
	}
	if t := tenantHeaderValue(ctx); t != "" {
		_ = proxywasm.ReplaceHttpRequestHeader("X-Tenant-ID", t)
	}
	// §6 推拉结合路由决策（仅显式启用时介入）：处方 L1 → 默认路由表 L2 → 无命中密态 fail-closed；
	// 命中则写 X-Otp-Engine / X-Otp-Target 供 Envoy 路由规则消费。必须在请求头放行前完成。
	if action := applyRouteDecision(ctx, config, log); action != types.HeaderContinue {
		return action
	}
	// P1b 修复：有请求体时持住请求头（ActionPause）——请求头在 HeaderContinue 后
	// 即刻转发上游，body 阶段的 X-Session-ID/content-type 替换不生效（TEE 收不到
	// 会话头 → 信封被当裸协议解码，审计表现为 decode_error/bad_signature 乱码）。
	// 放行路径不变：body 各分支以 HeaderContinue（Envoy 数据 Continue 连带放行
	// 被持住的头）/ ResumeHttpRequest / SendHttpResponse 收尾；无体请求直通防死等。
	if ctx.HasRequestBody() {
		return types.ActionPause
	}
	return types.HeaderContinue
}

// authReject 鉴权失败 401 拒绝（C-6）。
func authReject(log logs.Log, msg string) types.Action {
	log.Warnf("otpmask-plugin: 鉴权拒绝: %s", msg)
	_ = proxywasm.SendHttpResponse(401, [][2]string{{"Content-Type", "text/plain"}}, []byte("otpmask: unauthorized"), -1)
	return types.ActionContinue
}

// tenantHeaderValue 读取请求租户标识（优先上下文，header 阶段已保存）。
func tenantHeaderValue(ctx wrapper.HttpContext) string {
	if v, ok := ctx.GetContext(ctxKeyTenantID).(string); ok {
		return v
	}
	v, err := proxywasm.GetHttpRequestHeader("X-Tenant-ID")
	if err != nil {
		return ""
	}
	ctx.SetContext(ctxKeyTenantID, v)
	return v
}

// onHttpResponseHeaders 响应头阶段：移除 Content-Length → chunked 返回明文；
// B1：客户端 Accept: text/event-stream 且成功响应 → 设 text/event-stream（header 阶段替换才生效）。
func onHttpResponseHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	if err := proxywasm.RemoveHttpResponseHeader("content-length"); err != nil {
		log.Warnf("otpmask-plugin: 移除响应 content-length 失败: %v", err)
	}
	// body 阶段读不到响应伪头 :status → 此处缓存（SSE 增量 vs 整包路径判定依赖）。
	ctx.SetContext(ctxKeyRespStatus, responseStatus())
	// B1：客户端 Accept: text/event-stream 且成功响应 → text/event-stream；
	// P1b：quote 模式成功响应总是输出 SSE 信封明文（协议路径 buildSSE）→ 一并预置。
	// （header 阶段替换才生效，§4.3）
	if responseStatus() == "200" && (requestWantsSSE || (config.AttestMode == "quote" && !pendingVectorsPlain)) {
		_ = proxywasm.ReplaceHttpResponseHeader("content-type", "text/event-stream")
	}
	return types.HeaderContinue
}

// onRequestBody 请求侧加密：支持文本（M4/M5）与向量（兼容）输入。
func onRequestBody(ctx wrapper.HttpContext, config PluginConfig, body []byte, log logs.Log) types.Action {
	if tReq, err := parseTextRequest(body); err == nil {
		return handleTextRequest(ctx, config, tReq, log)
	}
	if pReq, err := parsePlainRequest(body); err == nil {
		return handleVectorsRequest(ctx, config, pReq.Vectors, log)
	}
	// §8 遗留点修复：fail-closed 回显式 503（替代裸 return 挂起至 stream_idle_timeout）
	return failClosed(log, "无法解析请求体（需 text 或 vectors）")
}

// handleVectorsRequest 向量输入：签发密钥（本地）→ 加密 → 南向协议请求。
// 注：本地签发密钥与 TEE 不共享，仅用于向量输入兼容场景（M2/M3 回归）。
func handleVectorsRequest(ctx wrapper.HttpContext, config PluginConfig, vectors [][]uint64, log logs.Log) types.Action {
	pendingVectorsPlain = true
	seed, nonceHex, err := KeyStore.Issue()
	if err != nil {
		return failClosed(log, fmt.Sprintf("签发密钥失败: %v", err))
	}
	defer wipe(seed)
	// P1b 待办3：登记本请求在 KeyStore 的密钥 key，供 onStreamDone 异常中断时兜底删除。
	getRespStream(ctx).keys = append(getRespStream(ctx).keys, nonceHex)

	cipherVecs, err := maskVectors(seed, config.MaskModulus, vectors)
	if err != nil {
		return failClosed(log, fmt.Sprintf("加密失败: %v", err))
	}
	cipherBody, err := encodeCipherRequest(&cipherRequest{
		CipherVectors: cipherVecs,
		Nonce:         nonceHex,
		Model:         config.Model,
	})
	if err != nil {
		return failClosed(log, fmt.Sprintf("密文编码失败: %v", err))
	}
	if err := proxywasm.ReplaceHttpRequestBody(cipherBody); err != nil {
		return failClosed(log, fmt.Sprintf("替换请求体失败: %v", err))
	}
	_ = proxywasm.ReplaceHttpRequestHeader("content-type", "application/json")
	log.Infof("otpmask-plugin: 向量请求加密完成 vectors=%d dim=%d nonce=%s",
		len(vectors), len(vectors[0]), nonceHex[:8])
	return types.HeaderContinue
}

// failClosed TEE 链路不可用时的默认拒绝响应（fail-closed，不降级明文）。
func failClosed(log logs.Log, msg string) types.Action {
	metricFailClosed.incr() // W-1：fail-closed 计数
	log.Errorf("otpmask-plugin: fail-closed 拒绝请求: %s", msg)
	_ = proxywasm.SendHttpResponse(503, [][2]string{{"Content-Type", "text/plain"}},
		[]byte("otpmask: secure inference unavailable"), -1)
	return types.ActionContinue
}

// responseStatus 读取下游响应状态码（":status" 伪头）。
func responseStatus() string {
	st, err := proxywasm.GetHttpResponseHeader(":status")
	if err != nil {
		return ""
	}
	return st
}

// handleTextRequest 文本输入（M5 南向协议链路 + P1b 段① 信封）：
//
//	[quote] 挑战-响应握手 → TEE /key/issue（信封）→ embedding /embed → 加密 →
//	        南向协议请求（签名，整体入信封）→ 替换 body
//	[token] TEE /key/issue（明文 JSON）→ embedding → 加密 → 南向协议请求（明文协议，dev 兼容）
//
// 请求体替换后由 Envoy 路由到 tee-infer-service（路径 A）。
// 任何 TEE 链路失败均 fail-closed（503 拒绝，不透传明文）。
// pendingRequestID 当前处理请求的 ID（onRequestBody 生成；SSE 响应用作 OpenAI chunk id）。
// 与 Session/KeyStore 同为包级状态，按 Envoy wasm 单请求串行回调语义使用。
var pendingRequestID string

// pendingVectorsPlain 请求级标记：向量明文直通（handleVectorsRequest 路径）。
// quote 默认模式下，向量场景（mock JSON 响应、无信封）须绕开 quote 信封解密与 SSE 预置，
// 否则被误判为降级攻击而 fail-closed（展示环境 2.0 兼容，§13）。
var pendingVectorsPlain bool

// requestWantsSSE 请求级标记：客户端 Accept: text/event-stream 时 mock 响应以 SSE 输出（B1）。
var requestWantsSSE bool

// handleTextRequest 文本请求主入口：quote 优先，token 兼容，遇证伪/解密失败一律 fail-closed。
func handleTextRequest(ctx wrapper.HttpContext, config PluginConfig, req *textRequest, log logs.Log) types.Action {
	requestID := newRequestID()
	pendingRequestID = requestID
	pendingVectorsPlain = false

	// quote 模式先确保挑战-响应会话（无有效会话 → 握手 → 完成后走正常流程）
	if config.AttestMode == "quote" {
		if !Session.valid() {
			doAttestHandshake(config, log,
				func(id string, ksig, kenc []byte) {
					// 握手完成 → 落存会话（K_sig + K_enc）→ 走 TEE 签发流程
					Session.set(id, ksig, kenc)
					proceedKeyIssue(ctx, config, req, requestID, log)
				},
				func(msg string) {
					failClosed(log, "quote 握手失败: "+msg)
				})
			return types.ActionPause
		}
		return proceedKeyIssue(ctx, config, req, requestID, log)
	}

	// token 模式（缺省，向后兼容）：第一层 TEE 签发密钥
	proceedKeyIssue(ctx, config, req, requestID, log)
	return types.ActionPause
}

// proceedKeyIssue 第一层：TEE 签发密钥（token 模式带 X-Attest-Token；quote 模式带 X-Session-ID）。
// quote 模式（P1b）：请求体与响应体均整体入 K_enc 信封（段①，AAD 绑定 /key/issue）；
// 200 响应非信封即拒绝（fail-closed，防降级攻击）。
func proceedKeyIssue(ctx wrapper.HttpContext, config PluginConfig, req *textRequest, requestID string, log logs.Log) types.Action {
	keyClient := wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: config.TEEService,
		Port: config.TEEPort,
	})
	keyBody, _ := json.Marshal(map[string]string{"model": config.Model, "request_id": requestID})
	attestHeaders := [][2]string{{"Content-Type", "application/json"}}
	if config.AttestMode == "quote" {
		attestHeaders = [][2]string{
			{"Content-Type", "application/octet-stream"},
			{"X-Session-ID", Session.SessionID},
		}
	} else if token := currentAttestToken(config); token != "" {
		attestHeaders = append(attestHeaders, [2]string{"X-Attest-Token", token})
	}
	// M9-1：密钥签发携带租户标识（TEE 侧按租户隔离主密钥与密钥表）
	if t := tenantHeaderValue(ctx); t != "" {
		attestHeaders = append(attestHeaders, [2]string{"X-Tenant-ID", t})
	}
	postBody := keyBody
	if config.AttestMode == "quote" {
		sealed, err := Session.sealPayload(protocol.EndpointKeyIssue, keyBody)
		if err != nil {
			return failClosed(log, "key/issue 请求加密失败: "+err.Error())
		}
		postBody = sealed
	}
	err := keyClient.Post("/key/issue", attestHeaders, postBody,
		func(statusCode int, _ http.Header, body []byte) {
			if statusCode == http.StatusUnauthorized && config.AttestMode == "quote" {
				// 会话失效（服务端 TTL/重启）→ 清除本地会话（下次请求重握手），本请求 fail-closed
				Session.clear()
				failClosed(log, fmt.Sprintf("TEE 密钥签发失败 %d（会话失效，已触发重握手）", statusCode))
				return
			}
			if statusCode != 200 {
				failClosed(log, fmt.Sprintf("TEE 密钥签发失败 %d", statusCode))
				return
			}
			if config.AttestMode == "quote" {
				pt, err := Session.openPayload(protocol.EndpointKeyIssue, body)
				if err != nil {
					// 信封解不开 = 会话密钥不同步（服务端重启等）→ 清会话，fail-closed
					Session.clear()
					failClosed(log, "key/issue 响应解密失败: "+err.Error())
					return
				}
				body = pt
			}
			parseKeyIssueResponse(ctx, config, req, requestID, body, log)
		}, 5000)
	if err != nil {
		return failClosed(log, fmt.Sprintf("调用 TEE 密钥服务失败: %v", err))
	}
	return types.ActionPause
}

// parseKeyIssueResponse 解析密钥签发响应并进入第二层（token/quote 模式共用）。
func parseKeyIssueResponse(ctx wrapper.HttpContext, config PluginConfig, req *textRequest,
	requestID string, body []byte, log logs.Log) {
	var ki struct {
		Seed            string `json:"seed"`
		Nonce           string `json:"nonce"`
		ProtocolVersion string `json:"protocol_version"`
	}
	if err := json.Unmarshal(body, &ki); err != nil {
		failClosed(log, fmt.Sprintf("解析密钥响应失败: %v", err))
		return
	}
	// C-4b 版本一致性校验：TEE 协议版本不匹配 → fail-closed，
	// 防止 wire 格式不兼容的插件/TEE 混合部署导致静默错乱。
	if ki.ProtocolVersion != "" && ki.ProtocolVersion != protocol.Version {
		failClosed(log, fmt.Sprintf("协议版本不匹配: TEE=%q 插件=%q", ki.ProtocolVersion, protocol.Version))
		return
	}
	seed, err := hex.DecodeString(ki.Seed)
	if err != nil {
		failClosed(log, fmt.Sprintf("seed hex 解码失败: %v", err))
		return
	}
	// 按 requestID 存密钥（响应解密回溯），seed 同时供本层加密
	KeyStore.Store(requestID, seed)
	// P1b 待办3：登记本请求在 KeyStore 的密钥 key，供 onStreamDone 异常中断时兜底删除。
	getRespStream(ctx).keys = append(getRespStream(ctx).keys, requestID)
	finishTextFlow(ctx, config, req, requestID, seed, ki.Nonce, log)
}

// finishTextFlow 第二层：按引擎类型分流——
// text 载荷直通（P2/P5：tee_gpu/cmaas，南向统一 text，D1）或
// 既有 embedding→vectors（未指定/masked_vector，向后兼容，路线 2 保留路径）。
func finishTextFlow(ctx wrapper.HttpContext, config PluginConfig, req *textRequest,
	requestID string, seed []byte, nonceHex string, log logs.Log) {

	if req.EngineType == protocol.EngineTypeTEEGPU || req.EngineType == protocol.EngineTypeCMAAS {
		finishTextDirect(ctx, config, req, requestID, seed, nonceHex, log)
		return
	}
	embClient := wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: config.EmbeddingService,
		Port: config.EmbeddingPort,
	})
	embedBody, _ := json.Marshal(map[string]string{"text": req.Text})
	err := embClient.Post("/embed",
		[][2]string{{"Content-Type", "application/json"}},
		embedBody,
		func(statusCode int, _ http.Header, respBody []byte) {
			defer wipe(seed)
			if statusCode != 200 {
				failClosed(log, fmt.Sprintf("embedding-service 返回 %d", statusCode))
				return
			}
			er, err := parseEmbedResponse(respBody)
			if err != nil {
				failClosed(log, fmt.Sprintf("%v", err))
				return
			}
			cipherVecs, err := maskVectors(seed, config.MaskModulus, er.Vectors)
			if err != nil {
				failClosed(log, fmt.Sprintf("加密失败: %v", err))
				return
			}
			nonce, _ := hex.DecodeString(nonceHex)
			infReq := &protocol.InferenceRequest{
				RequestID:     requestID,
				TimestampNS:   time.Now().UnixNano(),
				Model:         config.Model,
				MaxNewTokens:  32,
				Nonce:         nonce,
				CipherVectors: toProtocolVectors(cipherVecs),
			}
			// M9-4：附加 guardrail 密文文本（域分离掩码流，TEE 内解密检测）
			if ct, err := maskText(seed, req.Text); err != nil {
				failClosed(log, fmt.Sprintf("加密 guardrail 文本失败: %v", err))
				return
			} else {
				infReq.CipherText = ct
			}
			if kSig := requestK_sig(config); kSig != nil {
				protocol.SignRequest(kSig, infReq)
			}
			encBody, err := protocol.EncodeRequest(infReq)
			if err != nil {
				failClosed(log, fmt.Sprintf("编码协议请求失败: %v", err))
				return
			}
			// P1b：quote 模式下南向协议请求整体入 K_enc 信封（段①，AAD 绑定 /v1/infer）
			if config.AttestMode == "quote" {
				sealed, err := Session.sealPayload(protocol.EndpointInfer, encBody)
				if err != nil {
					failClosed(log, "推理请求加密失败: "+err.Error())
					return
				}
				encBody = sealed
			}
			if err := proxywasm.ReplaceHttpRequestBody(encBody); err != nil {
				failClosed(log, fmt.Sprintf("替换请求体失败: %v", err))
				return
			}
			_ = proxywasm.ReplaceHttpRequestHeader("content-type", "application/octet-stream")
			// P1b 修复：quote 模式推理请求须携带 X-Session-ID（此前缺失，
			// 服务端无法按会话校验信封通道，真实链路会 fail-closed 拒绝）
			if config.AttestMode == "quote" {
				_ = proxywasm.ReplaceHttpRequestHeader("X-Session-ID", Session.SessionID)
			}
			log.Infof("otpmask-plugin: 南向协议请求构造完成 text=%d chars tokens=%d dim=%d req=%s",
				len(req.Text), len(er.Tokens), len(er.Vectors[0]), requestID[:8])
			if err := proxywasm.ResumeHttpRequest(); err != nil {
				log.Errorf("otpmask-plugin: ResumeHttpRequest 失败: %v", err)
			}
		}, 5000)
	if err != nil {
		log.Errorf("otpmask-plugin: 调用 embedding-service 失败: %v", err)
		wipe(seed)
		failClosed(log, fmt.Sprintf("调用 embedding-service 失败: %v", err))
	}
}

// finishTextDirect P2/P5：text 载荷直通——南向统一 text（D1，不经 embedding）。
// 仅 quote 模式可用（服务端对无证明会话的 text 载荷 fail-closed 拒绝，防明文降级）；
// 请求为段① K_enc 信封 + X-Session-ID，响应为 SSE 信封流（onResponseBody 解密重组）。
func finishTextDirect(ctx wrapper.HttpContext, config PluginConfig, req *textRequest,
	requestID string, seed []byte, nonceHex string, log logs.Log) {
	defer wipe(seed)
	if config.AttestMode != "quote" {
		failClosed(log, "text 载荷引擎（tee_gpu/cmaas）须 quote 证明会话（token 模式不支持）")
		return
	}
	messages, err := marshalMessages(req)
	if err != nil {
		failClosed(log, err.Error())
		return
	}
	stream := true
	if req.Stream != nil {
		stream = *req.Stream
	}
	nonce, _ := hex.DecodeString(nonceHex)
	infReq := &protocol.InferenceRequest{
		RequestID:    requestID,
		TimestampNS:  time.Now().UnixNano(),
		Model:        config.Model,
		MaxNewTokens: 256,
		Nonce:        nonce,
		EngineType:   req.EngineType,
		AttestType:   protocol.AttestTypeQuote,
		TextPayload:  messages,
		Stream:       stream,
	}
	// M9-4：guardrail 密文文本（域分离掩码流，TEE 内解密检测；C-MaaS 无内容安全，本层补位）
	if ct, err := maskText(seed, req.Text); err != nil {
		failClosed(log, fmt.Sprintf("加密 guardrail 文本失败: %v", err))
		return
	} else {
		infReq.CipherText = ct
	}
	if kSig := requestK_sig(config); kSig != nil {
		protocol.SignRequest(kSig, infReq)
	}
	encBody, err := protocol.EncodeRequest(infReq)
	if err != nil {
		failClosed(log, fmt.Sprintf("编码协议请求失败: %v", err))
		return
	}
	// P1b：quote 模式下南向协议请求整体入 K_enc 信封（段①，AAD 绑定 /v1/infer）
	sealed, err := Session.sealPayload(protocol.EndpointInfer, encBody)
	if err != nil {
		failClosed(log, "推理请求加密失败: "+err.Error())
		return
	}
	if err := proxywasm.ReplaceHttpRequestBody(sealed); err != nil {
		failClosed(log, fmt.Sprintf("替换请求体失败: %v", err))
		return
	}
	_ = proxywasm.ReplaceHttpRequestHeader("content-type", "application/octet-stream")
	_ = proxywasm.ReplaceHttpRequestHeader("X-Session-ID", Session.SessionID)
	log.Infof("otpmask-plugin: text 载荷协议请求构造完成 engine=%s stream=%v req=%s",
		req.EngineType, stream, requestID[:8])
	if err := proxywasm.ResumeHttpRequest(); err != nil {
		log.Errorf("otpmask-plugin: ResumeHttpRequest 失败: %v", err)
	}
}

// respStreamState 请求级响应流式处理状态（跨帧保存于 ctx）。
// dec 非 nil 表示已判定为 SSE 信封流（增量解密）；否则按整包路径累积到 endOfStream。
type respStreamState struct {
	dec    *SSEStreamDecoder // 增量解密状态机（SSE 路径）
	buf    []byte            // 整包路径累积缓冲（JSON/协议/quote 单信封）
	first  bool              // 已见首个非空帧（路径判定仅一次）
	closed bool              // 整流拒绝后闭锁，不再外发任何字节
	keys   []string          // 本请求在 KeyStore 登记的密钥 key（onStreamDone 兜底删除）
}

// ctxKeyRespStream 请求级响应流状态的上下文键。
const ctxKeyRespStream = "otpmask-resp-stream"

// getRespStream 取/建请求级响应流状态。
func getRespStream(ctx wrapper.HttpContext) *respStreamState {
	if v, ok := ctx.GetContext(ctxKeyRespStream).(*respStreamState); ok {
		return v
	}
	v := &respStreamState{}
	ctx.SetContext(ctxKeyRespStream, v)
	return v
}

// looksLikeSSEEnvelope 首个非空帧判定：仅 quote 模式 200 且 body 以 "data:" 行首
// 视为段① SSE 信封流（走增量解密）；其余（mock JSON/协议二进制/quote 单信封）走整包。
// 状态码取 header 阶段缓存（body 阶段伪头 :status 不可读）。
func looksLikeSSEEnvelope(ctx wrapper.HttpContext, config PluginConfig, chunk []byte) bool {
	return config.AttestMode == "quote" && respStatusCached(ctx) == "200" && isSSEBody(chunk)
}

// onStreamingResponseBody 响应侧流式解密外发（P1b，取代整包 onResponseBody）：
//
//	SSE 信封流（quote 200）：SSEStreamDecoder 逐帧增量解密，逐片外发，规避 §4.2 响应整体缓冲限制；
//	                        任一分片解密失败/乱序/重放 → 整流拒绝（闭锁透传，HTTP 表现为流中断）。
//	整包路径（mock JSON/协议/quote 单信封）：缓冲到 endOfStream 一次性处理，与既有 onResponseBody 等价；
//	                        处理失败 → 返回 nil（fail-closed，不外发可疑明文）。
//	非 200 错误体：透传。
func onStreamingResponseBody(ctx wrapper.HttpContext, config PluginConfig, chunk []byte, isLastChunk bool, log logs.Log) []byte {
	st := getRespStream(ctx)
	if st.closed {
		return nil
	}
	// 路径判定：首个非空帧决定增量 vs 整包
	if !st.first && len(chunk) > 0 {
		st.first = true
		if looksLikeSSEEnvelope(ctx, config, chunk) {
			st.dec = NewSSEStreamDecoder(pendingRequestID, config.Model)
			out, err := st.dec.Feed(chunk, isLastChunk)
			if err != nil {
				st.closed = true
				st.dec = nil
				metricDecryptError.incr() // W-1：解密失败计数
				log.Errorf("otpmask-plugin: SSE 流解密失败（整流拒绝）: %v", err)
				return nil
			}
			return out
		}
	}
	if st.dec != nil {
		out, err := st.dec.Feed(chunk, isLastChunk)
		if err != nil {
			st.closed = true
			st.dec = nil
			// 会话密钥不同步（服务端重启等）→ 清会话触发重握手（与单响应分支一致）
			Session.clear()
			metricDecryptError.incr() // W-1：解密失败计数
			log.Errorf("otpmask-plugin: SSE 流解密失败（整流拒绝）: %v", err)
			return nil
		}
		return out
	}
	// 整包路径：累积
	st.buf = append(st.buf, chunk...)
	if !isLastChunk {
		return nil // 未收全，不外发
	}
	plain, passthrough := processOutputBody(ctx, config, st.buf, log)
	st.buf = nil
	if passthrough {
		return plain // 非 200/透传：原样返回（SDK 逐片替换 = 等价透传）
	}
	if plain == nil {
		metricDecryptError.incr() // W-1：解密/流校验失败（整包 fail-closed）
		return nil                // fail-closed：不外发可疑明文
	}
	// 向量请求（handleVectorsRequest）不设置 pendingRequestID，须防御性截断
	rid := pendingRequestID
	if len(rid) > 8 {
		rid = rid[:8]
	}
	log.Infof("otpmask-plugin: 响应解密完成 bytes=%d req=%s", len(plain), rid)
	return plain
}

// onStreamDone 流完成回调（P1b 待办3）。SDK 在 HTTP 流完全结束（成功或异常截断/reset）
// 后、HttpContext 销毁前触发最终收尾。MemKeyStore 无 TTL，本请求登记的请求级密钥只在
// 正常解密路径 Delete；若流被 fail-closed 截断/客户端断连，此处幂等兜底删除，防 seed 残留。
func onStreamDone(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) {
	cleanupRespKeys(getRespStream(ctx))
}

// cleanupRespKeys 幂等兜底删除本请求登记的请求级密钥（供异常中断流收尾）。
func cleanupRespKeys(st *respStreamState) {
	for _, k := range st.keys {
		KeyStore.Delete(k)
	}
	st.keys = nil
}

// processOutputBody 整包响应处理（与既有 onResponseBody 分流等价）。
// 返回 (输出字节, passthrough)。passthrough=true 表示非 200/错误体原样透传；
// false 且输出为 nil 表示 fail-closed（不外发）。
func processOutputBody(ctx wrapper.HttpContext, config PluginConfig, body []byte, log logs.Log) ([]byte, bool) {
	if status := respStatusCached(ctx); status != "" && status != "200" {
		// 非 200 错误体原样透传
		return body, true
	}
	if config.AttestMode == "quote" && !pendingVectorsPlain {
		// quote 单信封：信封解密 → 南向协议响应（走既有验签/解密）。
		// 明文响应拒绝（fail-closed，防降级攻击）；向量明文直通请求（演示链兼容）除外。
		pt, err := Session.openPayload(protocol.EndpointInfer, body)
		if err != nil {
			Session.clear()
			log.Errorf("otpmask-plugin: fail-closed 拒绝响应: 推理响应解密失败（疑似降级攻击）: %v", err)
			return nil, false
		}
		body = pt
	}
	resp, err := protocol.DecodeResponse(body)
	if err != nil {
		// 回退：尝试 mock JSON 密文响应（段①，M2/M3 协议）。
		// 与南向协议互斥：南向协议是非 UTF-8 二进制，mock JSON 必然含 cipher_output+nonce。
		if plain, mockErr := handleMockCipherResponse(config, body, log); mockErr == nil {
			// handleMockCipherResponse 已按 requestWantsSSE 返回 SSE 或 JSON 明文
			return plain, false
		}
		log.Warnf("otpmask-plugin: 非协议/非 mock 响应，透传错误体: %v", err)
		return body, true
	}
	if kSig := requestK_sig(config); kSig != nil && !protocol.VerifyResponse(kSig, resp) {
		log.Errorf("otpmask-plugin: 响应签名无效 req=%s", resp.RequestID[:8])
		return nil, false
	}

	// 按 requestID 回溯请求密钥
	seed, ok := KeyStore.Lookup(resp.RequestID)
	if !ok {
		log.Errorf("otpmask-plugin: 无法回溯 req=%s（密钥已过期或被篡改）", resp.RequestID[:8])
		return nil, false
	}
	defer KeyStore.Delete(resp.RequestID)
	defer wipe(seed)

	plain, err := unmaskVector(seed, config.MaskModulus, resp.CipherOutput.Data)
	if err != nil {
		log.Errorf("otpmask-plugin: 解密失败: %v", err)
		return nil, false
	}
	// G1：解密出多 token ID 序列，组装 SSE 流式响应（token-by-token + [DONE]）
	return buildSSE(plain), false
}

// handleMockCipherResponse 处理 mock JSON 密文响应（段①，M2/M3 协议）：
// {"cipher_output":[...],"nonce":hex} → 按 nonce 回溯 seed → 解密 → 明文 {"output":[...]}。
func handleMockCipherResponse(config PluginConfig, body []byte, log logs.Log) ([]byte, error) {
	cr, err := parseCipherResponse(body)
	if err != nil {
		return nil, err
	}
	seed, ok := KeyStore.Lookup(cr.Nonce)
	if !ok {
		return nil, fmt.Errorf("otpmask: mock 响应无对应请求密钥 nonce=%s", cr.Nonce[:8])
	}
	defer KeyStore.Delete(cr.Nonce)
	defer wipe(seed)
	plain, err := unmaskVector(seed, config.MaskModulus, cr.CipherOutput)
	if err != nil {
		return nil, fmt.Errorf("otpmask: mock 响应解密失败: %w", err)
	}
	plainBody, err := encodePlainResponse(plain, nil, "")
	if err != nil {
		return nil, err
	}
	// B1：客户端 Accept: text/event-stream → 以 OpenAI SSE 形式回传多 token 解密明文
	if requestWantsSSE {
		plainBody = buildSSE(plain)
	}
	log.Infof("otpmask-plugin: mock 密文响应解密完成 tokens=%d nonce=%s sse=%v", len(plain), cr.Nonce[:8], requestWantsSSE)
	return plainBody, nil
}

// buildSSE 组装 SSE 流式响应：每 token 一行 data + [DONE] 结束标记。
func buildSSE(tokens []uint64) []byte {
	var sb strings.Builder
	for _, tid := range tokens {
		sb.WriteString("data: ")
		sb.WriteString(fmt.Sprintf(`{"token":%q}`, string(tokenToRune(tid))))
		sb.WriteString("\n\n")
	}
	sb.WriteString("data: [DONE]\n\n")
	return []byte(sb.String())
}

// toProtocolVectors 转换 [][]uint64 → []protocol.CipherVector。
func toProtocolVectors(vecs [][]uint64) []protocol.CipherVector {
	out := make([]protocol.CipherVector, len(vecs))
	for i, v := range vecs {
		out[i] = protocol.CipherVector{Data: v}
	}
	return out
}

// newRequestID 生成请求 ID（MVP：纳秒时间戳 hex；生产由网关统一分配）。
func newRequestID() string {
	ts := time.Now().UnixNano()
	return hex.EncodeToString([]byte{
		byte(ts >> 56), byte(ts >> 48), byte(ts >> 40), byte(ts >> 32),
		byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts),
	})
}

// tokenToRune 演示词表映射（与 tee-infer-service/model 一致：0-15 → 'a'-'p'）。
func tokenToRune(id uint64) rune {
	if id >= 16 {
		return '?'
	}
	return rune('a' + id)
}

// wipe 清零敏感字节。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
