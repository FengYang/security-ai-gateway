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
	"github.com/higress-group/wasm-go/pkg/wrapper"
	logs "github.com/higress-group/wasm-go/pkg/log"
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
		wrapper.ProcessResponseBodyBy(onResponseBody),
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
	SigKeyHex        string `json:"sig_key"`    // 协议签名密钥 K_sig（32 字节 hex，M5 静态注入；token 模式用）
	AttestToken      string `json:"attest_token"` // 远程证明令牌（模拟凭证）
	AttestMode       string `json:"attest_mode"`  // 远程证明模式 "token"（缺省，MVP 兼容）| "quote"（挑战-响应）
	ExpectedAppHash  string `json:"expected_app_hash"` // quote 模式：期望测量值 app_hash（客户策略，）
	JWTSecretHex     string `json:"jwt_secret"`   // 租户鉴权 JWT 密钥（32 字节 hex，C-6）；空 = 不启用
	RequireAuth      bool   `json:"require_auth"` // true 时无有效 JWT 拒绝 401（C-6）
	ConfigVersion    string `json:"config_version"` // 配置版本标识（C-8 热更新观测；发布方维护）
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
	if config.MaskModulus < 2 {
		config.MaskModulus = defaultMaskModulus
	}
	if config.AttestMode == "" {
		config.AttestMode = "token"
	}
	if config.Model == "" {
		config.Model = "mock"
	}
	if config.EmbeddingService == "" {
		config.EmbeddingService = "embedding_service"
	}
	if config.EmbeddingPort == 0 {
		config.EmbeddingPort = 18080
	}
	if config.TEEService == "" {
		config.TEEService = "tee_infer_service"
	}
	if config.TEEPort == 0 {
		config.TEEPort = 19090
	}
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

// sigKey 解析后的协议签名密钥（K_sig，；token 模式静态注入）。
func (c *PluginConfig) sigKey() []byte {
	if c.SigKeyHex == "" {
		return nil
	}
	k, err := hex.DecodeString(c.SigKeyHex)
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

// onHttpRequestHeaders 请求头阶段：移除 Content-Length → chunked 传输密文；
// 读取并保存租户标识 X-Tenant-ID（M9-1，供 /key/issue 与 TEE 侧按租户隔离）；
// C-6：配置 jwt_secret 时校验 Bearer token，以 tenant claim 覆盖自声明头，
// require_auth=true 时无/无效 token → 401。
func onHttpRequestHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	if err := proxywasm.RemoveHttpRequestHeader("content-length"); err != nil {
		log.Warnf("otpmask-plugin: 移除 content-length 失败: %v", err)
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

// onHttpResponseHeaders 响应头阶段：移除 Content-Length → chunked 返回明文。
func onHttpResponseHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	if err := proxywasm.RemoveHttpResponseHeader("content-length"); err != nil {
		log.Warnf("otpmask-plugin: 移除响应 content-length 失败: %v", err)
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
	log.Errorf("otpmask-plugin: 无法解析请求体（需 text 或 vectors）")
	return types.HeaderStopAllIterationAndBuffer
}

// handleVectorsRequest 向量输入：签发密钥（本地）→ 加密 → 南向协议请求。
// 注：本地签发密钥与 TEE 不共享，仅用于向量输入兼容场景（M2/M3 回归）。
func handleVectorsRequest(ctx wrapper.HttpContext, config PluginConfig, vectors [][]uint64, log logs.Log) types.Action {
	seed, nonceHex, err := KeyStore.Issue()
	if err != nil {
		log.Errorf("otpmask-plugin: 签发密钥失败: %v", err)
		return types.HeaderStopAllIterationAndBuffer
	}
	defer wipe(seed)

	cipherVecs, err := maskVectors(seed, config.MaskModulus, vectors)
	if err != nil {
		log.Errorf("otpmask-plugin: 加密失败: %v", err)
		return types.HeaderStopAllIterationAndBuffer
	}
	cipherBody, err := encodeCipherRequest(&cipherRequest{
		CipherVectors: cipherVecs,
		Nonce:         nonceHex,
		Model:         config.Model,
	})
	if err != nil {
		log.Errorf("otpmask-plugin: %v", err)
		return types.HeaderStopAllIterationAndBuffer
	}
	if err := proxywasm.ReplaceHttpRequestBody(cipherBody); err != nil {
		log.Errorf("otpmask-plugin: 替换请求体失败: %v", err)
		return types.HeaderStopAllIterationAndBuffer
	}
	_ = proxywasm.ReplaceHttpRequestHeader("content-type", "application/json")
	log.Infof("otpmask-plugin: 向量请求加密完成 vectors=%d dim=%d nonce=%s",
		len(vectors), len(vectors[0]), nonceHex[:8])
	return types.HeaderContinue
}

// failClosed TEE 链路不可用时的默认拒绝响应（fail-closed，不降级明文）。
func failClosed(log logs.Log, msg string) types.Action {
	log.Errorf("otpmask-plugin: fail-closed 拒绝请求: %s", msg)
	_ = proxywasm.SendHttpResponse(503, [][2]string{{"Content-Type", "text/plain"}},
		[]byte("otpmask: secure inference unavailable"), -1)
	return types.ActionContinue
}

// handleTextRequest 文本输入（M5 南向协议链路）：
//
//	TEE /key/issue → embedding /embed → 加密 → 南向协议请求（签名）→ 替换 body
//
// 请求体替换为南向协议二进制后，由 Envoy 路由到 tee-infer-service（路径 A）。
// 任何 TEE 链路失败均 fail-closed（503 拒绝，不透传明文）。
func handleTextRequest(ctx wrapper.HttpContext, config PluginConfig, req *textRequest, log logs.Log) types.Action {
	requestID := newRequestID()

	// quote 模式先确保挑战-响应会话（无有效会话 → 握手 → 完成后走正常流程）
	if config.AttestMode == "quote" {
		if !Session.valid() {
			doAttestHandshake(config, log,
				func(_ string, _ []byte) {
					// 握手完成 → 走 TEE 签发流程（会话 K_sig 已缓存）
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
func proceedKeyIssue(ctx wrapper.HttpContext, config PluginConfig, req *textRequest, requestID string, log logs.Log) types.Action {
	keyClient := wrapper.NewClusterClient(wrapper.DnsCluster{
		ServiceName: config.TEEService,
		Port:        config.TEEPort,
	})
	keyBody, _ := json.Marshal(map[string]string{"model": config.Model, "request_id": requestID})
	attestHeaders := [][2]string{{"Content-Type", "application/json"}}
	if config.AttestMode == "quote" {
		attestHeaders = append(attestHeaders, [2]string{"X-Session-ID", Session.SessionID})
	} else if config.AttestToken != "" {
		attestHeaders = append(attestHeaders, [2]string{"X-Attest-Token", config.AttestToken})
	}
	// M9-1：密钥签发携带租户标识（TEE 侧按租户隔离主密钥与密钥表）
	if t := tenantHeaderValue(ctx); t != "" {
		attestHeaders = append(attestHeaders, [2]string{"X-Tenant-ID", t})
	}
	err := keyClient.Post("/key/issue", attestHeaders, keyBody,
		func(statusCode int, _ http.Header, body []byte) {
			if statusCode != 200 {
				failClosed(log, fmt.Sprintf("TEE 密钥签发失败 %d", statusCode))
				return
			}
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
			finishTextFlow(ctx, config, req, requestID, seed, ki.Nonce, log)
		}, 5000)
	if err != nil {
		return failClosed(log, fmt.Sprintf("调用 TEE 密钥服务失败: %v", err))
	}
	return types.ActionPause
}

// finishTextFlow 第二层：embedding → 加密 → 南向协议请求替换。
func finishTextFlow(ctx wrapper.HttpContext, config PluginConfig, req *textRequest,
	requestID string, seed []byte, nonceHex string, log logs.Log) {

	embClient := wrapper.NewClusterClient(wrapper.DnsCluster{
		ServiceName: config.EmbeddingService,
		Port:        config.EmbeddingPort,
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
			if err := proxywasm.ReplaceHttpRequestBody(encBody); err != nil {
				failClosed(log, fmt.Sprintf("替换请求体失败: %v", err))
				return
			}
			_ = proxywasm.ReplaceHttpRequestHeader("content-type", "application/octet-stream")
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

// onResponseBody 响应侧解密：南向协议二进制响应 → 验签 → 解密 → 明文 JSON。
func onResponseBody(ctx wrapper.HttpContext, config PluginConfig, body []byte, log logs.Log) types.Action {
	resp, err := protocol.DecodeResponse(body)
	if err != nil {
		// 非协议响应：TEE 已拒绝（403 guardrail / 400 协议错误），错误文本原样透传。
		log.Warnf("otpmask-plugin: 非协议响应，透传错误体: %v", err)
		return types.HeaderContinue
	}
	if kSig := requestK_sig(config); kSig != nil && !protocol.VerifyResponse(kSig, resp) {
		log.Errorf("otpmask-plugin: 响应签名无效 req=%s", resp.RequestID[:8])
		return types.HeaderStopAllIterationAndBuffer
	}

	// 按 requestID 回溯请求密钥
	seed, ok := KeyStore.Lookup(resp.RequestID)
	if !ok {
		log.Errorf("otpmask-plugin: 无法回溯 req=%s（密钥已过期或被篡改）", resp.RequestID[:8])
		return types.HeaderStopAllIterationAndBuffer
	}
	defer KeyStore.Delete(resp.RequestID)
	defer wipe(seed)

	plain, err := unmaskVector(seed, config.MaskModulus, resp.CipherOutput.Data)
	if err != nil {
		log.Errorf("otpmask-plugin: 解密失败: %v", err)
		return types.HeaderStopAllIterationAndBuffer
	}
	// G1：解密出多 token ID 序列，组装 SSE 流式响应（token-by-token + [DONE]）
	plainBody := buildSSE(plain)
	if err := proxywasm.ReplaceHttpResponseBody(plainBody); err != nil {
		log.Errorf("otpmask-plugin: 替换响应体失败: %v", err)
		return types.HeaderStopAllIterationAndBuffer
	}
	_ = proxywasm.ReplaceHttpResponseHeader("content-type", "text/event-stream")
	log.Infof("otpmask-plugin: 响应解密完成 tokens=%d req=%s", len(plain), resp.RequestID[:8])
	return types.HeaderContinue
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
