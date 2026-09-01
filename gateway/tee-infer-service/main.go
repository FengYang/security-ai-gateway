// tee-infer-service: TEE 飞地推理服务
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/tee-infer-service/model"
	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/internal/memzero"
	"security-ai-gateway/protocol/go"
)

// maskModulus 掩码模 R（与 otpmask-plugin 对齐 2^32）。
const maskModulus uint64 = 1 << 32

// seenTTL 防重放集合的 TTL（秒）：超过此时间的 request_id 被清理。
const seenTTL = 60

// seenCleanupInterval 防重放集合清理间隔。
const seenCleanupInterval = 30 * time.Second

// adminHeader 管理端点认证请求头。
const adminHeader = "X-Admin-Token"

// attestHeader 远程证明令牌请求头。
const attestHeader = "X-Attest-Token"

// unmaskVector 解密向量（与 otpmask-plugin 同 seed 同顺序对称）。
func unmaskVector(seed []byte, r uint64, vec []uint64) ([]uint64, error) {
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(vec))
	for i, c := range vec {
		m := s.Next()
		out[i] = (c + r - m%r) % r
	}
	return out, nil
}

// maskVector 加密向量。
func maskVector(seed []byte, r uint64, vec []uint64) ([]uint64, error) {
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(vec))
	for i, x := range vec {
		m := s.Next()
		out[i] = (x + m) % r
	}
	return out, nil
}

// guardrailTextDomain 文本密文通道域分离标签（与 otpmask-plugin 一致）。
var guardrailTextDomain = []byte("otpmask/guardrail-text/v1")

// unmaskText 解密 guardrail 文本（OTP-Mask 逐字节，R=256，域分离派生流）。
func unmaskText(seed []byte, ct []byte) (string, error) {
	s, err := mask.NewStreamDomain(seed, 256, guardrailTextDomain)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(ct))
	for i, c := range ct {
		m := s.Next() % 256
		out[i] = byte((int(c) + 256 - int(m)) % 256)
	}
	return string(out), nil
}

// toFloat 明文向量 → 浮点（模拟量化反量化：值域缩放，演示精度无损）。
func toFloat(v []uint64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = float64(x) / 1e6 // 缩放避免浮点精度抖动（演示模型）
	}
	return out
}

// keyIssueRequest 密钥签发请求（携带 request_id 用于派生，）。
type keyIssueRequest struct {
	Model     string `json:"model"`
	RequestID string `json:"request_id"`
}

// keyIssueResponse 密钥签发响应（seed 经"加密通道"下发，MVP 简化为 JSON 明文，
// 生产将使用 会话密钥加密）。
type keyIssueResponse struct {
	Seed  string `json:"seed"`
	Nonce string `json:"nonce"`
	// MasterID 主密钥版本（审计/轮换观测）。
	MasterID uint64 `json:"master_id"`
	// ProtocolVersion 南向协议版本。
	ProtocolVersion string `json:"protocol_version"`
}

type teeServer struct {
	km            *teecore.KeyManager            // 默认租户（向后兼容）
	tenants       map[string]*teecore.KeyManager // 租户 → 独立 KeyManager（M9 隔离）
	kSig          []byte
	attest        string             // 远程证明共享令牌（MVP）
	enclave       Enclave            // 飞地抽象
	requireAttest bool               // 强制证明模式
	adminToken    string             // 管理端点（/metrics /audit）认证令牌
	model         model.Engine       // 明文域推理引擎
	cmaasEngine   *model.CmaasEngine // 百炼 C-MaaS 引擎（P5；nil = 未配置，请求 fail-closed）
	protoVersion  string             // 南向协议版本声明（C-4：默认 protocol.Version，部署/测试可覆盖）
	// P2a：PII 处理模式（block = 拦截（默认，fail-closed）/ mask = 脱敏替换后放行）；
	// SQL 注入/提示注入在任何模式下均拦截。
	piiMode         string
	systemPrompt    string                  // 提示词装饰：非空时插入 system 消息（记录于 transformed_hash）
	usage           map[string]*usageRecord // 租户用量
	quota           map[string]int64        // 租户 token 配额上限（累计输入+输出；<=0 = 不限，P1）
	quotaDefault    int64                   // 未单独配置租户的默认配额（<=0 = 不限）
	audit           *auditChain             // 审计哈希链
	guard           *guardrail              // 内容安全检测（M9-4）
	metrics         *otpmaskMetrics         // Prometheus 指标
	seen            map[string]bool
	seenAt          map[string]int64       // request_id -> 首见时间戳（TTL 清理用）
	sessions        map[string]*teeSession // 挑战-响应会话（session_id -> 会话）
	recomputeStates *recomputeStates       // 补算层序状态机（会话级）
	weightProvider  LayerWeightProvider    // 层权重提供器（掩码像计算）
	route           *RouteConfig           // 双路线路由配置
	tokenizer       Tokenizer              // 计量口径（nil = 字符/4 估算；GF.2.4 真机 tokenizer 接入点）
	mu              sync.Mutex
}

// usageRecord 租户用量计量（token 级）。
type usageRecord struct {
	TokensIn  int `json:"tokens_in"`
	TokensOut int `json:"tokens_out"`
	Requests  int `json:"requests"`
	Denies    int `json:"denies"`
}

// tenantHeader 租户标识请求头。
const tenantHeader = "X-Tenant-ID"

// defaultTenant 未指定租户时的默认租户（向后兼容）。
const defaultTenant = "default"

// kmFor 返回租户对应的 KeyManager（懒创建，密钥按租户物理隔离）。
func (s *teeServer) kmFor(tenant string) *teecore.KeyManager {
	if tenant == "" {
		tenant = defaultTenant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if km, ok := s.tenants[tenant]; ok {
		return km
	}
	km, err := teecore.NewKeyManager(0)
	if err != nil {
		// 懒创建失败几乎不可能（仅随机数），fail-closed 返回 nil（上层拒绝请求）
		return nil
	}
	s.tenants[tenant] = km
	return km
}

// recordUsage 累加租户用量。
func (s *teeServer) recordUsage(tenant string, tokensIn, tokensOut int, denied bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.usage[tenant]
	if rec == nil {
		rec = &usageRecord{}
		s.usage[tenant] = rec
	}
	rec.TokensIn += tokensIn
	rec.TokensOut += tokensOut
	if denied {
		rec.Denies++
	} else {
		rec.Requests++
	}
}

// ---------- P1：token 配额管控 ----------

// reserveQuota 预占式配额检查（原子）：在 s.mu 内完成"检查 + 占位"，杜绝并发超卖。
// 占位计入 usage.TokensIn（输入侧控制，计费计量不丢）；推理成功后 recordUsage 只补记输出。
// 配额 <=0 = 不限（仍占位累计 TokensIn，仅跳过上限检查）；
// 失败路径（engine_error 等）占位不回收——保守方向（异常/攻击流量占用配额），审计 deny 可查。
// 输出侧配额控制为扩展项（流式输出无法预知）。
func (s *teeServer) reserveQuota(tenant string, tokensIn int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	max := s.quotaDefault
	if q, ok := s.quota[tenant]; ok {
		max = q
	}
	used := int64(0)
	if rec := s.usage[tenant]; rec != nil {
		used = int64(rec.TokensIn) + int64(rec.TokensOut)
	}
	if max > 0 && used+tokensIn > max {
		return false
	}
	rec := s.usage[tenant]
	if rec == nil {
		rec = &usageRecord{}
		s.usage[tenant] = rec
	}
	rec.TokensIn += int(tokensIn) // 预占（无限额时同样累计计量）
	return true
}

// quotaOf 读取租户配额上限（展示用）。
func (s *teeServer) quotaOf(tenant string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q, ok := s.quota[tenant]; ok {
		return q
	}
	return s.quotaDefault
}

// tenantOf 读取请求租户（空则默认）。
func tenantOf(r *http.Request) string {
	t := r.Header.Get(tenantHeader)
	if t == "" {
		return defaultTenant
	}
	return t
}

// checkAttest 校验远程证明令牌（模拟模式；TDX Quote 验证待硬件接入）。
func (s *teeServer) checkAttest(r *http.Request) bool {
	token := r.Header.Get(attestHeader)
	if token == "" || s.attest == "" {
		return false
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(s.attest))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// checkAdmin 校验管理端点令牌（/metrics /audit /usage）。
func (s *teeServer) checkAdmin(r *http.Request) bool {
	if s.adminToken == "" {
		return true // 未配置管理令牌时不拦截（开发/测试模式）
	}
	token := r.Header.Get(adminHeader)
	if token == "" {
		return false
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(s.adminToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// seenCleanup 定期清理过期的防重放 request_id（TTL = seenTTL 秒）。
func (s *teeServer) seenCleanup() {
	ticker := time.NewTicker(seenCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		s.mu.Lock()
		for id, ts := range s.seenAt {
			if now-ts > seenTTL {
				delete(s.seen, id)
				delete(s.seenAt, id)
			}
		}
		s.mu.Unlock()
	}
}

// attestChallenge 挑战-响应请求。
type attestChallenge struct {
	Nonce string `json:"nonce"` // 客户挑战（hex，32 字节随机）
}

// attestCompleteRequest complete 请求。
type attestCompleteRequest struct {
	SessionID string `json:"session_id"`
	ClientPub string `json:"client_pub"` // 客户端 ECDH 公钥（hex）
}

// handleAttest 远程证明挑战-响应：
// 1. 接收客户挑战 nonce → 2. 飞地生成证明载荷 → 3. 返回 proof + 服务端 ECDH 公钥 + 会话 ID。
// 向后兼容：旧协议（无 body / token 模式）仍返回 MVP 握手确认。
func (s *teeServer) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 读取挑战（可为空 body = 旧版握手）
	var chal attestChallenge
	body, _ := io.ReadAll(r.Body)
	if len(bytesTrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &chal); err != nil {
			http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
			return
		}
	}
	nonce := make([]byte, 32)
	if chal.Nonce != "" {
		n, err := hex.DecodeString(chal.Nonce)
		if err != nil || len(n) != 32 {
			http.Error(w, "nonce 须为 32 字节 hex", http.StatusBadRequest)
			return
		}
		nonce = n
	} else {
		// 旧版握手：服务端生成挑战（等价 nonce，客户可忽略）
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, "生成 nonce 失败", http.StatusInternalServerError)
			return
		}
	}

	// 先创建会话（服务端临时 ECDH 密钥对），再生成证明——
	// report_data = H(nonce ‖ server_pub) 绑定握手公钥（P1b，RA-TLS 标准做法，
	// 防中间人替换握手公钥劫持加密通道）
	sess, err := newSession(nonce)
	if err != nil {
		http.Error(w, fmt.Sprintf("创建会话失败: %v", err), http.StatusInternalServerError)
		return
	}
	reportData := reportDataBinding(nonce, sess.ServerPub())
	proof, err := s.enclave.Attest(nonce, reportData)
	if err != nil {
		http.Error(w, fmt.Sprintf("生成证明失败: %v", err), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":           "attested",
		"protocol":         "challenge-response",
		"attest_type":      protocol.AttestTypeQuote,
		"protocol_version": s.protoVersion,
		"session_id":       sess.ID,
		"proof":            proof,
		"server_pub":       hex.EncodeToString(sess.ServerPub()),
		"session_ttl":      int(sessionTTL.Seconds()),
	})
	log.Printf("[tee] attestation 挑战-响应完成 session=%s platform=%s", sess.ID[:8], proof.Platform)
}

// handleAttestComplete 远程证明 complete：
// 客户端 ECDH 公钥到达 → ECDH + HKDF 派生会话密钥（K_sig/K_enc）。
func (s *teeServer) handleAttestComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req attestCompleteRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("读取请求失败: %v", err), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	clientPub, err := hex.DecodeString(req.ClientPub)
	if err != nil {
		http.Error(w, "client_pub 须为 hex", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "会话不存在或已过期", http.StatusUnauthorized)
		return
	}
	if err := sess.Complete(clientPub); err != nil {
		http.Error(w, fmt.Sprintf("会话密钥派生失败: %v", err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"session_id":  sess.ID,
		"session_ttl": int(sessionTTL.Seconds()),
	})
	log.Printf("[tee] attestation complete session=%s（K_sig/K_enc 已派生）", sess.ID[:8])
}

// sessionK_sig 按请求会话取签名密钥：X-Session-ID 命中 → 会话 K_sig；否则全局 K_sig（MVP 兼容）。
func (s *teeServer) sessionK_sig(r *http.Request) []byte {
	if sess := s.sessionByID(r); sess != nil {
		return sess.K_sig
	}
	return s.kSig
}

// sessionAttested 请求是否携带有效（已完成、未过期）会话。
func (s *teeServer) sessionAttested(r *http.Request) bool {
	return s.sessionByID(r) != nil
}

// sessionByID 按 X-Session-ID 返回有效会话（nil = 无）。
func (s *teeServer) sessionByID(r *http.Request) *teeSession {
	id := r.Header.Get("X-Session-ID")
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || !sess.Completed || time.Since(sess.CreatedAt) > sessionTTL {
		return nil
	}
	return sess
}

// sessionCleanup 定期清理过期/未完成会话（TTL = sessionTTL）。
// P1c：清理时零化会话密钥（K_sig/K_enc 用后零化，best-effort）。
func (s *teeServer) sessionCleanup() {
	ticker := time.NewTicker(seenCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, sess := range s.sessions {
			if !sess.Completed || now.Sub(sess.CreatedAt) > sessionTTL {
				sess.destroy() // 会话密钥零化（best-effort，威胁模型如实声明）
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// bytesTrimSpace 去除首尾空白（io.ReadAll 后判断空 body）。
func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

// sessionPlaintextDev 会话明文兼容开关（仅 dev 调试；生产必须关闭）。
// OTPMASK_SESSION_PLAINTEXT=dev 时，有效会话下的明文载荷不拒绝（降级放行，审计可观测）。
func sessionPlaintextDev() bool {
	return os.Getenv("OTPMASK_SESSION_PLAINTEXT") == "dev"
}

func (s *teeServer) handleKeyIssue(w http.ResponseWriter, r *http.Request) {
	// 会话模式（X-Session-ID 有效会话）或 MVP token 模式，二选一通过
	sess := s.sessionByID(r)
	if sess == nil && !s.checkAttest(r) {
		http.Error(w, "远程证明失败：无效的 attestation 令牌", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("读取请求失败: %v", err), http.StatusBadRequest)
		return
	}
	payloadSHA := sha256hex(body) // 审计记录原始 wire 哈希（token=明文 / quote=密文）
	// P1c 解密入口：会话建立后请求须为 c2s 信封（fail-closed，防降级攻击）
	if sess != nil {
		pt, oerr := sess.openPayload(protocol.EndpointKeyIssue, body)
		if oerr != nil {
			if !sessionPlaintextDev() {
				s.denyAndAudit(tenantOf(r), "", "keyissue_envelope_error", payloadSHA)
				http.Error(w, "会话请求须为加密信封（fail-closed）", http.StatusBadRequest)
				return
			}
			pt = body // dev 兼容：明文放行（仅调试，生产禁用）
		}
		body = pt
	}
	var req keyIssueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	if req.RequestID == "" || req.Model == "" {
		http.Error(w, "request_id/model 必填", http.StatusBadRequest)
		return
	}
	// M9-1：密钥按租户物理隔离（独立 KeyManager -> 独立主密钥与密钥表）
	tenant := tenantOf(r)
	km := s.kmFor(tenant)
	if km == nil {
		http.Error(w, "密钥管理初始化失败（fail-closed）", http.StatusInternalServerError)
		return
	}
	seed, nonceHex, err := km.Issue(req.RequestID, req.Model)
	if err != nil {
		http.Error(w, fmt.Sprintf("签发密钥失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer wipe(seed)
	log.Printf("[tee] 密钥签发 tenant=%s req=%s master=%d", tenant, req.RequestID[:8], km.MasterID())
	// M9-3：审计
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: req.RequestID, Action: "key_issue",
		Result: "ok", PayloadSHA: payloadSHA,
	})
	// M10：指标
	s.metrics.incKeyIssue(tenant)
	respJSON, err := json.Marshal(keyIssueResponse{
		Seed: hex.EncodeToString(seed), Nonce: nonceHex, MasterID: km.MasterID(),
		ProtocolVersion: s.protoVersion,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("编码响应失败: %v", err), http.StatusInternalServerError)
		return
	}
	// P1c 加密出口：会话模式下响应整体入 s2c 信封
	if sess != nil {
		sealed, serr := sess.sealPayload(protocol.EndpointKeyIssue, respJSON)
		if serr != nil {
			s.denyAndAudit(tenant, req.RequestID, "keyissue_seal_error", payloadSHA)
			http.Error(w, "响应加密失败（fail-closed）", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(sealed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respJSON)
}

func (s *teeServer) handleInfer(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("读取请求失败: %v", err), http.StatusBadRequest)
		return
	}
	tenant := tenantOf(r)
	payloadSHA := sha256hex(body) // 审计记录原始 wire 哈希（token=明文 / quote=密文）
	// P1c 解密入口：有效会话（quote 模式）下请求须为 c2s 信封（fail-closed，防降级攻击）
	sess := s.sessionByID(r)
	if sess != nil {
		pt, oerr := sess.openPayload(protocol.EndpointInfer, body)
		if oerr != nil {
			if !sessionPlaintextDev() {
				s.denyAndAudit(tenant, "", "envelope_error", payloadSHA)
				http.Error(w, "推理请求须为加密信封（fail-closed）", http.StatusBadRequest)
				return
			}
			pt = body // dev 兼容：明文放行（仅调试，生产禁用）
		}
		body = pt
	}
	req, err := protocol.DecodeRequest(body)
	if err != nil {
		s.denyAndAudit(tenant, "", "decode_error", payloadSHA)
		http.Error(w, fmt.Sprintf("协议解码失败: %v", err), http.StatusBadRequest)
		return
	}

	// 验签
	if !protocol.VerifyRequest(s.sessionK_sig(r), req) {
		s.denyAndAudit(tenant, req.RequestID, "bad_signature", payloadSHA)
		http.Error(w, "签名无效", http.StatusUnauthorized)
		return
	}
	// 防重放
	s.mu.Lock()
	replayErr := protocol.CheckReplay(req.RequestID, req.TimestampNS, time.Now().UnixNano(), s.seen)
	if replayErr == nil {
		s.seenAt[req.RequestID] = time.Now().Unix() // 记录首见时间（TTL 清理用）
	}
	s.mu.Unlock()
	if replayErr != nil {
		s.denyAndAudit(tenant, req.RequestID, "replay", payloadSHA)
		http.Error(w, replayErr.Error(), http.StatusBadRequest)
		return
	}

	// 双路线路由校验
	if err := s.route.ValidateRequest(tenant, req.Model, req.EngineType, req.AttestType); err != nil {
		s.denyAndAudit(tenant, req.RequestID, "route_rejected", payloadSHA)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// token 模式流量告警（attest_type=token 计入指标，生产误用可观测）
	if req.AttestType == protocol.AttestTypeToken || req.AttestType == "" {
		s.metrics.incAttestTokenTraffic(tenant)
	}

	// P2/P5（D1）：text 载荷路径——南向统一 text（tee_gpu 流式 / cmaas SDK 通道），
	// 与 vectors 路径（路线 2 保留）在此分流。
	if len(req.TextPayload) > 0 {
		s.handleTextInfer(w, sess, tenant, req, payloadSHA)
		return
	}

	// M9-1：按租户取密钥（租户隔离；无签发记录 -> 拒绝）
	km := s.kmFor(tenant)
	if km == nil {
		s.denyAndAudit(tenant, req.RequestID, "keymgr_unavailable", payloadSHA)
		http.Error(w, "密钥管理初始化失败（fail-closed）", http.StatusInternalServerError)
		return
	}
	seed, ok := km.Lookup(hex.EncodeToString(req.Nonce))
	if !ok {
		s.denyAndAudit(tenant, req.RequestID, "unknown_nonce", payloadSHA)
		http.Error(w, "nonce 未知（密钥未签发或已过期）", http.StatusBadRequest)
		return
	}
	defer wipe(seed)

	// M9-4：内容安全 Guardrail（TEE 内解密明文检测，命中即拒绝推理，fail-closed）
	if len(req.CipherText) > 0 {
		text, err := unmaskText(seed, req.CipherText)
		if err != nil {
			s.denyAndAudit(tenant, req.RequestID, "guardrail_decrypt_error", payloadSHA)
			http.Error(w, "guardrail 文本解密失败", http.StatusBadRequest)
			return
		}
		if hit := s.guard.check(text); hit != nil {
			s.denyAndAudit(tenant, req.RequestID, "guardrail_"+hit.Category, payloadSHA)
			log.Printf("[tee] guardrail 拦截 tenant=%s req=%s category=%s match=%q",
				tenant, req.RequestID, hit.Category, hit.Match)
			http.Error(w, fmt.Sprintf("内容安全拦截（%s）", hit.Category), http.StatusForbidden)
			return
		}
	}

	// P1：配额预占（输入 token 数，超限 429 fail-closed；原子占位防并发超卖）
	if !s.reserveQuota(tenant, int64(len(req.CipherVectors))) {
		s.denyAndAudit(tenant, req.RequestID, "quota_exceeded", payloadSHA)
		log.Printf("[tee] 配额超限拒绝 tenant=%s req=%s tokens_in=%d", tenant, req.RequestID, len(req.CipherVectors))
		http.Error(w, "租户 token 配额超限（429）", http.StatusTooManyRequests)
		return
	}

	// 解密（飞地内明文）→ 模型推理：对每个输入向量采样一个 token（自回归 M8）
	tokens := make([]uint64, 0, len(req.CipherVectors))
	for _, cv := range req.CipherVectors {
		plain, err := unmaskVector(seed, maskModulus, cv.Data)
		if err != nil {
			s.denyAndAudit(tenant, req.RequestID, "decrypt_error", payloadSHA)
			http.Error(w, fmt.Sprintf("解密失败: %v", err), http.StatusBadRequest)
			return
		}
		tokenID := s.model.Predict(toFloat(plain))
		if tokenID < 0 {
			s.denyAndAudit(tenant, req.RequestID, "engine_unavailable", payloadSHA)
			http.Error(w, "推理引擎不可用（fail-closed）", http.StatusServiceUnavailable)
			return
		}
		tokens = append(tokens, uint64(tokenID))
	}
	log.Printf("[tee] infer tenant=%s request=%s vectors=%d -> %d tokens %v master=%d",
		tenant, req.RequestID, len(req.CipherVectors), len(tokens), tokens, km.MasterID())

	// 加密输出（同 seed）：token ID 序列密文（方案 C：TEE 内采样后加密回传）
	cipherOut, err := maskVector(seed, maskModulus, tokens)
	if err != nil {
		s.denyAndAudit(tenant, req.RequestID, "encrypt_error", payloadSHA)
		http.Error(w, fmt.Sprintf("加密失败: %v", err), http.StatusInternalServerError)
		return
	}

	resp := &protocol.InferenceResponse{
		RequestID:       req.RequestID,
		TimestampNS:     time.Now().UnixNano(),
		Status:          protocol.StatusOK,
		CipherOutput:    protocol.CipherVector{Data: cipherOut},
		TokensGenerated: 1, // M7：单 token 采样（自回归生成 M8）
	}
	protocol.SignResponse(s.sessionK_sig(r), resp)
	enc, err := protocol.EncodeResponse(resp)
	if err != nil {
		s.denyAndAudit(tenant, req.RequestID, "encode_error", payloadSHA)
		http.Error(w, fmt.Sprintf("编码响应失败: %v", err), http.StatusInternalServerError)
		return
	}
	// M9-2/M9-3：用量计量（token 级；输入已在配额预占计入，仅补记输出）+ 审计
	s.recordUsage(tenant, 0, len(tokens), false)
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: req.RequestID, Action: "infer",
		TokensIn: len(req.CipherVectors), TokensOut: len(tokens),
		Result: "ok", PayloadSHA: payloadSHA,
	})
	// M10：指标
	s.metrics.incRequest(tenant, "ok")
	s.metrics.addTokens(tenant, int64(len(req.CipherVectors)), int64(len(tokens)))
	// 自定义 media type：避免 Envoy wasm wrapper 对 octet-stream 的二进制 body 跳过处理
	// P1c 加密出口：会话模式下协议响应整体入 s2c 信封
	if sess != nil {
		sealed, serr := sess.sealPayload(protocol.EndpointInfer, enc)
		if serr != nil {
			s.denyAndAudit(tenant, req.RequestID, "envelope_seal_error", payloadSHA)
			http.Error(w, "响应加密失败（fail-closed）", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(sealed)
		return
	}
	w.Header().Set("Content-Type", "application/x-otpmask")
	_, _ = w.Write(enc)
}

// ---------- P2/P5：text 载荷推理路径（D1：南向统一 text） ----------

// textStreamChunk 信封内明文分片（与 otpmask-plugin envelope.go 的 streamChunk 一致）。
type textStreamChunk struct {
	Seq    uint64 `json:"seq"`              // 流内序号（1 起严格递增）
	Delta  string `json:"delta"`            // 增量文本
	Finish string `json:"finish,omitempty"` // ""=继续 / "stop"=正常结束 / "error"=引擎失败
}

// engineFor 按引擎类型返回推理引擎（text 路径）。
func (s *teeServer) engineFor(engineType string) (model.Engine, error) {
	switch engineType {
	case "", protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector:
		return s.model, nil // tee_gpu（vLLM 直连/本地演示）；masked_vector 下 text 为演示语义
	case protocol.EngineTypeCMAAS:
		if s.cmaasEngine == nil {
			return nil, errors.New("cmaas 引擎未配置（-cmaas-url，fail-closed）")
		}
		return s.cmaasEngine, nil
	default:
		return nil, fmt.Errorf("未知引擎类型 %q", engineType)
	}
}

// resolveEngineWithFailover 解析 text 路径的推理引擎（GF.3.3 / D-6）。
//
// 语义（保护 fail-closed 与租户显式选择）：
//   - preferred 非空（请求显式指定，已由 ValidateRequest 校验 ∈ 租户允许集）→ **fail-closed**：
//     引擎不可用直接返回 error，绝不静默降级到其他引擎（避免把敏感明文改道到租户未选引擎）；
//   - preferred 为空（仅当 route.Policy 配置了成本路由时进入）→ 自动择优：按成本排序的
//     候选列表顺序 failover（engineFor 失败才切下一个，流式开始后不切换，避免半截明文）。
func (s *teeServer) resolveEngineWithFailover(tenant, modelName, preferred string) (string, model.Engine, error) {
	allowed, _, err := s.route.Resolve(tenant, modelName)
	if err != nil {
		return "", nil, err
	}
	if preferred != "" {
		eng, err := s.engineFor(preferred)
		if err != nil {
			return "", nil, err
		}
		return preferred, eng, nil
	}
	ordered := s.route.orderEngines(allowed, modelName)
	var lastErr error
	for _, et := range ordered {
		eng, err := s.engineFor(et)
		if err != nil {
			lastErr = err
			log.Printf("[tee] 引擎 failover 跳过 tenant=%s model=%s engine=%s: %v", tenant, modelName, et, err)
			continue
		}
		return et, eng, nil
	}
	if lastErr == nil {
		lastErr = errors.New("无可用推理引擎（fail-closed）")
	}
	return "", nil, lastErr
}

// estimateTokens token 粗略估算（字符数/4，演示计量口径；生产接 tokenizer）。
// 计量口径已抽为 Tokenizer 接口（tokenizer.go，GF.2.4），本函数为默认估算实现。
func estimateTokens(text string) int {
	return (len(text) + 3) / 4
}

// handleTextInfer text 载荷推理：信封内明文 messages → Guardrail → 引擎流式生成 →
// SSE 逐块 s2c 信封（Stream=true）或单信封聚合响应（Stream=false）。
// fail-closed：text 载荷仅限证明会话信封通道（token 模式无信封，拒绝）。
func (s *teeServer) handleTextInfer(w http.ResponseWriter, sess *teeSession,
	tenant string, req *protocol.InferenceRequest, payloadSHA string) {
	if sess == nil {
		s.denyAndAudit(tenant, req.RequestID, "text_without_session", payloadSHA)
		http.Error(w, "text 载荷须在证明会话信封内（fail-closed）", http.StatusBadRequest)
		return
	}
	var msgs []model.ChatMessage
	if err := json.Unmarshal(req.TextPayload, &msgs); err != nil || len(msgs) == 0 {
		s.denyAndAudit(tenant, req.RequestID, "text_payload_invalid", payloadSHA)
		http.Error(w, "text 载荷无效（须为非空 messages JSON）", http.StatusBadRequest)
		return
	}
	// M9-4 Guardrail：明文检测（C-MaaS 官方明示不提供内容安全，本网关补位）。
	// P2a：pii-mode=mask 时 PII 脱敏替换后放行（数据保护类）；SQL 注入/提示注入
	// 在任何模式下均拦截（攻击类，fail-closed）。
	inputText := strings.Builder{}
	for i := range msgs {
		if hit := s.guard.check(msgs[i].Content); hit != nil {
			if hit.Category == "pii" && s.piiMode == "mask" {
				masked, n := s.guard.maskPII(msgs[i].Content)
				if n > 0 {
					msgs[i].Content = masked
					log.Printf("[tee] PII 脱敏（text）tenant=%s req=%s hits=%d", tenant, req.RequestID, n)
					inputText.WriteString(masked)
					continue
				}
			}
			s.denyAndAudit(tenant, req.RequestID, "guardrail_"+hit.Category, payloadSHA)
			log.Printf("[tee] guardrail 拦截（text）tenant=%s req=%s category=%s",
				tenant, req.RequestID, hit.Category)
			http.Error(w, fmt.Sprintf("内容安全拦截（%s）", hit.Category), http.StatusForbidden)
			return
		}
		inputText.WriteString(msgs[i].Content)
	}
	// P2a：提示词装饰——非空 system-prompt 时在 messages 头部插入 system 消息。
	// 系统提示词为平台信任内容，不过 Guardrail；装饰结果计入 transformed_hash。
	if s.systemPrompt != "" {
		msgs = append([]model.ChatMessage{{Role: "system", Content: s.systemPrompt}}, msgs...)
	}
	// P2a：transformed_hash = 引擎实收内容（装饰+脱敏后）哈希，供双 hash 审计回溯。
	var txHash string
	{
		var sb strings.Builder
		for _, m := range msgs {
			sb.WriteString(m.Content)
		}
		txHash = sha256hex([]byte(sb.String()))
	}
	// P1：配额预占（输入 token，超限 429 fail-closed；原子占位防并发超卖。
	// 计量口径为估算（字符/4），生产须接入真机 tokenizer，见 GA-AI网关能力补齐方案 D-3）
	if !s.reserveQuota(tenant, int64(s.countTokens(inputText.String()))) {
		s.denyAndAudit(tenant, req.RequestID, "quota_exceeded", payloadSHA)
		log.Printf("[tee] 配额超限拒绝（text）tenant=%s req=%s", tenant, req.RequestID)
		http.Error(w, "租户 token 配额超限（429）", http.StatusTooManyRequests)
		return
	}
	engType := req.EngineType
	if engType == "" {
		// GF.3.3 / D-6：未显式指定引擎时，若配置了成本路由策略（route.Policy）则自动择优
		// （首选 = 成本排序首候选）；否则回退 tee_gpu（既有缺省行为，向后兼容）。
		if s.route.Policy != "" {
			engType = "" // 交由 resolveEngineWithFailover 的成本择优分支选择
		} else {
			engType = protocol.EngineTypeTEEGPU
		}
	}
	// GF.3.3 / D-6：引擎选择带 failover——首选（请求显式指定或成本路由择优）不可用时，
	// 按候选顺序自动切换（engineFor 失败即失败，绝不产出半截明文；流式阶段不切换）。
	engType, eng, err := s.resolveEngineWithFailover(tenant, req.Model, engType)
	if err != nil {
		s.denyAndAudit(tenant, req.RequestID, "engine_unavailable", payloadSHA)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	genReq := model.GenerateRequest{Model: req.Model, Messages: msgs, MaxTokens: req.MaxNewTokens}
	log.Printf("[tee] infer(text) tenant=%s request=%s engine=%s stream=%v msgs=%d",
		tenant, req.RequestID, engType, req.Stream, len(msgs))

	// 统一 SSE 信封流输出（seq 严格递增 + finish 分片）；stream=false 语义为单分片聚合。
	var agg strings.Builder
	if serr := s.streamTextInfer(w, sess, eng, genReq, &agg); serr != nil {
		// 流式失败（200 已发出或写出失败）：审计 deny 后返回（流已以 error 分片终止）
		s.denyAndAudit(tenant, req.RequestID, "engine_error", payloadSHA)
		return
	}

	// M9-2/M9-3：计量 + 审计 + 指标（估算口径见 estimateTokens；输入已在配额预占计入，仅补记输出）
	tokensOut := s.countTokens(agg.String())
	s.recordUsage(tenant, 0, tokensOut, false)
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: req.RequestID, Action: "infer",
		TokensIn: s.countTokens(inputText.String()), TokensOut: tokensOut,
		Result: "ok", PayloadSHA: payloadSHA,
		// P2a：双 hash 审计——PayloadSHA 为入站密文哈希，TransformedHash 为引擎实收内容哈希
		TransformedHash: txHash,
	})
	s.metrics.incRequest(tenant, "ok")
	s.metrics.addTokens(tenant, int64(s.countTokens(inputText.String())), int64(tokensOut))
	// P5：C-MaaS 证明/透明度引用落审计链（含 Rekor 日志引用，SDK 开通后经
	// RecordAttestation 记录；独立审计事件，不动既有哈希链事件结构）
	if engType == protocol.EngineTypeCMAAS && s.cmaasEngine != nil {
		if ref := s.cmaasEngine.LastAttestation(); ref != "" {
			s.audit.append(AuditEvent{
				TenantID: tenant, RequestID: req.RequestID, Action: "cmaas_attest",
				Result: "ok", PayloadSHA: sha256hex([]byte(ref)),
			})
		}
	}
}

// streamTextInfer 流式生成并逐块写出加密 SSE（seq 严格递增；finish 分片终止）。
// 返回非 nil = 流式失败（调用方审计；error 分片已尽力写出）。
func (s *teeServer) streamTextInfer(w http.ResponseWriter, sess *teeSession,
	eng model.Engine, genReq model.GenerateRequest, agg *strings.Builder) error {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	var seq uint64
	writeChunk := func(delta, finish string) error {
		seq++
		chunkJSON, err := json.Marshal(textStreamChunk{Seq: seq, Delta: delta, Finish: finish})
		if err != nil {
			return err
		}
		sealed, err := sess.sealPayload(protocol.EndpointInfer, chunkJSON)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", hex.EncodeToString(sealed)); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	genErr := eng.Generate(genReq, func(delta string) error {
		agg.WriteString(delta)
		return writeChunk(delta, "")
	})
	if genErr != nil {
		// 200 已发出无法改状态码：以 error finish 分片终止，
		// 插件侧（envelope.go）对非 stop 终止整流 fail-closed（不产出半截明文）
		_ = writeChunk("", "error")
		fmt.Fprint(w, "data: [DONE]\n\n")
		return genErr
	}
	if err := writeChunk("", "stop"); err != nil {
		return err
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	return nil
}

// denyAndAudit 拒绝路径：用量 deny 计数 + 审计事件（result=拒绝原因）+ 指标。
func (s *teeServer) denyAndAudit(tenant, requestID, reason, payloadSHA string) {
	s.recordUsage(tenant, 0, 0, true)
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: "deny",
		Result: reason, PayloadSHA: payloadSHA,
	})
	s.metrics.incDeny(tenant, reason)
}

// handleHealthz 健康探针。
// readiness 语义：requireAttest 模式下，无有效证明会话 → 503（证明失效即不可服务）；
// liveness 语义：进程存活即 200（path=/healthz/live）。
func (s *teeServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// liveness：进程存活
	if r.URL.Path == "/healthz/live" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	// readiness：证明状态联动
	if s.requireAttest && !s.hasValidSession() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("attestation required: no valid session"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// hasValidSession 是否存在任意有效证明会话。
func (s *teeServer) hasValidSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.Completed && time.Since(sess.CreatedAt) < sessionTTL {
			return true
		}
	}
	return false
}
func (s *teeServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.render(w, s.audit.len())
}

// usageView 用量查询响应视图（含配额信息，P1）。
type usageView struct {
	*usageRecord
	Quota      int64 `json:"quota"`       // 配额上限（累计 token，<=0 = 不限）
	UsedTokens int64 `json:"used_tokens"` // 累计消耗 token（输入+输出）
}

// handleUsage 用量查询：GET /usage（全部租户）或 ?tenant=X（单租户）。
// P1 起响应含配额视图（quota / used_tokens）。
func (s *teeServer) handleUsage(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	view := func(tenant string, rec *usageRecord) *usageView {
		uv := &usageView{usageRecord: rec, Quota: s.quotaDefault}
		if q, ok := s.quota[tenant]; ok {
			uv.Quota = q
		}
		if rec != nil {
			uv.UsedTokens = int64(rec.TokensIn) + int64(rec.TokensOut)
		}
		return uv
	}
	if t := r.URL.Query().Get("tenant"); t != "" {
		rec := s.usage[t]
		if rec == nil {
			rec = &usageRecord{}
		}
		_ = json.NewEncoder(w).Encode(map[string]*usageView{t: view(t, rec)})
		return
	}
	out := map[string]*usageView{}
	for t, rec := range s.usage {
		out[t] = view(t, rec)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// quotaRequest 配额设置请求。
type quotaRequest struct {
	Tenant    string `json:"tenant"`
	MaxTokens int64  `json:"max_tokens"` // <=0 = 不限
}

// handleQuota 配额设置：POST /usage/quota {"tenant":"acme","max_tokens":1000000}。
// max_tokens <= 0 解除限制；返回当前生效配额。
func (s *teeServer) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req quotaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tenant == "" {
		http.Error(w, "bad json（须含 tenant）", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if req.MaxTokens <= 0 {
		delete(s.quota, req.Tenant)
	} else {
		s.quota[req.Tenant] = req.MaxTokens
	}
	effective := s.quotaDefault
	if q, ok := s.quota[req.Tenant]; ok {
		effective = q
	}
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"tenant": req.Tenant, "quota": effective})
	log.Printf("[tee] 配额设置 tenant=%s max_tokens=%d", req.Tenant, req.MaxTokens)
}

// handleAudit 审计查询：GET /audit（全部）或 ?tenant=X（按租户过滤）。
func (s *teeServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.audit.query(r.URL.Query().Get("tenant")))
}

// auditVerifyResponse /audit/verify 响应。
type auditVerifyResponse struct {
	OK     bool `json:"ok"`
	Events int  `json:"events"`
}

// handleAuditVerify 哈希链完整性校验：GET /audit/verify。
func (s *teeServer) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	ok, n := s.audit.verify()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(auditVerifyResponse{OK: ok, Events: n})
}

// handleAuditAnchor 触发审计锚定：POST /audit/anchor。
// 返回锚定记录；未启用锚定文件时 400。
func (s *teeServer) handleAuditAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec := s.audit.anchorNow()
	if rec == nil {
		http.Error(w, "锚定未启用（需 -audit-anchor 参数）", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

// orDefault 空串回退。
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// chainHashOf 锚定记录的链尾哈希（空记录返回空串）。
func chainHashOf(r *AnchorRecord) string {
	if r == nil {
		return ""
	}
	return r.ChainHash
}

func wipe(b []byte) {
	memzero.Bytes(b)
}

// mustMeasure 获取飞地测量值（失败 panic，启动阶段不允许失败）。
func mustMeasure(e Enclave) []byte {
	m, err := e.Measure()
	if err != nil {
		panic("enclave: Measure 失败: " + err.Error())
	}
	return m
}

// sealFileHeader 密封文件魔数（版本化格式）。
const sealFileHeader = "OTPMASK-SEAL-V1\n"

// readSealFile 读取密封文件：master_blob + k_sig_blob 两个 length-prefixed blob。
// 文件不存在返回 (nil, nil)；格式损坏返回 nil（按首次启动处理，但保留告警）。
func readSealFile(path string) (masterBlob, sigBlob []byte) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		log.Printf("[seal] 读取密封文件失败（按首次启动处理）: %v", err)
		return nil, nil
	}
	if len(raw) < len(sealFileHeader) || string(raw[:len(sealFileHeader)]) != sealFileHeader {
		log.Printf("[seal] 密封文件格式未知（忽略）: %s", path)
		return nil, nil
	}
	body := raw[len(sealFileHeader):]
	// 两个 length-prefixed blob（big-endian uint32 长度 + 数据）
	if len(body) < 4 {
		return nil, nil
	}
	l1 := int(uint32(body[0])<<24 | uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3]))
	if len(body) < 4+l1+4 {
		return nil, nil
	}
	mb := body[4 : 4+l1]
	rest := body[4+l1:]
	l2 := int(uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3]))
	if len(rest) < 4+l2 {
		return nil, nil
	}
	return mb, rest[4 : 4+l2]
}

// writeSealFile 写入密封文件（master_blob || k_sig_blob，0600 权限）。
func writeSealFile(path string, masterBlob, sigBlob []byte) error {
	buf := make([]byte, 0, len(sealFileHeader)+4+len(masterBlob)+4+len(sigBlob))
	buf = append(buf, sealFileHeader...)
	buf = append(buf, byte(len(masterBlob)>>24), byte(len(masterBlob)>>16), byte(len(masterBlob)>>8), byte(len(masterBlob)))
	buf = append(buf, masterBlob...)
	buf = append(buf, byte(len(sigBlob)>>24), byte(len(sigBlob)>>16), byte(len(sigBlob)>>8), byte(len(sigBlob)))
	buf = append(buf, sigBlob...)
	return os.WriteFile(path, buf, 0o600)
}

func main() {
	addr := flag.String("listen", ":19090", "监听地址")
	sigKeyHex := flag.String("sig-key", "", "协议签名密钥 K_sig（32 字节 hex；默认随机生成并打印）")
	attestToken := flag.String("attest-token", "", "远程证明共享令牌（模拟）；默认随机生成并打印")
	adminToken := flag.String("admin-token", "", "管理端点（/metrics /audit /usage）认证令牌；为空 = 开发模式不拦截")
	engineURL := flag.String("engine-url", "", "明文域推理引擎（vLLM OpenAI 兼容地址，如 http://vllm:8000；text 载荷流式直连；为空使用本地模拟引擎）")
	cmaasURL := flag.String("cmaas-url", "", "百炼 C-MaaS openai-proxy 地址（P5，如 http://127.0.0.1:8080；为空 = cmaas 引擎未配置，请求 fail-closed）")
	cmaasAPIKey := flag.String("cmaas-api-key", "", "C-MaaS API Key（DASHSCOPE_API_KEY，Bearer 透传代理；可由代理侧环境变量提供）")
	cmaasModel := flag.String("cmaas-model", "", "C-MaaS 缺省模型 code（cmaas-glm-5.2 等；请求未指定模型时使用）")
	auditFile := flag.String("audit-file", "", "审计事件 WORM 文件路径（JSON Lines 只追加；为空 = 内存模式）")
	auditAnchor := flag.String("audit-anchor", "", "审计锚定文件路径（链尾哈希追加；仅 audit-file 开启时生效）")
	tsaMode := flag.String("tsa", "mock", "RFC 3161 可信时间戳服务：mock（本地自签）| off（不绑定 TST，）")
	requireAttest := flag.Bool("require-attest", false, "强制证明模式")
	enclaveMode := flag.String("enclave", "mock", "飞地实现：mock|tdx|sgx")
	sealFile := flag.String("seal-file", "", "飞地密封数据文件（主密钥/K_sig 经 Seal 持久化；为空 = 内存模式，重启重新生成）")
	routeConfigFile := flag.String("route-config", "", "双路线路由配置 JSON")
	tokenQuota := flag.Int64("token-quota", 0, "每租户 token 配额上限（累计输入+输出；<=0 = 不限，P1；未单独配置租户的默认值）")
	piiMode := flag.String("pii-mode", "block", "PII 处理模式：block（拦截，默认，fail-closed）| mask（脱敏替换后放行，P2a）；SQL 注入/提示注入任何模式均拦截")
	systemPrompt := flag.String("system-prompt", "", "提示词装饰：非空时在 text 载荷 messages 头部插入 system 消息（P2a，记录于审计 transformed_hash）")
	protoVersion := flag.String("protocol-version", protocol.Version, "南向协议版本声明（C-4 版本一致性；默认 protocol.Version）")
	flag.Parse()

	// 双路线路由配置
	routeCfg := DefaultRouteConfig()
	if *routeConfigFile != "" {
		data, err := os.ReadFile(*routeConfigFile)
		if err != nil {
			log.Fatalf("读取路由配置失败（fail-closed）: %v", err)
		}
		routeCfg, err = ParseRouteConfig(data)
		if err != nil {
			log.Fatalf("解析路由配置失败（fail-closed）: %v", err)
		}
	}

	// 飞地抽象初始化（mock / tdx / sgx；tdx/sgx 需硬件接入）
	var encl Enclave
	switch *enclaveMode {
	case "mock":
		e, err := NewMockEnclave()
		if err != nil {
			log.Fatalf("初始化 mock 飞地失败: %v", err)
		}
		encl = e
	case "tdx", "sgx", "nv-cc":
		e, err := newPlatformEnclave(*enclaveMode)
		if err != nil {
			log.Fatalf("初始化 %s 飞地失败: %v", *enclaveMode, err)
		}
		encl = e
	default:
		log.Fatalf("未知飞地实现: %q（mock|tdx|sgx）", *enclaveMode)
	}
	log.Printf("飞地实现: %s（测量值 %s）", encl.Platform(), hex.EncodeToString(mustMeasure(encl)))

	// 密钥驻留：主密钥与 K_sig 经 Enclave.Seal 持久化，重启 Unseal 恢复
	masterBlob, sigBlob := readSealFile(*sealFile) // nil = 首次启动
	var masterKey []byte
	var kSig []byte
	if *sigKeyHex != "" {
		k, err := hex.DecodeString(*sigKeyHex)
		if err != nil || len(k) != 32 {
			log.Fatalf("sig-key 须为 32 字节 hex")
		}
		kSig = k
	} else if sigBlob != nil {
		k, err := encl.Unseal(sigBlob, "k_sig")
		if err != nil {
			log.Fatalf("恢复 K_sig 失败（fail-closed）: %v", err)
		}
		kSig = k
		log.Printf("恢复 K_sig（Enclave.Unseal, %d 字节）", len(kSig))
	} else {
		kSig = make([]byte, 32)
		if _, err := rand.Read(kSig); err != nil {
			log.Fatal(err)
		}
		log.Printf("生成的 K_sig（生产由 TEE 签发，此处 mock）")
	}
	if *attestToken == "" {
		*attestToken = randHex(32)
		log.Printf("生成的 attestation 令牌: %s（模拟凭证，生产环境用 TDX Quote）", *attestToken)
	}

	// 主密钥：密封文件恢复（Unseal）或飞地内生成后 Seal 持久化
	if masterBlob != nil {
		mk, err := encl.Unseal(masterBlob, "master")
		if err != nil {
			log.Fatalf("恢复主密钥失败（fail-closed）: %v", err)
		}
		masterKey = mk
	}
	if masterKey == nil {
		mk := make([]byte, 32)
		if _, err := rand.Read(mk); err != nil {
			log.Fatal(err)
		}
		masterKey = mk
	}
	// 持久化密封数据（主密钥 + K_sig 合并密封，重启可恢复；fail-closed：密封失败拒绝启动）
	if *sealFile != "" && masterBlob == nil {
		blob, err := encl.Seal(masterKey, "master")
		if err != nil {
			log.Fatalf("密封主密钥失败（fail-closed）: %v", err)
		}
		sigBlob2, err := encl.Seal(kSig, "k_sig")
		if err != nil {
			log.Fatalf("密封 K_sig 失败（fail-closed）: %v", err)
		}
		if err := writeSealFile(*sealFile, blob, sigBlob2); err != nil {
			log.Fatalf("写入密封文件失败（fail-closed）: %v", err)
		}
		log.Printf("密钥已 Seal 持久化: %s（重启经 Unseal 恢复）", *sealFile)
	}

	km, err := teecore.NewKeyManagerWithMaster(0, masterKey)
	if err != nil {
		log.Fatalf("初始化 KeyManager 失败: %v", err)
	}

	// M12：引擎可插拔——指定 -engine-url 时经 vLLM OpenAI 兼容接口推理（P2：text 流式直连；
	// vectors 路径经 vLLM 适配器 /generate 兼容保留），否则本地模拟引擎
	var eng model.Engine = model.New()
	if *engineURL != "" {
		eng = model.NewRemoteEngine(*engineURL)
		log.Printf("推理引擎: vLLM OpenAI 兼容 %s", *engineURL)
	}
	// P5：C-MaaS 引擎（openai-proxy 对接；未配置 -cmaas-url 时 cmaas 请求 fail-closed）
	var cmaasEng *model.CmaasEngine
	if *cmaasURL != "" {
		cmaasEng = model.NewCmaasEngine(*cmaasURL, *cmaasAPIKey, *cmaasModel)
		log.Printf("推理引擎: C-MaaS openai-proxy %s（model=%s）", *cmaasURL, orDefault(*cmaasModel, "-"))
	}

	// C-5：审计 WORM 持久化——指定 -audit-file 时启用文件追加与启动恢复
	// RFC 3161 可信时间戳（-tsa mock|off）
	var tsa TSASigner
	switch *tsaMode {
	case "mock":
		t, err := NewMockTSA()
		if err != nil {
			log.Fatalf("初始化 TSA 失败: %v", err)
		}
		tsa = t
	case "off":
		tsa = nil
	default:
		log.Fatalf("未知 TSA 模式: %q（mock|off）", *tsaMode)
	}
	var audit *auditChain
	if *auditFile != "" {
		audit, err = newAuditChainWORM(*auditFile, *auditAnchor)
		if err != nil {
			log.Fatalf("初始化 WORM 审计失败（fail-closed 拒绝启动）: %v", err)
		}
		audit.tsa = tsa
		rec := audit.anchorNow()
		log.Printf("审计模式: WORM 文件=%s 锚定=%s 恢复事件=%d（锚定 %s, TST=%v）",
			*auditFile, orDefault(*auditAnchor, "-"), audit.len(), orDefault(chainHashOf(rec), "-"), rec != nil && rec.TST != nil)
	} else {
		audit = newAuditChainWithTSA(tsa)
	}

	srv := &teeServer{
		km: km, kSig: kSig, attest: *attestToken,
		enclave:         encl,
		requireAttest:   *requireAttest,
		adminToken:      *adminToken,
		model:           eng,
		cmaasEngine:     cmaasEng,
		protoVersion:    *protoVersion,
		piiMode:         *piiMode,
		systemPrompt:    *systemPrompt,
		seen:            make(map[string]bool),
		seenAt:          make(map[string]int64),
		sessions:        make(map[string]*teeSession),
		recomputeStates: newRecomputeStates(),
		weightProvider:  NewMockWeightProvider(32),
		route:           routeCfg,
		tokenizer:       charDiv4Tokenizer{}, // GF.2.4：计量口径默认字符/4，真机 tokenizer 接入点
		tenants:         make(map[string]*teecore.KeyManager),
		usage:           make(map[string]*usageRecord),
		quota:           make(map[string]int64),
		quotaDefault:    *tokenQuota,
		audit:           audit,
		guard:           newGuardrail(),
		metrics:         newMetrics(),
	}
	go srv.seenCleanup()                                           // 防重放集合 TTL 清理
	go srv.sessionCleanup()                                        // 远程证明会话 TTL 清理
	go newReconciler(audit, srv.usage, &srv.mu, srv.metrics).run() // 审计-计费对账
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", srv.handleAttest)
	mux.HandleFunc("/attest/complete", srv.handleAttestComplete)
	mux.HandleFunc("/key/issue", srv.handleKeyIssue)
	mux.HandleFunc("/v1/infer", srv.handleInfer)
	mux.HandleFunc("/v1/recompute", srv.handleRecompute)   // 路线 2 非线性补算
	mux.HandleFunc("/infer", srv.handleInfer)              // 网关路由别名
	mux.HandleFunc("/usage", srv.handleUsage)              // M9-2 用量
	mux.HandleFunc("/usage/quota", srv.handleQuota)        // P1 配额设置
	mux.HandleFunc("/audit", srv.handleAudit)              // M9-3 审计
	mux.HandleFunc("/audit/verify", srv.handleAuditVerify) // M9-3 哈希链校验
	mux.HandleFunc("/audit/anchor", srv.handleAuditAnchor) // C-5 审计锚定
	mux.HandleFunc("/metrics", srv.handleMetrics)          // M10 可观测性
	mux.HandleFunc("/healthz", srv.handleHealthz)          // 探针与证明状态联动
	mux.HandleFunc("/healthz/live", srv.handleHealthz)     // liveness

	defer audit.Close() // WORM 模式落盘文件随进程退出关闭

	log.Printf("tee-infer-service 就绪: %s（KeyManager 主密钥轮换 TTL=%v + attestation 双向）", *addr, teecore.DefaultMasterTTL)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
