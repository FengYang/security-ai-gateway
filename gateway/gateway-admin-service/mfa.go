// Package main — 管理员双因素认证（P1-3 等保合规 §6.1，R2-04/R2-05/R2-13；ENB2-03 Go 侧）。
//
// 端点（详设 §6.1 表；统一挂 authMiddleware + epMFA 规则）：
//
//	POST /v1/adminext/mfa/enroll   绑定 TOTP 第二因素（仅已过第一因素会话；绑定落审计链）
//	POST /v1/adminext/mfa/verify   校验一次性口令；成功重签带 mfa 声明的内部令牌
//	GET  /v1/adminext/mfa/status   查询当前账号 MFA 绑定/锁定状态（供门户展示）
//
// 安全约束（详设 §6.1 MFA 设计细则）：
//   - TOTP 参数：RFC 6238，步长 30s、6 位数字、±1 步容差；**HMAC-SHA1 为 RFC 互操作
//     例外**（对接标准认证器 App；与 P0-4 cipher/mask 的 hmacPRG 例外同理，非存储保护 MAC）；
//   - 重放防护：记录最近成功时间片，同一口令/同时间片不得二次使用；
//   - 失败锁定：连续 5 次失败锁 30 分钟（解锁 = 等待窗口过期；锁定事件落审计并告警）；
//   - 密钥静态存储（R2-04）：TOTP 共享密钥经**信封加密**落盘（suite 前缀 + nonce‖ct，
//     固定双 provider 双读——profile 切换不 brick 已绑定账号；主密钥 ADMIN_MFA_MASTER_KEY
//     hex 32B，缺省 = 派生自 JWT 共享密钥并启动告警），严禁明文落盘/入链/入日志（C-6/C-7）；
//   - 应急码（R2-05 break-glass 支撑）：enroll 时生成 6 枚一次性应急码（仅存 SHA-256 摘要），
//     双人持有、使用即作废并落审计 + 告警；MFA/账号表故障时代替 TOTP 完成第二步；
//   - step-up：写端点按新鲜度校验 mfa/mfa_at 声明（authz.go requireRule）。
//
// 配置：ADMIN_MFA_STATE_FILE（状态文件路径，未配置 = MFA 特性关闭，端点 503）；
// ADMIN_MFA_MASTER_KEY（信封主密钥 hex 32B，缺省派生自 JWT 共享密钥 + 告警）。
//
// P2-4 T-1.5（S1(7) 进程内态清点收尾）：状态存储增加**共享库后端**（表 mfa_states，
// sqlite/PG 双方言），与 captcha/loginGuard/intervalGuard 共用 SECURITY_STORE_PG_DSN
// 开关；DSN 为空 = 原 JSON 文件实现，行为不变。至此 S1(7) 四类进程内态全部具备
// 共享后端（C-18 解除口径，详见 security_store.go 文件头清点注记）。
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 互操作例外（见文件头），非存储保护 MAC
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/protocol/go" // framing 复用 EnvelopeNonce/PutUint64 风格手写

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// MFA 端点路径（详设 §6.1 表；映射表 A 类已登记，authz.go epMFA）。
const (
	mfaEnrollPath = "/v1/adminext/mfa/enroll"
	mfaVerifyPath = "/v1/adminext/mfa/verify"
	mfaStatusPath = "/v1/adminext/mfa/status"
)

// TOTP / 锁定参数（详设 §6.1 R2-13）。
const (
	totpPeriod            = int64(30) // 步长 30s（RFC 6238）
	totpDigits            = 6
	totpWindow            = 1    // ±1 步容差
	totpSecretLen         = 20   // 共享密钥 160 位（RFC 6238 推荐）
	mfaMaxFails           = 5    // 连续失败锁定阈值
	mfaLockSeconds        = 1800 // 锁定 30 分钟
	emergencyCodeLen      = 16   // 应急码长度：16 位 hex（8 字节 = 64 位熵），不含连字符
	emergencyCodeCnt      = 6    // enroll 生成一次性应急码枚数
	breakGlassMaxLifetime = 900  // break_glass 令牌短时效 exp-iat ≤ 15min（authz.go）
)

// 审计动作（内部落链，不经 audit-events 白名单约束）。
const (
	auditActionMFAEnroll           = "mfa_enroll"
	auditActionMFAVerify           = "mfa_verify"
	auditActionMFALocked           = "mfa_locked"
	auditActionMFAEmergencyUsed    = "mfa_emergency_used"
	auditActionWhitelistEscalation = "whitelist_escalation"
)

// mfaEmergencyCode 一次性应急码（R2-05）：仅存 SHA-256 摘要，使用即作废。
type mfaEmergencyCode struct {
	Hash   string `json:"hash"`              // SHA-256(hex)（**证据字段不进 hash**，C-7 口径同 KeyFingerprint）
	UsedAt int64  `json:"used_at,omitempty"` // 使用时间（Unix 秒）；0 = 未使用
}

// mfaRecord 单管理员 MFA 状态（Secrets 严禁明文——SecretSealed 为信封密文）。
type mfaRecord struct {
	SecretSealed string             `json:"secret_sealed"` // suite(1)‖nonce‖ct 信封密文（hex）
	KeyVersion   int                `json:"key_version"`   // 主密钥版本（当前 v1）
	EnrolledAt   int64              `json:"enrolled_at"`   // Unix 秒
	LastTimestep int64              `json:"last_timestep"` // 重放防护：最近成功时间片
	FailCount    int                `json:"fail_count"`    // 连续失败计数（成功清零）
	LockedUntil  int64              `json:"locked_until"`  // 锁定至（Unix 秒）；0 = 未锁
	Emergency    []mfaEmergencyCode `json:"emergency,omitempty"`
}

// mfaStore MFA 状态存储。两种后端（P2-4 T-1.5，S1(7) 清点收尾）：
//   - 文件后端（默认，db==nil）：JSON 文件 0600 + 进程内互斥，行为零变化；
//   - 共享库后端（db!=nil）：表 mfa_states（sqlite/PG 双方言），多副本共享 + 持久化，
//     读-改-写经事务（PG 下另加 advisory xact lock）跨副本串行，等价文件后端的
//     进程锁 + 原子 rename 语义。
//
// 口径注记：共享库后端的 record 列是**整条 mfaRecord 的 JSON**，字段与文件序列化
// 格式逐字段等价（同 mfaRecord 的 json tag）。切换到共享库不读取/迁移旧 JSON 文件
// （历史文件不自动导入）——切换后已绑定账号须重新 enroll（或由 T-1.6 迁移工具对账
// 导入）。后端不可达时的取向：MFA 是等保强制的 step-up 控制，enrolled 判定取
// **fail-closed**（视为已绑定 → 要求 MFA 声明），与 captcha 的可用性优先相反。
type mfaStore struct {
	mu        sync.Mutex
	path      string                // 文件后端路径（共享库后端时保留作审计线索，不读写）
	db        *sqlutil.DB           // 共享库后端（nil = 文件后端）
	masterKey []byte                // 信封主密钥（32B）
	recs      map[string]*mfaRecord // 文件后端工作集；共享库后端不使用
	alarm     securityAlarm
}

// mfaState 全局 MFA 存储；nil = 特性未配置（mfaSatisfied 过渡期放行，端点 503）。
var mfaState *mfaStore

// ---- break-glass 启用开关（详设 §6.2：正常状态禁用）----

// breakGlassEnabled 应急通道启用开关（ADMIN_BREAK_GLASS_ENABLED=true；缺省 false fail-closed）。
func breakGlassEnabled() bool { return os.Getenv("ADMIN_BREAK_GLASS_ENABLED") == "true" }

// ---- TOTP（RFC 6238）----

// totpCode 计算给定时间片的 6 位 TOTP 口令（HMAC-SHA1，RFC 互操作例外见文件头）。
func totpCode(secret []byte, timestep int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(timestep))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	code := bin % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// currentTimestep 当前 TOTP 时间片。
func currentTimestep() int64 { return time.Now().Unix() / totpPeriod }

// ---- 信封加密（suite 前缀 + 固定双 provider 双读，P0-4 B5-a 同款口径）----

// sealMFASecret 信封加密 TOTP 共享密钥：wire = suite(1)‖nonce‖ct（跨 profile 可读）。
func sealMFASecret(key, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, cryptoProvider.NonceSize())
	rnd, err := cryptoProvider.Rand(len(nonce))
	if err != nil {
		return nil, err
	}
	copy(nonce, rnd)
	ct, err := cryptoProvider.Seal(key, nonce, plaintext, []byte("otpmask/mfa/v1"))
	if err != nil {
		return nil, err
	}
	suite := byte(protocol.SuiteAESGCM)
	if cryptoProvider.Profile() != cryptop.ProfileIntl {
		suite = byte(protocol.SuiteSM4GCM)
	}
	out := append([]byte{suite}, nonce...)
	return append(out, ct...), nil
}

// openMFASecret 按 wire suite 前缀双读解密（固定双 provider，与进程 profile 解耦）。
func openMFASecret(key, blob []byte) ([]byte, error) {
	if len(blob) < 1+16+16 {
		return nil, errors.New("mfa: 密文长度非法")
	}
	suite := blob[0]
	var prov cryptop.Provider
	switch suite {
	case byte(protocol.SuiteAESGCM):
		prov = hashProvSHA256 // 固定 intl provider（audit.go 既有固定双 provider 复用）
	case byte(protocol.SuiteSM4GCM):
		prov = hashProvSM3
	default:
		return nil, fmt.Errorf("mfa: 未知 suite %d", suite)
	}
	ns := prov.NonceSize()
	return prov.Open(key, blob[1:1+ns], blob[1+ns:], []byte("otpmask/mfa/v1"))
}

// ---- 存储 ----

// deriveMFAMasterKey 信封主密钥：ADMIN_MFA_MASTER_KEY（hex 32B）或派生自 JWT 共享密钥
// （启动告警；生产应显式配置独立主密钥）。文件/共享库两后端共用。
func deriveMFAMasterKey(jwtSecret []byte) []byte {
	mk, err := hex.DecodeString(os.Getenv("ADMIN_MFA_MASTER_KEY"))
	if err != nil || len(mk) != 32 {
		mk = cryptoProvider.Hash(append([]byte("otpmask/mfa-master/v1\x00"), jwtSecret...))[:32]
		log.Printf("[mfa] 警告：ADMIN_MFA_MASTER_KEY 未配置/非法，主密钥已派生自 JWT 共享密钥（生产应显式配置独立主密钥）")
	}
	return mk
}

// newSQLMFAStore 构造共享库 MFA 存储（表 mfa_states；不读取旧状态文件，见类型注记）。
func newSQLMFAStore(db *sqlutil.DB, jwtSecret []byte) *mfaStore {
	return &mfaStore{db: db, masterKey: deriveMFAMasterKey(jwtSecret)}
}

// loadMFAStore 加载/初始化 MFA 状态存储（fail-closed：文件存在但非法 → 拒绝启用）。
// masterKey 缺省派生自 JWT 共享密钥（启动告警；生产应显式配置 ADMIN_MFA_MASTER_KEY）。
// 安全计数器共享库已启用（SECURITY_STORE_PG_DSN，useSecurityPGStore 注入
// securitySharedDB）时改走共享库后端；否则保持原文件实现，行为不变。
func loadMFAStore(path string, jwtSecret []byte) (*mfaStore, error) {
	if path == "" {
		return nil, nil
	}
	if securitySharedDB != nil {
		log.Printf("[mfa] 安全计数器共享库已启用：MFA 状态改存 mfa_states 表（多副本共享；旧状态文件 %s 不自动迁移，已绑定账号须重新 enroll）", path)
		return newSQLMFAStore(securitySharedDB, jwtSecret), nil
	}
	mk := deriveMFAMasterKey(jwtSecret)
	s := &mfaStore{path: path, masterKey: mk, recs: map[string]*mfaRecord{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mfa: 读取状态文件失败: %w", err)
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.recs); err != nil {
		return nil, fmt.Errorf("mfa: 状态文件非法（fail-closed）: %w", err)
	}
	return s, nil
}

// saveLocked 落盘（0600 + 原子 rename；调用方须持锁）。仅文件后端使用。
func (s *mfaStore) saveLocked() error {
	raw, err := json.Marshal(s.recs)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ---- 存储临界区（文件后端 = 进程锁；共享库后端 = DB 事务 + advisory lock）----

// mfaTx MFA 存储的读-改-写临界区：commit/rollback 必须各调用一次（defer 兜底）。
type mfaTx struct {
	s   *mfaStore
	raw *sqlutil.Tx // 共享库后端事务；nil = 文件后端
}

// begin 开临界区（文件后端取进程锁；共享库后端开事务，PG 下自动取 advisory
// xact lock 使跨副本读-改-写串行，等价文件后端的进程锁语义）。
func (s *mfaStore) begin() (*mfaTx, error) {
	s.mu.Lock()
	if s.db == nil {
		return &mfaTx{s: s}, nil
	}
	raw, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	return &mfaTx{s: s, raw: raw}, nil
}

// get 读账号记录（共享库后端实时读库反序列化；不存在返回 nil,false）。
func (tx *mfaTx) get(sub string) (*mfaRecord, bool, error) {
	if tx.raw == nil {
		r, ok := tx.s.recs[sub]
		return r, ok, nil
	}
	var blob string
	if err := tx.raw.QueryRow(`SELECT record FROM mfa_states WHERE sub = ?`, sub).Scan(&blob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var r mfaRecord
	if err := json.Unmarshal([]byte(blob), &r); err != nil {
		return nil, false, fmt.Errorf("mfa: 状态记录反序列化失败: %w", err)
	}
	return &r, true, nil
}

// put 写账号记录：文件后端先落盘后更新缓存（失败即回滚内存态，与磁盘一致）；
// 共享库后端 upsert，提交时生效。
func (tx *mfaTx) put(sub string, rec *mfaRecord) error {
	if tx.raw == nil {
		tx.s.recs[sub] = rec
		if err := tx.s.saveLocked(); err != nil {
			delete(tx.s.recs, sub) // 回滚内存态，避免与磁盘不一致
			return err
		}
		return nil
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = tx.raw.Exec(`INSERT INTO mfa_states (sub, record, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (sub) DO UPDATE SET record = excluded.record, updated_at = excluded.updated_at`,
		sub, string(blob), time.Now().Unix())
	return err
}

// commit 提交临界区（文件后端 = 释放进程锁）。
func (tx *mfaTx) commit() error {
	if tx.raw == nil {
		tx.s.mu.Unlock()
		return nil
	}
	err := tx.raw.Commit()
	tx.s.mu.Unlock()
	return err
}

// rollback 回滚临界区（文件后端 = 释放进程锁；put 失败已自回滚内存态）。
func (tx *mfaTx) rollback() {
	if tx.raw != nil {
		_ = tx.raw.Rollback()
	}
	tx.s.mu.Unlock()
}

// enrolled 账号是否已绑定 MFA（特性关闭时恒 false）。
// 共享库后端查询失败 → 视为已绑定（fail-closed，等保 step-up 不降级，见类型注记）。
func (s *mfaStore) enrolled(sub string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		var one int
		if err := s.db.QueryRow(`SELECT 1 FROM mfa_states WHERE sub = ?`, sub).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false // 确未绑定（非故障；灰度期放行）
			}
			s.alarm.logf("mfa-enrolled", "MFA 绑定状态查询失败（fail-closed 视为已绑定）: %v", err)
			return true
		}
		return true
	}
	_, ok := s.recs[sub]
	return ok
}

// locked 账号当前是否处于失败锁定窗口。
func (s *mfaStore) locked(sub string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		var blob string
		if err := s.db.QueryRow(`SELECT record FROM mfa_states WHERE sub = ?`, sub).Scan(&blob); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				s.alarm.logf("mfa-locked", "MFA 锁定状态查询失败: %v", err)
			}
			return false
		}
		var r mfaRecord
		if err := json.Unmarshal([]byte(blob), &r); err != nil {
			return false
		}
		return r.LockedUntil > time.Now().Unix()
	}
	r, ok := s.recs[sub]
	return ok && r.LockedUntil > time.Now().Unix()
}

// mfaSatisfied 写端点 MFA 声明校验（authz.go requireRule 调用）：
//   - 特性未配置 / 账号未绑定 → 灰度期放行（过渡期兼容，详设 §6.2 迁移策略）；
//   - 已绑定 → 须 mfa=true 且 now-mfa_at ≤ freshness（fail-closed 403）。
func mfaSatisfied(c *claims, freshness time.Duration) bool {
	if mfaState == nil || !mfaState.enrolled(c.Sub) {
		return true // 灰度期：未绑定账号不阻断（绑定后即刻生效）
	}
	return c.MFA && c.MFAAt > 0 && time.Now().Unix()-c.MFAAt <= int64(freshness/time.Second)
}

// ---- 应急码（R2-05）----

// formatEmergencyCode 将 16 位 hex 归一为 XXXX-XXXX-XXXX-XXXX。
// 生成与核销共用本函数，避免两处格式漂移。
// 2026-10-09 修正 F-8：原实现生成 8 位 hex 而核销要求 16 位，致应急码恒不可核销
// （break-glass 通道失效）；现统一为 64 位熵。
func formatEmergencyCode(hexUpper string) string {
	return hexUpper[:4] + "-" + hexUpper[4:8] + "-" + hexUpper[8:12] + "-" + hexUpper[12:]
}

// newEmergencyCodes 生成 n 枚一次性应急码（形如 XXXX-XXXX-XXXX-XXXX；仅存 SHA-256 摘要）。
func newEmergencyCodes(n int) ([]mfaEmergencyCode, []string, error) {
	recs := make([]mfaEmergencyCode, 0, n)
	plain := make([]string, 0, n)
	rnd, err := cryptoProvider.Rand(n * 8) // 每枚 8 字节 → 16 hex 字符（64 位熵）
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < n; i++ {
		code := formatEmergencyCode(strings.ToUpper(hex.EncodeToString(rnd[i*8 : (i+1)*8])))
		h := cryptoProvider.Hash([]byte(code))
		recs = append(recs, mfaEmergencyCode{Hash: hex.EncodeToString(h)})
		plain = append(plain, code)
	}
	return recs, plain, nil
}

// consumeEmergencyLocked 核销一枚应急码（调用方持锁）；返回是否命中。
func (r *mfaRecord) consumeEmergencyLocked(code string) bool {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(norm) != emergencyCodeLen { // 16 位 hex（不含连字符）
		return false
	}
	h := hex.EncodeToString(cryptoProvider.Hash([]byte(formatEmergencyCode(norm))))
	for i := range r.Emergency {
		if r.Emergency[i].UsedAt == 0 && subtle.ConstantTimeCompare([]byte(r.Emergency[i].Hash), []byte(h)) == 1 {
			r.Emergency[i].UsedAt = time.Now().Unix()
			return true
		}
	}
	return false
}

// ---- HTTP handler ----

// mfaHandler MFA 三端点（enroll/verify/status）。
type mfaHandler struct {
	store     *mfaStore
	chain     *adminAuditChain // 未启用（nil）→ 端点 503 fail-closed（绑定动作须落审计链）
	jwtSecret []byte
	issuer    string
	audience  string
}

// handleEnroll POST /v1/adminext/mfa/enroll：绑定/换绑 TOTP（绑定落审计链）。
func (h *mfaHandler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRule(w, r, epMFA) {
		return
	}
	if h.store == nil || h.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "MFA 未启用（ADMIN_MFA_STATE_FILE/审计链未配置）")
		return
	}
	c := claimsFrom(r.Context())

	var body struct {
		Code string `json:"code"` // 换绑授权：已绑定账号须提供当前有效口令（R2-04 防劫持自绑）
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	_ = dec.Decode(&body) // 空体合法（首次绑定）

	// 生成 TOTP 共享密钥（20B 随机；base32 供认证器导入）。
	secret, err := cryptoProvider.Rand(totpSecretLen)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "随机数生成失败")
		return
	}
	emergRecs, emergPlain, err := newEmergencyCodes(emergencyCodeCnt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "应急码生成失败")
		return
	}

	mtx, err := h.store.begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态存储不可用")
		return
	}
	committed := false
	defer func() {
		if !committed {
			mtx.rollback()
		}
	}()
	rec, already, gerr := mtx.get(c.Sub)
	if gerr != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态读取失败")
		return
	}
	if already {
		// 换绑须再认证：当前有效 TOTP（或应急码）之一通过才允许（R2-04）。
		opened, oerr := openMFASecret(h.store.masterKey, mustDecodeHex(rec.SecretSealed))
		if oerr != nil {
			writeError(w, http.StatusInternalServerError, "MFA 密钥解封失败")
			return
		}
		if !verifyTOTPOrEmergency(rec, opened, body.Code) {
			writeError(w, http.StatusForbidden, "换绑须提供当前有效口令（再认证）")
			return
		}
	}
	sealed, err := sealMFASecret(h.store.masterKey, secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MFA 密钥封装失败")
		return
	}
	action := auditActionMFAEnroll
	if err := mtx.put(c.Sub, &mfaRecord{
		SecretSealed: hex.EncodeToString(sealed),
		KeyVersion:   1,
		EnrolledAt:   time.Now().Unix(),
		Emergency:    emergRecs,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态落盘失败")
		return
	}
	if err := mtx.commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态提交失败")
		return
	}
	committed = true
	h.appendAudit(c, r, action, c.Sub, "ok")

	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":             c.Sub,
		"secret_base32":   b32,
		"otpauth_url":     fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", "otpmask-admin", c.Sub, b32, "otpmask-admin"),
		"emergency_codes": emergPlain, // 仅此一次返回；链上/日志绝不记录（C-6）
		"enrolled_at":     time.Now().Unix(),
		"rebound":         already,
	})
}

// verifyTOTPOrEmergency 校验 TOTP（±1 步 + 重放防护）或核销应急码。调用方持锁。
func verifyTOTPOrEmergency(rec *mfaRecord, secret []byte, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) == totpDigits {
		t := currentTimestep()
		for _, dt := range []int64{-totpWindow, 0, totpWindow} {
			ts := t + dt
			if ts <= rec.LastTimestep { // 重放防护：已用过的时间片
				continue
			}
			if subtle.ConstantTimeCompare([]byte(totpCode(secret, ts)), []byte(code)) == 1 {
				rec.LastTimestep = ts
				rec.FailCount = 0
				return true
			}
		}
		return false
	}
	return rec.consumeEmergencyLocked(code)
}

// handleVerify POST /v1/adminext/mfa/verify：校验口令 → 重签带 mfa 声明的令牌。
func (h *mfaHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRule(w, r, epMFA) {
		return
	}
	if h.store == nil || h.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "MFA 未启用（ADMIN_MFA_STATE_FILE/审计链未配置）")
		return
	}
	c := claimsFrom(r.Context())

	var body struct {
		Code string `json:"code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	if err := dec.Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
		writeError(w, http.StatusBadRequest, "code 必填（6 位 TOTP 口令或应急码）")
		return
	}

	mtx, err := h.store.begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态存储不可用")
		return
	}
	committed := false
	defer func() {
		if !committed {
			mtx.rollback()
		}
	}()
	rec, ok, gerr := mtx.get(c.Sub)
	if gerr != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态读取失败")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "当前账号未绑定 MFA（先 enroll）")
		return
	}
	now := time.Now().Unix()
	if rec.LockedUntil > now {
		until := rec.LockedUntil
		writeError(w, http.StatusForbidden, fmt.Sprintf("账号已锁定至 %s（连续失败超阈值）", time.Unix(until, 0).Format(time.RFC3339)))
		return
	}
	secret, err := openMFASecret(h.store.masterKey, mustDecodeHex(rec.SecretSealed))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MFA 密钥解封失败")
		return
	}
	emergency := len(strings.TrimSpace(body.Code)) != totpDigits
	if !verifyTOTPOrEmergency(rec, secret, body.Code) {
		rec.FailCount++
		if rec.FailCount >= mfaMaxFails {
			rec.LockedUntil = now + mfaLockSeconds
			rec.FailCount = 0
			if perr := mtx.put(c.Sub, rec); perr != nil {
				h.store.alarm.logf("mfa-verify", "MFA 锁定状态写入失败（锁定仍会拒绝本次校验）: %v", perr)
			}
			_ = mtx.commit()
			committed = true
			h.appendAudit(c, r, auditActionMFALocked, c.Sub, "ok")
			log.Printf("[mfa] ALERT 账号锁定：sub=%s locked_until=%s rid=%s", c.Sub, time.Unix(rec.LockedUntil, 0).Format(time.RFC3339), r.Header.Get("X-Request-ID"))
			writeError(w, http.StatusForbidden, "连续失败超阈值，账号锁定 30 分钟")
			return
		}
		if perr := mtx.put(c.Sub, rec); perr != nil {
			h.store.alarm.logf("mfa-verify", "MFA 失败计数写入失败（计数可能丢失）: %v", perr)
		}
		_ = mtx.commit()
		committed = true
		writeError(w, http.StatusUnauthorized, "口令校验失败")
		return
	}
	if perr := mtx.put(c.Sub, rec); perr != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态落盘失败")
		return
	}
	if cerr := mtx.commit(); cerr != nil {
		writeError(w, http.StatusInternalServerError, "MFA 状态提交失败")
		return
	}
	committed = true

	if emergency {
		h.appendAudit(c, r, auditActionMFAEmergencyUsed, c.Sub, "ok")
		log.Printf("[mfa] ALERT 应急码已使用（break-glass 通道）：sub=%s rid=%s", c.Sub, r.Header.Get("X-Request-ID"))
	}

	// 重签内部令牌：保留原 sub/role/tenant，追加 mfa 声明 + 刷新 iat/lat/exp（≤8h）。
	now = time.Now().Unix()
	life := c.EXP - c.IAT
	if life <= 0 || life > maxSessionLifetimeSec {
		life = maxSessionLifetimeSec
	}
	nc := claims{
		Sub: c.Sub, Role: c.Role, Tenant: c.Tenant, Iss: h.issuer, Aud: h.audience,
		IAT: now, EXP: now + life, LAT: now, MFA: true, MFAAt: now,
	}
	h.appendAudit(c, r, auditActionMFAVerify, c.Sub, "ok")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":   signInternalToken(h.jwtSecret, nc),
		"mfa_at":  now,
		"expires": nc.EXP,
	})
}

// handleStatus GET /v1/adminext/mfa/status：查询绑定/锁定状态（门户展示）。
func (h *mfaHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epMFA) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "MFA 未启用（ADMIN_MFA_STATE_FILE 未配置）")
		return
	}
	c := claimsFrom(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":                 c.Sub,
		"enrolled":            mfaState.enrolled(c.Sub),
		"locked":              mfaState.locked(c.Sub),
		"break_glass_enabled": breakGlassEnabled(),
	})
}

// appendAudit 落 admin 审计链（nil 链跳过——调用方已 fail-closed 拦截 nil 链路径）。
func (h *mfaHandler) appendAudit(c *claims, r *http.Request, action, target, result string) {
	if h.chain == nil {
		return
	}
	if err := h.chain.append(adminAuditEvent{
		Actor: c.Sub, Action: action, Target: target,
		RequestID: r.Header.Get("X-Request-ID"), Result: result, HashAlg: hashAlgTag(),
	}); err != nil {
		log.Printf("[mfa] 审计落链失败（action=%s sub=%s）: %v", action, c.Sub, err)
	}
}

// signInternalToken 重签 HS256 内部令牌（与 verifyInternalToken 验签同密钥同算法族：
// HMAC 经 cryptoProvider，intl=HMAC-SHA256 / sm=HMAC-SM3）。
func signInternalToken(secret []byte, c claims) string {
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(c)
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := cryptoProvider.HMAC(secret, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac)
}

// mustDecodeHex hex 解码（状态文件已 json 校验；失败返回空切片走 Open 报错路径）。
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return []byte{}
	}
	return b
}
