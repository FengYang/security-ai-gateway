// mfa_test.go — P1-3 等保 §6.1 管理员双因素（W3/M2）单元测试（补齐遗留项 F-6）。
//
// 覆盖：TOTP 生成/容差/重放防护、应急码一次性、信封加密往返、
//       mfaSatisfied 灰度与新鲜度语义、enroll→verify→status 闭环、
//       锁定阈值、换绑再认证、fail-closed 503、审计落链。
package main

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mfaTestSub = "alice"

// newTestMFAStore 构造临时 MFA 状态存储（文件落测试临时目录）。
func newTestMFAStore(t *testing.T) *mfaStore {
	t.Helper()
	s, err := loadMFAStore(filepath.Join(t.TempDir(), "mfa-state.json"), testSecret)
	if err != nil {
		t.Fatalf("加载 MFA 存储失败: %v", err)
	}
	if s == nil {
		t.Fatal("配置了路径即应启用（不应为 nil）")
	}
	return s
}

// newMFATestMux 构造 MFA 端点 mux（挂 authMiddleware；alice 为白名单管理员 → sec:write 通过）。
func newMFATestMux(t *testing.T, s *mfaStore, chain *adminAuditChain) *http.ServeMux {
	t.Helper()
	cfg := testCfg()
	h := &mfaHandler{store: s, chain: chain, jwtSecret: testSecret, issuer: defaultIssuer, audience: defaultAudience}
	mux := http.NewServeMux()
	mux.HandleFunc(mfaEnrollPath, authMiddleware(cfg, h.handleEnroll))
	mux.HandleFunc(mfaVerifyPath, authMiddleware(cfg, h.handleVerify))
	mux.HandleFunc(mfaStatusPath, authMiddleware(cfg, h.handleStatus))
	return mux
}

// doMFA 以管理员身份发起 MFA 端点请求（body 非 nil 时 JSON 编码）。
func doMFA(t *testing.T, mux *http.ServeMux, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = strings.NewReader(string(raw))
	}
	now := time.Now().Unix()
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: mfaTestSub, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
		IAT: now, EXP: now + 3600,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// decodeMFA 解析 JSON 响应体。
func decodeMFA(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析响应失败: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// ---------- TOTP 基础 ----------

// totpCode 输出 6 位数字且同一 (secret, timestep) 稳定、不同时间片不同。
func TestTOTPCodeFormatAndStability(t *testing.T) {
	secret := []byte("0123456789abcdefghij") // 20B
	c1 := totpCode(secret, 100)
	if len(c1) != totpDigits || strings.Trim(c1, "0123456789") != "" {
		t.Fatalf("TOTP 应为 %d 位数字，实际 %q", totpDigits, c1)
	}
	if c2 := totpCode(secret, 100); c2 != c1 {
		t.Fatalf("同时间片应稳定：%q vs %q", c1, c2)
	}
	if totpCode(secret, 101) == c1 {
		t.Fatal("相邻时间片不应相同（1/10^6 概率外）")
	}
}

// ---------- 容差与重放 ----------

// ±1 步容差内接受；已成功的时间片再提交 → 拒绝（重放防护）。
func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret := []byte("0123456789abcdefghij")
	tNow := currentTimestep()

	// 上一时间片（容差内）应接受。
	rec := &mfaRecord{}
	if !verifyTOTPOrEmergency(rec, secret, totpCode(secret, tNow-1)) {
		t.Fatal("-1 步应在容差内接受")
	}
	// 重放同一时间片 → 拒绝。
	if verifyTOTPOrEmergency(rec, secret, totpCode(secret, tNow-1)) {
		t.Fatal("已用时间片重放应拒绝")
	}
	// 陈旧时间片（远超容差）→ 拒绝。
	rec2 := &mfaRecord{}
	if verifyTOTPOrEmergency(rec2, secret, totpCode(secret, tNow-10)) {
		t.Fatal("超出容差的时间片应拒绝")
	}
	// 成功校验后 FailCount 归零。
	rec3 := &mfaRecord{FailCount: 3}
	if !verifyTOTPOrEmergency(rec3, secret, totpCode(secret, tNow)) {
		t.Fatal("当前时间片应接受")
	}
	if rec3.FailCount != 0 {
		t.Fatalf("成功应清零 FailCount，实际 %d", rec3.FailCount)
	}
}

// ---------- 应急码 ----------

// 应急码：8 位、唯一、一次性核销（二次失败）。
func TestEmergencyCodesGenerateAndConsumeOnce(t *testing.T) {
	recs, plain, err := newEmergencyCodes(emergencyCodeCnt)
	if err != nil {
		t.Fatalf("生成应急码失败: %v", err)
	}
	if len(recs) != emergencyCodeCnt || len(plain) != emergencyCodeCnt {
		t.Fatalf("应生成 %d 枚，实际 %d/%d", emergencyCodeCnt, len(recs), len(plain))
	}
	seen := map[string]bool{}
	for i, p := range plain {
		if got := len(strings.ReplaceAll(p, "-", "")); got != emergencyCodeLen {
			t.Fatalf("应急码应为 %d 位，实际 %d（%q）", emergencyCodeLen, got, p)
		}
		if seen[p] {
			t.Fatalf("应急码重复：%q", p)
		}
		seen[p] = true
		// 明文与落库摘要不可相同（仅存 SHA-256）。
		if recs[i].Hash == p {
			t.Fatal("落库应为摘要而非明文")
		}
	}
	rec := &mfaRecord{Emergency: recs}
	code := strings.ReplaceAll(plain[0], "-", "")
	if !rec.consumeEmergencyLocked(code) {
		t.Fatal("首次核销应急码应成功")
	}
	if rec.consumeEmergencyLocked(code) {
		t.Fatal("应急码应一次性（二次核销须失败）")
	}
	if rec.Emergency[0].UsedAt == 0 {
		t.Fatal("核销后应记录 UsedAt")
	}
}

// ---------- 信封加密 ----------

// seal/open 往返一致；密文含 suite 前缀且不含明文；非法长度报错。
func TestSealOpenMFASecretRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plain := []byte("totp-secret-20bytes!")
	blob, err := sealMFASecret(key, plain)
	if err != nil {
		t.Fatalf("封装失败: %v", err)
	}
	if strings.Contains(string(blob), string(plain)) {
		t.Fatal("密文不得含明文")
	}
	got, err := openMFASecret(key, blob)
	if err != nil {
		t.Fatalf("解封失败: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("往返不一致：%q vs %q", got, plain)
	}
	if _, err := openMFASecret(key, blob[:10]); err == nil {
		t.Fatal("长度非法应报错")
	}
}

// ---------- mfaSatisfied 语义 ----------

// 全局未配置（mfaState=nil）→ 灰度放行；已绑定但无 mfa 声明 → 拒绝；新鲜声明 → 通过。
func TestMFASatisfiedGrayAndFreshness(t *testing.T) {
	prev := mfaState
	t.Cleanup(func() { mfaState = prev })

	// 灰度：未配置 → 放行（不阻断既有链路）。
	mfaState = nil
	if !mfaSatisfied(&claims{Sub: mfaTestSub}, time.Hour) {
		t.Fatal("未配置 MFA 时应放行（灰度语义）")
	}

	// 已配置但账号未绑定 → 放行（灰度期：绑定后即刻生效）。
	s := newTestMFAStore(t)
	mfaState = s
	if !mfaSatisfied(&claims{Sub: "nobody"}, time.Hour) {
		t.Fatal("未绑定账号应放行（灰度语义）")
	}

	// 账号已绑定：无 mfa 声明 → 拒绝；声明过期 → 拒绝；新鲜 → 通过。
	s.mu.Lock()
	s.recs[mfaTestSub] = &mfaRecord{SecretSealed: "00", EnrolledAt: time.Now().Unix()}
	s.mu.Unlock()

	if mfaSatisfied(&claims{Sub: mfaTestSub}, time.Hour) {
		t.Fatal("已绑定但无 mfa 声明应拒绝")
	}
	if mfaSatisfied(&claims{Sub: mfaTestSub, MFA: true, MFAAt: time.Now().Unix() - 7200}, time.Hour) {
		t.Fatal("声明超出新鲜度应拒绝")
	}
	if !mfaSatisfied(&claims{Sub: mfaTestSub, MFA: true, MFAAt: time.Now().Unix()}, time.Hour) {
		t.Fatal("新鲜声明应通过")
	}
}

// ---------- 端点闭环 ----------

// 未配置存储/审计链 → 503 fail-closed（不静默放行）。
func TestMFAEndpointsFailClosedWithoutStore(t *testing.T) {
	cfg := testCfg()
	h := &mfaHandler{store: nil, chain: nil, jwtSecret: testSecret, issuer: defaultIssuer, audience: defaultAudience}
	mux := http.NewServeMux()
	mux.HandleFunc(mfaEnrollPath, authMiddleware(cfg, h.handleEnroll))
	mux.HandleFunc(mfaVerifyPath, authMiddleware(cfg, h.handleVerify))
	mux.HandleFunc(mfaStatusPath, authMiddleware(cfg, h.handleStatus))

	if rec := doMFA(t, mux, http.MethodPost, mfaEnrollPath, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("enroll 未配置应 503，实际 %d", rec.Code)
	}
	if rec := doMFA(t, mux, http.MethodPost, mfaVerifyPath, map[string]string{"code": "123456"}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("verify 未配置应 503，实际 %d", rec.Code)
	}
	if rec := doMFA(t, mux, http.MethodGet, mfaStatusPath, nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status 未配置应 503，实际 %d", rec.Code)
	}
}

// enroll → verify（用签发的 secret 计算 TOTP）→ status 全链路；审计链落链。
func TestMFAEnrollVerifyStatusFlow(t *testing.T) {
	s := newTestMFAStore(t)
	chain := newAuditTestChain(t, false)
	mux := newMFATestMux(t, s, chain)
	prev := mfaState
	mfaState = s
	t.Cleanup(func() { mfaState = prev })

	// enroll（首次，无需再认证）
	rec := doMFA(t, mux, http.MethodPost, mfaEnrollPath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll 应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	enroll := decodeMFA(t, rec)
	b32, _ := enroll["secret_base32"].(string)
	if b32 == "" {
		t.Fatal("enroll 应返回 secret_base32")
	}
	if codes, _ := enroll["emergency_codes"].([]any); len(codes) != emergencyCodeCnt {
		t.Fatalf("应返回 %d 枚应急码", emergencyCodeCnt)
	}
	if rebound, _ := enroll["rebound"].(bool); rebound {
		t.Fatal("首次绑定 rebound 应为 false")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatalf("解码 base32 失败: %v", err)
	}

	// verify（当前时间片口令）→ 200 且返回带 mfa 声明的重签令牌
	rec = doMFA(t, mux, http.MethodPost, mfaVerifyPath, map[string]string{"code": totpCode(secret, currentTimestep())})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify 应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	verify := decodeMFA(t, rec)
	tok, _ := verify["token"].(string)
	if tok == "" {
		t.Fatal("verify 应返回重签令牌")
	}
	nc, err := verifyInternalToken(tok, testCfg())
	if err != nil {
		t.Fatalf("重签令牌应可校验: %v", err)
	}
	if !nc.MFA || nc.MFAAt == 0 {
		t.Fatalf("重签令牌应带 mfa 声明，实际 %+v", nc)
	}

	// status：已绑定
	rec = doMFA(t, mux, http.MethodGet, mfaStatusPath, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status 应 200，实际 %d", rec.Code)
	}
	st := decodeMFA(t, rec)
	if enrolled, _ := st["enrolled"].(bool); !enrolled {
		t.Fatal("status 应显示已绑定")
	}

	// 审计：至少 mfa_enroll + mfa_verify 各一条
	actions := auditActions(chain)
	if actions[auditActionMFAEnroll] == 0 || actions[auditActionMFAVerify] == 0 {
		t.Fatalf("应落链 mfa_enroll/mfa_verify，实际 %v", actions)
	}
}

// 未绑定账号 verify → 404（如实返回，不静默）。
func TestMFAVerifyUnenrolledReturns404(t *testing.T) {
	s := newTestMFAStore(t)
	chain := newAuditTestChain(t, false)
	mux := newMFATestMux(t, s, chain)
	if rec := doMFA(t, mux, http.MethodPost, mfaVerifyPath, map[string]string{"code": "123456"}); rec.Code != http.StatusNotFound {
		t.Fatalf("未绑定应 404，实际 %d", rec.Code)
	}
}

// 连续失败达阈值 → 锁定（403），并落 mfa_locked 审计。
func TestMFAVerifyLocksAfterMaxFails(t *testing.T) {
	s := newTestMFAStore(t)
	chain := newAuditTestChain(t, false)
	mux := newMFATestMux(t, s, chain)

	s.mu.Lock()
	s.recs[mfaTestSub] = &mfaRecord{SecretSealed: "00", EnrolledAt: time.Now().Unix()}
	// 写入合法密文（用真实 secret 封装，避免解封失败干扰计数路径）。
	secret := []byte("0123456789abcdefghij")
	sealed, err := sealMFASecret(s.masterKey, secret)
	if err != nil {
		s.mu.Unlock()
		t.Fatalf("封装失败: %v", err)
	}
	s.recs[mfaTestSub].SecretSealed = hex.EncodeToString(sealed)
	s.mu.Unlock()

	// 前 mfaMaxFails-1 次 → 401
	for i := 0; i < mfaMaxFails-1; i++ {
		rec := doMFA(t, mux, http.MethodPost, mfaVerifyPath, map[string]string{"code": "000000"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败应 401，实际 %d", i+1, rec.Code)
		}
	}
	// 第 mfaMaxFails 次 → 403 锁定
	rec := doMFA(t, mux, http.MethodPost, mfaVerifyPath, map[string]string{"code": "000000"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("达阈值应 403 锁定，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if actions := auditActions(chain); actions[auditActionMFALocked] == 0 {
		t.Fatalf("应落链 mfa_locked，实际 %v", actions)
	}

	// 锁定后即使口令正确也拒绝（先于校验返回）。
	s.mu.Lock()
	locked := s.recs[mfaTestSub].LockedUntil
	s.mu.Unlock()
	if locked <= time.Now().Unix() {
		t.Fatal("应写入 LockedUntil")
	}
	if rec := doMFA(t, mux, http.MethodPost, mfaVerifyPath, map[string]string{"code": totpCode(secret, currentTimestep())}); rec.Code != http.StatusForbidden {
		t.Fatalf("锁定期内应 403，实际 %d", rec.Code)
	}
}

// 换绑（已绑定）须再认证：无效口令 → 403；有效口令 → 200 且 rebound=true。
func TestMFARebindRequiresCurrentCode(t *testing.T) {
	s := newTestMFAStore(t)
	chain := newAuditTestChain(t, false)
	mux := newMFATestMux(t, s, chain)
	prev := mfaState
	mfaState = s
	t.Cleanup(func() { mfaState = prev })

	// 首次绑定
	if rec := doMFA(t, mux, http.MethodPost, mfaEnrollPath, nil); rec.Code != http.StatusOK {
		t.Fatalf("首次 enroll 应 200，实际 %d", rec.Code)
	}
	s.mu.Lock()
	secret, err := openMFASecret(s.masterKey, mustDecodeHex(s.recs[mfaTestSub].SecretSealed))
	s.mu.Unlock()
	if err != nil {
		t.Fatalf("解封失败: %v", err)
	}

	// 无再认证 → 403
	if rec := doMFA(t, mux, http.MethodPost, mfaEnrollPath, map[string]string{"code": "000000"}); rec.Code != http.StatusForbidden {
		t.Fatalf("换绑无再认证应 403，实际 %d", rec.Code)
	}

	// 有效口令 → 200 且 rebound=true
	rec := doMFA(t, mux, http.MethodPost, mfaEnrollPath, map[string]string{"code": totpCode(secret, currentTimestep())})
	if rec.Code != http.StatusOK {
		t.Fatalf("换绑应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	if rebound, _ := decodeMFA(t, rec)["rebound"].(bool); !rebound {
		t.Fatal("换绑 rebound 应为 true")
	}
}
