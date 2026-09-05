package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"security-ai-gateway/protocol/go"
)

// 会话密钥有效期，跟主密钥轮换对齐
const sessionTTL = 5 * time.Minute

const sessionInfo = "otpmask/session/v1"

// KDF 域分离标签
var kdfPurpose = map[string]string{
	"sig": "otpmask/kdf/sig/v1",
	"enc": "otpmask/kdf/enc/v1",
}

type teeSession struct {
	ID         string
	Nonce      []byte
	ServerPriv *ecdh.PrivateKey
	K_sig      []byte
	K_enc      []byte
	CreatedAt  time.Time
	Completed  bool

	// P1c：段① 信封通道状态（服务端侧）。独立于 teeServer.mu——
	// 会话从 map 取出后由各 handler 并发使用，信封计数器/窗口须自持锁。
	envMu       sync.Mutex
	sendCounter uint64                 // s2c 单调计数器（下一信封取值，从 1 起）
	recvWindow  protocol.CounterWindow // c2s 反重放滑动窗口（/key/issue 与 /v1/infer 共用）
}

func newSession(nonce []byte) (*teeSession, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("session: 生成 X25519 密钥失败: %w", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("session: 生成会话 ID 失败: %w", err)
	}
	return &teeSession{
		ID:         hex.EncodeToString(id),
		Nonce:      nonce,
		ServerPriv: priv,
		CreatedAt:  time.Now(),
	}, nil
}

// ServerPub 返回服务端 ECDH 公钥字节。
func (s *teeSession) ServerPub() []byte {
	return s.ServerPriv.PublicKey().Bytes()
}

// Complete 客户端公钥到达后做 ECDH + HKDF 派生会话密钥
func (s *teeSession) Complete(clientPubBytes []byte) error {
	if s.Completed {
		return errors.New("session: 会话已完成（不可重复 complete）")
	}
	pub, err := ecdh.X25519().NewPublicKey(clientPubBytes)
	if err != nil {
		return fmt.Errorf("session: 客户端公钥无效: %w", err)
	}
	shared, err := s.ServerPriv.ECDH(pub)
	if err != nil {
		return fmt.Errorf("session: ECDH 失败: %w", err)
	}
	sessionKey := hkdfSHA256(shared, s.Nonce, []byte(sessionInfo), 32)
	s.K_sig = kdf(sessionKey, "sig")
	s.K_enc = kdf(sessionKey, "enc")
	s.Completed = true
	// P1c：信封通道就绪（s2c 计数器从 1 起，c2s 反重放窗口清零——新会话 nonce 空间全新）
	s.envMu.Lock()
	s.sendCounter = 1
	s.recvWindow = protocol.CounterWindow{}
	s.envMu.Unlock()
	// 派生完就销毁共享秘密和私钥
	wipe(shared)
	wipe(sessionKey)
	s.ServerPriv = nil
	return nil
}

// ---------- 段① 信封通道（P1c：解密入口 / 加密出口） ----------

// sealPayload 以会话 K_enc 加密 s2c 载荷（响应出口；计数器单调递增保证 nonce 唯一，
// 跨端点共享计数器——AAD 中的 endpoint 防跨端点重放）。
func (s *teeSession) sealPayload(endpoint string, plaintext []byte) ([]byte, error) {
	s.envMu.Lock()
	defer s.envMu.Unlock()
	if !s.Completed || len(s.K_enc) != 32 {
		return nil, errors.New("session: 会话未完成或 K_enc 缺失")
	}
	counter := s.sendCounter
	s.sendCounter++
	return protocol.SealEnvelope(s.K_enc, s.ID, endpoint, protocol.DirectionS2C, counter, plaintext)
}

// openPayload 解密 c2s 信封并做反重放窗口校验（请求入口；重放/越窗拒绝）。
func (s *teeSession) openPayload(endpoint string, wire []byte) ([]byte, error) {
	s.envMu.Lock()
	defer s.envMu.Unlock()
	if !s.Completed || len(s.K_enc) != 32 {
		return nil, errors.New("session: 会话未完成或 K_enc 缺失")
	}
	pt, counter, err := protocol.OpenEnvelope(s.K_enc, s.ID, endpoint, protocol.DirectionC2S, wire)
	if err != nil {
		return nil, err
	}
	if err := s.recvWindow.Check(counter); err != nil {
		return nil, err
	}
	return pt, nil
}

// destroy 会话终止：零化会话密钥（K_sig/K_enc 用后零化，best-effort——
// Go GC 下切片拷贝不可控，威胁模型如实声明，P3 威胁模型文档同步）。
func (s *teeSession) destroy() {
	s.envMu.Lock()
	defer s.envMu.Unlock()
	wipe(s.K_sig)
	wipe(s.K_enc)
	s.K_sig = nil
	s.K_enc = nil
	s.Completed = false
	s.sendCounter = 0
	s.recvWindow = protocol.CounterWindow{}
}

// kdf 从会话密钥派生 sig/enc 用途密钥
func kdf(sessionKey []byte, purpose string) []byte {
	info, ok := kdfPurpose[purpose]
	if !ok {
		panic("session: 未知 KDF 用途: " + purpose)
	}
	return hkdfSHA256(sessionKey, nil, []byte(info), 32)
}

// hkdfSHA256 RFC 5869 HKDF-SHA256
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	// 标准库没有直接暴露 hkdf，这里手写 extract+expand
	prk := hmacSHA256(salt, ikm)
	out := make([]byte, 0, length)
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	wipe(prk)
	return out[:length]
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ---------- 验证链 ----------

// reportDataBinding quote report_data 绑定材料：H(nonce ‖ server_pub)。
// 双端一致（插件侧 attest.go 同名函数），防中间人替换握手公钥。
func reportDataBinding(nonce, serverPub []byte) []byte {
	h := sha256.New()
	h.Write(nonce)
	h.Write(serverPub)
	return h.Sum(nil)
}

// VerifyAttestationProof 验证证明载荷，失败即拒绝。
// expectedReportData 为客户端期望的绑定材料 H(nonce ‖ server_pub)（非空时强校验）。
func VerifyAttestationProof(proof *AttestationProof, expectedAppHash string, expectedReportData []byte) error {
	if proof == nil {
		return errors.New("attest: 空证明载荷")
	}
	if len(proof.Nonce) == 0 {
		return errors.New("attest: 证明载荷缺少 nonce")
	}
	if len(proof.ReportData) == 0 {
		return errors.New("attest: 证明缺少 report_data（握手公钥绑定）")
	}
	if len(expectedReportData) > 0 && subtle.ConstantTimeCompare(proof.ReportData, expectedReportData) != 1 {
		return errors.New("attest: report_data 与 H(nonce‖server_pub) 不匹配（疑似握手公钥被替换）")
	}
	switch proof.Platform {
	case "mock", "tdx", "sgx", "nv-cc":
	default:
		return fmt.Errorf("attest: 未知平台 %q", proof.Platform)
	}
	got := proof.Measurements["app_hash"]
	if expectedAppHash != "" && !constTimeEqualHex(got, expectedAppHash) {
		return errors.New("attest: app_hash 与期望测量值不匹配")
	}
	// 验签
	if err := verifyProofSignature(proof); err != nil {
		return err
	}
	return nil
}

// constTimeEqualHex 常量时间 hex 比较
func constTimeEqualHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// verifyProofSignature 校验证明签名（覆盖 report_data ‖ signing_key，P1b 绑定升级）
func verifyProofSignature(proof *AttestationProof) error {
	pub, err := parseP256Pub(proof.SigningKey)
	if err != nil {
		return err
	}
	toSign := append(append([]byte(nil), proof.ReportData...), proof.SigningKey...)
	h := sha256.Sum256(toSign)
	ok, err := verifyP256Sig(pub, h[:], proof.Signature)
	if err != nil {
		return fmt.Errorf("attest: 签名校验失败: %w", err)
	}
	if !ok {
		return errors.New("attest: 证明签名无效")
	}
	return nil
}

// ---------- 客户端 ECDH 辅助 ----------

func newClientSession() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// deriveClientSessionKey 客户端派生会话密钥，跟服务端 Complete 对称
func deriveClientSessionKey(clientPriv *ecdh.PrivateKey, serverPubBytes, nonce []byte) (ksig, kenc []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("session: 服务端公钥无效: %w", err)
	}
	shared, err := clientPriv.ECDH(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("session: 客户端 ECDH 失败: %w", err)
	}
	sessionKey := hkdfSHA256(shared, nonce, []byte(sessionInfo), 32)
	ksig = kdf(sessionKey, "sig")
	kenc = kdf(sessionKey, "enc")
	wipe(shared)
	wipe(sessionKey)
	return ksig, kenc, nil
}

func randomNonce() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---------- P-256 验签辅助 ----------

func parseP256Pub(raw []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil {
		return nil, errors.New("attest: signing_key 非 P-256 公钥")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func verifyP256Sig(pub *ecdsa.PublicKey, digest, sig []byte) (bool, error) {
	if len(sig) != 64 {
		return false, errors.New("attest: 签名长度须为 64 字节")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest, r, s), nil
}
