package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"security-ai-gateway/gateway/cryptop"
	protocol "security-ai-gateway/protocol/go"
)

// AttestationProof 远程证明载荷
type AttestationProof struct {
	Nonce        []byte            `json:"nonce"`
	Platform     string            `json:"platform"`
	ReportData   []byte            `json:"report_data"` // quote 绑定材料：H(nonce ‖ server_pub)（P1b，防握手公钥替换）
	Quote        []byte            `json:"quote,omitempty"`
	Measurements map[string]string `json:"measurements"`
	SigningKey   []byte            `json:"signing_key"`
	Signature    []byte            `json:"signature"`
}

// Enclave 定义飞地能力的抽象接口
type Enclave interface {
	// Attest 生成证明载荷；reportData 为握手绑定材料（quote report_data，
	// 真实 TDX 下注入 quote 的 REPORTDATA 字段，随证书链根植信任根）。
	Attest(challenge, reportData []byte) (*AttestationProof, error)
	Seal(plaintext []byte, context string) ([]byte, error)
	Unseal(ciphertext []byte, context string) ([]byte, error)
	Measure() ([]byte, error)
	Platform() string
	// rootKey 返回一级根密钥（KEK 封装密钥；§6 封装链）。仅供同进程内
	// cryptop.WrapKey 适配使用，不离开本进程。
	rootKey() []byte
}

// ---------- MockEnclave ----------

const mockSealKeyEnv = "OTPMASK_MOCK_SEAL_KEY"

// MockEnclave 进程内模拟飞地，suite 版本化 AEAD 密封（intl=AES-256-GCM / sm=SM4-GCM），
// 自签证明用于 CI。
type MockEnclave struct {
	sealKey     []byte
	sealKeyRing [][]byte // 历史密封密钥（跨 profile 解旧数据，按序试解）
	measure     []byte
	signKey     *ecdsa.PrivateKey
	platform    string
}

func NewMockEnclave() (*MockEnclave, error) {
	sealKey, err := loadSealKey(mockSealKeyEnv)
	if err != nil {
		return nil, err
	}
	keyRing, err := loadSealKeyHistory(mockSealKeyEnv + "_HISTORY")
	if err != nil {
		return nil, err
	}
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclave: 生成证明签名密钥失败: %w", err)
	}
	// 固定测量值，真实环境用二进制哈希（经 Provider：intl=SHA-256，sm=SM3）
	measure := cryptoProvider.Hash([]byte("mock-enclave-measurement:v1"))
	return &MockEnclave{
		sealKey:     sealKey,
		sealKeyRing: keyRing,
		measure:     measure,
		signKey:     signKey,
		platform:    "mock",
	}, nil
}

// loadSealKey 读取密封密钥（按环境变量名取；空则随机生成）。长度随 profile（intl=32B / sm=16B）。
func loadSealKey(envName string) ([]byte, error) {
	n := cryptoProvider.SymmetricKeySize()
	if v := os.Getenv(envName); v != "" {
		k, err := hex.DecodeString(v)
		if err != nil || len(k) != n {
			return nil, fmt.Errorf("enclave: %s 须为 %d 字节 hex", envName, n)
		}
		return k, nil
	}
	k, err := cryptoProvider.Rand(n)
	if err != nil {
		return nil, fmt.Errorf("enclave: 生成密封密钥失败: %w", err)
	}
	return k, nil
}

// loadSealKeyHistory 读取历史密封密钥环（env 值为冒号分隔的多枚 hex；
// 每枚 32B=AES 或 16B=SM4，可混列）。未设置返回 nil。
func loadSealKeyHistory(envName string) ([][]byte, error) {
	v := os.Getenv(envName)
	if v == "" {
		return nil, nil
	}
	parts := strings.Split(v, ":")
	ring := make([][]byte, 0, len(parts))
	for i, p := range parts {
		k, err := hex.DecodeString(p)
		if err != nil || (len(k) != 32 && len(k) != 16) {
			return nil, fmt.Errorf("enclave: %s 第 %d 项须为 32 或 16 字节 hex", envName, i+1)
		}
		ring = append(ring, k)
	}
	return ring, nil
}

// Platform 返回平台标识。
func (e *MockEnclave) Platform() string { return e.platform }

func (e *MockEnclave) rootKey() []byte { return append([]byte(nil), e.sealKey...) }

// Measure 返回应用测量值（Seal 上下文绑定）。
func (e *MockEnclave) Measure() ([]byte, error) {
	out := make([]byte, len(e.measure))
	copy(out, e.measure)
	return out, nil
}

// sealWithContext 经 cryptop.Provider 密封（AEAD，context 绑定防跨用途解封）。
// 输出格式（B5-a §5.4.3 组⑨）：suite(1) || AAD(HashSize) || nonce(NonceSize) || ciphertext||tag。
// mock 与 tdx 飞地共用同一格式，密封文件可跨实现恢复。
func sealWithContext(sealKey, plaintext []byte, context string) ([]byte, error) {
	suite := cryptoSuite()
	prov, _ := providerForSuite(suite)
	aad := contextHashFor(prov, context)
	nonce, sealed, err := cryptoProvider.SealWithNonce(sealKey, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("enclave: 密封失败: %w", err)
	}
	out := make([]byte, 0, 1+len(aad)+len(nonce)+len(sealed))
	out = append(out, suite)
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// unsealWithContext 解封 suite 版本化密封数据（B5-a）：
// 首字节为已知 suite → 先按新格式解（AEAD tag 认证判别）；
// 任一失败回退旧格式（无前缀，恒 AES-256-GCM，B-5.4-1 fail-safe）。
// 候选密钥：当前 sealKey 优先，历史密钥环按序；仅尝试长度与套件匹配者。
func unsealWithContext(sealKey []byte, keyRing [][]byte, ciphertext []byte, context string) ([]byte, error) {
	if len(ciphertext) > 0 {
		if prov, ok := providerForSuite(ciphertext[0]); ok {
			if plain, err := openWithSuite(prov, ciphertext[1:], sealKey, keyRing, context); err == nil {
				return plain, nil
			}
		}
	}
	plain, err := openWithSuite(hashProvSHA256, ciphertext, sealKey, keyRing, context)
	if err != nil {
		return nil, fmt.Errorf("enclave: 解封失败（数据被篡改、上下文不符或密钥不在环内）: %w", err)
	}
	return plain, nil
}

// openWithSuite 按指定 suite 解析 body（AAD‖nonce‖ct），校验上下文绑定后
// 依次尝试匹配长度的候选密钥；全失败返回最后错误。
func openWithSuite(prov cryptop.Provider, body, sealKey []byte, keyRing [][]byte, context string) ([]byte, error) {
	hs, ns := prov.HashSize(), prov.NonceSize()
	if len(body) < hs+ns+16 { // GCM tag 至少 16 字节
		return nil, errors.New("enclave: 密封数据长度不足")
	}
	aad := body[:hs]
	nonce := body[hs : hs+ns]
	sealed := body[hs+ns:]
	if !bytes.Equal(aad, contextHashFor(prov, context)) {
		return nil, errors.New("enclave: 密封上下文不匹配")
	}
	wantKeyLen := prov.SymmetricKeySize()
	candidates := make([][]byte, 0, 1+len(keyRing))
	if len(sealKey) == wantKeyLen {
		candidates = append(candidates, sealKey)
	}
	for _, k := range keyRing {
		if len(k) == wantKeyLen {
			candidates = append(candidates, k)
		}
	}
	var lastErr error
	for _, k := range candidates {
		plain, err := prov.Open(k, nonce, sealed, aad)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("enclave: 环内无匹配套件长度的密钥")
	}
	return nil, lastErr
}

// providerForSuite 按 suite 字节取固定 provider（与进程 profile 解耦：
// intl 进程须能解 SM4 blob，反之亦然）。
func providerForSuite(suite byte) (cryptop.Provider, bool) {
	switch suite {
	case protocol.SuiteAESGCM:
		return hashProvSHA256, true
	case protocol.SuiteSM4GCM:
		return hashProvSM3, true
	default:
		return nil, false
	}
}

// Seal 经 Provider 密封，context 绑定防止跨用途解封
// 输出格式：suite(1) || AAD(HashSize) || nonce(NonceSize) || ciphertext||tag
func (e *MockEnclave) Seal(plaintext []byte, context string) ([]byte, error) {
	return sealWithContext(e.sealKey, plaintext, context)
}

// Unseal 解封 suite 版本化密封数据（当前密钥 + 历史环 + 旧格式回退）
func (e *MockEnclave) Unseal(ciphertext []byte, context string) ([]byte, error) {
	return unsealWithContext(e.sealKey, e.sealKeyRing, ciphertext, context)
}

// signProofBinding 证明签名（mock 与 tdx 共用）：对 (reportData ‖ signing_pub)
// 的 sha256 做 ECDSA-P256 签名，返回公钥原始点与定长签名（r||s 各 32B）。
func signProofBinding(signKey *ecdsa.PrivateKey, reportData []byte) (signingPub, sig []byte, err error) {
	signingPub = elliptic.Marshal(signKey.PublicKey.Curve, signKey.PublicKey.X, signKey.PublicKey.Y)
	toSign := append(append([]byte(nil), reportData...), signingPub...)
	h := sha256.Sum256(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, signKey, h[:])
	if err != nil {
		return nil, nil, fmt.Errorf("enclave: 自签失败: %w", err)
	}
	return signingPub, encodeSig(r, s), nil
}

// Attest 生成模拟证明，mock 模式 Quote 为空，签名用测试私钥自签。
// 签名覆盖 (reportData ‖ signing_key)：reportData 含 H(nonce‖server_pub)，
// 客户端据此外验握手公钥绑定（真实 TDX 下 reportData 注入 quote REPORTDATA 字段）。
func (e *MockEnclave) Attest(challenge, reportData []byte) (*AttestationProof, error) {
	if len(reportData) == 0 {
		return nil, errors.New("enclave: report_data 为空（握手绑定材料必填）")
	}
	signingPub, sigBytes, err := signProofBinding(e.signKey, reportData)
	if err != nil {
		return nil, err
	}
	return &AttestationProof{
		Nonce:      challenge,
		Platform:   e.platform,
		ReportData: append([]byte(nil), reportData...),
		Measurements: map[string]string{
			"app_hash": hex.EncodeToString(e.measure),
			"runtime":  "mock",
		},
		SigningKey: signingPub,
		Signature:  sigBytes,
	}, nil
}

// contextHashFor 上下文哈希（Seal 的 AAD；由给定 suite 的固定 provider 计算：
// intl=SHA-256，sm=SM3），与进程 profile 解耦。
func contextHashFor(prov cryptop.Provider, context string) []byte {
	return prov.Hash([]byte("otpmask/enclave/ctx/" + context))
}

// encodeSig 编码 ECDSA 签名（r||s 定长，各 32 字节）。
func encodeSig(r, s *big.Int) []byte {
	out := make([]byte, 0, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	// 补齐到 32 字节（P-256 标量域）
	for i := 0; i < 32-len(rb); i++ {
		out = append(out, 0)
	}
	out = append(out, rb...)
	for i := 0; i < 32-len(sb); i++ {
		out = append(out, 0)
	}
	out = append(out, sb...)
	return out
}

// ---------- 平台骨架 ----------

// newPlatformEnclave 真实硬件飞地的注入点。
// tdx：阿里云机密 VM（g8i/g9i）真 TDX Quote（go-tdx-guest；构造期 fail-fast，
// 见 enclave_tdx.go）；sgx 等其余平台待接入。
func newPlatformEnclave(platform string) (Enclave, error) {
	switch platform {
	case "tdx":
		return NewTdxEnclave()
	default:
		return nil, fmt.Errorf("enclave: 平台 %q 实现待硬件接入；开发期使用 mock", platform)
	}
}

// ---------- JSON 辅助 ----------

func (p *AttestationProof) proofJSON() (string, error) {
	m := map[string]any{
		"nonce":        hex.EncodeToString(p.Nonce),
		"platform":     p.Platform,
		"report_data":  hex.EncodeToString(p.ReportData),
		"quote_len":    len(p.Quote),
		"measurements": p.Measurements,
		"signing_key":  hex.EncodeToString(p.SigningKey),
		"signature":    hex.EncodeToString(p.Signature),
	}
	if len(p.Quote) > 0 {
		// 真 TDX Quote 原文（hex；mock 为空不输出），供验证方独立验签（DCAP 链）。
		m["quote"] = hex.EncodeToString(p.Quote)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
