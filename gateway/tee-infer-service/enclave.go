package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
}

// ---------- MockEnclave ----------

const mockSealKeyEnv = "OTPMASK_MOCK_SEAL_KEY"

// MockEnclave 进程内模拟飞地，用 AES-256-GCM 做密封，自签证明用于 CI
type MockEnclave struct {
	sealKey  []byte
	measure  []byte
	signKey  *ecdsa.PrivateKey
	platform string
}

func NewMockEnclave() (*MockEnclave, error) {
	sealKey, err := loadSealKey(mockSealKeyEnv)
	if err != nil {
		return nil, err
	}
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclave: 生成证明签名密钥失败: %w", err)
	}
	// 固定测量值，真实环境用二进制哈希
	measure := sha256.Sum256([]byte("mock-enclave-measurement:v1"))
	return &MockEnclave{
		sealKey:  sealKey,
		measure:  measure[:],
		signKey:  signKey,
		platform: "mock",
	}, nil
}

// loadSealKey 读取密封密钥（按环境变量名取；空则随机生成）。
func loadSealKey(envName string) ([]byte, error) {
	if v := os.Getenv(envName); v != "" {
		k, err := hex.DecodeString(v)
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("enclave: %s 须为 32 字节 hex", envName)
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("enclave: 生成密封密钥失败: %w", err)
	}
	return k, nil
}

// Platform 返回平台标识。
func (e *MockEnclave) Platform() string { return e.platform }

// Measure 返回应用测量值（Seal 上下文绑定）。
func (e *MockEnclave) Measure() ([]byte, error) {
	out := make([]byte, len(e.measure))
	copy(out, e.measure)
	return out, nil
}

// gcmSeal AES-256-GCM 密封，context 绑定防止跨用途解封。
// 输出格式：AAD(sha256(context)) || nonce(12) || ciphertext||tag
// （mock 与 tdx 飞地共用同一密封格式，密封文件可跨实现恢复）。
func gcmSeal(sealKey, plaintext []byte, context string) ([]byte, error) {
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, fmt.Errorf("enclave: AES 初始化失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("enclave: GCM 初始化失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("enclave: 生成 nonce 失败: %w", err)
	}
	aad := contextHash(context)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(aad)+len(nonce)+len(sealed))
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// gcmUnseal 解封，验证 AAD 和 GCM tag。
func gcmUnseal(sealKey, ciphertext []byte, context string) ([]byte, error) {
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, fmt.Errorf("enclave: AES 初始化失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("enclave: GCM 初始化失败: %w", err)
	}
	hs := sha256.Size
	if len(ciphertext) < hs+gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("enclave: 密封数据长度不足")
	}
	aad := ciphertext[:hs]
	nonce := ciphertext[hs : hs+gcm.NonceSize()]
	sealed := ciphertext[hs+gcm.NonceSize():]
	// AAD 就是 context 哈希本身，直接比较
	wantAAD := contextHash(context)
	if !bytes.Equal(aad, wantAAD) {
		return nil, errors.New("enclave: 密封上下文不匹配")
	}
	plain, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("enclave: 解封失败（数据被篡改或密钥不符）: %w", err)
	}
	return plain, nil
}

// Seal 用 AES-256-GCM 密封，context 绑定防止跨用途解封
// 输出格式：AAD(sha256(context)) || nonce(12) || ciphertext||tag
func (e *MockEnclave) Seal(plaintext []byte, context string) ([]byte, error) {
	return gcmSeal(e.sealKey, plaintext, context)
}

// Unseal 解封，验证 AAD 和 GCM tag
func (e *MockEnclave) Unseal(ciphertext []byte, context string) ([]byte, error) {
	return gcmUnseal(e.sealKey, ciphertext, context)
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

// contextHash 上下文哈希（Seal 的 AAD 前缀）。
func contextHash(context string) []byte {
	h := sha256.Sum256([]byte("otpmask/enclave/ctx/" + context))
	return h[:]
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
