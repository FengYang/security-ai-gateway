// tsa.go - 可信时间戳服务
package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// tstAlgorithm TST 签名算法标识（P0-4 §5.4.1 组⑥ / §5.2.2「`TST.Algorithm` 版本化」）。
// intl 档保持历史值 `sha256`（**intl TST 逐字节不变**）；sm 档为 `sm3`。
// 验签按 §5.2.2 判定口径分派：**仅** `=="sm3"` 判 SM3；空/其它值一律按 SHA-256（fail-safe）。
func tstAlgorithm() string {
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		return "sha256"
	}
	return "sm3"
}

// TST 时间戳令牌
type TST struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	TimestampNS    int64  `json:"timestamp_ns"`
	MessageImprint string `json:"message_imprint"`
	Signature      string `json:"signature"`
	TSAPublicKey   string `json:"tsa_public_key"`
	Source         string `json:"source"`
}

// TSASigner 时间戳签名接口
type TSASigner interface {
	Sign(messageImprint []byte) (*TST, error)
	Verify(t *TST) error
}

// ---------- MockTSA ----------

// MockTSA 本地 TSA，HMAC-SHA256 自签
type MockTSA struct {
	key []byte
}

func NewMockTSA() (*MockTSA, error) {
	k, err := cryptoProvider.Rand(32)
	if err != nil {
		return nil, fmt.Errorf("tsa: 生成密钥失败: %w", err)
	}
	return &MockTSA{key: k}, nil
}

func (m *MockTSA) Sign(messageImprint []byte) (*TST, error) {
	if len(messageImprint) != cryptoProvider.HashSize() {
		return nil, fmt.Errorf("tsa: message_imprint 须为 %d 字节摘要", cryptoProvider.HashSize())
	}
	mac, merr := hmacByAlg(hashAlgTag(), m.key, messageImprint)
	if merr != nil {
		return nil, fmt.Errorf("tsa: MAC 计算失败: %w", merr)
	}
	// TSAPublicKey = 密钥指纹（Hash(key)），**仅供标识，绝不暴露密钥字节**。
	// 修复 F-9/U-7：原式 `sha256.New().Sum(append([]byte(nil), m.key...))[:16]` 的 Sum 语义为
	// "把当前（空输入的）摘要附加到入参之后"，故其返回值前 16 字节 = HMAC key 的前 16 字节，
	// 直接把密钥写进公开 TST —— 属泄密缺陷。
	fp, _ := hashByAlg(hashAlgTag(), m.key)
	return &TST{
		Version:        1,
		Algorithm:      tstAlgorithm(),
		TimestampNS:    time.Now().UnixNano(),
		MessageImprint: hex.EncodeToString(messageImprint),
		Signature:      hex.EncodeToString(mac),
		TSAPublicKey:   hex.EncodeToString(fp),
		Source:         "mock",
	}, nil
}

// Verify 验证 TST。算法按 §5.2.2 判定口径分派：**仅** `Algorithm=="sm3"` 判 SM3；
// 空/其它值一律按 SHA-256（fail-safe 默认，防伪造字段绕过）；未知算法必然导致 MAC 不符而拒绝。
func (m *MockTSA) Verify(t *TST) error {
	if t == nil {
		return errors.New("tsa: 空 TST")
	}
	if t.Version != 1 {
		return errors.New("tsa: 版本不支持")
	}
	imprint, err := hex.DecodeString(t.MessageImprint)
	if err != nil {
		return errors.New("tsa: message_imprint 非 hex")
	}
	alg := ""
	if t.Algorithm == "sm3" {
		alg = "sm3"
	}
	mac, merr := hmacByAlg(alg, m.key, imprint)
	if merr != nil {
		return errors.New("tsa: TST 签名无效（时间戳被篡改）")
	}
	got, _ := hex.DecodeString(t.Signature)
	if subtle.ConstantTimeCompare(got, mac) != 1 {
		return errors.New("tsa: TST 签名无效（时间戳被篡改）")
	}
	return nil
}

// ---------- HTTPTSA（生产预留） ----------

// HTTPTSA 对接外部 TSA 服务，接口预留
type HTTPTSA struct {
	Endpoint string
}

func (h *HTTPTSA) Sign(messageImprint []byte) (*TST, error) {
	return nil, errors.New("tsa: 外部 TSA 接入待部署（当前使用 mock 模式）")
}

func (h *HTTPTSA) Verify(t *TST) error {
	return errors.New("tsa: 外部 TSA 验证待部署")
}

func marshalTST(t *TST) ([]byte, error) {
	return json.Marshal(t)
}

func unmarshalTST(data []byte) (*TST, error) {
	var t TST
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
