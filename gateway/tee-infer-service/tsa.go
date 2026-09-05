// tsa.go - 可信时间戳服务
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("tsa: 生成密钥失败: %w", err)
	}
	return &MockTSA{key: k}, nil
}

func (m *MockTSA) Sign(messageImprint []byte) (*TST, error) {
	if len(messageImprint) != sha256.Size {
		return nil, errors.New("tsa: message_imprint 须为 32 字节摘要")
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write(messageImprint)
	return &TST{
		Version:        1,
		Algorithm:      "sha256",
		TimestampNS:    time.Now().UnixNano(),
		MessageImprint: hex.EncodeToString(messageImprint),
		Signature:      hex.EncodeToString(mac.Sum(nil)),
		TSAPublicKey:   hex.EncodeToString(sha256.New().Sum(append([]byte(nil), m.key...))[:16]),
		Source:         "mock",
	}, nil
}

// Verify 验证 TST
func (m *MockTSA) Verify(t *TST) error {
	if t == nil {
		return errors.New("tsa: 空 TST")
	}
	if t.Version != 1 || t.Algorithm != "sha256" {
		return errors.New("tsa: 版本/算法不支持")
	}
	imprint, err := hex.DecodeString(t.MessageImprint)
	if err != nil {
		return errors.New("tsa: message_imprint 非 hex")
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write(imprint)
	got, _ := hex.DecodeString(t.Signature)
	if !hmac.Equal(got, mac.Sum(nil)) {
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
