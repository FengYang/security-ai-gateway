// Package ohttp 最小 OHTTP（Oblivious HTTP）客户端封装（Azure Confidential Inferencing 使用 OHTTP+HPKE 端到端加密）。
//
// 本期实现 HPKE 加密核心（基于 Go 1.26 标准库 crypto/hpke，RFC 9180，真实可运行）；OHTTP 二进制 HTTP
// 消息封装为简化占位（pending-doc，待对齐 RFC 9458 的 binary HTTP framing 与 gateway 侧解密代理）。
// 设计依据：§1.4 / 设计文档 Azure P1 分支。
//
// 说明：刻意不引入第三方 HPKE/KEM 库——标准库 crypto/hpke 自 Go 1.26 起提供完整 RFC 9180 实现，
// 与本模块 go.mod 声明的 go 1.26.0 一致，且保证离线构建稳定（架构决策：不引入重型 SDK）。
package ohttp

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
)

// hpkeInfo 为 HPKE 上下文的 application info（RFC 9180 §5.1）。
// 真实部署须与 Azure 机密推理侧约定的 info 保持一致，否则密钥派生不匹配、解密失败。
// pending-doc：Azure 侧 info 约定待官方文档/商务对接确认后替换。
const hpkeInfo = "confllm-ohttp-v1"

// OHClient 基于 HPKE 的最小 OHTTP 客户端。
type OHClient struct {
	kem    hpke.KEM
	kdf    hpke.KDF
	aead   hpke.AEAD
	peerPK hpke.PublicKey
	info   []byte
}

// NewOHClient 以对端 HPKE 公钥字节构造客户端。
// peerPubHPK 为 RFC 9180 SerializePublicKey 输出（DHKEM(X25519, HKDF-SHA256) 下为 32 字节）。
func NewOHClient(peerPubHPK []byte) (*OHClient, error) {
	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.AES128GCM()
	pk, err := kem.NewPublicKey(peerPubHPK)
	if err != nil {
		return nil, fmt.Errorf("解析对端 HPKE 公钥失败: %w", err)
	}
	return &OHClient{kem: kem, kdf: kdf, aead: aead, peerPK: pk, info: []byte(hpkeInfo)}, nil
}

// Encrypt 用随机临时密钥封装并加密明文，返回 encapsulated key + ciphertext。
// 真实场景：客户端用此封装请求体，经 OHTTP proxy 转发至机密推理 enclave。
func (c *OHClient) Encrypt(plaintext []byte) (encapsulated []byte, ciphertext []byte, err error) {
	enc, sender, err := hpke.NewSender(c.peerPK, c.kdf, c.aead, c.info)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 HPKE sender 失败: %w", err)
	}
	// 标准库签名：Seal(aad, plaintext)。
	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("HPKE seal 失败: %w", err)
	}
	return enc, ct, nil
}

// Decrypt 网关/客户端侧用私钥解封（用于响应解密；真实场景由 OHTTP gateway 完成）。
func (c *OHClient) Decrypt(encapsulated, ciphertext []byte, priv hpke.PrivateKey) ([]byte, error) {
	recipient, err := hpke.NewRecipient(encapsulated, priv, c.kdf, c.aead, c.info)
	if err != nil {
		return nil, fmt.Errorf("创建 HPKE recipient 失败: %w", err)
	}
	// 标准库签名：Open(aad, ciphertext)。
	pt, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("HPKE open 失败: %w", err)
	}
	return pt, nil
}

// Seal 单次调用的便捷封装（RFC 9180 §6.1）：返回 encapsulated key || ciphertext 的拼接。
// 供不需要复用上下文（export secret 等）的调用方使用。
func (c *OHClient) Seal(plaintext []byte) ([]byte, error) {
	out, err := hpke.Seal(c.peerPK, c.kdf, c.aead, c.info, plaintext)
	if err != nil {
		return nil, fmt.Errorf("HPKE seal 失败: %w", err)
	}
	return out, nil
}

// PendingDocNote 记录 OHTTP 二进制 HTTP 封装待补全的约定（RFC 9458）。
const PendingDocNote = "OHTTP 二进制 HTTP 消息封装为简化实现（pending-doc）：当前仅提供 HPKE 加密核心，待对齐 RFC 9458 的 binary HTTP framing 与 gateway 侧解密代理。"
