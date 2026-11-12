// Package ohttp 最小 OHTTP（Oblivious HTTP）客户端封装（Azure Confidential Inferencing 使用 OHTTP+HPKE 端到端加密）。
//
// M8-1 后实现状态：HPKE 加密核心（Go 1.26 标准库 crypto/hpke，RFC 9180，真实可运行）+
// RFC 9292 binary HTTP 编解码（framing.go）+ RFC 9458 请求/响应封装与响应派生（ohttp_req.go，
// 封装算法逐字对齐 RFC 9458 §4.3/§4.4）。legacy 占位封装路径保留一个版本作回退。
// 设计依据：技术方案《网关侧缺口整改》§5.5 / 设计文档 Azure P1 分支。
//
// 说明：刻意不引入第三方 HPKE/KEM 库——标准库 crypto/hpke 自 Go 1.26 起提供完整 RFC 9180 实现，
// 与本模块 go.mod 声明的 go 1.26.0 一致，且保证离线构建稳定（架构决策：不引入重型 SDK）。
package ohttp

import (
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
)

// hpkeInfoLegacy 为 legacy 封装路径的 HPKE application info（占位实现专用）。
// RFC 9458 正式封装（framing.go + ohttp_req.go，M8-1 已实装）的方向化 info 为
// "message/bhttp request" / "message/bhttp response"（OHTTP_INFO_REQ/OHTTP_INFO_RES 可覆写，
// 见 ohttp_req.go）。legacy 路径保留一个版本作为回退（OHTTP_FRAMING=legacy，技术方案 §5.5），
// 其后删除——不得用于新集成。
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

// PendingDocNote 记录 OHTTP 封装实现状态（M8-1 后：RFC 9458/9292 framing 已实装；
// 本常量仅描述 legacy 占位路径的回退语义，新集成一律使用 RFC 9458 正式封装）。
const PendingDocNote = "legacy 占位封装（OHTTP_FRAMING=legacy 回退路径，保留一个版本）：仅提供 HPKE 加密核心；RFC 9458 binary HTTP framing 与请求/响应封装已在 framing.go / ohttp_req.go 实装（M8-1）。"
