package main

import (
	"fmt"

	"security-ai-gateway/cipher/mask"
)

// 向量 OTP-Mask 加解密核心（复用 cipher/mask 的 HMAC-SHA256 掩码流）。
//
// 加解密协议：
//
//	加密：cipher[i] = (plain[i] + PRG(seed, i)) mod R
//	解密：plain[i] = (cipher[i] - PRG(seed, i)) mod R
//
// 同一 seed + 相同遍历顺序（counter 从 0 递增）保证加解密对称。
// M2 使用与 secagg 一致的模数 R = 2^32（DefaultModulus 对齐）。

// defaultMaskModulus 默认掩码模 R = 2^32（与技术方案 精度量化对齐）。
const defaultMaskModulus uint64 = 1 << 32

// maskVector 用 seed 派生掩码流，对明文向量逐元素加密（向量加法掩码）。
// counter 从 0 开始递增，与 unmaskVector 的遍历顺序必须一致。
func maskVector(seed []byte, r uint64, vec []uint64) ([]uint64, error) {
	if len(seed) < mask.MinSeedLen {
		return nil, fmt.Errorf("otpmask: seed 长度 %d 小于最小值 %d", len(seed), mask.MinSeedLen)
	}
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, fmt.Errorf("otpmask: 构造掩码流失败: %w", err)
	}
	out := make([]uint64, len(vec))
	for i, x := range vec {
		if x >= r {
			return nil, fmt.Errorf("otpmask: 明文分量 %d 越界（>= R=%d）", x, r)
		}
		m := s.Next()
		out[i] = (x + m) % r
	}
	return out, nil
}

// unmaskVector 用同一 seed 派生掩码流，对密文向量逐元素解密。
// 遍历顺序必须与 maskVector 完全一致（counter 从 0 递增）。
func unmaskVector(seed []byte, r uint64, vec []uint64) ([]uint64, error) {
	if len(seed) < mask.MinSeedLen {
		return nil, fmt.Errorf("otpmask: seed 长度 %d 小于最小值 %d", len(seed), mask.MinSeedLen)
	}
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, fmt.Errorf("otpmask: 构造掩码流失败: %w", err)
	}
	out := make([]uint64, len(vec))
	for i, c := range vec {
		if c >= r {
			return nil, fmt.Errorf("otpmask: 密文分量 %d 越界（>= R=%d）", c, r)
		}
		m := s.Next()
		// (c - m) mod R，避免无符号下溢
		out[i] = (c + r - m%r) % r
	}
	return out, nil
}

// maskVectors 批量加密二维向量（每个向量独立掩码流，counter 从头开始）。
func maskVectors(seed []byte, r uint64, vecs [][]uint64) ([][]uint64, error) {
	out := make([][]uint64, len(vecs))
	for i, v := range vecs {
		enc, err := maskVector(seed, r, v)
		if err != nil {
			return nil, fmt.Errorf("otpmask: 加密向量 %d 失败: %w", i, err)
		}
		out[i] = enc
	}
	return out, nil
}

// guardrailTextDomain 文本密文通道域分离标签（与 tee-infer-service 一致）。
var guardrailTextDomain = []byte("otpmask/guardrail-text/v1")

// maskText OTP-Mask 逐字节加密文本（M9-4 guardrail 密文通道）。
// 使用域分离派生流，与向量掩码流互不干扰；TEE 侧按同域解密检测。
func maskText(seed []byte, text string) ([]byte, error) {
	if len(seed) < mask.MinSeedLen {
		return nil, fmt.Errorf("otpmask: seed 长度 %d 小于最小值 %d", len(seed), mask.MinSeedLen)
	}
	s, err := mask.NewStreamDomain(seed, 256, guardrailTextDomain)
	if err != nil {
		return nil, fmt.Errorf("otpmask: 构造文本掩码流失败: %w", err)
	}
	out := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		m := s.Next() % 256
		out[i] = byte((int(text[i]) + int(m)) % 256)
	}
	return out, nil
}
