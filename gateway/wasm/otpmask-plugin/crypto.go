package main

import (
	"fmt"
)

// 向量 OTP-Mask 加解密核心（PRG 求值下沉 cryptop sidecar，插件零密码，P0-4 §5.4.5）。
//
// 加解密协议（模算术保留在插件；掩码流由 sidecar `/v1/mask/stream` 产出）：
//
//	加密：cipher[i] = (plain[i] + PRG(seed, i)) mod R
//	解密：plain[i] = (cipher[i] - PRG(seed, i)) mod R
//
// 同一 seed + 相同遍历顺序（counter 从 0 递增）保证加解密对称。
// M2 使用与 secagg 一致的模数 R = 2^32（DefaultModulus 对齐）。
//
// v1.9（R4·方案 A）：本文件不再 import `cipher/mask`——seed 由调用方传入，PRG 求值经
// `CryptoClient.MaskStream`（§4.3.7），插件只做模算术（§9.1「Wasm 零密码」门禁 1）。

// defaultMaskModulus 默认掩码模 R = 2^32（与技术方案 精度量化对齐）。
const defaultMaskModulus uint64 = 1 << 32

// guardrailTextDomain 文本密文通道域分离标签（与 tee-infer-service 一致）。
var guardrailTextDomain = []byte("otpmask/guardrail-text/v1")

// maskKeystream 经 cryptop sidecar `/v1/mask/stream` 取 count 个 [0,r) 掩码元素（CPS）。
// 插件零密码：PRG 求值在 sidecar；sidecar 不可用 → 拒绝（fail-closed，无本地回退，C-4/R-11）。
func maskKeystream(seed []byte, r uint64, domain []byte, count int, cb func(vals []uint64, err error)) {
	if !cryptoUsable() {
		cb(nil, errCryptoUnavailable)
		return
	}
	CryptoClient.MaskStream(seed, domain, count, r, cb)
}

// maskVector 用 seed 派生掩码流，对明文向量逐元素加密（向量加法掩码，CPS）。
// counter 从 0 开始递增，与 unmaskVector 的遍历顺序必须一致。
func maskVector(seed []byte, r uint64, vec []uint64, cb func(out []uint64, err error)) {
	maskKeystream(seed, r, nil, len(vec), func(vals []uint64, err error) {
		if err != nil {
			cb(nil, fmt.Errorf("otpmask: 取掩码流失败: %w", err))
			return
		}
		out := make([]uint64, len(vec))
		for i, x := range vec {
			if x >= r {
				cb(nil, fmt.Errorf("otpmask: 明文分量 %d 越界（>= R=%d）", x, r))
				return
			}
			out[i] = (x + vals[i]) % r
		}
		cb(out, nil)
	})
}

// unmaskVector 用同一 seed 派生掩码流，对密文向量逐元素解密（CPS）。
// 遍历顺序必须与 maskVector 完全一致（counter 从 0 递增）。
func unmaskVector(seed []byte, r uint64, vec []uint64, cb func(out []uint64, err error)) {
	maskKeystream(seed, r, nil, len(vec), func(vals []uint64, err error) {
		if err != nil {
			cb(nil, fmt.Errorf("otpmask: 取掩码流失败: %w", err))
			return
		}
		out := make([]uint64, len(vec))
		for i, c := range vec {
			if c >= r {
				cb(nil, fmt.Errorf("otpmask: 密文分量 %d 越界（>= R=%d）", c, r))
				return
			}
			// (c - m) mod R，避免无符号下溢
			out[i] = (c + r - vals[i]%r) % r
		}
		cb(out, nil)
	})
}

// maskVectors 批量加密二维向量（每个向量独立掩码流，counter 从头开始，CPS 串行）。
func maskVectors(seed []byte, r uint64, vecs [][]uint64, cb func(out [][]uint64, err error)) {
	out := make([][]uint64, len(vecs))
	var step func(i int)
	step = func(i int) {
		if i >= len(vecs) {
			cb(out, nil)
			return
		}
		maskVector(seed, r, vecs[i], func(enc []uint64, err error) {
			if err != nil {
				cb(nil, fmt.Errorf("otpmask: 加密向量 %d 失败: %w", i, err))
				return
			}
			out[i] = enc
			step(i + 1)
		})
	}
	step(0)
}

// maskText OTP-Mask 逐字节加密文本（M9-4 guardrail 密文通道，CPS）。
// 使用域分离派生流，与向量掩码流互不干扰；TEE 侧按同域解密检测。
func maskText(seed []byte, text string, cb func(out []byte, err error)) {
	maskKeystream(seed, 256, guardrailTextDomain, len(text), func(vals []uint64, err error) {
		if err != nil {
			cb(nil, fmt.Errorf("otpmask: 取文本掩码流失败: %w", err))
			return
		}
		out := make([]byte, len(text))
		for i := 0; i < len(text); i++ {
			m := vals[i] % 256
			out[i] = byte((int(text[i]) + int(m)) % 256)
		}
		cb(out, nil)
	})
}
