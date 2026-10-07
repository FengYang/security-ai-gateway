package billing

// crypto_runtime.go —— 计费模块密码 provider（P0-4 §5.4.3 组⑬）。
//
// 计费链签名与账本条目哈希**均持久化**（历史账单/账本需长期可验）⇒ 必须"算法标识 + 旧算法可验"
// （B-5.4-1）：签名用既有 wire 前缀 `hmac-sha256:`/`hmac-sm3:` 自述，账本条目用 `hash_alg` 字段自述。
//
// **分派与进程 profile 解耦**：`sha256` 恒取 intl provider、`sm3` 恒取 sm provider——
// 否则 sm 进程算不出缺省（SHA-256）旧条目、intl 进程算不出 sm 条目，"旧数据可验"不成立。
//
// profile 取自 `CRYPTO_PROFILE`（§12.3；默认 intl，与现役 HMAC-SHA256/SHA-256 逐字节等价）。

import (
	"crypto/subtle"
	"encoding/hex"
	"os"
	"strings"

	"security-ai-gateway/gateway/cryptop"
)

var (
	// 固定双 provider（与进程 profile 无关，供双读分派）。
	hashProvSHA256 = mustProv(cryptop.ProfileIntl)
	hashProvSM3    = mustProv(cryptop.ProfileSMSW)
	// 本进程写入端 profile。
	profileProvider = mustProv(cryptoProfile())
)

// cryptoProfile 取本进程 profile（缺省 intl，与现役 SHA-256/HMAC-SHA256 等价）。
func cryptoProfile() cryptop.Profile {
	if p := os.Getenv("CRYPTO_PROFILE"); p != "" {
		return cryptop.Profile(p)
	}
	return cryptop.ProfileIntl
}

func mustProv(p cryptop.Profile) cryptop.Provider {
	prov, err := cryptop.New(p)
	if err != nil {
		panic("billing: 初始化 " + string(p) + " provider 失败: " + err.Error())
	}
	return prov
}

// hashAlgTag 账本条目写入端的 `hash_alg` 取值（intl → ""（缺省 = SHA-256）；sm-* → "sm3"）。
func hashAlgTag() string {
	if profileProvider.Profile() == cryptop.ProfileIntl {
		return ""
	}
	return "sm3"
}

// hmacAlgTag 账单签名写入端的算法前缀（intl → "hmac-sha256"（历史值不变）；sm-* → "hmac-sm3"）。
func hmacAlgTag() string {
	if profileProvider.Profile() == cryptop.ProfileIntl {
		return "hmac-sha256"
	}
	return "hmac-sm3"
}

// macByAlg 按**签名前缀**分派 MAC：仅 `"hmac-sm3"` 判 SM3，其余（含空/未知）一律 SHA-256
// （B-5.4-1：无标识的历史数据按 intl 解析，fail-safe）。
func macByAlg(prefix string, key, data []byte) []byte {
	if prefix == "hmac-sm3" {
		return hashProvSM3.HMAC(key, data)
	}
	return hashProvSHA256.HMAC(key, data)
}

// VerifyEventMAC 校验推送事件签名（`X-Signature: sha256=<hex>`），**兼容 intl↔sm 双算法**（★ SEC-001）。
//
// 头前缀恒为 `sha256=`（既有 wire 契约，不改），但实际 MAC 算法随**发送端** `CRYPTO_PROFILE` 变化。
// 本函数依次以 SHA-256 与 SM3 两种 provider 复算，任一命中即通过（常量时间比较）——
// 从而消除「发送端（tee-infer）与本端 profile 不一致 → 推送全部 401」的部署耦合。
func VerifyEventMAC(secret, body []byte, sig string) bool {
	const prefix = "sha256="
	if len(secret) == 0 || !strings.HasPrefix(sig, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(sig, prefix))
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(got, hashProvSHA256.HMAC(secret, body)) == 1 {
		return true
	}
	// SM3 与 SHA-256 输出长度不同；ConstantTimeCompare 对不等长返回 0（安全）。
	return subtle.ConstantTimeCompare(got, hashProvSM3.HMAC(secret, body)) == 1
}
