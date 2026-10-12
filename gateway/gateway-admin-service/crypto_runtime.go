package main

// crypto_runtime.go —— 管理面进程级密码 provider（P0-4 §5.4.4 组⑪⑫/§12.3）。
//
// 定位：Go 服务侧**内联**（in-process）使用 `cryptop`，不经 sidecar（sidecar 只服务 Wasm 插件，
// B-4.6-1/R-7）。profile 取自环境变量 `CRYPTO_PROFILE`（§12.3 `crypto_profile`，
// 须与 sidecar 一致，R-17 延伸）。
//
// **sm-module 装配（P1-5 M3，2026-10-12）**：`CRYPTO_PROFILE=sm-module` 时由 `cryptop.New`
// 经 `MODULE_*` 环境变量构造模块后端（sdf/pkcs11）；厂商 SDK 未接入/配置缺失 → panic
// （启动拒，C-3）。本文件对 sm-module **零代码改动**（env 驱动 + 启动拒即装配校验）。
//
// **零行为变更约束（intl）**：intl 档下 Provider 与现役 stdlib 逐字节等价
// （HMAC-SHA256 / SHA-256），故替换后既有 token/签名/指纹不变。
//
// ⚠️ **标识类字段例外**：`keyFingerprint`（凭据指纹，API 可见、跨服务引用）**恒 SHA-256**，
// 不随 profile 迁移（与审计链 §5.2.2 的 `KeyFingerprint` 口径一致）。

import (
	"fmt"
	"log"
	"os"

	"security-ai-gateway/gateway/cryptop"
)

// cryptoProvider 进程级密码原语入口。默认 intl（与现役 stdlib 逐字节等价）；
// 包级默认值使单测路径（不经 main）天然可用。
var cryptoProvider = defaultCryptoProvider()

func defaultCryptoProvider() cryptop.Provider {
	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		panic("crypto: 初始化 intl provider 失败: " + err.Error())
	}
	return p
}

// initCryptoRuntime 按 `CRYPTO_PROFILE` 装配进程级 provider（非法档 → 返回错误，调用方 fail-closed）。
func initCryptoRuntime() error {
	profile := os.Getenv("CRYPTO_PROFILE")
	if profile == "" {
		profile = string(cryptop.ProfileIntl)
	}
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		return fmt.Errorf("crypto: CRYPTO_PROFILE=%q 不可用: %w", profile, err)
	}
	cryptoProvider = p
	log.Printf("[crypto] 管理面已装配 profile=%s note=%q", p.Profile(), p.ComplianceNote())
	return nil
}

// hashAlgTag 管理面写入审计事件时的 `hash_alg` 取值（intl → ""（缺省=SHA-256），sm-* → "sm3"）。
func hashAlgTag() string {
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		return "" // R-13：缺省即 SHA-256，不写字段以保旧链行逐字节不变
	}
	return "sm3"
}
