package main

// crypto_runtime.go —— 进程级密码 provider（P0-4 §5.4.4 组⑪）。
// profile 取自 `CRYPTO_PROFILE`（§12.3；默认 intl，与现役 HMAC-SHA256 逐字节等价）。
//
// sm-module 装配（P1-5 M3，2026-10-12）：`CRYPTO_PROFILE=sm-module` 时经 `MODULE_*`
// 环境变量构造模块后端；厂商 SDK 未接入/配置缺失 → panic（启动拒，C-3）。本文件零改动。

import (
	"os"

	"security-ai-gateway/gateway/cryptop"
)

var cryptoProvider = newCryptoProvider()

func newCryptoProvider() cryptop.Provider {
	profile := os.Getenv("CRYPTO_PROFILE")
	if profile == "" {
		profile = string(cryptop.ProfileIntl)
	}
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		panic("auth-service: 初始化 cryptop provider 失败（CRYPTO_PROFILE=" + profile + "）: " + err.Error())
	}
	return p
}
