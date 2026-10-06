package mcpsec

// crypto_runtime.go —— 进程级密码 provider（P0-4 §5.4.4 组⑫ MCP 工具目录/调用凭证签名）。
// profile 取自 `CRYPTO_PROFILE`（§12.3；默认 intl，与现役 HMAC-SHA256 逐字节等价）。

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
		panic("mcpsec: 初始化 cryptop provider 失败（CRYPTO_PROFILE=" + profile + "）: " + err.Error())
	}
	return p
}
