// Package confllm — 配置校验（§7.10 QA2-19，fail-closed）。
//
// 凭据单一通道：所有厂商凭据必须经 SecretRef 指向 broker .env；严禁把明文 key
// 直接写进 ProviderConfig。ValidateConfig 在装配期拦截此类误配（invalid_secret_literal）。
package confllm

import (
	"fmt"
	"strings"
)

// ValidateConfig 校验单个 ProviderConfig（装配期 fail-closed）。
//
// 当前硬护栏：
//   - 配置含字面量 key（LiteralKey 非空）→ invalid_secret_literal，拒绝启动；
//     凭据必须改走 SecretRef（broker .env），绝不明文入配置（§7.10 QA2-19）。
func ValidateConfig(cfg ProviderConfig) error {
	if strings.TrimSpace(cfg.LiteralKey) != "" {
		return NewProviderError(CodeInvalidSecretLiteral, 400,
			fmt.Sprintf("provider %q 配置含字面量 key（禁止）：请改用 SecretRef 指向 broker .env（§7.10 QA2-19）", cfg.ID))
	}
	return nil
}
