package main

// crypto_runtime.go —— tee-infer 进程级 `cryptop.Provider` 装配（P0-4 §5.4.4 组①③⑥⑦/§12.3）。
//
// 定位：Go 服务侧**内联**（in-process）使用 `cryptop`，不经 sidecar（sidecar 只服务 Wasm 插件，
// B-4.6-1/R-7）。profile 是**配置**（`-crypto-profile`）而非编译开关（§11.5）。
//
// **零行为变更约束（intl）**：intl 档下 `Provider` 的实现与现役 stdlib 逐字节等价
// （X25519 / HKDF-SHA256 / HMAC-SHA256 / SHA-256 / AES-256-GCM），故替换后既有 wire/密文不变。
//
// 例外（§5.4.2，**不迁移**）：证明链（quote 自签 + 验签 + 绑定材料哈希）恒 P-256/SHA-256——
// 相关文件（`enclave.go`/`enclave_tdx.go` 的自签、`session.go` 的 `reportDataBinding`）
// 如实保留 stdlib 密码 import，见 v1.10 变更记录。

import (
	"encoding/hex"
	"fmt"
	"log"

	"security-ai-gateway/gateway/cryptop"
	protocol "security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// cryptoProvider 进程级密码原语入口（§5.4.4）。默认 intl（与现役 stdlib 逐字节等价）；
// 由 `initCryptoRuntime` 按 `-crypto-profile` 覆盖。**包级默认值**使各服务构造路径
// （含单测直接构造 server，不经 main）天然可用，无需显式注入。
var cryptoProvider = defaultCryptoProvider()

// cryptoMaskPRG 掩码 PRG 档（§5.3.2 选择点，`-mask-prg`）。B2 仅装配与校验；
// 消费点（`recompute.go` 掩码流派生）随 B4 接线。
var cryptoMaskPRG = ""

func defaultCryptoProvider() cryptop.Provider {
	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		// intl 为合法 profile，仅当构造器被破坏才会失败——启动期 fail-fast 优于静默降级。
		panic("crypto: 初始化 intl provider 失败: " + err.Error())
	}
	return p
}

// initCryptoRuntime 按配置装配进程级 provider 与掩码 PRG 档。
//
// 校验（R-2/R-14/R-21）：
//   - profile 非法 / sm-module（ErrNotImplemented）→ 返回错误（**启动拒**，绝不回退软件实现冒充合规）；
//   - `mask_prg=bridge` 且 profile=intl → 返回错误（R-21①，intl 无 SM4 实现）；
//   - `mask_prg=bridge` 且 profile=sm-* → 允许，但**启动告警**（R-21②）。
func initCryptoRuntime(profile, maskPRG string) error {
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		return fmt.Errorf("crypto: crypto_profile=%q 不可用: %w", profile, err)
	}
	if maskPRG == "" {
		if p.Profile() == cryptop.ProfileIntl {
			maskPRG = "hmac-sha256"
		} else {
			maskPRG = "sm4"
		}
	}
	switch maskPRG {
	case "hmac-sha256", "sm4":
	case "bridge":
		if p.Profile() == cryptop.ProfileIntl {
			return fmt.Errorf("crypto: mask_prg=bridge 须 profile ∈ {sm-software, sm-module}（R-21①；intl 无 SM4 实现）")
		}
		log.Printf("[crypto] WARN mask_prg=bridge 迁移桥接档已启用（R-21②：profile=%s 经 hmacPRG 产 HMAC-SHA256 流）", p.Profile())
	default:
		return fmt.Errorf("crypto: mask_prg=%q 非法（须 hmac-sha256|sm4|bridge，R-14）", maskPRG)
	}
	cryptoProvider = p
	cryptoMaskPRG = maskPRG
	// §5.1：suite↔provider 绑死；sm 档须注册 SM4-GCM 套件（AES 套件为内置缺省，恒可用）。
	if p.Profile() != cryptop.ProfileIntl {
		if err := cryptoops.RegisterSM4Suite(p); err != nil {
			return fmt.Errorf("crypto: 注册 SM4-GCM 套件失败: %w", err)
		}
	}
	log.Printf("[crypto] 已装配 profile=%s mask_prg=%s note=%q", p.Profile(), maskPRG, p.ComplianceNote())
	return nil
}

// cryptoSuite 本进程信封套件（§5.1：suite↔provider 绑死）。intl=AES-256-GCM（内置）；
// sm-*=SM4-GCM（须先经 `initCryptoRuntime` 注册）。intl 档下 `SealEnvelopeWithSuite(..., SuiteAESGCM, ...)`
// 与既有 `SealEnvelope` 逐字节等价。
func cryptoSuite() byte {
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		return protocol.SuiteAESGCM
	}
	return protocol.SuiteSM4GCM
}

// ---- 审计链算法分派（P0-4 §5.2.2）----
//
// `hash_alg` 为**逐事件**自述（R-13：缺省/空 = SHA-256；"sm3" = SM3；R-12：未知值 → 验证失败）。
// 分派必须**与进程 profile 无关**：intl 进程要能复算 sm 事件、sm 进程要能复算"缺省 = SHA-256"事件
// ⇒ 固定两份 provider（SHA-256 恒取 intl；SM3 恒取 sm），不得用 `cryptoProvider`（随 profile 漂移）。
var (
	hashProvSHA256 = mustProvider(cryptop.ProfileIntl)
	hashProvSM3    = mustProvider(cryptop.ProfileSMSW)
)

func mustProvider(p cryptop.Profile) cryptop.Provider {
	prov, err := cryptop.New(p)
	if err != nil {
		panic("crypto: 初始化 " + string(p) + " provider 失败: " + err.Error())
	}
	return prov
}

// hashAlgTag 本进程写入事件时的 `hash_alg` 取值（intl → ""（缺省=SHA-256），sm-* → "sm3"）。
func hashAlgTag() string {
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		return "" // R-13：缺省即 SHA-256，不写字段以保 WORM 旧行逐字节不变
	}
	return "sm3"
}

// hashByAlg 按事件自述算法哈希；未知值返回错误（R-12，绝不静默回退 SHA-256）。
func hashByAlg(alg string, data []byte) ([]byte, error) {
	switch alg {
	case "":
		return hashProvSHA256.Hash(data), nil
	case "sm3":
		return hashProvSM3.Hash(data), nil
	default:
		return nil, fmt.Errorf("crypto: 未知 hash_alg %q（R-12：验证失败，不得回退 SHA-256）", alg)
	}
}

// hashHexByAlg 同上，返回 hex。
func hashHexByAlg(alg string, data []byte) (string, error) {
	sum, err := hashByAlg(alg, data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
}

// hmacByAlg 按算法标识计算 MAC（""=HMAC-SHA256，"sm3"=HMAC-SM3），与进程 profile 解耦
// （用于 TST 的跨档验签，§5.2.2 判定口径）。未知值返回错误。
func hmacByAlg(alg string, key, data []byte) ([]byte, error) {
	switch alg {
	case "":
		return hashProvSHA256.HMAC(key, data), nil
	case "sm3":
		return hashProvSM3.HMAC(key, data), nil
	default:
		return nil, fmt.Errorf("crypto: 未知 TST algorithm %q（R-12：验证失败，不得回退 SHA-256）", alg)
	}
}

// payloadHashHex 请求载荷摘要（随 profile：intl=SHA-256 / sm=SM3）——与同事件的 `hash_alg` 同档
// （§5.2.2 F-P2-4 裁决）。仅用于**请求路径**的 PayloadSHA；外部固定摘要（策略 manifest 自摘要等）
// 不得经此函数。
func payloadHashHex(b []byte) string {
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		return hashHexMust(hashProvSHA256, b)
	}
	return hashHexMust(hashProvSM3, b)
}

func hashHexMust(p cryptop.Provider, b []byte) string {
	return hex.EncodeToString(p.Hash(b))
}
