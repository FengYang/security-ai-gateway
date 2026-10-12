// Package cryptopmodule —— 密码模块适配层（P1-5 §6.1，M1）。
//
// 定位：抹平 PKCS#11（通用 Cryptoki）/ 国密 SDF（GM/T 0018）两套厂商接口差异，
// 向 cryptop 包的 moduleProvider 暴露统一 ModuleBackend 语义——moduleProvider
// 只依赖本包，不感知具体后端。
//
// 合规边界（C-4/P4，务必如实）：
//   - 生产路径的密码运算必须在**模块内**执行；本包适配层只做接口调用/编码转换/
//     会话与健康编排（B-6.1-8），**不自研密码**；
//   - MockBackend 为**功能验证档**（内存密钥对象 + 软件国密库委托），**不满足密评**，
//     仅供适配层单测与联调，禁止用于生产合规声明；
//   - 厂商绑定（sdf.go/pkcs11.go，cgo + 厂商 SDK）随 S3-a 采购到位后接入；
//     未接入前 NewBackend 对 sdf/pkcs11 返回明确错误（fail-closed 启动拒），
//     绝不静默回退软件实现冒充合规（C-3）。
//
// 设计依据：《GA-AI网关能力补齐方案--P1--国密S3-S4认证模块与密评.md》§6.1-§6.4
// （ModuleBackend 方法表 / 配置项 / 校验规则 R-S3-1..12 / 边界 B-6.1-1..9）。
package cryptopmodule

import (
	"errors"
	"sort"
)

// KeyRef 模块内密钥对象句柄（不透明 token；B-6.1-4）。
//
// sm-module 档下，cryptop.Provider 各方法的 []byte 密钥形参即本 token 的序列化形态
// （可序列化为 []byte，**不是任何密钥字节**）；业务侧不构造、不解释、不缓存其含义。
type KeyRef []byte

// String 仅用于日志/错误消息的安全展示（token 本身不含密钥材料）。
func (k KeyRef) String() string { return string(k) }

// Session 模块会话句柄（池化管理，B-6.1-7）。
type Session uintptr

// 密钥用途（GenerateKeyPair 的 usage 参数）。
const (
	// UsageSign 签名密钥对（SM2）。
	UsageSign = "sign"
	// UsageECDH 密钥协商密钥对（SM2；G3-02）。
	UsageECDH = "ecdh"
)

// 机制名（module_required_mechanisms 取值；R-S3-11 启动校验集）。
const (
	MechSM4GCM  = "sm4-gcm"  // SM4-GCM 对称 AEAD
	MechSM3     = "sm3"      // SM3 哈希
	MechHMACSM3 = "hmac-sm3" // HMAC-SM3
	MechSM2Sign = "sm2-sign" // SM2 签名/验签
	MechSM2ECDH = "sm2-ecdh" // SM2 密钥协商（G3-02）
	MechRand    = "rand"     // 模块 CSPRNG（GM2-03）
)

// knownMechanisms 机制名全集（配置解析与能力校验用）。
var knownMechanisms = map[string]bool{
	MechSM4GCM: true, MechSM3: true, MechHMACSM3: true,
	MechSM2Sign: true, MechSM2ECDH: true, MechRand: true,
}

// IsKnownMechanism 机制名是否在全集内。
func IsKnownMechanism(m string) bool { return knownMechanisms[m] }

// DefaultRequiredMechanisms §6.4 module_required_mechanisms 缺省值
// （sm4-gcm,sm3,hmac-sm3,sm2-sign,sm2-ecdh,rand）。
func DefaultRequiredMechanisms() []string {
	return []string{MechSM4GCM, MechSM3, MechHMACSM3, MechSM2Sign, MechSM2ECDH, MechRand}
}

// 后端类型（module_backend 取值）。
const (
	BackendSDF    = "sdf"    // 国密 SDF（GM/T 0018）——金融/政务首选（D-3）
	BackendPKCS11 = "pkcs11" // PKCS#11（Cryptoki）——通用/云 HSM
	BackendMock   = "mock"   // 功能验证档（仅测试/联调；非合规）
)

// IsKnownBackend 后端类型是否合法。
func IsKnownBackend(b string) bool {
	switch b {
	case BackendSDF, BackendPKCS11, BackendMock:
		return true
	}
	return false
}

// 错误码（适配层稳定枚举；上层映射见 P1-5 §6.5）。
var (
	// ErrModuleUnavailable 模块不可达/未登录/探针失败/池已关闭。
	ErrModuleUnavailable = errors.New("cryptopmodule: 模块不可用")
	// ErrSessionExhausted 会话池耗尽且排队超限（B-6.1-7）。
	ErrSessionExhausted = errors.New("cryptopmodule: 会话池耗尽（排队超限）")
	// ErrKeyNotFound 模块内密钥对象不存在（KeyRef 失效）。
	ErrKeyNotFound = errors.New("cryptopmodule: 密钥对象不存在")
	// ErrMechanismMissing 模块缺少必需机制（R-S3-11）。
	ErrMechanismMissing = errors.New("cryptopmodule: 模块缺少必需机制")
	// ErrNotExtractable 尝试导出不可导出密钥（R-S3-4 违规）。
	ErrNotExtractable = errors.New("cryptopmodule: 密钥不可导出")
	// ErrNotImplemented 该后端/方法尚未实现（如厂商绑定未随 SDK 接入）。
	ErrNotImplemented = errors.New("cryptopmodule: 后端或方法尚未实现")
)

// HealthLevel 分级健康（GM2-08；Down 才触发切换，Degraded 仅告警）。
type HealthLevel int

const (
	// HealthOK 健康。
	HealthOK HealthLevel = iota
	// HealthDegraded 降级（可用但异常；仅告警不切换）。
	HealthDegraded
	// HealthDown 不可用（触发切换或 fail-closed）。
	HealthDown
)

// String 健康级别名（指标/日志）。
func (h HealthLevel) String() string {
	switch h {
	case HealthOK:
		return "ok"
	case HealthDegraded:
		return "degraded"
	case HealthDown:
		return "down"
	default:
		return "unknown"
	}
}

// Capabilities 模块能力快照（B-6.1-6；写入 /v1/capabilities 与 metrics 标签）。
type Capabilities struct {
	Backend    string   // sdf|pkcs11|mock
	Vendor     string   // 厂商（mock = "mock"）
	Model      string   // 型号（mock = "in-memory"）
	Mechanisms []string // 支持的机制名（有序）
}

// HasMechanism 是否支持某机制。
func (c Capabilities) HasMechanism(m string) bool {
	for _, x := range c.Mechanisms {
		if x == m {
			return true
		}
	}
	return false
}

// MissingMechanisms 返回 required 中缺失的机制（空 = 全覆盖；R-S3-11）。
func MissingMechanisms(caps Capabilities, required []string) []string {
	var miss []string
	for _, r := range required {
		if !caps.HasMechanism(r) {
			miss = append(miss, r)
		}
	}
	sort.Strings(miss)
	return miss
}

// ModuleBackend 统一后端接口（P1-5 §6.1 方法表，2026-10-12 研发落地）。
//
// 契约要点：
//   - 会话池由各后端**内部**维护（B-6.1-7），方法签名不暴露 session；
//     AcquireSession/ReleaseSession 供池管理编排与测试使用；
//   - 所有密钥形参为 KeyRef token（B-6.1-4）；返回的公钥为原始字节；
//   - 适配层不得缓存密钥明文（B-6.1-1）；运算失败返回稳定错误（§6.5 映射）。
type ModuleBackend interface {
	// ---- 生命周期 ----
	// Init 初始化设备/库并做启动校验（R-S3-1 库可加载 / R-S3-11 能力覆盖
	// RequiredMechanisms；失败即启动拒，C-3）。
	Init(cfg *Config) error
	// Capabilities 能力探测（B-6.1-6；禁止仅靠 profile 静态值宣称能力）。
	Capabilities() Capabilities
	// AcquireSession 从会话池获取会话（池满按 module_session_queue_size 排队，
	// 超排队上限失败并计入 cryptop_call_timeout_total）。
	AcquireSession() (Session, error)
	// ReleaseSession 归还会话到池。
	ReleaseSession(s Session) error
	// Health 分级健康探针（GM2-08）。
	Health() HealthLevel
	// Close 释放设备/库资源（关闭池并销毁空闲会话）。
	Close() error

	// ---- 对称运算 ----
	// Seal SM4-GCM 加密（keyRef 为对称密钥对象）。
	Seal(keyRef KeyRef, nonce, plaintext, aad []byte) ([]byte, error)
	// Open SM4-GCM 解密。
	Open(keyRef KeyRef, nonce, ciphertext, aad []byte) ([]byte, error)
	// Hash SM3（无密钥；免会话）。
	Hash(data []byte) ([]byte, error)
	// HMAC HMAC-SM3。
	HMAC(keyRef KeyRef, data []byte) ([]byte, error)
	// KDF SM3-KDF 派生（parentRef 为父密钥对象；alias 非空时派生结果同时
	// 登记为模块内对象——D-4 的执行位置由 S3-b 实测裁决，两条路径均满足 C-4/C-5）。
	KDF(parentRef KeyRef, salt, info []byte, outLen int, alias string) ([]byte, error)
	// Rand 生成随机数（**必须来自模块 CSPRNG**，GM2-03；启动前执行 GM/T 0050 自检，R-S3-12）。
	Rand(n int) ([]byte, error)

	// ---- 非对称运算 ----
	// Sign SM2 签名（uid 可空=用 module_sm2_uid 缺省，GM2-06）。
	Sign(privRef KeyRef, msg []byte, uid string) ([]byte, error)
	// Verify SM2 验签（pub 为原始字节公钥）。
	Verify(pub, msg, sig []byte, uid string) error
	// GenerateKeyPair SM2 密钥对（usage ∈ {UsageSign, UsageECDH}）；
	// 返回 (模块内私钥句柄, 公钥字节)。
	GenerateKeyPair(usage string) (KeyRef, []byte, error)
	// ECDH SM2 密钥协商：以模块内协商私钥与对端公钥派生共享秘密（G3-02/B-6.1-9）。
	ECDH(privRef KeyRef, peerPub []byte) ([]byte, error)

	// ---- 密钥管理 ----
	// WrapKey 以 KEK 封装 DEK（模块内封装；AAD 绑定用途标签）。
	WrapKey(kekRef KeyRef, dek []byte) ([]byte, error)
	// UnwrapKey 以 KEK 解封 DEK。
	UnwrapKey(kekRef KeyRef, wrapped []byte) ([]byte, error)
	// ImportKey 将外部密钥字节导入模块（密钥导入/ceremony 路径；M4）。
	// spec ∈ {"sm4-128"/""（对称）, "sm2-sign"/"sm2-ecdh"（非对称私钥）}；
	// 字节仅瞬态经适配层进入模块，**不得缓存**（B-6.1-1）。
	ImportKey(spec string, key []byte, alias string) (KeyRef, error)
	// GenerateKey 生成对称密钥对象（spec 如 "sm4-128"；alias 为模块内对象名，可空）。
	GenerateKey(spec, alias string) (KeyRef, error)
	// DestroyKey 销毁模块内密钥对象（GM2-02）。
	DestroyKey(keyRef KeyRef) error
	// RotateKey 模块内密钥轮换（GM2-02/R2-06；返回新句柄，旧句柄按调用方策略归档）。
	RotateKey(oldRef KeyRef, spec string) (KeyRef, error)
}
