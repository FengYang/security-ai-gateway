// Package meta 密态四字段（confidentiality_class / attestation / data_retention / deployment）
// 的枚举常量、静态缺省值与 managed→A override 硬护栏（§1.5 / §7.5 / §7.11 B2）。
//
// 该包独立无外部依赖，被 confllm 根包、providers、admin-service 共同引用。
package meta

import (
	"fmt"
	"strings"
)

// ---------- 枚举常量 ----------

// ConfidentialityClass 密态强度等级（§7.5）。
type ConfidentialityClass = string

const (
	ClassA       = "A"       // 硬件 TEE / 机密计算推理
	ClassB       = "B"       // 密码学密态推理（FHE/MPC/ZK）
	ClassC       = "C"       // 协议/网关侧「数据不出域」（合同保证，非硬件 TEE）
	ClassUnknown = "unknown" // 未确认（缺省）
)

// Attestation 可远程证明形态。
type Attestation = string

const (
	AttestNone            = "none"
	AttestQuoteTDX        = "quote:tdx"         // Intel TDX
	AttestQuoteSEVSNP     = "quote:sev-snp"     // AMD SEV-SNP
	AttestQuoteNVIDIANRAS = "quote:nvidia-nras" // NVIDIA NRAS
	AttestToken           = "attestation-token" // 厂商证明 token
	AttestUnknown         = "unknown"
)

// DataRetention 数据留存策略。
type DataRetention = string

const (
	RetentionUnknown = "unknown"
	RetentionZero    = "zero"    // 零留存（不落盘、不训练）
	RetentionBounded = "bounded" // 有界留存
)

// Deployment 部署形态（与 confllm.Deployment 同源，但此处为字符串便于序列化）。
type Deployment = string

const (
	DeployManaged       = "managed"
	DeploySelfHostedCVM = "self-hosted-cvm"
	DeployProxyMediated = "proxy-mediated"
	DeployUnknown       = "unknown"
)

// Verification 校验状态（§7.11 B2：引用≠已验证）。
type Verification string

const (
	// VerificationUnverified 未验证（缺省，模型目录呈现「未验证」）。
	VerificationUnverified Verification = "unverified"
	// VerificationClaimWithReferenceUnverified 有声明引用但尚未真实验证（目录写入该值）。
	VerificationClaimWithReferenceUnverified = "claim-with-reference-unverified"
	// VerificationVerified 真实远程证明校验通过（P2 才会出现）。
	VerificationVerified Verification = "verified"
)

// ---------- 数据结构 ----------

// ConfidentialityMeta 密态四字段（一等公民，缺省 unknown）+ 校验状态（引用≠已验证）。
type ConfidentialityMeta struct {
	ConfidentialityClass string       `json:"confidentialityClass" yaml:"confidentialityClass"`
	Attestation          string       `json:"attestation" yaml:"attestation"`
	DataRetention        string       `json:"dataRetention" yaml:"dataRetention"`
	Deployment           string       `json:"deployment" yaml:"deployment"`
	Verification         Verification `json:"verification" yaml:"verification"` // 引用≠已验证（§7.11）
}

// DefaultMeta 返回全 unknown 的静态缺省（managed 形态默认 unknown：§7.5 R3/R5）。
func DefaultMeta() ConfidentialityMeta {
	return ConfidentialityMeta{
		ConfidentialityClass: ClassUnknown,
		Attestation:          AttestUnknown,
		DataRetention:        RetentionUnknown,
		Deployment:           DeployUnknown,
		Verification:         VerificationUnverified,
	}
}

// normalize 将空字符串归并为 unknown（Verification 空 → unverified）。
func (m ConfidentialityMeta) normalize() ConfidentialityMeta {
	if m.ConfidentialityClass == "" {
		m.ConfidentialityClass = ClassUnknown
	}
	if m.Attestation == "" {
		m.Attestation = AttestUnknown
	}
	if m.DataRetention == "" {
		m.DataRetention = RetentionUnknown
	}
	if m.Deployment == "" {
		m.Deployment = DeployUnknown
	}
	if m.Verification == "" {
		m.Verification = VerificationUnverified
	}
	return m
}

// IsVerified 是否已完成真实验证（§7.11：仅 VerificationVerified 为真；
// 「有书面引用」= VerificationClaimWithReferenceUnverified ≠ 已验证，恒返回 false）。
func (m ConfidentialityMeta) IsVerified() bool {
	return m.Verification == VerificationVerified
}

// ---------- managed→A override 硬护栏（§7.11 B2）----------

// ManagedToAOverride 将 managed 形态 override 为 A 类的证明引用。
type ManagedToAOverride struct {
	// ProofReference 厂商书面证明引用（必须 https:// 开头的官方文档 URL 或带编号书面证明）。
	// 缺失 / 非 https / 空串 → override 无效（拒绝并保持 unknown，§7.11）。
	ProofReference string `json:"proofReference" yaml:"proofReference"`
}

// ApplyManagedToAOverride 应用 override（§7.11 B2 硬护栏，可判定版）。
//
// 硬护栏：
//   - 引用缺失 / 空串 / 非 https:// → 返回 error，confidentialityClass 保持 unknown。
//   - 引用合法（https://）→ Class 置 A，但 **IsVerified() 仍为 false**（引用≠已验证），
//     Verification 写为 "claim-with-reference-unverified"，attestation 不追加 verified 标记。
func ApplyManagedToAOverride(m ConfidentialityMeta, deployment string, ov *ManagedToAOverride) (ConfidentialityMeta, error) {
	m = m.normalize()
	if ov == nil || strings.TrimSpace(ov.ProofReference) == "" {
		// R5/B2：未附证明 → override 无效，保持缺省 unknown。
		m.Attestation = AttestUnknown
		m.Verification = VerificationUnverified
		return m, fmt.Errorf("managed→A override 缺少厂商书面证明引用（§7.11 B2）：拒绝 override，保持缺省 unknown")
	}
	ref := strings.TrimSpace(ov.ProofReference)
	if !strings.HasPrefix(ref, "https://") {
		// 引用形态校验：必须 https:// 开头（§7.11）。
		m.Attestation = AttestUnknown
		m.Verification = VerificationUnverified
		return m, fmt.Errorf("managed→A override 证明引用必须为 https:// 开头的厂商官方文档或带编号书面证明（§7.11）：%q", ref)
	}
	m.ConfidentialityClass = ClassA
	m.Deployment = deployment
	// 引用 ≠ 已验证：仅登记「有声明引用、尚未真实验证」。
	m.Attestation = AttestToken
	m.Verification = VerificationClaimWithReferenceUnverified
	return m, nil
}
