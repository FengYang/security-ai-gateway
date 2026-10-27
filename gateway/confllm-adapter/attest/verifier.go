// Package attest 可插拔远程证明校验抽象（§1.4 / §7.7 / R4）。
//
// 本期仅提供 NoopVerifier / LogOnlyVerifier + 各家占位；所有占位 Verify 必须返回
// Verdict=unknown（非 pass），防上层误判「已验证通过」（R4）。真实 MAA/NRAS/Trustee
// 校验留 P2 对接 gateway/attest-verify/*。
package attest

import "context"

// Verdict 证明结论枚举。
type Verdict string

const (
	// VerdictUnknown 未验证（本期所有占位均返回此值，R4）。
	VerdictUnknown Verdict = "unknown"
	// VerdictPass 校验通过（P2 真实校验后可能返回）。
	VerdictPass Verdict = "pass"
	// VerdictFail 校验失败。
	VerdictFail Verdict = "fail"
	// VerdictUnverified 证据不足 / 无法校验。
	VerdictUnverified Verdict = "unverified"
)

// Evidence 证明证据（quote / token）。
type Evidence struct {
	Type   string // tdx / sev-snp / nvidia-nras / attestation-token
	Raw    []byte // quote / token 原始字节（不入日志）
	Model  string // 绑定的模型名
	Issuer string // 签发方（如 maa / nras / trustee / near / privatemode）
}

// VerificationResult 校验结果。
type VerificationResult struct {
	Verdict  Verdict
	Detail   string
	Verifier string
}

// AttestationVerifier 可插拔证明校验接口。
type AttestationVerifier interface {
	Verify(ctx context.Context, ev Evidence) (*VerificationResult, error)
}

// NoopVerifier 完全跳过校验（Verdict=unknown）。
type NoopVerifier struct{}

func (NoopVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "noop verifier: 跳过校验（R4）", Verifier: "noop"}, nil
}

// LogOnlyVerifier 记录证据但不校验（Verdict=unknown，非 pass）。
type LogOnlyVerifier struct {
	Log func(format string, args ...any)
}

func (v LogOnlyVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	if v.Log != nil {
		v.Log("attest evidence received type=%s issuer=%s model=%s", ev.Type, ev.Issuer, ev.Model)
	}
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "log-only verifier: 仅记录不校验（R4）", Verifier: "log-only"}, nil
}

// ---------- 各家占位（均返回 Verdict=unknown，R4）----------

// MAAVerifier Azure 机密推理证明占位（MAA）。
type MAAVerifier struct{}

func (MAAVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "MAA 占位：未对接真实校验（pending-doc, P2）", Verifier: "maa"}, nil
}

// NRASVerifier 阿里/英伟达机密推理证明占位（NRAS）。
type NRASVerifier struct{}

func (NRASVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "NRAS 占位：未对接真实校验（pending-doc, P2）", Verifier: "nras"}, nil
}

// TrusteeVerifier 阿里机密 AI KMS/Trustee 证明占位。
type TrusteeVerifier struct{}

func (TrusteeVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "Trustee 占位：未对接真实校验（pending-doc, P2）", Verifier: "trustee"}, nil
}

// NearQuoteVerifier NEAR AI 每响应签名 quote 占位。
type NearQuoteVerifier struct{}

func (NearQuoteVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "NEAR quote 占位：未对接真实校验（pending-doc, P2）", Verifier: "near"}, nil
}

// PrivatemodeVerifier Privatemode 客户端 proxy 证明占位。
type PrivatemodeVerifier struct{}

func (PrivatemodeVerifier) Verify(ctx context.Context, ev Evidence) (*VerificationResult, error) {
	return &VerificationResult{Verdict: VerdictUnknown, Detail: "Privatemode 占位：未对接真实校验（pending-doc, P2）", Verifier: "privatemode"}, nil
}
