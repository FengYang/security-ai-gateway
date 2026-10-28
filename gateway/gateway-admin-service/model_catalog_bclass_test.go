// Package main — 模型目录富化的两项回归举证（本次验收评审缺陷的回归网）。
//
//  1. B 类（隐语 SecretFlow）已声明的 class=B 不得被吞：此前 SecretFlow 未实现统一契约
//     ConfidentialLLMProvider → 进不了 confllm 注册表 → 富化走「未匹配」分支 →
//     已声明值被降级为 unknown（比「未声明填 unknown」更严重）。
//  2. 内部中间态（claim-with-reference-unverified）绝不出现在 /v1/adminext/models 的
//     wire 输出上（§7.11：内部结构保留审计，wire 一律 claim-unverified）。
package main

import (
	"encoding/json"
	"strings"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/meta"
	"security-ai-gateway/gateway/confllm-adapter/providers/bclass"
)

// TestEnrichWithConfidentialityKeepsDeclaredClassB 【B 类声明值被吞 · 回归网】
// 真实 B 类适配器（类型键 secretflow）装配进注册表后富化，class 必须仍为 B。
func TestEnrichWithConfidentialityKeepsDeclaredClassB(t *testing.T) {
	const id = "qa-bclass-secretflow"
	p, err := confllm.GlobalRegistry.NewFromConfig(confllm.ProviderConfig{
		Type: bclass.SecretFlowTypeKey, ID: id,
	})
	if err != nil {
		t.Fatalf("secretflow 装配失败（B 类仍进不了注册表 = 声明值必被吞）：%v", err)
	}
	confllm.GlobalRegistry.Register(p)

	e := modelRouteEntry{Route: "r-bclass", Provider: id}
	enrichWithConfidentiality(&e)
	m := assertRouteWireEntry(t, "bclassSecretFlow", e)

	if got := routeWireString(t, "bclassSecretFlow", m, "confidentialityClass"); got != meta.ClassB {
		t.Fatalf("confidentialityClass=%q 期望 B（已声明值不得被降级为 unknown）", got)
	}
	if got := routeWireString(t, "bclassSecretFlow", m, "deployment"); got != meta.DeploySelfHostedCVM {
		t.Fatalf("deployment=%q 期望 self-hosted-cvm", got)
	}
	// 举证三字段仍恒为举证值（B 类也不得升级）。
	if got := routeWireString(t, "bclassSecretFlow", m, "attestationVerdict"); got != meta.WireVerdictUnknown {
		t.Fatalf("attestationVerdict=%q 期望 unknown", got)
	}
	if got := routeWireString(t, "bclassSecretFlow", m, "verificationStatus"); got != meta.WireVerificationStatusClaimUnverified {
		t.Fatalf("verificationStatus=%q 期望 claim-unverified", got)
	}
}

// TestModelRouteEntryWireOmitsInternalVerification 【内部中间态泄漏 · 回归网】
// 内部 Verification 中间态（claim-with-reference-unverified）json:"-"，绝不进 wire；
// wire 上且与 verificationStatus 并存会造成「疑似已验证」误读（§7.11）。
func TestModelRouteEntryWireOmitsInternalVerification(t *testing.T) {
	e := modelRouteEntry{Route: "r-internal", Provider: "p-absent-in-confllm"}
	// 手工置内部中间态（模拟 managed→A override 后的审计值）。
	e.Verification = string(meta.VerificationClaimWithReferenceUnverified)
	enrichWithConfidentiality(&e)

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("反序列化失败：%v", err)
	}
	if _, ok := m["verification"]; ok {
		t.Fatalf("wire 出现内部 verification 字段（中间态泄漏）：%s", string(raw))
	}
	if strings.Contains(string(raw), string(meta.VerificationClaimWithReferenceUnverified)) {
		t.Fatalf("wire 出现内部中间态文本 %q：%s", meta.VerificationClaimWithReferenceUnverified, string(raw))
	}
	// wire 仍以 verificationStatus 呈现，且恒 claim-unverified。
	if got := routeWireString(t, "internalVerification", m, "verificationStatus"); got != meta.WireVerificationStatusClaimUnverified {
		t.Fatalf("verificationStatus=%q 期望 claim-unverified", got)
	}
	// 内部结构保留中间态用于审计（不被清空）。
	if e.Verification != string(meta.VerificationClaimWithReferenceUnverified) {
		t.Fatalf("内部 verification=%q 应保留中间态用于审计", e.Verification)
	}
}
