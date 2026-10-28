// Package main — 模型目录密态 wire 举证验收测试（QA 评审补证据，PRD P0-3 / P0-7）。
//
// 举证目标：/v1/adminext/models 的每一条 routes[] 序列化后必须**真实存在** 7 个密态字段，
// 且 attestationVerdict=="unknown"、verificationStatus=="claim-unverified"、connectivity 存在。
// 特别覆盖**老 CR / 未匹配路径**（P0-7 向后兼容）：不得因缺字段而消失，也不得借缺失冒充通过。
package main

import (
	"context"
	"encoding/json"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// adminextSevenFields /v1/adminext/models 每条目必带的 7 个密态字段（与 confllm wire 同名）。
var adminextSevenFields = []string{
	"confidentialityClass",
	"attestation",
	"attestationVerdict",
	"verificationStatus",
	"dataRetention",
	"deployment",
	"connectivity",
}

// assertRouteWireEntry 断言单条 modelRouteEntry 序列化后 7 字段齐全且值合规。
func assertRouteWireEntry(t *testing.T, where string, entry modelRouteEntry) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("%s 序列化失败：%v", where, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s 反序列化失败：%v", where, err)
	}
	for _, k := range adminextSevenFields {
		v, ok := m[k]
		if !ok {
			t.Fatalf("%s 缺失密态字段 %q（禁 omitempty，不得以「字段缺失」冒充通过）：%s", where, k, string(raw))
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			t.Fatalf("%s 字段 %q 非字符串：%s", where, k, string(v))
		}
		if s == "" {
			t.Fatalf("%s 字段 %q 为空串（缺省须 unknown）", where, k)
		}
	}
	if got := routeWireString(t, where, m, "attestationVerdict"); got != meta.WireVerdictUnknown {
		t.Fatalf("%s attestationVerdict=%q 期望 unknown", where, got)
	}
	if got := routeWireString(t, where, m, "verificationStatus"); got != meta.WireVerificationStatusClaimUnverified {
		t.Fatalf("%s verificationStatus=%q 期望 claim-unverified", where, got)
	}
	switch cls := routeWireString(t, where, m, "confidentialityClass"); cls {
	case meta.ClassA, meta.ClassB, meta.ClassC, meta.ClassUnknown:
	default:
		t.Fatalf("%s confidentialityClass=%q 不在枚举 {A,B,C,unknown} 内", where, cls)
	}
	switch conn := routeWireString(t, where, m, "connectivity"); conn {
	case meta.ConnNeverTested, meta.ConnPendingCredential:
	default:
		t.Fatalf("%s connectivity=%q 不在 {never-tested,pending-credential} 内（无 integration 不得 smoke-ok）", where, conn)
	}
	return m
}

func routeWireString(t *testing.T, where string, m map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		t.Fatalf("%s 解析 %s 失败：%s", where, key, string(m[key]))
	}
	return s
}

// TestModelRouteEntryZeroValueEmitsSevenFields 【P0-3 禁 omitempty 直接举证】
// 零值 modelRouteEntry 序列化后 7 字段仍全部出现（值为空串 → 由富化层填 unknown）。
func TestModelRouteEntryZeroValueEmitsSevenFields(t *testing.T) {
	raw, err := json.Marshal(modelRouteEntry{})
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("反序列化失败：%v", err)
	}
	for _, k := range adminextSevenFields {
		if _, ok := m[k]; !ok {
			t.Fatalf("零值 modelRouteEntry 缺失 %q（举证字段禁 omitempty）：%s", k, string(raw))
		}
	}
}

// TestEnrichWithConfidentialityLegacyCR 【P0-7 向后兼容 + P0-3 老 CR 路径举证】
// 老 CR（无密态字段、provider 在 confllm 注册表未匹配）富化后 7 字段齐全且为举证缺省值。
func TestEnrichWithConfidentialityLegacyCR(t *testing.T) {
	cases := []struct {
		name    string
		entry   modelRouteEntry
		wantCls string
	}{
		{
			name:    "老 CR 完全无密态字段",
			entry:   modelRouteEntry{Route: "legacy-route", Provider: "legacy-provider-absent-in-confllm"},
			wantCls: meta.ClassUnknown,
		},
		{
			name: "老 CR 只声明了 class（其余留空）",
			entry: modelRouteEntry{
				Route:    "legacy-route-partial",
				Provider: "legacy-provider-absent-in-confllm",
				// 密态字段来自匿名嵌入的 meta.WireMetadata（单一事实源），
				// 复合字面量须显式写嵌入字段名（断言语义不变：老 CR 已声明 class=C 须保留）。
				WireMetadata: meta.WireMetadata{ConfidentialityClass: meta.ClassC},
			},
			wantCls: meta.ClassC,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			e := c.entry
			enrichWithConfidentiality(&e)
			m := assertRouteWireEntry(t, "legacyCR/"+c.name, e)
			if got := routeWireString(t, "legacyCR", m, "confidentialityClass"); got != c.wantCls {
				t.Fatalf("confidentialityClass=%q 期望 %q", got, c.wantCls)
			}
			// 未匹配且无 override → 举证三字段恒为举证值，绝不为 pass/verified。
			if got := routeWireString(t, "legacyCR", m, "connectivity"); got != meta.ConnNeverTested {
				t.Fatalf("connectivity=%q 期望 never-tested", got)
			}
			if got := routeWireString(t, "legacyCR", m, "attestation"); got != meta.AttestUnknown {
				t.Fatalf("attestation=%q 期望 unknown（老 CR 未声明）", got)
			}
		})
	}
}

// qaWireStubProvider 测试桩：注入 confllm 注册表以覆盖「已匹配」富化路径。
type qaWireStubProvider struct {
	id   string
	meta confllm.ConfidentialityMeta
}

func (p qaWireStubProvider) ID() string                            { return p.id }
func (p qaWireStubProvider) Region() confllm.Region                { return confllm.RegionDomestic }
func (p qaWireStubProvider) Metadata() confllm.ConfidentialityMeta { return p.meta }
func (p qaWireStubProvider) Capabilities() confllm.Capabilities    { return confllm.Capabilities{} }
func (p qaWireStubProvider) Chat(context.Context, *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503, "qa stub")
}
func (p qaWireStubProvider) Stream(context.Context, *confllm.ChatRequest) (confllm.StreamReader, error) {
	return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503, "qa stub")
}
func (p qaWireStubProvider) ListModels(context.Context) ([]confllm.ModelInfo, error) {
	return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503, "qa stub")
}
func (p qaWireStubProvider) Health(context.Context) confllm.HealthStatus {
	return confllm.HealthStatus{}
}

// TestEnrichWithConfidentialityMatchedDoesNotUpgradeVerdict 【P0-3 举证边界红线】
// 即使 provider 已匹配、且 managed→A override 成立（class 提升为 A），
// attestationVerdict / verificationStatus / connectivity 也绝不被升级（引用≠已验证）。
func TestEnrichWithConfidentialityMatchedDoesNotUpgradeVerdict(t *testing.T) {
	const stubID = "qa-wire-stub-managed-a"
	confllm.GlobalRegistry.Register(qaWireStubProvider{
		id: stubID,
		meta: confllm.ConfidentialityMeta{
			ConfidentialityClass: meta.ClassUnknown,
			Attestation:          meta.AttestUnknown,
			DataRetention:        meta.RetentionUnknown,
			Deployment:           meta.DeployManaged,
			Verification:         meta.VerificationUnverified,
		},
	})
	// managed→A override：合法 https 书面证明引用（应提升 class 为 A）。
	ovKey := stubID
	if _, had := confllmManagedOverrides[ovKey]; had {
		t.Fatalf("测试桩 override 键冲突：%s", ovKey)
	}
	confllmManagedOverrides[ovKey] = meta.ManagedToAOverride{
		ProofReference: "https://example.com/qa-wire-proof-reference",
	}
	defer delete(confllmManagedOverrides, ovKey)

	e := modelRouteEntry{Route: "r-with-managed-override", Provider: stubID}
	enrichWithConfidentiality(&e)
	m := assertRouteWireEntry(t, "matchedManagedA", e)

	// ① managed→A override 生效：class 提升为 A（证明 override 路径确实被执行，测试非空跑）。
	if got := routeWireString(t, "matchedManagedA", m, "confidentialityClass"); got != meta.ClassA {
		t.Fatalf("confidentialityClass=%q 期望 A（https 证明引用应生效）", got)
	}
	// ② 但举证三字段绝不升级（红线）。
	if got := routeWireString(t, "matchedManagedA", m, "attestationVerdict"); got != meta.WireVerdictUnknown {
		t.Fatalf("attestationVerdict=%q 期望 unknown：managed→A 不得升级举证结论", got)
	}
	if got := routeWireString(t, "matchedManagedA", m, "verificationStatus"); got != meta.WireVerificationStatusClaimUnverified {
		t.Fatalf("verificationStatus=%q 期望 claim-unverified：引用≠已验证", got)
	}
	if got := routeWireString(t, "matchedManagedA", m, "connectivity"); got != meta.ConnNeverTested {
		t.Fatalf("connectivity=%q 期望 never-tested：无真实冒烟不得 smoke-ok", got)
	}
	// ③ 内部 audit 字段保留中间态（引用≠已验证）。
	if e.Verification != string(meta.VerificationClaimWithReferenceUnverified) {
		t.Fatalf("内部 verification=%q 期望 claim-with-reference-unverified", e.Verification)
	}
}
