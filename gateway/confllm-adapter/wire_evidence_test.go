// Package confllm_test — P0-3 密态元数据 wire 举证端到端验收测试（QA 评审补证据）。
//
// 目的（PRD §3.3「举证边界」判定物三段式，缺一即验收失败）：
//  1. 正向存在性：/v1/confllm/models 的 providers[] 与 models[] **每一条目**都必须真实存在
//     7 个密态字段（attestationVerdict 禁 omitempty），不得以「字段缺失」冒充通过；
//  2. 值域：confidentialityClass ∈ {A,B,C,unknown}、attestationVerdict == "unknown"、
//     verificationStatus == "claim-unverified"、connectivity ∈ {never-tested,pending-credential}；
//  3. 负向文本：响应体不得出现 `"verdict":"pass"` / `"verified":true` / `smoke-ok` / 已证明 / 已通过校验。
//
// 取证方式：真实构造 ConfllmHandler（NewConfllmHandler）+ 真实注册 12 家 provider
// （9 家 HTTP 走本地 mock 内核 + 离线 Transport，2 家 SDK 走 *Fake，移动云走骨架），
// 用 httptest.ResponseRecorder 捕获**真实 JSON 响应体**后逐条目解析断言 —— 而非断言结构体定义。
//
// 全程不触外网（P0-5 离线纪律）：出网 client 一律 mock.NewOfflineTransport()。
package confllm_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/meta"
	"security-ai-gateway/gateway/confllm-adapter/mock"
	"security-ai-gateway/gateway/confllm-adapter/providers"
)

// wireSevenFields PRD P0-3 要求每条目必带的 7 个密态字段（JSON 名）。
var wireSevenFields = []string{
	"confidentialityClass",
	"attestation",
	"attestationVerdict",
	"verificationStatus",
	"dataRetention",
	"deployment",
	"connectivity",
}

// wireNegativeRE PRD §3.3 举证边界「负向文本」判定物。
// 注意：不得匹配 unverified / claim-unverified / unknown（避免自伤）。
var wireNegativeRE = regexp.MustCompile(
	`"[Aa]ttestation[Vv]erdict"\s*:\s*"pass"` + // attestationVerdict:"pass"
		`|"verdict"\s*:\s*"pass"` + // 兼容旧键名
		`|"verified"\s*:\s*true` + // verified:true（注意不匹配 "…unverified"）
		`|smoke-ok` + // 无 -tags=integration 不得出现冒烟举证
		`|已证明|已通过校验`)

// httpWireFactory 9 家 HTTP 型（7 家机密 HTTP + 阿里百炼 / 华为 MaaS 两枚非密态 HTTP，K1 双服务）。
var httpWireFactory = []struct {
	id      string
	factory confllm.ProviderFactory
}{
	{"tencent", providers.NewTencentProvider},
	{"volcengine", providers.NewVolcengineProvider},
	{"nearai", providers.NewNEARAIProvider},
	{"privatemode", providers.NewPrivatemodeProvider},
	{"azure", providers.NewAzureProvider},
	{"gcp", providers.NewGCPProvider},
	{"aws", providers.NewAWSProvider},
	{"aliyun-bailian", providers.NewAliyunBailianProvider},
	{"huawei-maas", providers.NewHuaweiMaaSProvider},
}

// newWireRegistry 注册 12 家运行期实例（HTTP 9 + SDK 2 *Fake + 移动云骨架 1），全程离线。
func newWireRegistry(t *testing.T, endpoint string) *confllm.Registry {
	t.Helper()
	reg := confllm.NewRegistry()

	for _, c := range httpWireFactory {
		p, err := c.factory(confllm.ProviderConfig{ID: c.id, Endpoint: endpoint},
			confllm.WithHTTPClient(&http.Client{Transport: mock.NewOfflineTransport()}),
			confllm.WithStaticCredential(&confllm.Credential{Key: []byte("qa-wire-test-key")}),
		)
		if err != nil {
			t.Fatalf("构造 HTTP provider %s 失败：%v", c.id, err)
		}
		reg.Register(p)
	}

	// SDK 型 2 家（阿里 CAI 机密 AI / 华为密态 SDK）：以 *Fake 注入，不触真实 SDK 与网络。
	aliyun, err := providers.NewAliyunProvider(confllm.ProviderConfig{ID: "aliyun-confidential"},
		confllm.WithSDKClient(providers.NewAliyunConfidentialClientFake()))
	if err != nil {
		t.Fatalf("构造 aliyun-confidential 失败：%v", err)
	}
	reg.Register(aliyun)
	huawei, err := providers.NewHuaweiProvider(confllm.ProviderConfig{ID: "huawei-confidential"},
		confllm.WithSDKClient(providers.NewHuaweiConfidentialClientFake()))
	if err != nil {
		t.Fatalf("构造 huawei-confidential 失败：%v", err)
	}
	reg.Register(huawei)

	// 移动云骨架（pending-credential，不计入 10 家）。
	mc, err := providers.NewMobileCloudProvider(confllm.ProviderConfig{ID: "mobilecloud"})
	if err != nil {
		t.Fatalf("构造 mobilecloud 失败：%v", err)
	}
	reg.Register(mc)

	return reg
}

// modelsWireResponse /v1/confllm/models 原始响应（按条目保序解析，用于「字段是否存在」判定）。
type modelsWireResponse struct {
	Providers []map[string]json.RawMessage `json:"providers"`
	Models    []map[string]json.RawMessage `json:"models"`
}

// assertWireEntry 单条目三段式断言（存在性 + 值域 + 负向）。
func assertWireEntry(t *testing.T, where string, entry map[string]json.RawMessage) {
	t.Helper()
	for _, k := range wireSevenFields {
		raw, ok := entry[k]
		if !ok {
			t.Fatalf("%s 缺失密态字段 %q（PRD P0-3：不得以「字段缺失」冒充通过）", where, k)
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("%s 字段 %q 不是字符串：%s", where, k, string(raw))
		}
		if s == "" {
			t.Fatalf("%s 字段 %q 为空串（缺省须填 unknown，不得为空）", where, k)
		}
	}
	assertWireValue(t, where, entry, "attestationVerdict", meta.WireVerdictUnknown)
	assertWireValue(t, where, entry, "verificationStatus", meta.WireVerificationStatusClaimUnverified)

	// 值域：class 必须机器可读枚举（不得写展示串）。
	cls := wireString(t, where, entry, "confidentialityClass")
	switch cls {
	case meta.ClassA, meta.ClassB, meta.ClassC, meta.ClassUnknown:
	default:
		t.Fatalf("%s confidentialityClass=%q 不在枚举 {A,B,C,unknown} 内", where, cls)
	}
	// 值域：connectivity 本期仅允许 never-tested / pending-credential（无 integration 不得 smoke-ok）。
	conn := wireString(t, where, entry, "connectivity")
	switch conn {
	case meta.ConnNeverTested, meta.ConnPendingCredential:
	default:
		t.Fatalf("%s connectivity=%q 不在 {never-tested,pending-credential} 内（无 tag 运行不得 smoke-ok）", where, conn)
	}
}

func wireString(t *testing.T, where string, entry map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(entry[key], &s); err != nil {
		t.Fatalf("%s 解析 %s 失败：%s", where, key, string(entry[key]))
	}
	return s
}

func assertWireValue(t *testing.T, where string, entry map[string]json.RawMessage, key, want string) {
	t.Helper()
	if got := wireString(t, where, entry, key); got != want {
		t.Fatalf("%s %s=%q 期望 %q", where, key, got, want)
	}
}

// TestWireEvidenceModelsEndpointSevenFields 【P0-3 正向存在性 + 值域 + 负向】
// /v1/confllm/models 真实响应体逐条目举证。
func TestWireEvidenceModelsEndpointSevenFields(t *testing.T) {
	k := mock.NewKernel(nil)
	defer k.Close()

	h := confllm.NewConfllmHandler(newWireRegistry(t, k.URL()))

	rec := httptest.NewRecorder()
	h.HandleModels(rec, httptest.NewRequest(http.MethodGet, "/v1/confllm/models", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleModels 期望 200，实际 %d（body=%s）", rec.Code, rec.Body.String())
	}
	body := rec.Body.Bytes()

	var out modelsWireResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("响应非合法 JSON：%v（body=%s）", err, string(body))
	}
	// 12 家全部注册 → providers[] 必须 12 条（含移动云骨架）。
	if len(out.Providers) != 12 {
		t.Fatalf("providers[] 期望 12 条，实际 %d", len(out.Providers))
	}
	if len(out.Models) < 11 {
		t.Fatalf("models[] 期望 ≥11 条（9 HTTP + 2 SDK），实际 %d", len(out.Models))
	}

	seen := map[string]bool{}
	for _, e := range out.Providers {
		pid := wireString(t, "providers[]", e, "provider")
		seen[pid] = true
		assertWireEntry(t, "providers["+pid+"]", e)
	}
	for _, e := range out.Models {
		pid := wireString(t, "models[]", e, "provider")
		mid := wireString(t, "models[]", e, "model")
		assertWireEntry(t, "models["+pid+"/"+mid+"]", e)
	}
	// 10 家密态核心 + 2 枚非密态（百炼 / MaaS）必须全部出现，不得因缺字段被整条丢弃。
	for _, want := range []string{
		"tencent", "volcengine", "nearai", "privatemode", "azure", "gcp", "aws",
		"aliyun-confidential", "huawei-confidential", "aliyun-bailian", "huawei-maas",
	} {
		if !seen[want] {
			t.Fatalf("providers[] 缺少 %s（密态/非密态全量条目必须出现）", want)
		}
	}
	if !seen["mobilecloud"] {
		t.Fatalf("providers[] 缺少 mobilecloud 骨架（pending-credential 也须呈现）")
	}

	// 负向文本（举证边界判定物③）。
	if m := wireNegativeRE.FindString(string(body)); m != "" {
		t.Fatalf("响应体命中负向举证文本 %q（PRD §3.3：命中即验收失败）", m)
	}
}

// TestWireEvidenceNoSmokeOKWithoutIntegrationTag 【P0-3 负向】
// 无 -tags=integration、无真实凭据的默认运行中，任何 wire 输出都不得出现 smoke-ok。
func TestWireEvidenceNoSmokeOKWithoutIntegrationTag(t *testing.T) {
	k := mock.NewKernel(nil)
	defer k.Close()
	h := confllm.NewConfllmHandler(newWireRegistry(t, k.URL()))

	// 1) models 端点
	rec := httptest.NewRecorder()
	h.HandleModels(rec, httptest.NewRequest(http.MethodGet, "/v1/confllm/models", nil))
	if strings.Contains(rec.Body.String(), "smoke-ok") {
		t.Fatalf("/v1/confllm/models 出现 smoke-ok（无 integration tag 不得写冒烟举证）：%s", rec.Body.String())
	}
	// 2) health 端点
	rec2 := httptest.NewRecorder()
	h.HandleHealth(rec2, httptest.NewRequest(http.MethodGet, "/v1/confllm/health", nil))
	if strings.Contains(rec2.Body.String(), "smoke-ok") {
		t.Fatalf("/v1/confllm/health 出现 smoke-ok：%s", rec2.Body.String())
	}
	// 3) meta 常量层也不得提供 smoke-ok 形态（防误写）。
	src := meta.ConnNeverTested + "|" + meta.ConnPendingCredential
	if strings.Contains(src, "smoke-ok") {
		t.Fatal("meta 常量意外包含 smoke-ok 形态")
	}
}

// TestWireMetadataHardNormalization 【P0-3 值域 · 硬归一】
// 即使内部 meta 自称 verified / A 类 / quote:tdx，wire 层也绝不放行「已验证」表述。
func TestWireMetadataHardNormalization(t *testing.T) {
	cases := []struct {
		name         string
		in           meta.ConfidentialityMeta
		connectivity string
	}{
		{"缺省全空", meta.ConfidentialityMeta{}, ""},
		{"自称 verified + A 类 + quote:tdx", meta.ConfidentialityMeta{
			ConfidentialityClass: meta.ClassA,
			Attestation:          meta.AttestQuoteTDX,
			DataRetention:        meta.RetentionZero,
			Deployment:           meta.DeployManaged,
			Verification:         meta.VerificationVerified,
		}, meta.ConnNeverTested},
		{"有书面引用但未验证", meta.ConfidentialityMeta{
			ConfidentialityClass: meta.ClassA,
			Attestation:          meta.AttestToken,
			Verification:         meta.VerificationClaimWithReferenceUnverified,
		}, meta.ConnPendingCredential},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			w := meta.ToWireMetadata(c.in, c.connectivity)
			if w.AttestationVerdict != meta.WireVerdictUnknown {
				t.Fatalf("attestationVerdict=%q 期望 unknown（硬归一，恒 unknown）", w.AttestationVerdict)
			}
			if w.VerificationStatus != meta.WireVerificationStatusClaimUnverified {
				t.Fatalf("verificationStatus=%q 期望 claim-unverified，绝不得输出 verified", w.VerificationStatus)
			}
			// 序列化后 7 键齐全（禁 omitempty）：零值也必须出现。
			raw, err := json.Marshal(w)
			if err != nil {
				t.Fatalf("序列化失败：%v", err)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("反序列化失败：%v", err)
			}
			for _, k := range wireSevenFields {
				if _, ok := m[k]; !ok {
					t.Fatalf("WireMetadata 序列化缺失 %q（禁 omitempty）：%s", k, string(raw))
				}
			}
			if m := wireNegativeRE.FindString(string(raw)); m != "" {
				t.Fatalf("WireMetadata 命中负向文本 %q：%s", m, string(raw))
			}
		})
	}
}

// TestWireMetadataZeroValueEmitsAllSeven 零值 WireMetadata 也必须输出 7 键（禁 omitempty 的直接举证）。
func TestWireMetadataZeroValueEmitsAllSeven(t *testing.T) {
	raw, err := json.Marshal(meta.WireMetadata{})
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("反序列化失败：%v", err)
	}
	for _, k := range wireSevenFields {
		v, ok := m[k]
		if !ok {
			t.Fatalf("零值 WireMetadata 缺失 %q：%s", k, string(raw))
		}
		if string(v) != `""` {
			t.Fatalf("零值 %q 应为 \"\"，实际 %s", k, string(v))
		}
	}
}
