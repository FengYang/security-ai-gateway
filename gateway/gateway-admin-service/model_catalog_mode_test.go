// Package main — 模型目录 D2 mode 呈现验收（chat | job）。
//
// 推导规则（enrichWithConfidentiality）：匹配到的 confllm provider 实现
// confllm.GraphProvider（类型断言）→ "job"（任务式）；否则 / 未匹配 / 老 CR → "chat"。
// mode="job" 的条目不得进 chat 路由候选集（chat/stream 侧 422 门禁兜底，目录标记供
// 路由/前端排除用）。
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/meta"
	"security-ai-gateway/gateway/confllm-adapter/providers/bclass"
)

// qaModeGraphProvider 测试桩：实现 confllm.GraphProvider 的任务式 provider
// （chat 式方法由内嵌 qaWireStubProvider 提供）。
type qaModeGraphProvider struct {
	qaWireStubProvider
}

func (p qaModeGraphProvider) SubmitGraphJSON(context.Context, json.RawMessage) (string, error) {
	return "qa-mode-job-1", nil
}

func (p qaModeGraphProvider) PollGraphJSON(context.Context, string) (string, json.RawMessage, error) {
	return confllm.GraphStatusDone, json.RawMessage(`{}`), nil
}

// modeTestMeta 测试用密态元数据（不触发 managed→A override 分支）。
var modeTestMeta = confllm.ConfidentialityMeta{
	ConfidentialityClass: meta.ClassUnknown,
	Attestation:          meta.AttestUnknown,
	DataRetention:        meta.RetentionUnknown,
	Deployment:           meta.DeploySelfHostedCVM,
	Verification:         meta.VerificationUnverified,
}

// TestEnrichModeJobForGraphProvider 【D2】GraphProvider 条目 mode=job（wire 可见）。
func TestEnrichModeJobForGraphProvider(t *testing.T) {
	const id = "qa-mode-graph-stub"
	confllm.GlobalRegistry.Register(qaModeGraphProvider{
		qaWireStubProvider: qaWireStubProvider{id: id, meta: modeTestMeta},
	})

	e := modelRouteEntry{Route: "r-mode-job", Provider: id}
	enrichWithConfidentiality(&e)
	if e.Mode != catalogModeJob {
		t.Fatalf("GraphProvider 条目 mode=%q 期望 %q", e.Mode, catalogModeJob)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if !strings.Contains(string(raw), `"mode":"job"`) {
		t.Fatalf("wire 缺 mode=job：%s", raw)
	}
}

// TestEnrichModeChatForPlainProvider 【D2】普通 chat 式 provider 条目 mode=chat。
func TestEnrichModeChatForPlainProvider(t *testing.T) {
	const id = "qa-mode-chat-stub"
	confllm.GlobalRegistry.Register(qaWireStubProvider{id: id, meta: modeTestMeta})

	e := modelRouteEntry{Route: "r-mode-chat", Provider: id}
	enrichWithConfidentiality(&e)
	if e.Mode != catalogModeChat {
		t.Fatalf("普通 provider 条目 mode=%q 期望 %q", e.Mode, catalogModeChat)
	}
}

// TestEnrichModeChatForUnmatchedLegacyCR 【D2】未匹配 / 老 CR → chat（缺省语义正确）。
func TestEnrichModeChatForUnmatchedLegacyCR(t *testing.T) {
	e := modelRouteEntry{Route: "r-mode-legacy", Provider: "qa-mode-absent-in-confllm"}
	enrichWithConfidentiality(&e)
	if e.Mode != catalogModeChat {
		t.Fatalf("老 CR 条目 mode=%q 期望 %q（老 CR 是 ai-proxy chat 式）", e.Mode, catalogModeChat)
	}
}

// TestEnrichModeJobForRealBClassSecretFlow 【D2】真实 B 类（隐语 SecretFlow）任务式
// 适配器装配后 mode=job（不止测试桩——真实实现亦须被类型断言识别）。
func TestEnrichModeJobForRealBClassSecretFlow(t *testing.T) {
	const id = "qa-mode-secretflow"
	p, err := confllm.GlobalRegistry.NewFromConfig(confllm.ProviderConfig{
		Type: bclass.SecretFlowTypeKey, ID: id,
	})
	if err != nil {
		t.Fatalf("secretflow 装配失败：%v", err)
	}
	confllm.GlobalRegistry.Register(p)

	e := modelRouteEntry{Route: "r-mode-sf", Provider: id}
	enrichWithConfidentiality(&e)
	if e.Mode != catalogModeJob {
		t.Fatalf("B 类 secretflow 条目 mode=%q 期望 %q", e.Mode, catalogModeJob)
	}
}
