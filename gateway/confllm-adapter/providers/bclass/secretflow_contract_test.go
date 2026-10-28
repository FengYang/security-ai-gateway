// Package bclass — 隐语 B 类密态推理契约测试（T05：离线，SFFake 状态机）。
//
// 覆盖（QA-6）：
//   - SFFake 任务式状态机 SubmitGraph（pending/running）→ PollResult（running → done）；
//   - 未知 job 报错；
//   - Health 始终就绪（Fake 不依赖真实桥接）；
//   - SecretFlowProviderImpl 真实桥接骨架在未配置 endpoint/binary 时返回 pending-credential。
package bclass

import (
	"context"
	"encoding/json"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/meta"
)

func TestSFFakeStateMachine(t *testing.T) {
	f := NewSFFake("sf1")
	ctx := context.Background()
	job, err := f.SubmitGraph(ctx, &SFFlowSpec{Name: "g", DAG: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != SFJobRunning {
		t.Fatalf("提交后应为 running，实际 %s", job.Status)
	}
	res, err := f.PollResult(ctx, job.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != SFJobDone {
		t.Fatalf("轮询后应为 done，实际 %s", res.Status)
	}
	// 未知 job 报错。
	if _, err := f.PollResult(ctx, "nope"); err == nil {
		t.Fatal("未知 job 应报错")
	}
	// Health 始终就绪。
	if !f.Health(ctx).Ready {
		t.Fatal("SFFake 应就绪")
	}
}

func TestSecretFlowProviderImplBridgeMissing(t *testing.T) {
	p := NewSecretFlowProvider("sf", NewSFBridge("", "", nil))
	if p.Health(context.Background()).Ready {
		t.Fatal("未配置桥接应 not ready")
	}
	_, err := p.SubmitGraph(context.Background(), &SFFlowSpec{Name: "g", DAG: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("未配置桥接提交应返回 pending-credential")
	}
}

// TestSecretFlowUnifiedContractKeepsClassB 【B 类声明值被吞 · 回归网】
//
// 断言：SecretFlow 适配统一契约后能进注册表，且 wire 层保留已声明的 class=B
// （此前因缺 Chat/Stream/ListModels 走富化「未匹配」分支 → 被降级为 unknown）。
func TestSecretFlowUnifiedContractKeepsClassB(t *testing.T) {
	// ① 统一契约装配入口：类型键 secretflow 已注册且可构造。
	p, err := confllm.GlobalRegistry.NewFromConfig(confllm.ProviderConfig{
		Type: SecretFlowTypeKey, ID: "sf-unified",
	})
	if err != nil {
		t.Fatalf("secretflow 未注册或构造失败（B 类仍进不了注册表）：%v", err)
	}
	var unified confllm.ConfidentialLLMProvider = p
	if unified.ID() != "sf-unified" {
		t.Fatalf("实例 ID=%q 期望 sf-unified", unified.ID())
	}
	// ② 已声明的 class=B 不得被吞。
	if got := unified.Metadata().ConfidentialityClass; got != meta.ClassB {
		t.Fatalf("confidentialityClass=%q 期望 B（已声明值不得降级为 unknown）", got)
	}
	// ③ wire 层同样保留 B，且举证三字段硬归一（绝不因 B 类而升级）。
	w := meta.ToWireMetadata(unified.Metadata(), meta.ConnNeverTested)
	if w.ConfidentialityClass != meta.ClassB {
		t.Fatalf("wire confidentialityClass=%q 期望 B", w.ConfidentialityClass)
	}
	if w.AttestationVerdict != meta.WireVerdictUnknown || w.VerificationStatus != meta.WireVerificationStatusClaimUnverified {
		t.Fatalf("B 类 wire 举证字段被升级：verdict=%q status=%q", w.AttestationVerdict, w.VerificationStatus)
	}
	// ④ chat 式三个方法：返回明确错误，绝不 panic、绝不伪造成功响应。
	ctx := context.Background()
	if _, err := unified.Chat(ctx, &confllm.ChatRequest{Model: "m"}); err == nil {
		t.Fatal("B 类 Chat 应返回 not-implemented 错误，不得伪造成功响应")
	}
	if _, err := unified.Stream(ctx, &confllm.ChatRequest{Model: "m"}); err == nil {
		t.Fatal("B 类 Stream 应返回 not-implemented 错误")
	}
	if _, err := unified.ListModels(ctx); err == nil {
		t.Fatal("B 类 ListModels 应返回 not-implemented 错误")
	}
	// ⑤ 未配置 endpoint/binary → Health 报 pending-credential（不是「未知」）。
	h := unified.Health(ctx)
	if !h.PendingCredential || h.Ready {
		t.Fatalf("未配置桥接的 Health 应 pending-credential：%+v", h)
	}
}
