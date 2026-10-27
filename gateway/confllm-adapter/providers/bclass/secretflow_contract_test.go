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
