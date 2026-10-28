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
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestSecretFlowGraphProviderParity 【D2】GraphProvider JSON 形态与 typed 方法行为一致。
//
// 覆盖：
//   - 桥接未配置（endpoint/binary 皆空）→ SubmitGraphJSON 与 typed SubmitGraph 同为
//     pending-credential 语义；
//   - 非法 JSON → 归一化 invalid_request（绝不伪装成上游错误）；
//   - httptest 桥接（离线 loopback，P0-5 允许）：提交 parity（同 jobID）、done 态
//     状态/output 与 typed PollResult 一致；
//   - failed 语义（绝不伪造成功）：res.Error 非空 ⇒ 状态归一 failed、失败详情经 err、
//     部分输出仍随 result 返回。
func TestSecretFlowGraphProviderParity(t *testing.T) {
	ctx := context.Background()

	// ① 桥接未配置：typed 与 JSON 形态同为 pending-credential。
	p := NewSecretFlowProvider("sf-json", NewSFBridge("", "", nil))
	var gp confllm.GraphProvider = p
	spec := json.RawMessage(`{"name":"g","dag":{}}`)

	if _, err := p.SubmitGraph(ctx, &SFFlowSpec{Name: "g", DAG: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("typed SubmitGraph 未配置桥接应报错")
	} else if pe := confllm.ParseError(err); pe.Code != confllm.CodePendingCredential {
		t.Fatalf("typed SubmitGraph 错误码=%q 期望 pending-credential", pe.Code)
	}
	_, err := gp.SubmitGraphJSON(ctx, spec)
	if err == nil {
		t.Fatal("SubmitGraphJSON 未配置桥接应报错")
	}
	if pe := confllm.ParseError(err); pe.Code != confllm.CodePendingCredential {
		t.Fatalf("SubmitGraphJSON 错误码=%q 期望 pending-credential（与 typed 一致）", pe.Code)
	}

	// ② 非法 JSON → 归一化 invalid_request。
	_, err = gp.SubmitGraphJSON(ctx, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("非法 JSON 应报错")
	}
	if pe := confllm.ParseError(err); pe.Code != confllm.CodeInvalidRequest {
		t.Fatalf("非法 JSON 错误码=%q 期望 invalid_request", pe.Code)
	}

	// ③ httptest 桥接：parity + failed 语义（仅 loopback，无真实网络）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/graphs":
			_, _ = w.Write([]byte(`{"job_id":"j-77"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/j-77":
			_, _ = w.Write([]byte(`{"jobId":"j-77","status":"done","output":{"answer":42}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/j-fail":
			_, _ = w.Write([]byte(`{"jobId":"j-fail","status":"failed","output":{"partial":1},"error":"task exploded"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p2 := NewSecretFlowProvider("sf-json2", NewSFBridge(srv.URL, "", nil))
	var gp2 confllm.GraphProvider = p2

	// 提交 parity：JSON 与 typed 同 jobID。
	job, err := p2.SubmitGraph(ctx, &SFFlowSpec{Name: "g", DAG: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := gp2.SubmitGraphJSON(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if job.JobID != "j-77" || jobID != job.JobID {
		t.Fatalf("SubmitGraphJSON jobID=%q typed=%q 期望同为 j-77", jobID, job.JobID)
	}

	// done parity：状态与 output 与 typed PollResult 一致。
	status, out, err := gp2.PollGraphJSON(ctx, "j-77")
	if err != nil || status != confllm.GraphStatusDone {
		t.Fatalf("done 态：status=%q err=%v 期望 done/nil", status, err)
	}
	res, err := p2.PollResult(ctx, "j-77")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != SFJobDone || string(res.Output) != string(out) {
		t.Fatalf("PollGraphJSON 与 typed PollResult 不一致：typed=%+v jsonOut=%s", res, out)
	}
	var outObj map[string]any
	_ = json.Unmarshal(out, &outObj)
	if v, _ := outObj["answer"].(float64); v != 42 {
		t.Fatalf("done 输出应含 answer=42：%v", outObj)
	}

	// failed 语义（绝不伪造成功）：status 归一 failed、err 携带 res.Error、部分输出随 result。
	status, out, err = gp2.PollGraphJSON(ctx, "j-fail")
	if status != confllm.GraphStatusFailed {
		t.Fatalf("failed 态 status=%q 期望 failed（绝不伪造成功，不得包装成 done）", status)
	}
	if err == nil {
		t.Fatal("failed 态应携带失败详情 err")
	}
	if pe := confllm.ParseError(err); pe.Code != confllm.CodeUpstreamError || pe.Message != "task exploded" {
		t.Fatalf("failed 详情不符：%+v", pe)
	}
	if !strings.Contains(string(out), "partial") {
		t.Fatalf("failed 态部分输出应随 result 返回：%s", out)
	}
}
