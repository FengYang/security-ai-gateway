package main

// S2-2 转 enforcing 演练与回滚验证（甲类第 3 项）。
//
// 既有资产已分别验证两半：enforcing 真实流式拦截（TestOutputGuardFramewiseE2EEnforcing）
// 与运行时降级端点（TestOutputGuardConfigEnforceToShadow 等）。本测试把两者串成一次
// 完整作战闭环，关键增量是证明——**运行时回滚后，同一服务的“新请求”恢复正常下发**，
// 且运行时不能重新升回 enforcing（D4' 单向安全闸门）。全程离线可重复（stub L2/引擎）。

import (
	"net/http"
	"strings"
	"testing"

	"security-ai-gateway/protocol/go"
)

func TestS22EnforcingDrillAndRollback(t *testing.T) {
	srv, ts := newM9Server(t)

	// ① 启动即 enforcing：拦截只能经启动参数开启（D4'）；L2 恒判 block/A1-06。
	srv.outputGuardMode = outputGuardEnforcing
	srv.outputGuardParams = defaultOutputGuardParams()
	srv.outputGuardCascade = cascadeParams(true)
	srv.outputGuardL2 = fakeL2Classifier{cat: "A1-06", conf: 0.9}
	deltas := []string{"好的。", "这是。", "结束。"}
	srv.model = framewiseStubEngine{deltas: deltas}

	// doDrillRequest 在一个全新会话上发起真实加密流式请求，返回下发帧。
	doDrillRequest := func(counter uint64) []deliveredFrame {
		t.Helper()
		sessionID, ksig, kenc := setupTestSession(t, ts)
		hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
			"请讲个笑话", protocol.EngineTypeTEEGPU, true, counter)
		resp, err := http.DefaultClient.Do(hr)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("流式请求 HTTP 应 200（拦截体现在终止码），got %d", resp.StatusCode)
		}
		return parseWireFrames(t, mustReadAll(t, resp.Body), sessionID, kenc)
	}

	// ② 演练拦截：enforcing 请求零 delta、content_filter 终止。
	f1 := doDrillRequest(1)
	for i, f := range f1 {
		if f.Delta != "" {
			t.Fatalf("enforcing 不得泄漏任何 delta（帧 %d 泄漏 %q）", i, f.Delta)
		}
	}
	last1 := f1[len(f1)-1]
	if last1.Finish != "content_filter" {
		t.Fatalf("enforcing 终止码应为 content_filter，实际 %q", last1.Finish)
	}

	// ③ 运行时回滚 enforcing → shadow（fail-safe 允许降级；纯内存演练，不落盘）。
	rec := doOutputGuardConfig(srv, http.MethodPost, true, `{"mode":"shadow"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("回滚降级应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	if v := srv.currentOutputGuardMode(); v != outputGuardShadow {
		t.Fatalf("回滚后 mode 应为 shadow，实际 %q", v)
	}

	// ④ 回滚后新请求：同一服务恢复完整下发（delta 齐 + 终止码恢复 stop），证明业务已恢复。
	f2 := doDrillRequest(2)
	var got strings.Builder
	for _, f := range f2 {
		got.WriteString(f.Delta)
	}
	if want := strings.Join(deltas, ""); got.String() != want {
		t.Fatalf("回滚后新请求应完整下发 %q，实际 %q", want, got.String())
	}
	last2 := f2[len(f2)-1]
	if last2.Finish != "stop" {
		t.Fatalf("回滚后终止码应恢复 stop，实际 %q", last2.Finish)
	}

	// ⑤ 单向安全闸门：运行时不得重新升回 enforcing（即便当前在 shadow）。
	rec2 := doOutputGuardConfig(srv, http.MethodPost, true, `{"mode":"enforcing"}`)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("运行时升 enforcing 应被 400 拒绝，got %d", rec2.Code)
	}
	if v := srv.currentOutputGuardMode(); v != outputGuardShadow {
		t.Fatalf("拒绝升级后 mode 应仍为 shadow，实际 %q", v)
	}

	// ⑥ 审计留痕：拦截仅发生在回滚前（1 条 output_blocked）；成功的 mode 变更 1 条；
	//    T3b：被拒的运行时升级亦落 1 条（同 action，result=rejected_bad_request）。
	if n := srv.audit.countByAction("output_blocked"); n != 1 {
		t.Fatalf("回滚前应仅 1 条 output_blocked，实际 %d", n)
	}
	if n := countByActionResult(srv.audit, "output_guard_mode_change", "applied"); n != 1 {
		t.Fatalf("应留 1 条 output_guard_mode_change/applied，实际 %d", n)
	}
	if n := countByActionResult(srv.audit, "output_guard_mode_change", "rejected_bad_request"); n != 1 {
		t.Fatalf("被拒升级应留 1 条 output_guard_mode_change/rejected_bad_request，实际 %d", n)
	}
}
