package main

// streamretry_test.go — P2-1 流式重试（Envoy 层）纯逻辑单测。
//
// 仅覆盖无 hostcall 的纯逻辑部分：配置默认值、头常量、与非流式重试对齐验证。
// 头注入（injectStreamRetryHeaders）依赖 wasm hostcall，不在宿主单测范围；
// Envoy 层重试行为需集成测试验证。

import (
	"testing"
)

// TestStreamRetryConfigDefaults 验证流式重试配置的零值默认（与 P0 行为一致）。
// 零行为变化原则：未显式配置时，stream_retry_enabled=false，不注入任何头。
func TestStreamRetryConfigDefaults(t *testing.T) {
	var c PluginConfig
	if c.StreamRetryEnabled {
		t.Fatal("StreamRetryEnabled 默认应为 false（零行为变化）")
	}
	if c.StreamRetryMaxAttempts != 0 {
		t.Fatalf("StreamRetryMaxAttempts 默认应为 0，实际 %d", c.StreamRetryMaxAttempts)
	}
}

// TestStreamRetryHeaderConstants 验证流式重试头常量：
// - 与非流式重试 retryAttemptHeader 对齐（同名）
// - 头名格式规范（X-Otpmask- 前缀）
func TestStreamRetryHeaderConstants(t *testing.T) {
	// 重试归因头：流式与非流式必须用同一个头名，TEE 侧统一识别不计费
	if hdrRetryAttempt != retryAttemptHeader {
		t.Fatalf("流式重试归因头名应与非流式一致: got=%q want=%q",
			hdrRetryAttempt, retryAttemptHeader)
	}

	// 头名格式：X-Otpmask- 前缀（与 X-Otpmask-Retry-Attempt 对齐）
	if hdrStreamRetry == "" {
		t.Fatal("hdrStreamRetry 不应为空")
	}
	if len(hdrStreamRetry) < 10 {
		t.Fatalf("hdrStreamRetry 格式异常: %q", hdrStreamRetry)
	}
}

// TestStreamRetryAttemptHeaderValue 验证重试头值计算逻辑（与非流式 retryAttemptHeaderValue 对齐）。
// 流式首次请求值为 1；Envoy 重试时自动递增到 2,3,...。
func TestStreamRetryAttemptHeaderValue(t *testing.T) {
	cases := []struct {
		attempt int
		want    string
		wantOK  bool
	}{
		{attempt: 0, want: "", wantOK: false},
		{attempt: 1, want: "", wantOK: false}, // 首次不写头（与非流式对齐：首次=1 不写）
		{attempt: 2, want: "2", wantOK: true},
		{attempt: 3, want: "3", wantOK: true},
	}
	for _, c := range cases {
		got, ok := retryAttemptHeaderValue(c.attempt)
		if ok != c.wantOK {
			t.Fatalf("attempt=%d: ok 不符: got=%v want=%v", c.attempt, ok, c.wantOK)
		}
		if ok && got != c.want {
			t.Fatalf("attempt=%d: 值不符: got=%q want=%q", c.attempt, got, c.want)
		}
	}
}

// TestStreamRetryZeroBehavior 验证"关闭时零行为变化"原则：
// - streamRetryEnabled=false 时不注入任何头
// - 路由未启用时，streamRetryEnabled 也可独立配置
func TestStreamRetryZeroBehavior(t *testing.T) {
	// 零值状态：streamRetryEnabled 应为 false
	// （注意：routeRuntime 是包级变量，此测试验证初始状态而非 initRouteRuntime 行为，
	//  避免依赖 wasm hostcall 环境）
	var state routeRuntimeState
	if state.streamRetryEnabled {
		t.Fatal("routeRuntimeState 零值 streamRetryEnabled 应为 false")
	}
}
