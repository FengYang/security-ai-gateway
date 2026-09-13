package main

// C 项（门禁 #7 边界 C）：gateway-core 通道令牌集拉取的应用逻辑（纯逻辑单测）。
// 覆盖：过短拒绝（保留旧值）、首值生效、同值不触发重拉（changed=false）、轮换生效（changed=true）。

import "testing"

func TestApplyCoreChannelToken(t *testing.T) {
	credRuntime.coreToken = ""
	// 过短 → 拒绝（保留旧值；空串同样被拒）
	if _, err := applyCoreChannelToken("short"); err == nil {
		t.Fatal("过短令牌应被拒绝")
	}
	if _, err := applyCoreChannelToken(""); err == nil {
		t.Fatal("空令牌应被拒绝")
	}
	if credRuntime.coreToken != "" {
		t.Fatalf("拒绝时不得写入运行态: %q", credRuntime.coreToken)
	}

	// 首值生效
	const tok1 = "core-channel-token-0123456789abcdef"
	changed, err := applyCoreChannelToken(tok1)
	if err != nil || !changed || credRuntime.coreToken != tok1 {
		t.Fatalf("首值应生效: changed=%v err=%v token=%q", changed, err, credRuntime.coreToken)
	}
	if got := runtimeCoreChannelToken(); got != tok1 {
		t.Fatalf("运行态读取不符: %q", got)
	}

	// 同值不触发重拉（避免每 tick 都重拉限流表）
	changed, err = applyCoreChannelToken(tok1)
	if err != nil || changed {
		t.Fatalf("同值应 changed=false: changed=%v err=%v", changed, err)
	}

	// 轮换生效
	const tok2 = "core-channel-token-rotated-0123456789"
	changed, err = applyCoreChannelToken(tok2)
	if err != nil || !changed || credRuntime.coreToken != tok2 {
		t.Fatalf("轮换应生效: changed=%v err=%v token=%q", changed, err, credRuntime.coreToken)
	}
}
