package main

// P2-4 T-3.4：集群心跳上报装配单测（默认关闭 / 开关生效 / 配置不完整 fail-closed）。

import (
	"strings"
	"testing"
)

// clearHeartbeatEnv 清理心跳相关环境变量（避免用例间串扰）。
func clearHeartbeatEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GATEWAY_CORE_HEARTBEAT_ENABLED",
		"GATEWAY_CORE_HEARTBEAT_URL",
		"GATEWAY_CORE_CLUSTER_ID",
		"GATEWAY_CORE_CLUSTER_CREDENTIAL",
		"GATEWAY_CORE_HEARTBEAT_INTERVAL",
	} {
		t.Setenv(k, "")
	}
}

// TestSetupHeartbeatDefaultOff 默认关闭：未开启 ⇒ 不装配、无任何副作用。
func TestSetupHeartbeatDefaultOff(t *testing.T) {
	clearHeartbeatEnv(t)
	status, stop, err := setupHeartbeat(nil)
	if err != nil {
		t.Fatalf("默认关闭不应报错: %v", err)
	}
	if status != "未启用" {
		t.Fatalf("默认状态应为未启用: %q", status)
	}
	if stop == nil {
		t.Fatalf("停止函数不应为 nil")
	}
	stop() // 必须可安全调用
}

// TestSetupHeartbeatEnabled 开启且配置齐全 ⇒ 装配成功并返回状态描述。
func TestSetupHeartbeatEnabled(t *testing.T) {
	clearHeartbeatEnv(t)
	t.Setenv("GATEWAY_CORE_HEARTBEAT_ENABLED", "true")
	t.Setenv("GATEWAY_CORE_HEARTBEAT_URL", "http://127.0.0.1:1/v1/adminext/clusters/c1/heartbeat")
	t.Setenv("GATEWAY_CORE_CLUSTER_ID", "c1")
	t.Setenv("GATEWAY_CORE_CLUSTER_CREDENTIAL", "cred")
	status, stop, err := setupHeartbeat(nil)
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	defer stop()
	if !strings.Contains(status, "已启用") || !strings.Contains(status, "c1") {
		t.Fatalf("状态描述错误: %q", status)
	}
}

// TestSetupHeartbeatIncompleteConfigFailsClosed 开启但配置不完整 ⇒ 报错（fail-closed）。
func TestSetupHeartbeatIncompleteConfigFailsClosed(t *testing.T) {
	clearHeartbeatEnv(t)
	t.Setenv("GATEWAY_CORE_HEARTBEAT_ENABLED", "true")
	t.Setenv("GATEWAY_CORE_HEARTBEAT_URL", "http://127.0.0.1:1/hb")
	// 缺集群 ID 与凭证
	if _, _, err := setupHeartbeat(nil); err == nil {
		t.Fatalf("配置不完整应报错（fail-closed）")
	}
}

// TestSetupHeartbeatInvalidInterval 周期配置非法 ⇒ 报错。
func TestSetupHeartbeatInvalidInterval(t *testing.T) {
	clearHeartbeatEnv(t)
	t.Setenv("GATEWAY_CORE_HEARTBEAT_ENABLED", "true")
	t.Setenv("GATEWAY_CORE_HEARTBEAT_URL", "http://127.0.0.1:1/hb")
	t.Setenv("GATEWAY_CORE_CLUSTER_ID", "c1")
	t.Setenv("GATEWAY_CORE_CLUSTER_CREDENTIAL", "cred")
	t.Setenv("GATEWAY_CORE_HEARTBEAT_INTERVAL", "abc")
	if _, _, err := setupHeartbeat(nil); err == nil {
		t.Fatalf("非法周期应报错")
	}
}
