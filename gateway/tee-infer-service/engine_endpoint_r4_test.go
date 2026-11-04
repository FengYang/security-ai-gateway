// engine_endpoint_r4_test.go - 明文引擎端点信任域告警（方案 §6.1 R4）判定逻辑。
package main

import "testing"

// TestWarnPlaintextEngineEndpoint 覆盖判定矩阵：只有「明文 http + 非回环」才告警。
//
// 该判定的意义：进程内成环时 https 已经足够（同信任域内 TLS 终止常见），把 https 也
// 一律告警会让日志失去信号；反过来漏掉非回环 http 则等于放过「明文落到别的机器」。
func TestWarnPlaintextEngineEndpoint(t *testing.T) {
	cases := []struct {
		raw  string
		warn bool
		why  string
	}{
		{"http://vllm:8000", true, "明文 + 非回环（K8s 服务名）必须告警"},
		{"http://10.0.0.7:8000", true, "明文 + 私网 IP 必须告警"},
		{"http://127.0.0.1:8000", false, "同机回环不告警"},
		{"http://localhost:8000", false, "localhost 不告警"},
		{"http://[::1]:8000", false, "IPv6 回环不告警"},
		{"https://vllm.example.com:8443", false, "https 不告警"},
		{"", false, "空串（未配置引擎）不告警"},
		{"vllm:8000", false, "无 scheme 不误报"},
	}
	for _, c := range cases {
		if got := warnPlaintextEngineEndpoint("engine-url", c.raw); got != c.warn {
			t.Errorf("warnPlaintextEngineEndpoint(%q)=%v want %v（%s）", c.raw, got, c.warn, c.why)
		}
	}
}
