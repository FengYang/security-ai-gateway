package cryptopsvc

// 本文件验证 P2-3 组级指标（T-1「指标」/ V-1「指标可见」）的渲染通路。

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"security-ai-gateway/gateway/cryptop/module/group"
)

// 编译期契约：真实组类型必须满足收集器接口。
//
// 采用结构化接口（不导入即满足），此处断言防止 group 侧改签名后
// 到装配期才发现接口不匹配。
var _ GroupMetricsCollector = (*group.ModuleGroup)(nil)

type fakeGroupMetrics struct{ rendered int }

func (f *fakeGroupMetrics) RenderMetrics(w io.Writer) {
	f.rendered++
	_, _ = io.WriteString(w, "# HELP gateway_group_ops_total 组级运算计数（测试替身）\n")
	_, _ = io.WriteString(w, "# TYPE gateway_group_ops_total counter\n")
	_, _ = io.WriteString(w, "gateway_group_ops_total{op=\"seal\",result=\"ok\"} 3\n")
}

// 未装配组模式时 /metrics 不得出现组序列（缺指标不可伪装成有组）。
func TestGroupMetricsAbsentWhenNotRegistered(t *testing.T) {
	m := newMetrics()
	var buf bytes.Buffer
	m.render(&buf)
	if strings.Contains(buf.String(), "gateway_group_") {
		t.Fatal("未注册组实例时 /metrics 不应输出组序列")
	}
}

// 注册后组序列随 /metrics 输出。
func TestGroupMetricsRenderedAfterRegister(t *testing.T) {
	m := newMetrics()
	f := &fakeGroupMetrics{}
	m.RegisterGroupMetrics(f)
	m.RegisterGroupMetrics(f) // 幂等：重复注册同一实例不重复渲染

	var buf bytes.Buffer
	m.render(&buf)
	out := buf.String()
	if !strings.Contains(out, "gateway_group_ops_total") {
		t.Fatalf("注册后 /metrics 应输出组序列：\n%s", out)
	}
	if f.rendered != 1 {
		t.Fatalf("重复注册应幂等（渲染 1 次），实际渲染 %d 次", f.rendered)
	}
	// 既有 cryptop 指标不受影响（#4 为恒定输出的序列）
	if !strings.Contains(out, "cryptop_call_timeout_total") {
		t.Fatal("组指标不得破坏既有 cryptop 指标段")
	}
}

// Server 层注册通路可用（装配层调用入口）。
func TestServerRegisterGroupMetrics(t *testing.T) {
	m := newMetrics()
	s := &Server{m: m}
	f := &fakeGroupMetrics{}
	s.RegisterGroupMetrics(f)

	var buf bytes.Buffer
	s.m.render(&buf)
	if !strings.Contains(buf.String(), "gateway_group_ops_total") {
		t.Fatal("Server.RegisterGroupMetrics 未生效")
	}
}
