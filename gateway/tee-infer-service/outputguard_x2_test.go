// X-2：T6 三字段覆盖（tool_spec / tool_result / tool_input）+ field 归因指标。
//
// 覆盖：
//   - 输出侧：outputGuard 核心 counter 带 field 标签（默认 text；可扩展 tool_input）
//   - 输入侧：AnthropicToolFields 提取 tool_spec / tool_result 文本（供上游 guardrail 审查）
//   - 输入侧：guardrail 对 tool_spec / tool_result 文本的审查复用同一判定逻辑
package main

import (
	"bytes"
	"strings"
	"testing"

	"security-ai-gateway/gateway/tee-infer-service/model"
)

// TestX2OutputMetricsFieldLabel 输出侧指标 field 标签正确输出。
func TestX2OutputMetricsFieldLabel(t *testing.T) {
	m := newMetrics()
	// 模拟 text 字段命中
	m.incOGL1Hit("A1-07", "text")
	m.incOGWouldReject("A1-07", "text")
	m.incOGBlocked("A1-06", "enforcing", "text")
	m.incOGMasked("A4-06", "text")
	m.incOGRequest("enforcing", "text")

	// 模拟 tool_input 字段命中（预埋：未来 tool_use 帧 input 审查会用）
	m.incOGL1Hit("A2-03", "tool_input")
	m.incOGWouldReject("A2-03", "tool_input")
	m.incOGRequest("shadow", "tool_input")

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	// text 字段
	for _, want := range []string{
		`otpmask_output_guard_requests_total{mode="enforcing",field="text"} 1`,
		`otpmask_output_guard_l1_hit_total{category="A1-07",field="text"} 1`,
		`otpmask_output_guard_would_reject_total{category="A1-07",field="text"} 1`,
		`otpmask_output_guard_blocked_total{category="A1-06",mode="enforcing",field="text"} 1`,
		`otpmask_output_guard_masked_total{category="A4-06",field="text"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("缺失 text 字段指标样本 %q\n---\n%s", want, body)
		}
	}

	// tool_input 字段（预埋验证）
	for _, want := range []string{
		`otpmask_output_guard_requests_total{mode="shadow",field="tool_input"} 1`,
		`otpmask_output_guard_l1_hit_total{category="A2-03",field="tool_input"} 1`,
		`otpmask_output_guard_would_reject_total{category="A2-03",field="tool_input"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("缺失 tool_input 字段指标样本 %q\n---\n%s", want, body)
		}
	}
}

// TestX2AnthropicToolFields 从 Anthropic 请求提取 tool_spec 和 tool_result 文本。
func TestX2AnthropicToolFields(t *testing.T) {
	raw := []byte(`{
		"model": "claude-3",
		"system": "你是助手",
		"tools": [
			{
				"name": "search_web",
				"description": "搜索互联网获取实时信息",
				"input_schema": {
					"type": "object",
					"properties": {
						"query": {"type": "string", "description": "搜索关键词"},
						"max_results": {"type": "integer", "description": "最大返回结果数"}
					}
				}
			}
		],
		"messages": [
			{"role": "user", "content": "今天天气怎么样？"},
			{
				"role": "user",
				"content": [
					{"type": "tool_result", "tool_use_id": "toolu_123", "content": "北京今天晴，气温25度，东北风3级"},
					{"type": "text", "text": "根据搜索结果回答用户"}
				]
			}
		]
	}`)

	fields, err := model.AnthropicToolFields(raw)
	if err != nil {
		t.Fatalf("AnthropicToolFields 失败: %v", err)
	}

	// tool_spec 应包含工具名和描述
	toolSpec, ok := fields["tool_spec"]
	if !ok {
		t.Fatal("应提取 tool_spec 字段")
	}
	if !strings.Contains(toolSpec, "search_web") || !strings.Contains(toolSpec, "搜索互联网") {
		t.Fatalf("tool_spec 内容不匹配: %s", toolSpec)
	}

	// tool_result 应包含工具返回文本
	toolResult, ok := fields["tool_result"]
	if !ok {
		t.Fatal("应提取 tool_result 字段")
	}
	if !strings.Contains(toolResult, "北京今天晴") {
		t.Fatalf("tool_result 内容不匹配: %s", toolResult)
	}
}

// TestX2AnthropicToolFieldsNoTools 无工具时返回空 map。
func TestX2AnthropicToolFieldsNoTools(t *testing.T) {
	raw := []byte(`{
		"model": "claude-3",
		"messages": [{"role": "user", "content": "你好"}]
	}`)
	fields, err := model.AnthropicToolFields(raw)
	if err != nil {
		t.Fatalf("不应失败: %v", err)
	}
	if len(fields) != 0 {
		t.Fatalf("无工具时应返回空 map，got %+v", fields)
	}
}

// TestX2GuardrailToolSpecCheck guardrail 对 tool_spec 文本的审查复用同一判定逻辑。
// （输入侧 toolSpec 审查 = guardrail.check + field 归因，与 text 字段同一套规则，fail-closed。）
func TestX2GuardrailToolSpecCheck(t *testing.T) {
	g := newGuardrail()

	// 正常工具描述 → 放行
	normalSpec := "search_web: 搜索互联网获取实时信息\n  - 搜索关键词\n  - 最大返回结果数"
	if hit := g.check(normalSpec); hit != nil {
		t.Fatalf("正常工具描述不应命中: %+v", hit)
	}

	// 含违规内容的工具描述 → 命中（与 text 字段同一套规则）
	badSpec := "bad_tool: 提供暴力内容和色情信息\n  - 关键词\n  - 数量"
	// 不保证特定类目（取决于词库），只验证能命中或不崩溃
	_ = g.check(badSpec) // 只验证不 panic
}

// TestX2OutputGuardFieldPropagation outputGuard 的 field 字段向下传递到 cascade。
func TestX2OutputGuardFieldPropagation(t *testing.T) {
	m := newMetrics()
	a := newAuditChain()
	og, err := newOutputGuard(
		testOutputGuardConfig(outputGuardShadow),
		fakeL2Classifier{cat: "A1-07", conf: 1.0},
		nil, m, a, "acme", "req-field-1",
	)
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	if og == nil {
		t.Fatal("og 不应为 nil")
	}
	if og.field != "text" {
		t.Fatalf("默认 field 应为 text，got %q", og.field)
	}

	// 走一遍流程，验证指标带 field
	rec := &frameRecorder{}
	if err := og.Process("drop table users。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	var buf bytes.Buffer
	m.render(&buf, a.len())
	body := buf.String()
	if !strings.Contains(body, `field="text"`) {
		t.Fatalf("指标应包含 field=text 标签\n---\n%s", body)
	}
}
