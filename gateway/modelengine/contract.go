// Package modelengine 明文推理引擎平面（方案 §0.6 / D7）。
//
// 本包是**明文引擎契约与确定性演示引擎**的独立归属地，供两侧共同依赖：
//   - 宿主 `gateway/tee-infer-service/model`：在 TEE 明文域内按此契约选用
//     Local / Remote(vLLM) / Cmaas 三类实现；
//   - 对端 `gateway/vllm-adapter`：独立的 TEE 内适配器进程，**不得** import 宿主包
//     （方案 §8.2 完成判据④），只依赖本契约与演示引擎。
//
// 【与掩码平面不得合并】本包属明文平面（`Engine`：明文向量/文本进，token/文本出）；
// 掩码单步平面是 `gateway/tee-infer-service/route2step`（`MaskedStepBackend`：
// 掩码态 `[][]uint64` 进出）。两侧契约由 model/plane_test.go 与
// route2step/backend_test.go 的反射断言各自钉死，禁止互相吸收。
package modelengine

// ChatMessage OpenAI 兼容消息（text 载荷，D1）。
// P1-1 G-8 / M8-1：扩展 tool_calls/tool_call_id（承载模型发起的工具调用与工具结果）。
// 向后兼容：缺省无这些字段时序列化逐字节不变（omitempty）。
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall 模型发起的工具调用（OpenAI 兼容 function 形态；M8-1，与插件 chatToolCall 同构）。
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function ToolCallFunc `json:"function"`
}

// ToolCallFunc 工具调用函数体：name + JSON 字符串形态的 arguments。
type ToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// GenerateRequest text 载荷生成请求（明文域）。
type GenerateRequest struct {
	Model     string        // 模型名（vLLM served-model-name / C-MaaS 模型 code）
	Messages  []ChatMessage // OpenAI 兼容 messages
	MaxTokens uint32        // 生成上限（0 = 引擎缺省）
}

// Engine 明文域推理引擎。
// Predict：vectors 路径（路线 2 保留，单 token 采样；不可用返回 -1）。
// Generate：text 路径（路线 1，D1）流式生成；onDelta 逐块回调，
// 任一错误（连接/超时/状态码/流中断）整体失败（fail-closed，不产出半截结果）。
type Engine interface {
	Predict(x []float64) int
	Generate(req GenerateRequest, onDelta func(delta string) error) error
}
