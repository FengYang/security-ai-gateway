// model.go — 演示引擎的别名转发（实现主体已迁至 gateway/modelengine）。
//
// 【为什么只剩别名】演示引擎（词表 16 / dim 8 的确定性小模型）同时被两处使用：
//   - 宿主 tee-infer-service（`-engine-url` 为空时的本地引擎）；
//   - gateway/vllm-adapter（无 GPU 环境下的对等 mock）。
//
// 后者是独立进程、不得 import 宿主包（方案 §8.2④），故实现归入明文引擎平面包
// `gateway/modelengine`；本文件只保留 `model.New()/model.Model` 等历史名字的转发，
// 使既有调用点与测试零改动。
//
// 保留 `Model`/`New`/`TokenToRune` 这三个名字的原因：它们是 M7 起沿用的公开符号，
// 直接改名会波及 36 处调用点与多个测试，而收益仅是命名整洁——不值得。
package model

import "security-ai-gateway/gateway/modelengine"

// VocabSize 词表大小（演示模型）。
const VocabSize = modelengine.VocabSize

// InputDim 输入维度（与 embedding-service 默认 dim 对齐）。
const InputDim = modelengine.InputDim

// Model 小型确定性模型：y = softmax(W·relu(W0·x + b0) + b1)，argmax 采样。
type Model = modelengine.Demo

// New 构造确定性模型（权重由固定公式生成，可复现、跨进程一致）。
func New() *Model { return modelengine.NewDemo() }

// TokenToRune 演示词表映射：token ID → 字符（0-15 → 'a'-'p'）。
var TokenToRune = modelengine.TokenToRune
