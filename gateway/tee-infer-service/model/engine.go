// Package model — 推理引擎抽象（M12 vLLM 对接层）。
//
// Engine 接口把"TEE 内推理引擎"从 tee-infer 的本地确定性模型解耦为可插拔：
// - LocalEngine（默认）：tee-infer 进程内的确定性演示模型（M7 既有行为）
// - RemoteEngine：经 TEE 内 vLLM 适配器（gateway/vllm-adapter）远程推理，
// 适配器在可信环境内对接真实 vLLM，对 tee-infer 暴露同一明文接口
//
// 明文边界不变：向量/文本仅在 TEE 内明文域出现，Engine 是明文域内的推理后端。
package model

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Engine 明文域推理引擎：输入向量 → token ID（单 token 采样，方案 C 兼容）。
type Engine interface {
	Predict(x []float64) int
}

// ensure *Model implements Engine（本地确定性引擎，M7 既有行为不变）。
var _ Engine = (*Model)(nil)

// generateRequest / generateResponse vLLM 适配器明文接口（TEE 内部协议）。
type generateRequest struct {
	Vectors [][]float64 `json:"vectors,omitempty"`
	Text    string      `json:"text,omitempty"`
}

type generateResponse struct {
	Tokens []uint64 `json:"tokens"`
}

// RemoteEngine 经 vLLM 适配器远程推理（TEE 内，明文域）。
type RemoteEngine struct {
	baseURL string
	client  *http.Client
}

// NewRemoteEngine 构造远程引擎；baseURL 形如 http://vllm-adapter:19190。
func NewRemoteEngine(baseURL string) *RemoteEngine {
	return &RemoteEngine{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Predict 远程推理：单向量 → token ID（适配器 batch 生成后取首个）。
func (r *RemoteEngine) Predict(x []float64) int {
	body, _ := json.Marshal(generateRequest{Vectors: [][]float64{x}})
	resp, err := r.client.Post(r.baseURL+"/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return -1 // 调用失败由上层 fail-closed 处理（不可信引擎不产生明文）
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	raw, _ := io.ReadAll(resp.Body)
	var gr generateResponse
	if err := json.Unmarshal(raw, &gr); err != nil || len(gr.Tokens) == 0 {
		return -1
	}
	return int(gr.Tokens[0])
}

// Close 预留（远程引擎无本地资源；真实 vLLM 场景可扩展会话管理）。
func (r *RemoteEngine) Close() error { return nil }
