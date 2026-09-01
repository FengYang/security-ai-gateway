package main

// 段① 信封客户端（P1b）：SSE 分块解密与流式重组。
//
// tee-infer 流式响应（tee_gpu 引擎，P2 接线）经 K_enc 逐块加密回传：
//
//	Content-Type: text/event-stream
//	data: <hex(s2c 信封)>        （外层：全局 s2c 计数器 → nonce 唯一 + 反重放窗口）
//	data: <hex(s2c 信封)>
//	...
//
// 信封内明文为流分片 JSON（内层）：
//
//	{"seq":1,"delta":"Hello","finish":""}
//	{"seq":2,"delta":" world","finish":"stop"}
//
// seq 为流内严格递增序号（1 起，跳号/回退/重复即拒绝），防止流内容被重排。
// 双层设计原因：外层计数器全局唯一（GCM nonce 安全），内层 seq 绑定流位置
// （并发流交错时仍可严格校验单流顺序）。
//
// 插件解密后重组为客户端 SSE：data: {"token":"..."} 分片 + data: [DONE]。

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"security-ai-gateway/protocol/go"
)

// streamChunk SSE 信封内明文分片。
type streamChunk struct {
	Seq    uint64 `json:"seq"`              // 流内序号（1 起严格递增）
	Delta  string `json:"delta"`            // 增量文本
	Finish string `json:"finish,omitempty"` // 终止标记（""=继续，"stop"=正常结束）
}

// sseStreamDecryptor 单条 SSE 流的解密状态（请求级，onResponseBody 内创建）。
type sseStreamDecryptor struct {
	lastSeq uint64 // 已见最大流内序号（严格递增校验）
}

// decryptSSEChunk 解密单个 SSE 分片：外层信封（K_enc + 反重放窗口）→ 内层 seq 严格递增。
func (d *sseStreamDecryptor) decryptSSEChunk(dataLine string) (*streamChunk, error) {
	wire, err := hex.DecodeString(strings.TrimSpace(dataLine))
	if err != nil {
		return nil, fmt.Errorf("envelope: SSE 分片非 hex: %w", err)
	}
	pt, err := Session.openPayload(protocol.EndpointInfer, wire)
	if err != nil {
		return nil, fmt.Errorf("envelope: SSE 分片解密失败: %w", err)
	}
	var chunk streamChunk
	if err := json.Unmarshal(pt, &chunk); err != nil {
		return nil, fmt.Errorf("envelope: SSE 分片 JSON 无效: %w", err)
	}
	if err := protocol.CheckStreamSequence(d.lastSeq, chunk.Seq); err != nil {
		return nil, err
	}
	d.lastSeq = chunk.Seq
	return &chunk, nil
}

// decryptSSEBody 解密整段 tee-infer SSE 响应体，重组为客户端明文 SSE。
// 任一分片解密失败/序号乱序/重放 → 整流拒绝（fail-closed，不输出半截明文）。
func decryptSSEBody(body []byte) ([]byte, error) {
	dec := &sseStreamDecryptor{}
	var sb strings.Builder
	sawAny := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue // 空行/注释行（SSE 帧分隔），忽略
		}
		if strings.TrimSpace(data) == "[DONE]" {
			continue // tee 侧流结束标记（P2 服务端发送；解密侧由 finish 判定）
		}
		chunk, err := dec.decryptSSEChunk(data)
		if err != nil {
			return nil, err
		}
		sawAny = true
		sb.WriteString("data: ")
		payload, _ := json.Marshal(map[string]string{"token": chunk.Delta})
		sb.Write(payload)
		sb.WriteString("\n\n")
		if chunk.Finish != "" {
			sb.WriteString("data: [DONE]\n\n")
			return []byte(sb.String()), nil
		}
	}
	if !sawAny {
		return nil, errors.New("envelope: SSE 流无有效加密分片")
	}
	// 无 finish 标记即截断的流：拒绝（fail-closed，防截断攻击导致静默丢尾）
	return nil, errors.New("envelope: SSE 流未正常终止（缺 finish 分片）")
}

// isSSEBody 响应体是否为 tee-infer 加密 SSE 流（按 data: 行首判定）。
func isSSEBody(body []byte) bool {
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimRight(line, "\r"), "data:") {
			return true
		}
	}
	return false
}
