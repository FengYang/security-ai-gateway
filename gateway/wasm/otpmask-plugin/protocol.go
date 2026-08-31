package main

import (
	"encoding/json"
	"fmt"
)

// mock 加解密协议（M4 版本，技术方案 南向协议的前身）。
//
// 请求路径（客户端 → 网关 → mock vLLM）：
//
//	文本请求：  {"text": "hello world"}                    （Agent 原始输入，M4）
//	向量请求：  {"vectors": [[1,2,3], ...]}                （M2/M3 兼容输入）
//	密文请求：  {"cipher_vectors": [[...]], "nonce": "hex", "model": "mock"}
//
// 响应路径（mock vLLM → 网关 → 客户端）：
//
//	密文响应：  {"cipher_output": [...], "nonce": "hex"}
//	明文响应：  {"output": [...], "tokens": [...], "text": "..."}   （M4 含文本还原）
//
// embedding-service 响应：
//
//	{"tokens": [...], "vectors": [[...]]}

// plainRequest 明文请求（向量输入，M2/M3 兼容）。
type plainRequest struct {
	Vectors [][]uint64 `json:"vectors"`
}

// textRequest 明文请求（文本输入，M4）。
type textRequest struct {
	Text string `json:"text"`
}

// embedResponse embedding-service 响应。
type embedResponse struct {
	Tokens  []uint32  `json:"tokens"`
	Vectors [][]uint64 `json:"vectors"`
}

// cipherRequest 网关发往 mock vLLM 的密文请求。
type cipherRequest struct {
	CipherVectors [][]uint64 `json:"cipher_vectors"`
	Nonce         string     `json:"nonce"`
	Model         string     `json:"model"`
}

// cipherResponse mock vLLM 返回的密文响应。
type cipherResponse struct {
	CipherOutput []uint64 `json:"cipher_output"`
	Nonce        string   `json:"nonce"`
}

// plainResponse 网关返回客户端的明文响应。
type plainResponse struct {
	Output []uint64 `json:"output"`
	Tokens []uint32 `json:"tokens,omitempty"`
	Text   string   `json:"text,omitempty"`
}

// parsePlainRequest 解析向量明文请求（M2/M3 兼容）。
func parsePlainRequest(body []byte) (*plainRequest, error) {
	var req plainRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("otpmask: 解析明文请求失败: %w", err)
	}
	if len(req.Vectors) == 0 {
		return nil, fmt.Errorf("otpmask: 明文请求无 vectors")
	}
	for i, v := range req.Vectors {
		if len(v) == 0 {
			return nil, fmt.Errorf("otpmask: vectors[%d] 为空", i)
		}
	}
	return &req, nil
}

// parseTextRequest 解析文本明文请求。
func parseTextRequest(body []byte) (*textRequest, error) {
	var req textRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("otpmask: 解析文本请求失败: %w", err)
	}
	if req.Text == "" {
		return nil, fmt.Errorf("otpmask: 文本请求无 text")
	}
	return &req, nil
}

// parseEmbedResponse 解析 embedding-service 响应。
func parseEmbedResponse(body []byte) (*embedResponse, error) {
	var resp embedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("otpmask: 解析 embedding 响应失败: %w", err)
	}
	if len(resp.Vectors) == 0 {
		return nil, fmt.Errorf("otpmask: embedding 响应无 vectors")
	}
	return &resp, nil
}

// encodeCipherRequest 编码密文请求体。
func encodeCipherRequest(req *cipherRequest) ([]byte, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("otpmask: 编码密文请求失败: %w", err)
	}
	return data, nil
}

// parseCipherResponse 解析密文响应体。
func parseCipherResponse(body []byte) (*cipherResponse, error) {
	var resp cipherResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("otpmask: 解析密文响应失败: %w", err)
	}
	if resp.Nonce == "" || len(resp.CipherOutput) == 0 {
		return nil, fmt.Errorf("otpmask: 密文响应字段缺失（nonce/cipher_output）")
	}
	return &resp, nil
}

// encodePlainResponse 编码明文响应体。
func encodePlainResponse(out []uint64, tokens []uint32, text string) ([]byte, error) {
	data, err := json.Marshal(&plainResponse{Output: out, Tokens: tokens, Text: text})
	if err != nil {
		return nil, fmt.Errorf("otpmask: 编码明文响应失败: %w", err)
	}
	return data, nil
}
