// Package normalize L1 强制归一化（§1.3 / §7.8 R2）。
//
// 职责：
//   - 解析上游 OpenAI 兼容响应（非流式 / SSE 流式）为 L1 类型；
//   - 上游 HTTP 错误 → 6 类归一化错误码（unauthorized/rate_limited/invalid_request/
//     upstream_error/upstream_timeout/pending_credential，§7.1）；
//   - usage 子字段 / stream delta / tool_calls 等均在 L1 内归一，不漏进 L2。
package normalize

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"security-ai-gateway/gateway/confllm-adapter"
)

// ParseChatCompletion 解析上游 OpenAI 兼容非流式响应为 L1 ChatResponse。
func ParseChatCompletion(body []byte) (*confllm.ChatResponse, error) {
	var resp confllm.ChatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析上游响应失败: %w", err)
	}
	return &resp, nil
}

// MapHTTPError 将上游 HTTP 状态/body 映射为归一化 ProviderError（§7.1）。
// 返回的 Message 不含上游原始 body / token（脱敏，§7.2）。
func MapHTTPError(status int, body []byte) *confllm.ProviderError {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return confllm.NewProviderError(confllm.CodeUnauthorized, http.StatusUnauthorized,
			"上游返回 401/403，凭据缺失或无效")
	case http.StatusTooManyRequests:
		return confllm.NewProviderError(confllm.CodeRateLimited, http.StatusTooManyRequests,
			"上游限流（429）")
	case http.StatusBadRequest:
		return confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusBadRequest,
			"上游判定请求非法（400）")
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return confllm.NewProviderError(confllm.CodeUpstreamTimeout, http.StatusGatewayTimeout,
			"上游连接/读取超时（504）")
	}
	if status >= 500 {
		return confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway,
			"上游 5xx 错误（502）")
	}
	if status >= 400 {
		return confllm.NewProviderError(confllm.CodeInvalidRequest, status,
			"上游返回客户端错误")
	}
	return confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway,
		"上游返回非预期状态")
}

// NewStreamReader 包裹上游 SSE 响应体，实现 confllm.StreamReader。
func NewStreamReader(rc io.ReadCloser) confllm.StreamReader {
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return &streamReaderImpl{sc: sc, rc: rc}
}

type streamReaderImpl struct {
	sc *bufio.Scanner
	rc io.ReadCloser
}

// Next 读取下一帧 SSE `data:` 并解析为 StreamChunk；流末返回 io.EOF。
func (r *streamReaderImpl) Next() (*confllm.StreamChunk, error) {
	for r.sc.Scan() {
		line := strings.TrimSpace(r.sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			return nil, io.EOF
		}
		var chunk confllm.StreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			// 单行解析失败跳过（容错），继续读下一帧
			continue
		}
		return &chunk, nil
	}
	if err := r.sc.Err(); err != nil {
		return nil, fmt.Errorf("SSE 流读取错误: %w", err)
	}
	return nil, io.EOF
}

// Close 释放底层连接。
func (r *streamReaderImpl) Close() error {
	return r.rc.Close()
}
