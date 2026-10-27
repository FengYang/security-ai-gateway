package providers

import (
	"io"

	"security-ai-gateway/gateway/confllm-adapter"
)

// fillMeta 将空字段归并为 unknown（§7.5：managed 默认 unknown，缺省 unknown）。
func fillMeta(m confllm.ConfidentialityMeta) confllm.ConfidentialityMeta {
	if m.ConfidentialityClass == "" {
		m.ConfidentialityClass = "unknown"
	}
	if m.Attestation == "" {
		m.Attestation = "unknown"
	}
	if m.DataRetention == "" {
		m.DataRetention = "unknown"
	}
	if m.Deployment == "" {
		m.Deployment = "unknown"
	}
	return m
}

// firstNonEmpty 返回首个非空字符串（用于配置回退）。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// memStreamReader 内存流式读取器（*Fake 离线验证用，不触网）。
type memStreamReader struct {
	chunks []*confllm.StreamChunk
	idx    int
}

func (m *memStreamReader) Next() (*confllm.StreamChunk, error) {
	if m.idx >= len(m.chunks) {
		return nil, io.EOF
	}
	c := m.chunks[m.idx]
	m.idx++
	return c, nil
}

func (m *memStreamReader) Close() error { return nil }
