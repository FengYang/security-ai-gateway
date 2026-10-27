package confllm

import (
	"context"
	"strings"
	"sync"
)

// Logger 最小结构化日志接口（脱敏白名单，§7.2）。
//
// 约定：kv 仅允许传递结构化字段（上游 ID、模型名、状态码、耗时、request_id），
// 严禁传入 header / body / token 原文。
type Logger interface {
	Infof(ctx context.Context, msg string, kv ...any)
	Errorf(ctx context.Context, msg string, kv ...any)
}

// NopLogger 丢弃所有日志（默认占位，避免 nil）。
type NopLogger struct{}

func (NopLogger) Infof(ctx context.Context, msg string, kv ...any)  {}
func (NopLogger) Errorf(ctx context.Context, msg string, kv ...any) {}

// logEntry 单条结构化日志（不含敏感值）。
type logEntry struct {
	level string
	msg   string
	kv    []any
}

// BufferLogger 内存 buffer 实现，用于测试断言（脱敏：仅记录结构化字段）。
type BufferLogger struct {
	mu      sync.Mutex
	entries []logEntry
}

// NewBufferLogger 构造内存日志器。
func NewBufferLogger() *BufferLogger { return &BufferLogger{} }

func (b *BufferLogger) Infof(ctx context.Context, msg string, kv ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, logEntry{"info", msg, append([]any(nil), kv...)})
}

func (b *BufferLogger) Errorf(ctx context.Context, msg string, kv ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, logEntry{"error", msg, append([]any(nil), kv...)})
}

// Entries 返回已记录日志快照。
func (b *BufferLogger) Entries() []logEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]logEntry(nil), b.entries...)
}

// Contains 判断是否存在包含 substr 的日志消息（用于断言脱敏，绝不用于匹配 token）。
func (b *BufferLogger) Contains(substr string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range b.entries {
		if strings.Contains(e.msg, substr) {
			return true
		}
	}
	return false
}
