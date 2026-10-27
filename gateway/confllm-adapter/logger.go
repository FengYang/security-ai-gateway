package confllm

import (
	"context"
	"fmt"
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

// LogField 平坦化后的单条日志字段视图（logEntry 未导出，供外部测试包断言脱敏，§7.2）。
type LogField struct {
	Level string // info / error
	Msg   string // 日志消息
	Key   string // kv 键（Msg 本身用 key="msg" 表示）
	Value string // kv 值（字符串化）
}

// Fields 返回全部日志的平坦化字段视图：每条 kv 键值各一项，另加 msg 一项。
//
// 用途：外部测试包无法直接读 logEntry（未导出），借此断言
// ① 所有 Value 不含凭据明文；② Key 集合 ⊆ 白名单 {provider,model,status,duration,request_id,msg}。
func (b *BufferLogger) Fields() []LogField {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]LogField, 0, len(b.entries))
	for _, e := range b.entries {
		out = append(out, LogField{Level: e.level, Msg: e.msg, Key: "msg", Value: e.msg})
		kv := e.kv
		for i := 0; i+1 < len(kv); i += 2 {
			out = append(out, LogField{
				Level: e.level,
				Msg:   e.msg,
				Key:   fmt.Sprintf("%v", kv[i]),
				Value: fmt.Sprintf("%v", kv[i+1]),
			})
		}
	}
	return out
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
