package secagg

import (
	"context"
	"time"
)

// AuditEvent 一次协议事件的审计记录（结构化，供审计日志/监控导出）。
type AuditEvent struct {
	// Time 事件发生时间（UTC）。
	Time time.Time
	// SessionID 会话 ID（副本）。
	SessionID []byte
	// Round 关联协议轮次；聚合器全局事件为 -1。
	Round Round
	// PartyID 关联参与方；-1 表示聚合器全局事件。
	PartyID int
	// Category 事件分类（协议阶段/错误分类）。
	Category Category
	// Message 人类可读描述。
	Message string
}

// AuditSink 审计日志接收器。实现方负责持久化（文件/ELK/对象存储等）；
// 实现必须非阻塞（建议异步队列），不得拖慢协议主流程。
type AuditSink interface {
	// Emit 写入一条审计事件。ctx 提供取消信号，实现方应尽快返回。
	Emit(ctx context.Context, ev AuditEvent)
}

// NoopAuditSink 空实现（默认，丢弃审计事件）。
type NoopAuditSink struct{}

// Emit 丢弃事件。
func (NoopAuditSink) Emit(context.Context, AuditEvent) {}
