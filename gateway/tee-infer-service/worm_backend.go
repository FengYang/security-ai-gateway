package main

// WORM 后端抽象（P1-8 T5，GAP-09）。
//
// 职责：将审计链的持久化后端抽象为 WormBackend 接口，支持多种实现：
//   - fileWorm：本地 JSONL 文件（O_APPEND，与既有行为同构，默认实现）
//   - 对象存储 WORM（如 S3 Object Lock）：后续实现，预留接口
//
// 设计原则：
//   - 只追加（WORM = Write Once Read Many），不修改历史
//   - Append 语义：成功返回 nil，失败返回 error（由调用方决定 fail-closed 还是 fail-open）
//   - 与 auditChain 的耦合：仅通过 WormBackend 接口交互，auditChain 不知具体后端类型
//
// 注意：本期仅实现 fileWorm（与现有 newAuditChainWORM 行为对齐）；
// 对象存储 WORM 为后续增量（需配置 endpoint/bucket/credential，见 §6.5）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// WormBackend WORM 持久化后端接口（只追加语义）。
//
// 实现须保证：Append 成功后数据已落盘（或至少进入持久化队列）；
// 失败返回 error，由调用方（auditChain.appendOrFail）按 fail-closed 策略处置。
type WormBackend interface {
	// Append 追加一条事件（JSON 行）。返回 error 表示写入失败。
	Append(e AuditEvent) error
	// Close 关闭后端释放资源。
	Close() error
	// Name 返回后端标识（用于日志/指标标签）。
	Name() string
}

// ---------- fileWorm（本地 JSONL，与既有 WORM 模式同构） ----------

// fileWorm 本地文件 WORM 后端：O_APPEND 只追加写 JSONL。
//
// 与既有 newAuditChainWORM 的差异：抽出为独立后端实现，
// 使 auditChain 不直接操作 *os.File，便于接入对象存储等其它后端。
// 行为等价于既有实现（逐行 JSON + O_APPEND）。
type fileWorm struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// newFileWorm 构造本地文件 WORM 后端。
//
// 文件以 O_CREATE|O_APPEND|O_WRONLY 打开；若文件已存在不截断（WORM 语义）。
// path 为空返回错误（fail-closed：不静默降级为内存）。
func newFileWorm(path string) (*fileWorm, error) {
	if path == "" {
		return nil, errors.New("audit: fileWorm 路径为空")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开 WORM 文件失败: %w", err)
	}
	return &fileWorm{file: f, path: path}, nil
}

// Append 写一条 JSON 行（追加）。
func (w *fileWorm) Append(e AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: 序列化审计事件失败: %w", err)
	}
	if _, err := w.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: WORM 写入失败: %w", err)
	}
	return nil
}

// Close 关闭文件。
func (w *fileWorm) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// Name 返回后端名。
func (w *fileWorm) Name() string { return "file:" + w.path }

// ---------- memoryWorm（测试用，不暴露外部） ----------

// memoryWorm 内存 WORM 后端：仅用于单元测试，不进生产路径。
type memoryWorm struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool // 设为 true 时 Append 返回错误（模拟写失败场景）
}

func newMemoryWorm() *memoryWorm { return &memoryWorm{} }

func (w *memoryWorm) Append(e AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail {
		return errors.New("audit: memoryWorm 模拟写入失败")
	}
	w.events = append(w.events, e)
	return nil
}

func (w *memoryWorm) Close() error { return nil }
func (w *memoryWorm) Name() string { return "memory" }

// Len 返回已写入事件数（仅测试用）。
func (w *memoryWorm) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events)
}

// SetFail 设置模拟失败开关（仅测试用）。
func (w *memoryWorm) SetFail(v bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fail = v
}
