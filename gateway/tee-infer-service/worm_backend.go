package main

// WORM 后端抽象（P1-8 T5，GAP-09；P1-7 T0 增补 D-17 落盘强度）。
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
// P1-7 T0（D-17 / A4-01）：
//   - fileWorm 是审计链的**唯一写盘句柄**——append()（既有 30 处落链点 + T2a 上报通道）
//     与 appendOrFail()（业务变更类）**均经此落盘**；auditChain.file 已移除。
//     该收口保证「fsync 计数与档位单一化」与「文件行序 ≡ 链序」（A4-07）。
//   - 落盘强度可配：批量 fsync（默认每 1000 条或 1 秒，先到者触发）或每事件 fsync（合规档）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// WormBackend WORM 持久化后端接口（只追加语义）。
//
// 实现须保证：Append 成功后数据已落盘（或至少进入持久化队列）；
// 失败返回 error，由调用方（auditChain.append / appendOrFail）按 fail-closed 策略处置。
type WormBackend interface {
	// Append 追加一条事件（JSON 行）。返回 error 表示写入失败。
	Append(e AuditEvent) error
	// Close 关闭后端释放资源。
	Close() error
	// Name 返回后端标识（用于日志/指标标签）。
	Name() string
}

// ---------- 落盘强度档位（D-17） ----------

// FsyncMode 落盘强度档位（D-17）。
type FsyncMode string

const (
	// FsyncBatch 批量 fsync：每 N 条或每 T 间隔（先到者触发）；**默认档**（D-17 选 (b)）。
	FsyncBatch FsyncMode = "batch"
	// FsyncPerEvent 每事件 fsync（合规档，D-17 选 (a)）：每条 Append 后立即 Sync。
	// 与 V-10「p99 增量 <3%」可能冲突，须重新基准、不默认沿用 3%。
	FsyncPerEvent FsyncMode = "per_event"
)

// WormFsyncConfig WORM 落盘强度配置（D-17）。
type WormFsyncConfig struct {
	Mode     FsyncMode     // batch | per_event
	Every    int           // batch 档：每 N 条触发一次（≤0 → 取默认 1000）
	Interval time.Duration // batch 档：每 T 触发一次（≤0 → 取默认 1s）
}

// defaultWormFsyncConfig 返回 D-17 默认档：**每 1000 条或每 1 秒（先到者触发）**。
func defaultWormFsyncConfig() WormFsyncConfig {
	return WormFsyncConfig{Mode: FsyncBatch, Every: 1000, Interval: time.Second}
}

// normalize 修正非法/零值配置为默认值（fail-safe：**不静默降级为「不 fsync」**）。
func (c WormFsyncConfig) normalize() WormFsyncConfig {
	if c.Mode != FsyncBatch && c.Mode != FsyncPerEvent {
		c.Mode = FsyncBatch
	}
	if c.Every <= 0 {
		c.Every = 1000
	}
	if c.Interval <= 0 {
		c.Interval = time.Second
	}
	return c
}

// ---------- fileWorm（本地 JSONL，唯一写盘句柄） ----------

// fileWorm 本地文件 WORM 后端：O_APPEND 只追加写 JSONL。
//
// 与既有 newAuditChainWORM 的差异：抽出为独立后端实现，
// 使 auditChain 不直接操作 *os.File，便于接入对象存储等其它后端。
// 行为等价于既有实现（逐行 JSON + O_APPEND），并增补 D-17 落盘强度。
type fileWorm struct {
	mu   sync.Mutex
	file *os.File
	path string

	// ---- D-17 落盘强度 ----
	mode     FsyncMode
	every    int           // batch 档阈值（条）
	interval time.Duration // batch 档阈值（时间）
	pending  int           // 自上次 fsync 以来未同步的写入数（batch 档）
	syncs    uint64        // 累计 fsync 次数（单一计数点；含关闭前最终 flush）

	// 周期 flush goroutine（仅 batch 档启用）
	stop chan struct{}
	wg   sync.WaitGroup
}

// newFileWorm 构造本地文件 WORM 后端（默认落盘强度 D-17 档：每 1000 条或 1 秒）。
//
// 文件以 O_CREATE|O_APPEND|O_WRONLY 打开；若文件已存在不截断（WORM 语义）。
// path 为空返回错误（fail-closed：不静默降级为内存）。
func newFileWorm(path string) (*fileWorm, error) {
	return newFileWormWithConfig(path, defaultWormFsyncConfig())
}

// newFileWormWithConfig 构造本地文件 WORM 后端并指定落盘强度（P1-7 T0 / D-17）。
func newFileWormWithConfig(path string, cfg WormFsyncConfig) (*fileWorm, error) {
	if path == "" {
		return nil, errors.New("audit: fileWorm 路径为空")
	}
	cfg = cfg.normalize()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: 打开 WORM 文件失败: %w", err)
	}
	w := &fileWorm{
		file: f, path: path,
		mode: cfg.Mode, every: cfg.Every, interval: cfg.Interval,
	}
	// batch 档：启动周期 flush goroutine，保证「静默期」尾部事件亦在 T 内落盘
	// （若仅在 Append 时判定时间阈值，则无后续写入时尾部事件会一直滞留 page cache）。
	if w.mode == FsyncBatch {
		w.stop = make(chan struct{})
		w.wg.Add(1)
		go w.loop()
	}
	return w, nil
}

// loop 周期触发 flush（batch 档）。
func (w *fileWorm) loop() {
	defer w.wg.Done()
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.flush()
		}
	}
}

// flush 将 page cache 中的待落盘数据同步到磁盘（batch 档的定时/阈值触发点）。
// 调用方无需持锁。fsync 失败保留 pending，下次重试（避免静默丢失）。
func (w *fileWorm) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == 0 || w.file == nil {
		return
	}
	if err := w.file.Sync(); err != nil {
		log.Printf("[audit] WORM fsync 失败（落盘强度未达 D-17 档位，保留待重试）: %v", err)
		return
	}
	w.pending = 0
	w.syncs++
}

// Append 写一条 JSON 行（追加），并按落盘强度档位决定 fsync 时机（D-17）。
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
	switch w.mode {
	case FsyncPerEvent:
		// 合规档：每条事件立即落盘。
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("audit: WORM fsync 失败（per_event 档）: %w", err)
		}
		w.syncs++
	default: // FsyncBatch
		w.pending++
		if w.pending >= w.every {
			if err := w.file.Sync(); err != nil {
				// 阈值触发失败：保留 pending（下次 Append/定时重试），并上报错误。
				return fmt.Errorf("audit: WORM fsync 失败（batch 档）: %w", err)
			}
			w.pending = 0
			w.syncs++
		}
	}
	return nil
}

// SyncCount 返回累计 fsync 次数（单一计数点，供 /config 与指标暴露）。
func (w *fileWorm) SyncCount() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.syncs
}

// FsyncConfig 返回生效的落盘档位与参数（供 /config 暴露）。
func (w *fileWorm) FsyncConfig() (mode string, every int, interval time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.mode), w.every, w.interval
}

// Close 停止周期 flush、执行最终落盘并关闭文件。
func (w *fileWorm) Close() error {
	// 1) 停 goroutine（先释放锁，避免与正在执行的 flush 互等）。
	w.mu.Lock()
	if w.stop != nil {
		close(w.stop)
		w.stop = nil
	}
	w.mu.Unlock()
	w.wg.Wait()

	// 2) 最终落盘（确保尾部 <every 条事件持久化）后关闭。
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	if w.pending > 0 {
		if err := w.file.Sync(); err != nil {
			log.Printf("[audit] WORM 关闭前 fsync 失败: %v", err)
		} else {
			w.pending = 0
			w.syncs++
		}
	}
	err := w.file.Close()
	w.file = nil
	return err
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
