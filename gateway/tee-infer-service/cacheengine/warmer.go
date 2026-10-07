package cacheengine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// ErrWarmupBusy 已有活跃预热任务（B-6.7-1）。
var ErrWarmupBusy = errors.New("cache: warmup already running")

// ErrWarmupDisabled 预热未启用（B-6.7-9；API 层映射 CACHE_DISABLED）。
var ErrWarmupDisabled = errors.New("cache: warmup disabled")

// WarmStatus 预热状态。
type WarmStatus string

const (
	WarmIdle      WarmStatus = "idle"
	WarmRunning   WarmStatus = "running"
	WarmSucceeded WarmStatus = "succeeded"
	WarmFailed    WarmStatus = "failed"
)

// WarmItem 预热条目（§6.7.2）：只含问题与参数，正文由推理产出（不允许直灌文本）。
type WarmItem struct {
	Tenant       string `json:"tenant"`
	Engine       string `json:"engine"`
	Model        string `json:"model"`
	Prompt       string `json:"prompt"`
	MaxNewTokens int    `json:"max_new_tokens"`
}

// WarmInferFunc 注入的"与真实请求同一链路"回调（§6.7.3 的 w.infer）：
// 负责完整推理 + 输出侧审查 + 写前门禁，返回写入上下文（含真实键字段）与推理结果。
// 返回的 StoreContext.Writable 即写前门禁结论（false → 该条计 not_writable，不算失败，B-6.7-2）。
type WarmInferFunc func(ctx context.Context, it WarmItem) (StoreContext, InferResult, error)

// WarmAuditFunc 审计回调（§7.5：cache_warmup_done + source_file_hash）。
type WarmAuditFunc func(action string, fields map[string]any)

// WarmTask 预热任务进度快照（§6.7.3）。
type WarmTask struct {
	ID         string     `json:"id"`
	Status     WarmStatus `json:"status"`
	Total      int        `json:"total"`
	Succeeded  int        `json:"succeeded"`
	Failed     int        `json:"failed"`
	Skipped    int        `json:"skipped"`
	Truncated  int        `json:"truncated,omitempty"` // 超 max_items 被截断的条数（B-6.7-5，不静默）
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt time.Time  `json:"finished_at"`
	LastError  string     `json:"last_error,omitempty"`
}

// CacheWarmer 缓存预热器接口（§6.7）。
type CacheWarmer interface {
	// Run 启动预热任务（异步）；已有活跃任务时返回 ErrWarmupBusy 与已有 task_id（B-6.7-1）。
	Run(items []WarmItem, reset bool) (taskID string, err error)
	// Status 返回当前（或最近一次）任务的进度快照。
	Status() WarmTask
	// Cancel 取消正在运行的预热任务。
	Cancel()
}

// WarmOption 预热器可选注入。
type WarmOption func(*fileWarmer)

// WithWarmAudit 注入审计回调（§7.5）。
func WithWarmAudit(fn WarmAuditFunc) WarmOption { return func(w *fileWarmer) { w.audit = fn } }

// WithWarmSourceHash 记录预热来源文件哈希（§7.5：source_file_hash）。
func WithWarmSourceHash(h string) WarmOption { return func(w *fileWarmer) { w.sourceHash = h } }

// LoadWarmItems 解析 JSONL 预热清单（§6.7.2）；错误按行号定位（B-6.7-4）。
// 空行跳过；缺 prompt 视为格式错误。
func LoadWarmItems(r io.Reader) ([]WarmItem, error) {
	var items []WarmItem
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var it WarmItem
		if err := json.Unmarshal(raw, &it); err != nil {
			return nil, fmt.Errorf("warmup line %d: invalid JSON: %w", line, err)
		}
		if strings.TrimSpace(it.Prompt) == "" {
			return nil, fmt.Errorf("warmup line %d: prompt is required", line)
		}
		items = append(items, it)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("warmup read: %w", err)
	}
	return items, nil
}

// fileWarmer 预热器实现（清单由调用方经 LoadWarmItems 加载后传入 Run）。
type fileWarmer struct {
	cfg        *CacheConfig
	engine     CacheEngine
	infer      WarmInferFunc
	audit      WarmAuditFunc
	sourceHash string

	mu     sync.Mutex
	active *warmTaskState
	done   WarmTask
}

type warmTaskState struct {
	task     WarmTask
	cancel   context.CancelFunc
	interval time.Duration // 启动时配置快照（B-6.7-6：进行中任务不受热更新影响）
}

// NewFileWarmer 构造预热器（§6.7）。infer 为必需的"推理 + 输出侧审查"回调。
func NewFileWarmer(cfg *CacheConfig, engine CacheEngine, infer WarmInferFunc, opts ...WarmOption) CacheWarmer {
	w := &fileWarmer{cfg: cfg, engine: engine, infer: infer, done: WarmTask{Status: WarmIdle}}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Status 返回当前/最近任务快照。
func (w *fileWarmer) Status() WarmTask {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active != nil {
		return w.active.task
	}
	return w.done
}

// Cancel 取消正在运行的预热任务。
func (w *fileWarmer) Cancel() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active != nil && w.active.cancel != nil {
		w.active.cancel()
	}
}

// Run 启动预热（§6.7.3）。异步返回 task_id；已有活跃任务返回 ErrWarmupBusy。
func (w *fileWarmer) Run(items []WarmItem, reset bool) (string, error) {
	if w.infer == nil {
		return "", errors.New("cache: warmup infer func is required")
	}
	if !w.cfg.Warmup.Enabled {
		return "", ErrWarmupDisabled // B-6.7-9
	}
	// B-6.7-5：超过 max_items 截断（不静默，记 Truncated）。
	truncated := 0
	if max := w.cfg.Warmup.MaxItems; max > 0 && len(items) > max {
		truncated = len(items) - max
		items = items[:max]
	}

	w.mu.Lock()
	if w.active != nil {
		id := w.active.task.ID
		w.mu.Unlock()
		return id, ErrWarmupBusy // B-6.7-1
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &warmTaskState{
		task: WarmTask{
			ID:        newWarmTaskID(),
			Status:    WarmRunning,
			Total:     len(items),
			Truncated: truncated,
			StartedAt: time.Now(),
		},
		cancel:   cancel,
		interval: w.interval(), // 启动时配置快照（B-6.7-6）
	}
	w.active = st
	id := st.task.ID
	w.mu.Unlock()

	if reset {
		_, _ = w.engine.Invalidate(InvalidateSelector{All: true})
	}
	go w.loop(ctx, st, items)
	return id, nil
}

// loop 后台执行预热（§6.7.3）：推理 → 写前门禁 → Store（豁免写入限流）→ 计数 → QPS 节流。
func (w *fileWarmer) loop(ctx context.Context, st *warmTaskState, items []WarmItem) {
	interval := st.interval // 启动时快照（B-6.7-6：进行中任务不受热更新影响）
	var lastAt time.Time
	canceled := false
	for _, it := range items {
		if ctx.Err() != nil {
			canceled = true
			break
		}
		if interval > 0 {
			if wait := interval - time.Since(lastAt); wait > 0 {
				select {
				case <-ctx.Done():
					canceled = true
				case <-time.After(wait):
				}
			}
			if canceled {
				break
			}
			lastAt = time.Now()
		}

		sc, res, err := w.infer(ctx, it)
		switch {
		case err != nil:
			w.record(st, "fail")
			w.setLastError(st, err.Error())
			w.engine.RecordWarmupItem("fail") // §9.1 #18
		case !sc.Writable:
			w.record(st, "skip") // B-6.7-2：被写前门禁拦截，不算失败
		default:
			sc.Writable = true
			sc.BypassWriteLimit = true // 受信离线路径：豁免 §7.4.2 写入限流
			if out := w.engine.Store(sc, res); out.Stored {
				w.record(st, "ok")
				w.engine.RecordWarmupItem("ok") // §9.1 #18
			} else {
				w.record(st, "skip")
			}
		}
	}
	w.finish(st, canceled)
}

// finish 结算任务（B-6.7-8：上游全失败 → failed；取消 → failed）并回调审计。
func (w *fileWarmer) finish(st *warmTaskState, canceled bool) {
	w.mu.Lock()
	t := st.task
	t.FinishedAt = time.Now()
	switch {
	case canceled:
		t.Status = WarmFailed
		if t.LastError == "" {
			t.LastError = "canceled"
		}
	case t.Total > 0 && t.Succeeded == 0 && t.Failed > 0:
		t.Status = WarmFailed // B-6.7-8
	default:
		t.Status = WarmSucceeded
	}
	st.task = t
	w.done = t
	w.active = nil
	w.mu.Unlock()

	if w.audit != nil {
		w.audit("cache_warmup_done", map[string]any{
			"task_id":          t.ID,
			"total":            t.Total,
			"succeeded":        t.Succeeded,
			"failed":           t.Failed,
			"skipped":          t.Skipped,
			"truncated":        t.Truncated,
			"status":           string(t.Status),
			"source_file_hash": w.sourceHash,
		})
	}
}

// record 更新任务计数（kind ∈ {ok,fail,skip}）。
func (w *fileWarmer) record(st *warmTaskState, kind string) {
	w.mu.Lock()
	switch kind {
	case "ok":
		st.task.Succeeded++
	case "fail":
		st.task.Failed++
	default:
		st.task.Skipped++
	}
	w.mu.Unlock()
}

// setLastError 记录最近错误。
func (w *fileWarmer) setLastError(st *warmTaskState, msg string) {
	w.mu.Lock()
	st.task.LastError = msg
	w.mu.Unlock()
}

// interval 返回相邻条目最小间隔（QPS 节流，§6.7.3；0 = 不限）。
func (w *fileWarmer) interval() time.Duration {
	if qps := w.cfg.Warmup.QPS; qps > 0 {
		return time.Second / time.Duration(qps)
	}
	return 0
}

// newWarmTaskID 生成预热任务 ID。
func newWarmTaskID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("wm-%d", time.Now().UnixNano())
	}
	return "wm-" + hex.EncodeToString(b[:])
}
