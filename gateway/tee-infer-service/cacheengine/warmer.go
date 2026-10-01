package cacheengine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// WarmStatus 预热状态。
type WarmStatus string

const (
	WarmIdle      WarmStatus = "idle"
	WarmRunning   WarmStatus = "running"
	WarmSucceeded WarmStatus = "succeeded"
	WarmFailed    WarmStatus = "failed"
)

// WarmResult 预热执行结果。
type WarmResult struct {
	Status      WarmStatus `json:"status"`
	Total       int        `json:"total"`
	Succeeded   int        `json:"succeeded"`
	Failed      int        `json:"failed"`
	Skipped     int        `json:"skipped"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  time.Time  `json:"finished_at"`
	LastError   string     `json:"last_error,omitempty"`
}

// WarmEntry 预热条目（JSONL 单行格式）。
// 最少需要 prompt + text；transformed_hash 可选，缺省时引擎自行计算。
type WarmEntry struct {
	// 精确键（可选；为空时由引擎根据 prompt 生成）
	TransformedHash string `json:"transformed_hash,omitempty"`
	// 用户 prompt
	Prompt string `json:"prompt"`
	// 缓存正文
	Text string `json:"text"`
	// 租户（可选，默认 "warmup"）
	TenantID string `json:"tenant_id,omitempty"`
	// 引擎类型（可选，默认 "cmaas"）
	EngineType string `json:"engine_type,omitempty"`
	// 模型（可选，默认 "default"）
	Model string `json:"model,omitempty"`
	// 场景（可选；为空时由场景分类器判定）
	Scene string `json:"scene,omitempty"`
	// 输出 token 数（可选）
	TokensOut int `json:"tokens_out,omitempty"`
	// policy 版本（可选，默认 "1"）
	PolicyVer string `json:"policy_ver,omitempty"`
	// guard 版本（可选，默认 "1"）
	GuardVer string `json:"guard_ver,omitempty"`
	// 最大新 token 数（可选）
	MaxNewTokens int `json:"max_new_tokens,omitempty"`
	// 是否也写入语义层（语义模式下有效，默认 true）
	Semantic bool `json:"semantic,omitempty"`
}

// CacheWarmer 缓存预热器接口（§6.9）。
type CacheWarmer interface {
	// Warm 执行预热，阻塞直到完成或 ctx 取消。
	// 同一时刻只允许一个预热任务运行。
	Warm(ctx context.Context) WarmResult

	// Status 获取预热状态与进度。
	Status() WarmResult

	// Cancel 取消正在运行的预热任务。
	Cancel()
}

// fileWarmer 基于 JSONL 文件的预热器。
type fileWarmer struct {
	cfg    *CacheConfig
	engine CacheEngine
	path   string

	mu     sync.Mutex
	status WarmResult
	cancel context.CancelFunc
	running atomic.Bool
}

// NewFileWarmer 构造文件源预热器。
// path 为 JSONL 文件路径，每行一个 WarmEntry。
// engine 用于实际写入缓存。
func NewFileWarmer(cfg *CacheConfig, engine CacheEngine, path string) CacheWarmer {
	return &fileWarmer{
		cfg:    cfg,
		engine: engine,
		path:   path,
		status: WarmResult{Status: WarmIdle},
	}
}

// Status 返回当前预热状态。
func (w *fileWarmer) Status() WarmResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// Cancel 取消正在运行的预热。
func (w *fileWarmer) Cancel() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
	}
}

// Warm 执行预热。
func (w *fileWarmer) Warm(ctx context.Context) WarmResult {
	// 互斥：只允许一个任务运行
	if !w.running.CompareAndSwap(false, true) {
		return w.Status()
	}
	defer w.running.Store(false)

	ctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.cancel = cancel
	w.status = WarmResult{
		Status:    WarmRunning,
		StartedAt: time.Now(),
	}
	w.mu.Unlock()

	defer cancel()

	result := w.run(ctx)

	w.mu.Lock()
	result.FinishedAt = time.Now()
	w.status = result
	w.cancel = nil
	w.mu.Unlock()

	return result
}

// run 实际执行预热逻辑。
func (w *fileWarmer) run(ctx context.Context) WarmResult {
	result := WarmResult{Status: WarmRunning, StartedAt: time.Now()}

	f, err := os.Open(w.path)
	if err != nil {
		result.Status = WarmFailed
		result.LastError = err.Error()
		return result
	}
	defer f.Close()

	maxItems := w.cfg.Warmup.MaxItems
	if maxItems <= 0 {
		maxItems = 10000
	}

	scanner := bufio.NewScanner(f)
	// 支持较大的行（默认 64KB 可能不够）
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			result.Status = WarmFailed
			result.LastError = ctx.Err().Error()
			return result
		default:
		}

		if maxItems > 0 && result.Total >= maxItems {
			break
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry WarmEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			result.Failed++
			result.Total++
			continue
		}

		if entry.Prompt == "" || entry.Text == "" {
			result.Skipped++
			result.Total++
			continue
		}

		// 填充默认值
		if entry.TenantID == "" {
			entry.TenantID = "warmup"
		}
		if entry.EngineType == "" {
			entry.EngineType = "cmaas"
		}
		if entry.Model == "" {
			entry.Model = "default"
		}
		if entry.PolicyVer == "" {
			entry.PolicyVer = "1"
		}
		if entry.GuardVer == "" {
			entry.GuardVer = "1"
		}
		if entry.TokensOut <= 0 {
			entry.TokensOut = len(entry.Text) / 4 // 粗估
		}
		if entry.MaxNewTokens <= 0 {
			entry.MaxNewTokens = 2048 // 默认 max_new_tokens
		}

		// 若未提供 transformed_hash，用 prompt 的 sha256 作为精确键
		// 这样不同 prompt 不会互相覆盖
		if entry.TransformedHash == "" {
			h := sha256.Sum256([]byte(entry.Prompt))
			entry.TransformedHash = "warmup:" + hex.EncodeToString(h[:16])
		}

		storeCtx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        entry.TenantID,
				EngineType:      entry.EngineType,
				Model:           entry.Model,
				MaxNewTokens:    entry.MaxNewTokens,
				TransformedHash: entry.TransformedHash,
				PromptText:      entry.Prompt,
				PolicyVer:       entry.PolicyVer,
				GuardVer:        entry.GuardVer,
			},
			Writable: true,
		}
		if entry.Scene != "" {
			storeCtx.Scene = SceneClass(entry.Scene)
		}

		res := InferResult{
			Text:      entry.Text,
			TokensOut: entry.TokensOut,
			Finish:    "stop",
		}

		outcome := w.engine.Store(storeCtx, res)
		result.Total++
		if outcome.Stored {
			result.Succeeded++
		} else {
			result.Skipped++
		}
	}

	if err := scanner.Err(); err != nil {
		result.Status = WarmFailed
		result.LastError = err.Error()
		return result
	}

	result.Status = WarmSucceeded
	return result
}
