package a2aproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// A2A Task 审计扩展（P2-2 T-3b）。
//
// 冻结契约（冻结清单 §2.6 Task 审计接口契约）：
//
//   - 事件 schema（接口级）见 a2a_task_event：event_id/timestamp/request_id/
//     trace_id/tenant/agent/skill/skill_source/task_id/context_id/state/
//     prev_state/duration_ms/result/error_code/a2a_version/producer/
//     dedup_key/out_of_order；
//   - state 归一化为小写短横线枚举（线上 TASK_STATE_*）；
//   - 仅记观测状态、不合成；去重键 24h 窗口只记首条；乱序标记可见、不阻断协议；
//   - 链/失败：复用既有审计链/上报；写失败进 outbox；治理拒绝类审计失败 fail-closed；
//   - 保留期跟随 U-4（审计元数据口径，内容不落 R-2）。
//
// 完整状态机/V-3 全用例归 F-6（本子任务不做，见 §7.2 T-3b）。

// TaskProducer 是事件生产者枚举（MVP 仅 gateway）。
type TaskProducer string

const (
	TaskProducerGateway TaskProducer = "gateway"
	// TaskProducerBackend / TaskProducerBoth 预留（未来后端亦上报）。
)

// TaskEvent 是归一化后的 A2A Task 审计事件（接口级 schema，§2.6）。
//
// 不含任何任务正文/Parts/历史（R-2 元数据级）。
type TaskEvent struct {
	EventID     string `json:"event_id"`
	Timestamp   string `json:"timestamp"` // RFC3339Nano
	RequestID   string `json:"request_id,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
	Tenant      string `json:"tenant"`
	Agent       string `json:"agent"`
	Skill       string `json:"skill"`
	SkillSource string `json:"skill_source"`
	TaskID      string `json:"task_id,omitempty"`
	ContextID   string `json:"context_id,omitempty"`
	State       string `json:"state"` // 归一化枚举
	PrevState   string `json:"prev_state,omitempty"`
	DurationMs  int64  `json:"duration_ms,omitempty"`
	Result      string `json:"result"`
	ErrorCode   string `json:"error_code,omitempty"`
	A2AVersion  string `json:"a2a_version"`
	Producer    string `json:"producer"`
	DedupKey    string `json:"dedup_key"`
	OutOfOrder  bool   `json:"out_of_order,omitempty"`
}

// taskStateMap 线上 TASK_STATE_* → 归一化枚举。
var taskStateMap = map[string]string{
	"TASK_STATE_SUBMITTED":      "submitted",
	"TASK_STATE_WORKING":        "working",
	"TASK_STATE_INPUT_REQUIRED": "input-required",
	"TASK_STATE_AUTH_REQUIRED":  "auth-required",
	"TASK_STATE_COMPLETED":      "completed",
	"TASK_STATE_FAILED":         "failed",
	"TASK_STATE_CANCELED":       "canceled",
	"TASK_STATE_REJECTED":       "rejected",
	"TASK_STATE_UNSPECIFIED":    "unspecified",
}

// taskStateRank 用于乱序判定（数值越大越靠后；终态同级）。
var taskStateRank = map[string]int{
	"unspecified":    0,
	"submitted":      1,
	"working":        2,
	"input-required": 3,
	"auth-required":  4,
	"completed":      5,
	"failed":         5,
	"canceled":       5,
	"rejected":       5,
}

// NormalizeTaskState 将线上 TASK_STATE_* 归一化为小写短横线枚举。
// 已是归一化枚举则幂等返回；空/未知/UNSPECIFIED → unspecified（仅审计，不作状态机判定）。
func NormalizeTaskState(raw string) string {
	if v, ok := taskStateMap[raw]; ok {
		return v
	}
	switch raw {
	case "submitted", "working", "input-required", "auth-required",
		"completed", "failed", "canceled", "rejected", "unspecified":
		return raw
	}
	return "unspecified"
}

// isTerminalState 报告归一化状态是否为终态。
func isTerminalState(s string) bool {
	switch s {
	case "completed", "failed", "canceled", "rejected":
		return true
	}
	return false
}

// TaskEventDedupKey 计算去重键：sha256(LP(tenant)||LP(agent)||LP(task_id)||LP(state))。
//
// 采用长度前缀帧（F-6 §3.1 同族，与 T-3a 复合限流键一致）防拼接歧义；
// 冻结 §2.6 记为 sha256(tenant|agent|task_id|state) 的简写，此处以长度前缀帧
// 实现以消除 task_id 含 '|' 的拼接碰撞风险（已与 F-6/T-3a 口径对齐）。
func TaskEventDedupKey(tenant, agent, taskID, state string) string {
	var b []byte
	b = append(b, rlLPEncode(tenant)...)
	b = append(b, rlLPEncode(agent)...)
	b = append(b, rlLPEncode(taskID)...)
	b = append(b, rlLPEncode(state)...)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TaskObserver 接收归一化 Task 事件（由治理/数据面在观测到任务状态时调用）。
type TaskObserver func(ctx context.Context, ev TaskEvent)

// defaultTaskEventRetention 是去重/保留窗口（24h，冻结 §2.6）；
// 真正落盘的保留期跟随 U-4 审计元数据口径（由审计链负责，本存储不重复承诺）。
const defaultTaskEventRetention = 24 * time.Hour

// TaskAuditStore 是 Task 审计事件的进程内存储（MVP）：负责去重、乱序标记。
//
// 它不负责持久化——落盘交给既有审计链（§2.6）。本存储仅维护去重窗口与
// 观察序状态，供数据面判重/标乱序。生产可由 TaskObserver 转发至审计链。
type TaskAuditStore struct {
	mu        sync.Mutex
	seen      map[string]time.Time // dedup_key -> 首次观测时间（24h 窗口内同键只记首条）
	lastState map[string]string    // task_id -> 上次归一化状态（prev_state + 乱序判定）
	retention time.Duration
}

// NewTaskAuditStore 构造存储；retention<=0 用默认 24h。
func NewTaskAuditStore(retention time.Duration) *TaskAuditStore {
	if retention <= 0 {
		retention = defaultTaskEventRetention
	}
	return &TaskAuditStore{
		seen:      map[string]time.Time{},
		lastState: map[string]string{},
		retention: retention,
	}
}

// Record 记录一个事件，返回 (recorded, outOfOrder)：
//
//   - recorded=false 表示 24h 窗口内同 dedup_key 已记（含 working 重复不追加、终态唯一）；
//   - outOfOrder=true 表示相对同 task_id 上次观测状态出现回退或终态后再观测。
//
// 调用方应把 recorded 事件转发至审计链；out_of_order 仅标记、不阻断协议。
func (s *TaskAuditStore) Record(ev TaskEvent) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.evictLocked(now)

	recorded := true
	if t, ok := s.seen[ev.DedupKey]; ok && now.Sub(t) < s.retention {
		recorded = false
	}

	outOfOrder := false
	if ev.TaskID != "" {
		if prev, ok := s.lastState[ev.TaskID]; ok && prev != "" {
			ev.PrevState = prev
			if isTerminalState(prev) && !(isTerminalState(ev.State) && prev == ev.State) {
				// 终态后再观测（且非同一终态）→ 乱序。
				outOfOrder = true
			} else if taskStateRank[ev.State] < taskStateRank[prev] {
				// 状态回退 → 乱序。
				outOfOrder = true
			}
		}
		s.lastState[ev.TaskID] = ev.State
	}

	if recorded {
		s.seen[ev.DedupKey] = now
	}
	return recorded, outOfOrder
}

// evictLocked 清理超过保留窗口的条目（调用方须持锁）。
func (s *TaskAuditStore) evictLocked(now time.Time) {
	for k, t := range s.seen {
		if now.Sub(t) >= s.retention {
			delete(s.seen, k)
		}
	}
}

// TaskOutbox 是审计链写入失败时的兜底队列（§2.6：写失败进 outbox 并告警，不静默丢）。
//
// MVP 为进程内环形；告警通过 Alert 回调上送。生产可替换为持久化 outbox。
type TaskOutbox struct {
	mu    sync.Mutex
	items []TaskEvent
	cap   int
	Alert func(ev TaskEvent)
}

// NewTaskOutbox 构造 outbox；cap<=0 用默认 1024。
func NewTaskOutbox(cap int) *TaskOutbox {
	if cap <= 0 {
		cap = 1024
	}
	return &TaskOutbox{cap: cap}
}

// Add 入队一条链写失败的事件并触发告警。
func (o *TaskOutbox) Add(ev TaskEvent) {
	o.mu.Lock()
	o.items = append(o.items, ev)
	if len(o.items) > o.cap {
		o.items = o.items[1:]
	}
	alert := o.Alert
	o.mu.Unlock()
	if alert != nil {
		alert(ev)
	}
}

// Pending 返回当前积压条数（运维观测用）。
func (o *TaskOutbox) Pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.items)
}

// newTaskEventID 生成事件标识（MVP 用随机 hex；§2.6 推荐 UUIDv7/ULID）。
func newTaskEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
