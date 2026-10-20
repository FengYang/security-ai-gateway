package a2aproxy

import (
	"testing"
	"time"
)

// TestNormalizeTaskState 状态归一化：8 有效值 + UNSPECIFIED + 未知 + 幂等。
func TestNormalizeTaskState(t *testing.T) {
	cases := map[string]string{
		"TASK_STATE_SUBMITTED":      "submitted",
		"TASK_STATE_WORKING":        "working",
		"TASK_STATE_INPUT_REQUIRED": "input-required",
		"TASK_STATE_AUTH_REQUIRED":  "auth-required",
		"TASK_STATE_COMPLETED":      "completed",
		"TASK_STATE_FAILED":         "failed",
		"TASK_STATE_CANCELED":       "canceled",
		"TASK_STATE_REJECTED":       "rejected",
		"TASK_STATE_UNSPECIFIED":    "unspecified",
		"":                          "unspecified",
		"TASK_STATE_UNKNOWN_X":      "unspecified",
		"garbage":                   "unspecified",
	}
	for in, want := range cases {
		if got := NormalizeTaskState(in); got != want {
			t.Fatalf("NormalizeTaskState(%q) = %q, want %q", in, got, want)
		}
	}
	// 幂等：已是归一化枚举原样返回。
	for _, e := range []string{"submitted", "working", "input-required", "auth-required", "completed", "failed", "canceled", "rejected", "unspecified"} {
		if got := NormalizeTaskState(e); got != e {
			t.Fatalf("归一化枚举应幂等: %q -> %q", e, got)
		}
	}
}

// TestTaskEventDedupKey 去重键：长度前缀帧、确定性、抗拼接歧义。
func TestTaskEventDedupKey(t *testing.T) {
	k1 := TaskEventDedupKey("tenant-a", "agent-x", "task-1", "working")
	k2 := TaskEventDedupKey("tenant-a", "agent-x", "task-1", "working")
	if k1 != k2 {
		t.Fatal("同输入去重键应稳定")
	}
	if len(k1) != 7+64 { // "sha256:" + 64 hex
		t.Fatalf("去重键格式异常: %q", k1)
	}
	// 拼接歧义：("a","b","c","s") 与 ("ab","","c","s") 不应碰撞。
	if TaskEventDedupKey("a", "b", "c", "s") == TaskEventDedupKey("ab", "", "c", "s") {
		t.Fatal("task_id 含 '|' 的拼接歧义未消除")
	}
	// 不同 state 不同键（working vs completed）。
	if TaskEventDedupKey("a", "b", "c", "working") == TaskEventDedupKey("a", "b", "c", "completed") {
		t.Fatal("不同 state 应得不同去重键")
	}
}

// TestTaskAuditStoreDedup 去重窗口：24h 内同键只记首条；working 重复不追加；终态唯一。
func TestTaskAuditStoreDedup(t *testing.T) {
	s := NewTaskAuditStore(0) // 默认 24h
	ev := func(state string) TaskEvent {
		return TaskEvent{
			Tenant: "t", Agent: "a", TaskID: "task-1", State: state,
			Result: "success", Producer: string(TaskProducerGateway),
			DedupKey: TaskEventDedupKey("t", "a", "task-1", state),
		}
	}
	rec, ooo := s.Record(ev("working"))
	if !rec || ooo {
		t.Fatalf("首条应记录且非乱序: rec=%v ooo=%v", rec, ooo)
	}
	// 同键（working）24h 内重复 → 不记录。
	rec, _ = s.Record(ev("working"))
	if rec {
		t.Fatal("同键 24h 内重复应不记录（working 不追加）")
	}
	// 不同状态（completed）新键 → 记录。
	rec, _ = s.Record(ev("completed"))
	if !rec {
		t.Fatal("completed 应为新键、记录")
	}
	// 终态后再同一终态（同键）→ 不记录。
	rec, _ = s.Record(ev("completed"))
	if rec {
		t.Fatal("终态同键重复应不记录")
	}
}

// TestTaskAuditStoreOutOfOrder 乱序标记：终态后再观测 → out_of_order=true。
func TestTaskAuditStoreOutOfOrder(t *testing.T) {
	s := NewTaskAuditStore(0)
	ev := func(state string) TaskEvent {
		return TaskEvent{
			Tenant: "t", Agent: "a", TaskID: "task-x", State: state,
			Result: "success", Producer: string(TaskProducerGateway),
			DedupKey: TaskEventDedupKey("t", "a", "task-x", state),
		}
	}
	s.Record(ev("completed"))            // 终态
	rec, ooo := s.Record(ev("working"))  // 终态后再 working → 乱序
	if !rec {
		t.Fatal("working 应为新键、应记录")
	}
	if !ooo {
		t.Fatal("终态后再观测应标记 out_of_order")
	}
}

// TestTaskAuditStoreEviction 超保留窗口后同键可再次记录。
func TestTaskAuditStoreEviction(t *testing.T) {
	s := NewTaskAuditStore(10 * time.Millisecond)
	ev := TaskEvent{
		Tenant: "t", Agent: "a", TaskID: "task-e", State: "working",
		Producer: string(TaskProducerGateway),
		DedupKey: TaskEventDedupKey("t", "a", "task-e", "working"),
	}
	if rec, _ := s.Record(ev); !rec {
		t.Fatal("首条应记录")
	}
	if rec, _ := s.Record(ev); rec {
		t.Fatal("窗口内重复不应记录")
	}
	time.Sleep(15 * time.Millisecond)
	if rec, _ := s.Record(ev); !rec {
		t.Fatal("超过保留窗口后应可再次记录")
	}
}

// TestTaskOutbox outbox 累积 + 告警回调。
func TestTaskOutbox(t *testing.T) {
	var alerted int
	o := NewTaskOutbox(0)
	o.Alert = func(TaskEvent) { alerted++ }
	ev := TaskEvent{Tenant: "t", TaskID: "x", State: "working", DedupKey: "sha256:abc"}
	o.Add(ev)
	o.Add(ev)
	if o.Pending() != 2 {
		t.Fatalf("pending = %d, want 2", o.Pending())
	}
	if alerted != 2 {
		t.Fatalf("alerted = %d, want 2", alerted)
	}
}
