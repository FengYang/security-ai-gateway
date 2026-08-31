package secagg

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A-01 错误分类：哨兵错误映射到正确分类。
func TestClassifySentinel(t *testing.T) {
	cases := []struct {
		err  error
		want Category
	}{
		{ErrInsufficientParties, CategoryInsufficient},
		{ErrSignatureVerification, CategoryProtocol},
		{ErrCommitmentMismatch, CategoryProtocol},
		{ErrInvalidInput, CategoryConfig},
		{errors.New("随机错误"), CategoryUnknown},
		{nil, CategoryUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Fatalf("Classify(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// A-02 错误分类：gRPC 状态码映射。
func TestClassifyGRPCStatus(t *testing.T) {
	if got := Classify(status.Error(codes.Unavailable, "服务不可用")); got != CategoryNetwork {
		t.Fatalf("Unavailable 应归为 network, got %v", got)
	}
	if got := Classify(status.Error(codes.InvalidArgument, "参数错误")); got != CategoryConfig {
		t.Fatalf("InvalidArgument 应归为 config, got %v", got)
	}
}

// A-03 错误分类：包装错误（%w）仍可识别哨兵。
func TestClassifyWrapped(t *testing.T) {
	err := errors.Join(ErrInsufficientParties, errors.New("并发驱动失败"))
	if got := Classify(err); got != CategoryInsufficient {
		t.Fatalf("包装错误应归为 insufficient, got %v", got)
	}
}

// A-04 审计事件：成功会话产生 start/阶段/success 事件。
func TestAuditEventsOnSuccess(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)

	rec := &recordingSink{ch: make(chan AuditEvent, 32)}
	agg, _ := NewAggregator(cfg)
	agg.SetAuditSink(rec)

	if _, err := runAll(agg, parties); err != nil {
		t.Fatal(err)
	}

	evs := rec.drain()
	got := map[string]bool{}
	for _, e := range evs {
		got[e.Message] = true
	}
	for _, want := range []string{"session_start"} {
		if !got[want] {
			t.Fatalf("缺少审计事件 %q，实际: %v", want, evs)
		}
	}
	// session_success 带参数，前缀匹配
	if !hasPrefixEvent(evs, "session_success") {
		t.Fatalf("缺少 session_success 事件，实际: %v", evs)
	}
	// 各阶段事件
	for _, round := range []Round{Round0Advertise, Round1ShareSeeds, Round2MaskedInput, Round4Unmask} {
		found := false
		for _, e := range evs {
			if e.Round == round {
				found = true
			}
		}
		if !found {
			t.Fatalf("缺少阶段审计事件 %v", round)
		}
	}
	// 事件必须携带 sessionID
	for _, e := range evs {
		if len(e.SessionID) != SessionIDLen {
			t.Fatalf("审计事件缺少会话 ID: %+v", e)
		}
	}
}

// A-05 审计事件：失败会话产生 session_failed 且分类正确。
func TestAuditEventsOnFailure(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)

	rec := &recordingSink{ch: make(chan AuditEvent, 32)}
	agg, _ := NewAggregator(cfg)
	agg.SetAuditSink(rec)

	// 两个参与方在 Round0 掉线（阈值 3）→ ErrInsufficientParties
	parties[2].dropAt = Round0Advertise
	parties[3].dropAt = Round0Advertise
	if _, err := runAll(agg, parties); err == nil {
		t.Fatal("应失败")
	}
	found := false
	for _, e := range rec.drain() {
		if e.Message == "session_failed: "+ErrInsufficientParties.Error() && e.Category == CategoryInsufficient {
			found = true
		}
	}
	if !found {
		t.Fatal("缺少分类正确的 session_failed 审计事件")
	}
}

// hasPrefixEvent 检查是否存在消息以 prefix 开头的事件。
func hasPrefixEvent(evs []AuditEvent, prefix string) bool {
	for _, e := range evs {
		if len(e.Message) >= len(prefix) && e.Message[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// recordingSink 内存审计接收器（测试用）。
type recordingSink struct {
	mu sync.Mutex
	ch chan AuditEvent
}

func (r *recordingSink) Emit(_ context.Context, ev AuditEvent) {
	select {
	case r.ch <- ev:
	default: // 满则丢弃，避免阻塞协议主流程（与生产 sink 约束一致）
	}
}

func (r *recordingSink) drain() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []AuditEvent
	for {
		select {
		case e := <-r.ch:
			out = append(out, e)
		default:
			return out
		}
	}
}
