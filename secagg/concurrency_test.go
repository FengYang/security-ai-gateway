package secagg

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// C-01 限并发扇出：多配置下结果与无限并发一致且正确。
func TestConcurrentFanOutCorrect(t *testing.T) {
	configs := []struct{ n, t, dim int }{
		{3, 2, 4}, {4, 3, 8}, {5, 3, 16}, {8, 5, 8}, {12, 7, 4},
	}
	for _, c := range configs {
		cfg := testConfig(c.n, c.t, c.dim)
		values := make([][]uint64, c.n)
		for i := range values {
			values[i] = randVector(cfg.Modulus, c.dim)
		}
		parties := newParties(cfg, values)

		// 限并发（2）与无限并发（默认）结果应一致
		aggLim, _ := NewAggregator(cfg)
		aggLim.SetMaxConcurrency(2)
		resLim, err := runAll(aggLim, parties)
		if err != nil {
			t.Fatalf("n=%d 限并发失败: %v", c.n, err)
		}
		aggFull, _ := NewAggregator(cfg)
		resFull, err := runAll(aggFull, parties)
		if err != nil {
			t.Fatalf("n=%d 无限并发失败: %v", c.n, err)
		}
		want := sumVectors(values, cfg.Modulus)
		for i := range want {
			if resLim.Sum[i] != want[i] || resFull.Sum[i] != want[i] {
				t.Fatalf("n=%d 分量 %d 错误: lim=%d full=%d want=%d",
					c.n, i, resLim.Sum[i], resFull.Sum[i], want[i])
			}
		}
	}
}

// C-02 runPhase 并发上限：sem 容量 3 时最大并发不超过 3。
func TestRunPhaseConcurrencyLimit(t *testing.T) {
	const limit = 3
	const total = 20
	sem := make(chan struct{}, limit)
	var cur, max int64

	idx := make([]int, total)
	for i := range idx {
		idx[i] = i
	}
	results, err := runPhase(context.Background(), sem, idx, func(i int) (int, error) {
		c := atomic.AddInt64(&cur, 1)
		defer atomic.AddInt64(&cur, -1)
		for {
			m := atomic.LoadInt64(&max)
			if c <= m || atomic.CompareAndSwapInt64(&max, m, c) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond) // 模拟阶段计算，制造并发窗口
		return i * 2, nil
	})
	if err != nil {
		t.Fatalf("runPhase 失败: %v", err)
	}
	if max > limit {
		t.Fatalf("最大并发 %d 超过上限 %d", max, limit)
	}
	for i, v := range results {
		if v != i*2 {
			t.Fatalf("结果 %d 错误: got=%d want=%d", i, v, i*2)
		}
	}
}

// C-03 context 取消：聚合驱动层响应取消，返回 context.Canceled。
func TestContextCancelAborts(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	drivers := make([]PartyDriver, len(parties))
	for i, p := range parties {
		drivers[i] = &cancelAwareParty{party: p}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	agg, _ := NewAggregator(cfg)
	_, err := agg.RunContext(ctx, drivers)
	if err == nil {
		t.Fatal("已取消的 context 应导致运行失败")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 context.Canceled，got: %v", err)
	}
}

// C-04 超时：context 过期后驱动层中止（不返回成功结果）。
func TestContextTimeoutAborts(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	drivers := make([]PartyDriver, len(parties))
	for i, p := range parties {
		drivers[i] = &cancelAwareParty{party: p}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // 确保已过期

	agg, _ := NewAggregator(cfg)
	if _, err := agg.RunContext(ctx, drivers); err == nil {
		t.Fatal("过期的 context 应导致运行失败")
	}
}

// cancelAwareParty 包装本地 party：在 advertise 阶段响应 ctx 取消，
// 用于验证 context 贯穿（本地纯计算不会自然响应取消）。
type cancelAwareParty struct {
	*party
}

func (c *cancelAwareParty) advertise(ctx context.Context) (advertiseMsg, error) {
	if err := ctx.Err(); err != nil {
		return advertiseMsg{}, fmt.Errorf("advertise: %w", err)
	}
	return c.party.advertise(ctx)
}
