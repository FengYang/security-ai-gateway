// S3-2 策略 C 首段预审门（P-FIRST-CHUNK）端到端测试。
package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingL2Classifier 包装一个 OutputClassifier，计数 Classify 调用次数。
type countingL2Classifier struct {
	inner OutputClassifier
	calls atomic.Int64
}

func (c *countingL2Classifier) Classify(text string) (string, float64, string) {
	c.calls.Add(1)
	return c.inner.Classify(text)
}

// TestS32FirstChunkSafeSkipsL2 首段安全 → 后续单元跳过 L2。
func TestS32FirstChunkSafeSkipsL2(t *testing.T) {
	m := newMetrics()
	a := newAuditChain()

	// L1：纯 pass（不命中任何规则）→ 首段必然安全
	l1 := fakeL2Classifier{cat: "", conf: 0.0} // L1 未命中
	// L2：也返回空（pass），但我们只关心调用次数
	l2 := &countingL2Classifier{inner: fakeL2Classifier{cat: "", conf: 0.0}}

	og, err := newOutputGuard(
		outputGuardConfig{
			Mode:     outputGuardShadow,
			Strategy: outputStrategyC,
			Params: outputGuardParams{
				Unit:              unitFixedWindow,
				MaxKeywordRunes:   10,
				WindowMargin:      10, // WindowRunes = 20
				MaxBufferBytes:    4096,
			},
			Cascade: outputGuardCascadeParams{
				Concurrency: 4,
				Timeout:     100 * time.Millisecond,
			},
		},
		l1, l2, m, a, "acme", "req-fc-safe",
	)
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	if og == nil {
		t.Fatal("og 不应为 nil")
	}

	// 发送 5 段内容（每段 20+ 字节，保证生成多个窗口）
	rec := &frameRecorder{}
	segments := []string{
		"今天天气很好，阳光明媚，适合出去散步。",
		"公园里有很多人在跑步和打球。",
		"孩子们在草坪上放风筝，笑声不断。",
		"远处的山上有一座古老的寺庙。",
		"湖面上倒映着蓝天和白云。",
	}
	for _, s := range segments {
		if err := og.Process(s, rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	// 验证首段门状态：首段安全 → firstChunkSkipL2 = true
	if !og.casc.firstChunkDone {
		t.Fatal("首段门应已完成判定")
	}
	if !og.casc.firstChunkSkipL2 {
		t.Fatal("首段安全时 firstChunkSkipL2 应为 true")
	}

	// 指标验证：首段跳过计数应该 > 0
	body := renderMetrics(m, 0)
	if !strings.Contains(body, "otpmask_output_guard_c_first_chunk_skip_l2_total") {
		t.Fatalf("应输出首段跳过指标\n---\n%s", body)
	}
}

// TestS32FirstChunkHitBlockKeepsL2 首段命中 block → 后续单元保持完整级联（不跳 L2）。
func TestS32FirstChunkHitBlockKeepsL2(t *testing.T) {
	m := newMetrics()
	a := newAuditChain()

	// L1：首段命中 A1-06（暴力 block 类目）
	l1 := fakeL2Classifier{cat: "A1-06", conf: 1.0}
	// L2：也命中
	l2 := &countingL2Classifier{inner: fakeL2Classifier{cat: "A1-06", conf: 0.99}}

	og, err := newOutputGuard(
		outputGuardConfig{
			Mode:     outputGuardShadow,
			Strategy: outputStrategyC,
			Params: outputGuardParams{
				Unit:              unitFixedWindow,
				MaxKeywordRunes:   10,
				WindowMargin:      10,
				MaxBufferBytes:    4096,
			},
			Cascade: outputGuardCascadeParams{
				Concurrency: 4,
				Timeout:     100 * time.Millisecond,
			},
		},
		l1, l2, m, a, "acme", "req-fc-hit",
	)
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}

	rec := &frameRecorder{}
	segments := []string{
		"第一段内容涉及违规暴力内容需要拦截。",
		"第二段也有问题内容。",
		"第三段继续有违规。",
		"第四段也是。",
		"第五段同样有。",
	}
	for _, s := range segments {
		if err := og.Process(s, rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	// 验证首段门状态：首段 L1 命中 → firstChunkSkipL2 = false
	if !og.casc.firstChunkDone {
		t.Fatal("首段门应已完成判定")
	}
	if og.casc.firstChunkSkipL2 {
		t.Fatal("首段 L1 命中时 firstChunkSkipL2 应为 false")
	}

	// 首段跳过指标应该为 0（不输出）
	body := renderMetrics(m, 0)
	if strings.Contains(body, "otpmask_output_guard_c_first_chunk_skip_l2_total") {
		t.Fatalf("首段命中时不应输出首段跳过指标\n---\n%s", body)
	}
}

// TestS32StrategyBNoFirstChunkGate 策略 B 没有首段门（始终走 L2）。
func TestS32StrategyBNoFirstChunkGate(t *testing.T) {
	m := newMetrics()
	a := newAuditChain()

	l1 := fakeL2Classifier{cat: "", conf: 0.0} // L1 未命中
	l2 := &countingL2Classifier{inner: fakeL2Classifier{cat: "", conf: 0.0}}

	og, err := newOutputGuard(
		outputGuardConfig{
			Mode:     outputGuardShadow,
			Strategy: outputStrategyB,
			Params: outputGuardParams{
				Unit:              unitFixedWindow,
				MaxKeywordRunes:   10,
				WindowMargin:      10,
				MaxBufferBytes:    4096,
			},
			Cascade: outputGuardCascadeParams{
				Concurrency: 4,
				Timeout:     100 * time.Millisecond,
			},
		},
		l1, l2, m, a, "acme", "req-b-nofc",
	)
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}

	rec := &frameRecorder{}
	segments := []string{
		"今天天气很好，阳光明媚。",
		"公园里有很多人。",
		"孩子们在放风筝。",
		"远处有一座山。",
		"湖面上有白云。",
	}
	for _, s := range segments {
		if err := og.Process(s, rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	// 策略 B 没有首段门（firstChunkSkipL2Enabled 应为 false）
	if og.casc.firstChunkSkipL2Enabled {
		t.Fatal("策略 B 下 firstChunkSkipL2Enabled 应为 false")
	}

	// 首段跳过指标不应该存在（策略 B 不触发）
	body := renderMetrics(m, 0)
	if strings.Contains(body, "otpmask_output_guard_c_first_chunk_skip_l2_total") {
		t.Fatalf("策略 B 不应输出首段跳过指标\n---\n%s", body)
	}
}

// TestS32StrategyCAvailable C 策略现在可运行（首段门已落地）。
func TestS32StrategyCAvailable(t *testing.T) {
	if !strategyRunnable(outputStrategyC) {
		t.Fatal("策略 C 首段门已落地，应可运行")
	}
}
