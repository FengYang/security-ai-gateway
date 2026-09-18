// 输出侧内容审查 — OG-13 B2 浸泡 harness（级联并发控制器 + L2 HTTP stub 实跑）。
//
// 定位：**不是常规单测**，而是端到端浸泡的 Go 侧 driver——默认跳过，
// 仅当 SPIKE_SOAK=1 时执行，配合 scripts/og13-l2-stub.py（Python HTTP stub）
// 和 scripts/og13-soak.ps1（PowerShell 编排）使用。
//
// 浸泡维度（由环境变量控制，由 og13-soak.ps1 注入）：
//   - L2_URL            ：L2 HTTP stub 地址（如 http://127.0.0.1:19099/）
//   - L2_TIMEOUT        ：L2 调用超时（Go duration，如 2s）
//   - SOAK_PROFILE      ：cpu / gpu / custom（仅用于报告标签）
//   - SOAK_CONCURRENCY  ：P-CONCURRENCY（在飞句数上限）
//   - SOAK_MAX_SLOTS    ：P-MAX-SLOTS（句槽位上限）
//   - SOAK_BLOCKING     ：true/false，是否按 enforcing 时序阻塞下发
//   - SOAK_LAMBDA       ：句到达速率（句/秒，泊松到达）
//   - SOAK_SENTENCES    ：总句数（含预热）
//   - SOAK_WARMUP       ：预热句数（不计入统计窗）
//   - SOAK_SEED         ：随机种子
//
// 模型：单 outputGuard + 流式逐句提交（模拟一个长请求的句子生成节奏）。
// 级联控制器在同请求内并发处理多句 L2 调用，形成 M/G/c/c 损失系统（Erlang-B）。
//
// 输出：stdout 打印一行 SOAK_RESULT CSV（由 ps1 捕获落盘）。
//   列：profile,lambda,concurrency,blocking,sentences,
//        first_latency_ms,
//        throughput_sent_per_sec,
//        queue_depth_p50,queue_depth_p99,
//        failclosed_ratio,
//        l2_call_ratio,
//        l2_timeout_ratio,l2_unavailable_ratio,l2_bad_conf_ratio,l2_unmapped_ratio,
//        erlang_b_pct
package main

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const spikeSoakENV = "SPIKE_SOAK"

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	return n
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var f float64
	fmt.Sscanf(v, "%f", &f)
	return f
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "yes"
}

// erlangB 计算 M/G/c/c 阻塞率（递推法）。
func erlangB(a float64, c int) float64 {
	if a <= 0 || c <= 0 {
		return 0
	}
	b := 1.0
	for i := 1; i <= c; i++ {
		b = (a * b) / (float64(i) + a*b)
	}
	return b
}

// poissonIntervals 生成泊松到达间隔（指数分布）。
func poissonIntervals(rng *rand.Rand, lambda float64, n int) []time.Duration {
	intervals := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		u := rng.Float64()
		for u == 0 {
			u = rng.Float64()
		}
		t := -math.Log(u) / lambda
		intervals[i] = time.Duration(t * float64(time.Second))
	}
	return intervals
}

// soakEmitter 记录首帧时间（阻塞模式下第一句被放行的时间 = 首帧延迟）。
type soakEmitter struct {
	mu       sync.Mutex
	firstAt  time.Time
	firstSet bool
}

func (e *soakEmitter) emit(delta, finish string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.firstSet && delta != "" {
		e.firstAt = time.Now()
		e.firstSet = true
	}
	return nil
}

func (e *soakEmitter) firstEmit() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.firstAt
}

// TestCascadeSoak OG-13 级联端到端浸泡。
func TestCascadeSoak(t *testing.T) {
	if os.Getenv(spikeSoakENV) != "1" {
		t.Skipf("OG-13 浸泡：设置 %s=1 才执行（需 L2 HTTP stub 运行中）", spikeSoakENV)
	}

	l2URL := os.Getenv("L2_URL")
	if l2URL == "" {
		t.Fatal("L2_URL 环境变量未设置（需指向 og13-l2-stub.py 地址）")
	}

	profile := os.Getenv("SOAK_PROFILE")
	if profile == "" {
		profile = "custom"
	}
	timeout := envDuration("L2_TIMEOUT", 2*time.Second)
	concurrency := envInt("SOAK_CONCURRENCY", 4)
	maxSlots := envInt("SOAK_MAX_SLOTS", 1024)
	blocking := envBool("SOAK_BLOCKING", false)
	lambda := envFloat("SOAK_LAMBDA", 1.0)
	numSentences := envInt("SOAK_SENTENCES", 200)
	warmup := envInt("SOAK_WARMUP", 20)
	seed := envInt("SOAK_SEED", 20260917)
	// 期望服务时间（秒），用于 Erlang-B 对照；由 ps1 注入
	expServiceS := envFloat("SOAK_EXP_SERVICE_S", 0)

	rng := rand.New(rand.NewSource(int64(seed)))

	// L2 HTTP 分类器（真实 HTTP 调用 stub）
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	l2 := newOutputL2HTTPClassifier(l2URL, "", timeout, nil, m, nil)

	casc := outputGuardCascadeParams{
		Timeout:       timeout,
		Concurrency:   concurrency,
		MaxSlots:      maxSlots,
		Degrade:       degradeFailClosed,
		BlockEmission: blocking,
	}
	cfg := outputGuardConfig{
		Mode:          outputGuardShadow,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       casc,
	}

	og, err := newOutputGuard(cfg, fakeL2Classifier{}, l2, m, a, "acme", "soak-stream")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	defer og.Close()

	rec := &soakEmitter{}

	// 队列深度采样 goroutine：每 5ms 读一次 buffer_queue_depth gauge
	var queueMu sync.Mutex
	queueSamples := make([]float64, 0, 4096)
	sampleDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.mu.Lock()
				d := float64(m.ogBufferQueueDepth)
				m.mu.Unlock()
				queueMu.Lock()
				queueSamples = append(queueSamples, d)
				queueMu.Unlock()
			case <-sampleDone:
				return
			}
		}
	}()

	// 生成泊松间隔
	totalN := warmup + numSentences
	intervals := poissonIntervals(rng, lambda, totalN)

	// 逐句提交（模拟流式逐句输出）
	startAt := time.Now()
	var firstProcessAt time.Time

	for i := 0; i < totalN; i++ {
		if i > 0 {
			time.Sleep(intervals[i])
		}
		if i == warmup {
			// 预热结束，重置时间起点（统计从第 warmup 句开始）
			startAt = time.Now()
		}
		if i == 0 {
			firstProcessAt = time.Now()
		}
		// 每句作为一个 delta（以 "。" 结尾 = 一个判定单元）
		delta := fmt.Sprintf("S%d。", i)
		og.Process(delta, rec.emit)
	}
	og.Finish(rec.emit)
	close(sampleDone)
	totalDur := time.Since(startAt)

	// 首帧延迟：第一句从提交到被放行的时间（阻塞模式才有意义；非阻塞≈0）
	firstLatency := time.Duration(0)
	if fe := rec.firstEmit(); !fe.IsZero() {
		firstLatency = fe.Sub(firstProcessAt)
	}
	if firstLatency < 0 {
		firstLatency = 0
	}

	// 吞吐：有效句数 / 有效时长
	effectiveSentences := float64(numSentences)
	throughput := effectiveSentences / totalDur.Seconds()
	if totalDur <= 0 {
		throughput = 0
	}

	// 队列深度百分位
	queueMu.Lock()
	qs := make([]float64, len(queueSamples))
	copy(qs, queueSamples)
	queueMu.Unlock()
	sort.Float64s(qs)
	queuePct := func(p float64) float64 {
		if len(qs) == 0 {
			return 0
		}
		idx := int(float64(len(qs)-1) * p)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(qs) {
			idx = len(qs) - 1
		}
		return qs[idx]
	}
	queueP50 := queuePct(0.50)
	queueP99 := queuePct(0.99)

	// 读 metrics（直接读结构体字段）
	m.mu.Lock()
	ogSentencesF := float64(m.ogSentences)
	failClosedSentF := float64(m.ogFailclosedSent)
	l2CallsStartedF := float64(m.ogL2CallsStarted)
	degradedTimeout := float64(m.ogDegraded["l2|l2_timeout"])
	degradedUnavail := float64(m.ogDegraded["l2|l2_unavailable"])
	degradedBadConf := float64(m.ogDegraded["l2|l2_bad_conf"])
	degradedUnmapped := float64(m.ogDegraded["l2|l2_unmapped"])
	m.mu.Unlock()

	// fail-closed 率
	failClosedRatio := 0.0
	if ogSentencesF > 0 {
		failClosedRatio = failClosedSentF / ogSentencesF
	}

	// L2 占比
	l2Ratio := 0.0
	if ogSentencesF > 0 {
		l2Ratio = l2CallsStartedF / ogSentencesF
	}

	// 各降级原因占比
	timeoutRatio := 0.0
	unavailRatio := 0.0
	badConfRatio := 0.0
	unmappedRatio := 0.0
	if ogSentencesF > 0 {
		timeoutRatio = degradedTimeout / ogSentencesF
		unavailRatio = degradedUnavail / ogSentencesF
		badConfRatio = degradedBadConf / ogSentencesF
		unmappedRatio = degradedUnmapped / ogSentencesF
	}

	// Erlang-B 理论阻塞率（用期望服务时间计算；未提供则 0）
	erlangBPct := 0.0
	if expServiceS > 0 && concurrency > 0 {
		a := lambda * expServiceS // erl 流量
		erlangBPct = erlangB(a, concurrency) * 100.0
	}

	// 输出 CSV 结果行
	fmt.Printf("SOAK_RESULT,%s,%.3f,%d,%t,%d,%.1f,%.2f,%.1f,%.1f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f\n",
		profile,
		lambda,
		concurrency,
		blocking,
		numSentences,
		float64(firstLatency)/float64(time.Millisecond),
		throughput,
		queueP50,
		queueP99,
		failClosedRatio,
		l2Ratio,
		timeoutRatio,
		unavailRatio,
		badConfRatio,
		unmappedRatio,
		erlangBPct,
	)
}

// ---- 第二轮：多请求并发浸泡（OG-13 验收：首帧延迟增量 P50/P99 + 受影响请求占比）----

// formatTopCats 把类目命中计数按降序格式化为 "cat:count|cat:count"（用 | 分隔以免破坏 CSV）。
func formatTopCats(counts map[string]int64, limit int) string {
	if len(counts) == 0 {
		return ""
	}
	cats := make([]string, 0, len(counts))
	for c := range counts {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool {
		if counts[cats[i]] != counts[cats[j]] {
			return counts[cats[i]] > counts[cats[j]]
		}
		return cats[i] < cats[j] // 计数相同按类目名定序，保证输出确定
	})
	if limit > 0 && len(cats) > limit {
		cats = cats[:limit]
	}
	parts := make([]string, 0, len(cats))
	for _, c := range cats {
		parts = append(parts, fmt.Sprintf("%s:%d", c, counts[c]))
	}
	return strings.Join(parts, "|")
}

// TestCascadeSoakMultiRequest OG-13 多请求并发浸泡（第二轮）。
//
// 与 TestCascadeSoak（单请求流式）的区别：
//   - N 路并发请求，每路持**独立** outputGuard（独立级联/槽位/容量阀），但**共享**同一
//     L2 HTTP 客户端 → 侧车侧产生真实竞争，服务时间被排队放大（OG-1 §10 待测「排队分量」）；
//   - 每路贡献 1 个首帧延迟增量观测 → 可算 P50/P99（OG-13 验收要求，单请求模型拿不到）；
//   - 可算「受影响请求占比」= 至少一句按 P-DEGRADE 处置的请求数 / N。
//
// 默认阻塞形态（SOAK_BLOCKING 缺省 true）：非阻塞下首帧延迟增量恒 ≈ 0，闸门判定无意义。
//
// 环境变量：SOAK_REQUESTS(N) / SOAK_LAMBDA(每请求句到达速率) / SOAK_SENTENCES(每请求句数)
// 加其余与单请求 driver 同名的变量。
//
// 输出：stdout 一行 SOAK_MR_RESULT CSV（由 og13-soak.ps1 -MultiRequest 捕获落盘）。
//
//	列：profile,requests,lambda_per_req,concurrency,blocking,sentences_per_req,
//	    first_frame_p50_ms,first_frame_p99_ms,first_frame_max_ms,
//	    affected_req_ratio,failclosed_ratio,l2_call_ratio,l2_calls_total,
//	    l2_throughput_per_sec,would_reject_top,erlang_b_per_req_pct
func TestCascadeSoakMultiRequest(t *testing.T) {
	if os.Getenv(spikeSoakENV) != "1" {
		t.Skipf("OG-13 多请求浸泡：设置 %s=1 才执行（需 L2 HTTP stub 运行中）", spikeSoakENV)
	}
	l2URL := os.Getenv("L2_URL")
	if l2URL == "" {
		t.Fatal("L2_URL 环境变量未设置（需指向 og13-l2-stub.py 地址）")
	}

	profile := os.Getenv("SOAK_PROFILE")
	if profile == "" {
		profile = "custom"
	}
	timeout := envDuration("L2_TIMEOUT", 2*time.Second)
	requests := envInt("SOAK_REQUESTS", 4)
	lambda := envFloat("SOAK_LAMBDA", 1.0) // 每请求句到达速率
	numSentences := envInt("SOAK_SENTENCES", 30)
	concurrency := envInt("SOAK_CONCURRENCY", 4)
	maxSlots := envInt("SOAK_MAX_SLOTS", 512)
	blocking := envBool("SOAK_BLOCKING", true)
	seed := envInt("SOAK_SEED", 20260917)
	expServiceS := envFloat("SOAK_EXP_SERVICE_S", 0)
	if requests < 1 {
		requests = 1
	}

	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	// 共享 L2 客户端：N 路请求竞争同一侧车（本轮要测的效应）
	l2 := newOutputL2HTTPClassifier(l2URL, "", timeout, nil, m, nil)

	firstFrames := make([]time.Duration, requests) // 各路首帧延迟增量（来自 cascade 口径）
	failClosedPerReq := make([]int64, requests)    // 各路 P-DEGRADE 句数
	var wg sync.WaitGroup

	startAt := time.Now()
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// 每路独立随机流（种子派生）：请求之间到达时刻不同，但整体可复现
			rng := rand.New(rand.NewSource(int64(seed) + int64(idx)*7919))
			casc := outputGuardCascadeParams{
				Timeout:       timeout,
				Concurrency:   concurrency,
				MaxSlots:      maxSlots,
				Degrade:       degradeFailClosed,
				BlockEmission: blocking,
			}
			cfg := outputGuardConfig{
				Mode:          outputGuardShadow,
				PolicyVersion: defaultPolicyVersion,
				Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
				Cascade:       casc,
			}
			og, err := newOutputGuard(cfg, fakeL2Classifier{}, l2, m, a, "acme", fmt.Sprintf("soak-mr-%d", idx))
			if err != nil {
				t.Errorf("第 %d 路 newOutputGuard: %v", idx, err) // 子 goroutine 内不用 Fatalf
				return
			}
			defer og.Close()

			sink := &soakEmitter{}
			intervals := poissonIntervals(rng, lambda, numSentences)
			for k := 0; k < numSentences; k++ {
				if k > 0 {
					time.Sleep(intervals[k])
				}
				og.Process(fmt.Sprintf("R%dS%d。", idx, k), sink.emit)
			}
			og.Finish(sink.emit)

			st := og.casc.stats()
			if st.HasFirstFrame {
				firstFrames[idx] = st.FirstFrameDelay
			}
			failClosedPerReq[idx] = st.FailClosed
		}(i)
	}
	wg.Wait()
	totalDur := time.Since(startAt)

	// 首帧延迟增量分布（每请求一个观测；毫秒）
	frames := make([]float64, 0, requests)
	for _, d := range firstFrames {
		frames = append(frames, float64(d)/float64(time.Millisecond))
	}
	sort.Float64s(frames)
	pct := func(p float64) float64 {
		if len(frames) == 0 {
			return 0
		}
		i := int(float64(len(frames)-1) * p)
		if i < 0 {
			i = 0
		}
		if i >= len(frames) {
			i = len(frames) - 1
		}
		return frames[i]
	}
	frameP50, frameP99 := pct(0.50), pct(0.99)
	frameMax := 0.0
	if len(frames) > 0 {
		frameMax = frames[len(frames)-1]
	}

	// 受影响请求占比：至少一句按 P-DEGRADE 处置的请求
	affected := 0
	for _, fc := range failClosedPerReq {
		if fc > 0 {
			affected++
		}
	}
	affectedRatio := float64(affected) / float64(requests)

	// 全局指标（读结构体字段，不走 Prometheus 文本解析）
	m.mu.Lock()
	ogSentencesF := float64(m.ogSentences)
	failClosedF := float64(m.ogFailclosedSent)
	l2CallsF := float64(m.ogL2CallsStarted)
	wouldReject := make(map[string]int64, len(m.ogWouldReject))
	for k, v := range m.ogWouldReject {
		wouldReject[k] = v
	}
	m.mu.Unlock()

	failClosedRatio, l2Ratio := 0.0, 0.0
	if ogSentencesF > 0 {
		failClosedRatio = failClosedF / ogSentencesF
		l2Ratio = l2CallsF / ogSentencesF
	}
	l2Throughput := 0.0
	if totalDur > 0 {
		l2Throughput = l2CallsF / totalDur.Seconds()
	}

	// 每请求 Erlang-B（无侧车竞争的基线；多请求下实测预期更高）
	erlangBPct := 0.0
	if expServiceS > 0 && concurrency > 0 {
		erlangBPct = erlangB(lambda*expServiceS, concurrency) * 100.0
	}

	fmt.Printf("SOAK_MR_RESULT,%s,%d,%.3f,%d,%t,%d,%.1f,%.1f,%.1f,%.4f,%.4f,%.4f,%.0f,%.2f,%s,%.2f\n",
		profile,
		requests,
		lambda,
		concurrency,
		blocking,
		numSentences,
		frameP50,
		frameP99,
		frameMax,
		affectedRatio,
		failClosedRatio,
		l2Ratio,
		l2CallsF,
		l2Throughput,
		formatTopCats(wouldReject, 5),
		erlangBPct,
	)
}
