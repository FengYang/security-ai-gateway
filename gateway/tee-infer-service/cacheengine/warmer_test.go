package cacheengine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ===== 预热器专项用例（§6.7 四件套 T-6.7-1..8） =====

// warmupCfg 构造启用预热的测试配置（其余沿用 testConfig 的低阈值）。
func warmupCfg() CacheConfig {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Warmup = WarmupConfig{
		Enabled:  true,
		Source:   "file",
		File:     "/tmp/warmup.jsonl",
		MaxItems: 100,
		QPS:      0,
	}
	return cfg
}

// probeInfer 模拟"与真实请求同一链路"的注入回调：构造含真实键字段的 StoreContext。
func probeInfer(_ context.Context, it WarmItem) (StoreContext, InferResult, error) {
	sc := StoreContext{
		LookupContext: LookupContext{
			TenantID:        it.Tenant,
			EngineType:      "cmaas",
			Model:           "default",
			MaxNewTokens:    it.MaxNewTokens,
			TransformedHash: "wh-" + it.Prompt,
			PromptText:      it.Prompt,
			PolicyVer:       "1",
			GuardVer:        "1",
		},
		Writable: true,
	}
	return sc, InferResult{Text: "answer for " + it.Prompt, TokensOut: 5, Finish: "stop"}, nil
}

func warmItems(prompts ...string) []WarmItem {
	items := make([]WarmItem, 0, len(prompts))
	for _, p := range prompts {
		items = append(items, WarmItem{Tenant: "t1", Engine: "cmaas", Model: "default", Prompt: p, MaxNewTokens: 100})
	}
	return items
}

// waitWarmDone 轮询等待预热任务结束（Run 为异步）。
func waitWarmDone(t *testing.T, w CacheWarmer) WarmTask {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s := w.Status(); s.Status != WarmRunning {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("warmup 未在限时内结束")
	return WarmTask{}
}

// TestWarmup_RunAndHit 基本链路：预热后条目可命中（键与真实请求一致）。
func TestWarmup_RunAndHit(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	w := NewFileWarmer(&cfg, eng, probeInfer)

	if s := w.Status(); s.Status != WarmIdle {
		t.Fatalf("初始应为 idle，实际 %s", s.Status)
	}
	id, err := w.Run(warmItems("warm prompt one", "warm prompt two", "warm prompt three"), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if id == "" {
		t.Fatal("task id 不应为空")
	}
	task := waitWarmDone(t, w)
	if task.Status != WarmSucceeded || task.Total != 3 || task.Succeeded != 3 {
		t.Fatalf("任务结果异常：%+v", task)
	}

	r := eng.Lookup(LookupContext{
		TenantID: "t1", EngineType: "cmaas", Model: "default", MaxNewTokens: 100,
		TransformedHash: "wh-warm prompt one", PromptText: "warm prompt one",
		PolicyVer: "1", GuardVer: "1",
	})
	if !r.Hit {
		t.Fatalf("预热后应命中，reason=%s", r.RejectReason)
	}
}

// TestWarmup_SingleFlight T-6.7-1：并发触发只允许一个任务（B-6.7-1）。
func TestWarmup_SingleFlight(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	infer := func(ctx context.Context, it WarmItem) (StoreContext, InferResult, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return probeInfer(ctx, it)
	}
	w := NewFileWarmer(&cfg, eng, infer)

	id1, err := w.Run(warmItems("warm prompt one", "warm prompt two"), false)
	if err != nil {
		t.Fatalf("首次 Run: %v", err)
	}
	<-started // 确保任务已进入执行
	id2, err2 := w.Run(warmItems("warm prompt three"), false)
	if !errors.Is(err2, ErrWarmupBusy) {
		t.Fatalf("并发 Run 应返回 ErrWarmupBusy，实际 %v", err2)
	}
	if id2 != id1 {
		t.Fatalf("BUSY 应返回已有 task_id：got %s want %s", id2, id1)
	}
	close(release)
	waitWarmDone(t, w)
}

// TestWarmup_BlockedItemNotFailure T-6.7-2：被写前门禁拦截计入 skipped，不算失败（B-6.7-2）。
func TestWarmup_BlockedItemNotFailure(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	infer := func(ctx context.Context, it WarmItem) (StoreContext, InferResult, error) {
		sc, res, err := probeInfer(ctx, it)
		if it.Prompt == "warm prompt two" {
			sc.Writable = false // 模拟被输出侧审查拦截
		}
		return sc, res, err
	}
	w := NewFileWarmer(&cfg, eng, infer)

	if _, err := w.Run(warmItems("warm prompt one", "warm prompt two", "warm prompt three"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	task := waitWarmDone(t, w)
	if task.Skipped != 1 || task.Failed != 0 || task.Succeeded != 2 {
		t.Fatalf("被拦截条目应计 skipped 而非 failed：%+v", task)
	}
	if task.Status != WarmSucceeded {
		t.Fatalf("应 succeeded，实际 %s", task.Status)
	}
}

// TestWarmup_ItemErrorContinues T-6.7-3：单项失败（如配额耗尽）任务继续，其余照常。
func TestWarmup_ItemErrorContinues(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	infer := func(ctx context.Context, it WarmItem) (StoreContext, InferResult, error) {
		if it.Prompt == "warm prompt two" {
			return StoreContext{}, InferResult{}, errors.New("quota exceeded")
		}
		return probeInfer(ctx, it)
	}
	w := NewFileWarmer(&cfg, eng, infer)

	if _, err := w.Run(warmItems("warm prompt one", "warm prompt two", "warm prompt three"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	task := waitWarmDone(t, w)
	if task.Failed != 1 || task.Succeeded != 2 || task.Status != WarmSucceeded {
		t.Fatalf("单项失败不应中止任务：%+v", task)
	}
	if task.LastError != "quota exceeded" {
		t.Fatalf("LastError = %q", task.LastError)
	}
}

// TestWarmup_AllFailed T-6.7（B-6.7-8）：上游全失败 → failed、succeeded=0。
func TestWarmup_AllFailed(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	infer := func(context.Context, WarmItem) (StoreContext, InferResult, error) {
		return StoreContext{}, InferResult{}, errors.New("upstream down")
	}
	w := NewFileWarmer(&cfg, eng, infer)

	if _, err := w.Run(warmItems("warm prompt one", "warm prompt two"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	task := waitWarmDone(t, w)
	if task.Status != WarmFailed || task.Succeeded != 0 || task.Failed != 2 {
		t.Fatalf("全失败应标 failed：%+v", task)
	}
}

// TestWarmup_LoadItemsLineError T-6.7-4：JSONL 格式错误按行号报错（B-6.7-4）。
func TestWarmup_LoadItemsLineError(t *testing.T) {
	// 空行跳过 + 合法行
	items, err := LoadWarmItems(strings.NewReader("\n{\"prompt\":\"p one\"}\n\n{\"prompt\":\"p two\"}\n"))
	if err != nil {
		t.Fatalf("合法输入不应报错：%v", err)
	}
	if len(items) != 2 {
		t.Fatalf("应解析 2 条，实际 %d", len(items))
	}

	// 第 3 行非法 JSON
	if _, err := LoadWarmItems(strings.NewReader("{\"prompt\":\"ok\"}\n\n{bad json}\n")); err == nil ||
		!strings.Contains(err.Error(), "line 3") {
		t.Fatalf("非法 JSON 应报 line 3，实际 %v", err)
	}

	// 第 2 行缺 prompt
	if _, err := LoadWarmItems(strings.NewReader("{\"prompt\":\"ok\"}\n{\"tenant\":\"t1\"}\n")); err == nil ||
		!strings.Contains(err.Error(), "line 2") {
		t.Fatalf("缺 prompt 应报 line 2，实际 %v", err)
	}
}

// TestWarmup_TruncateOverMax T-6.7-5：超 max_items 截断且不静默（B-6.7-5）。
func TestWarmup_TruncateOverMax(t *testing.T) {
	cfg := warmupCfg()
	cfg.Warmup.MaxItems = 2
	eng := NewCacheEngine(cfg)
	w := NewFileWarmer(&cfg, eng, probeInfer)

	if _, err := w.Run(warmItems("p1 long", "p2 long", "p3 long", "p4 long", "p5 long"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	task := waitWarmDone(t, w)
	if task.Total != 2 || task.Truncated != 3 {
		t.Fatalf("应截断至 2 条、Truncated=3：%+v", task)
	}
}

// TestWarmup_ConfigSnapshotStable T-6.7-6：进行中任务使用启动时配置快照（B-6.7-6）。
func TestWarmup_ConfigSnapshotStable(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	infer := func(ctx context.Context, it WarmItem) (StoreContext, InferResult, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return probeInfer(ctx, it)
	}
	w := NewFileWarmer(&cfg, eng, infer)

	if _, err := w.Run(warmItems("warm prompt one", "warm prompt two", "warm prompt three"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	<-started
	// 任务进行中"热更新"配置（若未被快照，Total 会被改写为 1）
	cfg.Warmup.MaxItems = 1
	close(release)

	task := waitWarmDone(t, w)
	if task.Total != 3 || task.Succeeded != 3 {
		t.Fatalf("进行中任务应使用启动快照：%+v", task)
	}
}

// TestWarmup_DisabledReturnsError T-6.7-7：warmup.enabled=false → 报错（B-6.7-9）。
func TestWarmup_DisabledReturnsError(t *testing.T) {
	cfg := warmupCfg()
	cfg.Warmup.Enabled = false
	eng := NewCacheEngine(cfg)
	w := NewFileWarmer(&cfg, eng, probeInfer)

	if _, err := w.Run(warmItems("warm prompt one"), false); !errors.Is(err, ErrWarmupDisabled) {
		t.Fatalf("未启用应返回 ErrWarmupDisabled，实际 %v", err)
	}
}

// TestWarmup_ThrottleRespected T-6.7-8：节流生效（不高于配置 QPS）。
func TestWarmup_ThrottleRespected(t *testing.T) {
	cfg := warmupCfg()
	cfg.Warmup.QPS = 5 // 间隔 200ms
	eng := NewCacheEngine(cfg)
	w := NewFileWarmer(&cfg, eng, probeInfer)

	start := time.Now()
	if _, err := w.Run(warmItems("warm prompt one", "warm prompt two", "warm prompt three"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	waitWarmDone(t, w)
	// 3 条 → 2 个间隔 ≈ 400ms；放宽下界以避免调度抖动
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Fatalf("节流未生效：耗时 %v < 300ms", elapsed)
	}
}

// TestWarmup_AuditCalled §7.5：任务结束回调审计（cache_warmup_done + source_file_hash）。
func TestWarmup_AuditCalled(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	var gotAction string
	var gotFields map[string]any
	w := NewFileWarmer(&cfg, eng, probeInfer,
		WithWarmSourceHash("sha256:abc"),
		WithWarmAudit(func(action string, fields map[string]any) {
			gotAction, gotFields = action, fields
		}),
	)

	if _, err := w.Run(warmItems("warm prompt one"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	waitWarmDone(t, w)
	if gotAction != "cache_warmup_done" {
		t.Fatalf("审计 action = %q", gotAction)
	}
	if gotFields["source_file_hash"] != "sha256:abc" {
		t.Fatalf("审计缺 source_file_hash：%+v", gotFields)
	}
	if gotFields["succeeded"] != 1 {
		t.Fatalf("审计 succeeded 异常：%+v", gotFields)
	}
}

// TestWarmup_MetricEmitted §9.1 #18：预热条目结果发射 warmup_items_total{ok|fail}。
func TestWarmup_MetricEmitted(t *testing.T) {
	cfg := warmupCfg()
	eng := NewCacheEngine(cfg)
	e := eng.(*engine)
	infer := func(ctx context.Context, it WarmItem) (StoreContext, InferResult, error) {
		if it.Prompt == "warm prompt two" {
			return StoreContext{}, InferResult{}, errors.New("boom")
		}
		return probeInfer(ctx, it)
	}
	w := NewFileWarmer(&cfg, eng, infer)

	if _, err := w.Run(warmItems("warm prompt one", "warm prompt two"), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	waitWarmDone(t, w)

	snap := e.stats.warmupItemsC.snapshot()
	if snap["ok"] != 1 || snap["fail"] != 1 {
		t.Fatalf("warmup_items 计数异常：%+v", snap)
	}
}
