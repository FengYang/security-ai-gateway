package main

// P0-2 批次 B2 测试：原生语义缓存主链接线
//   - 单元：segmentReplayEngine（§6.12 首段即回 + 节拍钳制 + 单块降级）
//   - 单元：segmentCapturingEngine（§6.12 写入侧分片采集 + 可选方法转发）
//   - 集成：原生命中（I-2/I-5/I-6/I-8，经 newNativeCacheServer 启用 native 路径）

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
	"security-ai-gateway/gateway/tee-infer-service/model"
	"security-ai-gateway/protocol/go"
)

// ===== 单元：分段回放引擎（§6.12.3）=====

// TestSegmentReplayEngine_FirstImmediateAndPaced 首段即回 + 节拍被钳制到 [min_gap, max_gap]。
func TestSegmentReplayEngine_FirstImmediateAndPaced(t *testing.T) {
	segs := []cacheengine.Segment{
		{Text: "A", At: 0},
		{Text: "B", At: 5 * time.Millisecond},  // 小于 min_gap（10ms）→ 抬升
		{Text: "C", At: 30 * time.Millisecond}, // 与上片差 25ms > max_gap（20ms）→ 压低
	}
	r := &segmentReplayEngine{
		text: "ABC", segs: segs, releaseAt: time.Now(),
		minGap: 10 * time.Millisecond, maxGap: 20 * time.Millisecond,
	}

	var got []string
	var times []time.Time
	start := time.Now()
	if err := r.Generate(model.GenerateRequest{}, func(d string) error {
		got = append(got, d)
		times = append(times, time.Now())
		return nil
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if strings.Join(got, "") != "ABC" {
		t.Fatalf("回放文本=%q，want ABC", strings.Join(got, ""))
	}
	if d := times[0].Sub(start); d > 8*time.Millisecond {
		t.Fatalf("首片未立即发出（应在节拍前）：%v", d)
	}
	if d := times[1].Sub(times[0]); d < 9*time.Millisecond {
		t.Fatalf("第 2 片节拍未抬升到 min_gap：%v", d)
	}
	if d := times[2].Sub(times[1]); d > 25*time.Millisecond {
		t.Fatalf("第 3 片节拍未压到 max_gap：%v", d)
	}
}

// TestSegmentReplayEngine_SingleBlockNoSegments 无分片 → 单块回放（B-6.12-2）。
func TestSegmentReplayEngine_SingleBlockNoSegments(t *testing.T) {
	r := &segmentReplayEngine{text: "hello", releaseAt: time.Now()}
	var got []string
	if err := r.Generate(model.GenerateRequest{}, func(d string) error {
		got = append(got, d)
		return nil
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(got) != 1 || got[0] != "hello" {
		t.Fatalf("无分片应单块回放，got=%v", got)
	}
}

// ===== 单元：分片采集包装器（§6.12 写入侧）=====

type fakeDeltaEngine struct {
	deltas []string
	fp     string
}

func (f *fakeDeltaEngine) Predict([]float64) int { return -1 }

func (f *fakeDeltaEngine) Generate(_ model.GenerateRequest, onDelta func(string) error) error {
	for _, d := range f.deltas {
		if err := onDelta(d); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeDeltaEngine) LastKeyFingerprint() string { return f.fp }

func TestSegmentCapturingEngine_RecordsSegmentsAndForwardsFP(t *testing.T) {
	inner := &fakeDeltaEngine{deltas: []string{"x", "y", "z"}, fp: "kf-1"}
	c := newSegmentCapturingEngine(inner, time.Now())

	var got []string
	if err := c.Generate(model.GenerateRequest{}, func(d string) error {
		got = append(got, d)
		return nil
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Join(got, "") != "xyz" {
		t.Fatalf("delta 未透传：%v", got)
	}
	if len(c.segments()) != 3 {
		t.Fatalf("采集分片数=%d，want 3", len(c.segments()))
	}
	if c.segments()[0].Text != "x" || c.segments()[0].At != 0 {
		t.Fatalf("首片记录不符：%+v", c.segments()[0])
	}
	// 可选方法必须显式转发（否则审计 KeyFP 归因丢失）
	if c.LastKeyFingerprint() != "kf-1" {
		t.Fatalf("LastKeyFingerprint 未转发：%q", c.LastKeyFingerprint())
	}
}

// ===== 集成：原生命中（I-2/I-5/I-6/I-8）=====

// newNativeCacheServer 在 newM9Server 基础上启用原生语义缓存（mode=exact），并移除 legacy 兜底。
func newNativeCacheServer(t *testing.T) (*teeServer, *httptest.Server) {
	t.Helper()
	srv, ts := newM9Server(t)

	cfg := cacheengine.DefaultConfig()
	cfg.Mode = cacheengine.ModeExact
	cfg.Exact.MinPromptTokens = 1
	cfg.Exact.MinTokens = 1
	cfg.Guard.ReadFastCheck = false // 无分类器环境下避免读时快审 mass-miss（§7.2 由专门用例覆盖）
	cfg.Semantic.Jitter.MaxMs = 1   // 缩短用例耗时（仍 >0，验证注入路径可达）
	cfg.Stream.MinGap = cacheengine.Duration(1 * time.Millisecond)
	cfg.Stream.MaxGap = cacheengine.Duration(5 * time.Millisecond)

	srv.cacheEngine = cacheengine.NewCacheEngine(cfg)
	srv.cacheEnabled = true
	srv.cache = nil // 排除 legacy 路径，确保走原生
	srv.cacheReplay = cacheReplayConfig{minGap: time.Millisecond, maxGap: 5 * time.Millisecond}
	return srv, ts
}

// TestTextInferCacheHitNative 原生命中：第二次同输入命中缓存，回放文本一致、审计 cache_hit、
// 命中路径交付 token 按实且上游 token 计 0（§4.5），分片信封逐片用当前会话密钥重封且 counter 单调（I-8）。
func TestTextInferCacheHitNative(t *testing.T) {
	srv, ts := newNativeCacheServer(t)
	const text = "原生缓存命中测试内容"

	// 第一次（会话1）：未命中 → 本地引擎回显 → 原生回填
	sess1, ksig1, kenc1 := setupTestSession(t, ts)
	req1 := buildTextInferRequest(t, ts.URL+"/v1/infer", sess1, ksig1, kenc1, text, protocol.EngineTypeTEEGPU, true, 1)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	body1 := mustReadAll(t, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("首次推理应 200，got %d", resp1.StatusCode)
	}
	out1, finish1 := decodeTextSSE(t, body1, sess1, kenc1) // I-8：内部断言 s2c counter 逐片严格递增
	if out1 != text || finish1 != "stop" {
		t.Fatalf("首次明文不符: %q finish=%q", out1, finish1)
	}

	// 第二次（会话2，同租户）：同输入 → 原生命中（分段回放）
	sess2, ksig2, kenc2 := setupTestSession(t, ts)
	req2 := buildTextInferRequest(t, ts.URL+"/v1/infer", sess2, ksig2, kenc2, text, protocol.EngineTypeTEEGPU, true, 1)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body2 := mustReadAll(t, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("命中推理应 200，got %d", resp2.StatusCode)
	}
	out2, finish2 := decodeTextSSE(t, body2, sess2, kenc2) // I-8：会话2 独立密钥重封，counter 单调
	if out2 != text || finish2 != "stop" {
		t.Fatalf("命中明文不符: %q finish=%q", out2, finish2)
	}

	// I-6：审计 cache_hit 标记（首次 false / 第二次 true）
	var infers []AuditEvent
	for _, e := range srv.audit.query("") {
		if e.Action == "infer" {
			infers = append(infers, e)
		}
	}
	if len(infers) < 2 {
		t.Fatalf("应有至少 2 次 infer 审计，got %d", len(infers))
	}
	first, second := infers[len(infers)-2], infers[len(infers)-1]
	if first.CacheHit {
		t.Fatal("首次 infer 不应 cache_hit")
	}
	if !second.CacheHit {
		t.Fatal("第二次 infer 应 cache_hit（原生精确缓存命中）")
	}

	// I-5：命中路径计费口径（§4.5）——命中也全额计入请求数、交付 token 按实（不折扣）。
	// 注：「上游 token=0」由 `recordUsage(tenant, 0, tokensOut, false)` 落地；该 0 是**上游**消耗槽位，
	// 与 usageRecord.TokensIn（含输入预占）不同口径，故此处只断言可观测的请求数与交付 token。
	rec := srv.usage["default"]
	if rec == nil {
		t.Fatal("用量记录缺失")
	}
	if rec.Requests != 2 {
		t.Fatalf("请求数应 +1 每次（共 2），got %d", rec.Requests)
	}
	wantOut := 2 * srv.countTokens(text)
	if rec.TokensOut != wantOut {
		t.Fatalf("交付 token 应按实累计（命中不折扣），got %d want %d", rec.TokensOut, wantOut)
	}
	if second.TokensOut != srv.countTokens(text) {
		t.Fatalf("命中审计 tokens_out 应按实，got %d want %d", second.TokensOut, srv.countTokens(text))
	}
}
