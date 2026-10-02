package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------- T-6.3 计量接入单元测试 ----------

func TestAggToEntries_Empty(t *testing.T) {
	// 空窗口返回空
	entries := AggToEntries(nil)
	if len(entries) != 0 {
		t.Errorf("nil window -> %d entries, want 0", len(entries))
	}

	entries = AggToEntries(&UsageWindow{Tenants: map[string]*TenantAgg{}})
	if len(entries) != 0 {
		t.Errorf("empty tenants -> %d entries, want 0", len(entries))
	}
}

func TestAggToEntries_SingleTenantMultiModel(t *testing.T) {
	win := &UsageWindow{
		FromNs: 1700000000000000000,
		ToNs:   1700086400000000000,
		Tenants: map[string]*TenantAgg{
			"t1": {
				TokensIn:  1000,
				TokensOut: 500,
				Requests:  10,
				ByModel: map[string]*ModelAgg{
					"m1": {TokensIn: 600, TokensOut: 300, Requests: 6},
					"m2": {TokensIn: 400, TokensOut: 200, Requests: 4},
				},
			},
		},
		Source:   "pull",
		EventKey: "pull-1700000000-1700086400",
	}

	entries := AggToEntries(win)
	if len(entries) != 2 {
		t.Fatalf("entries count = %d, want 2", len(entries))
	}

	// 验证 event_key 确定性（按模型名排序：m1, m2）
	if entries[0].ModelKey != "m1" {
		t.Errorf("entries[0].ModelKey = %q, want m1", entries[0].ModelKey)
	}
	if entries[0].TokensIn != 600 {
		t.Errorf("m1 TokensIn = %d, want 600", entries[0].TokensIn)
	}
	if entries[1].ModelKey != "m2" {
		t.Errorf("entries[1].ModelKey = %q, want m2", entries[1].ModelKey)
	}

	// 验证 event_key 格式
	expected := "pull-pull-1700000000-1700086400-t1-m1"
	if entries[0].EventKey != expected {
		t.Errorf("event_key = %q, want %q", entries[0].EventKey, expected)
	}
}

func TestAggToEntries_DayCalculation(t *testing.T) {
	// 验证 UTC+8 自然日计算
	// 2023-11-14 23:00 UTC = 2023-11-15 07:00 UTC+8
	ns := int64(1700000400) * int64(1e9) // 2023-11-14 23:00:00 UTC
	day := dayOfNs(ns)
	if day != "2023-11-15" {
		t.Errorf("dayOfNs(2023-11-14 23:00 UTC) = %q, want 2023-11-15 (UTC+8)", day)
	}
}

func TestCanWrite_SyncModes(t *testing.T) {
	// R-30 / A-12：单写者

	// pull 模式
	if !CanWrite(SyncModePull, "pull") {
		t.Error("pull mode should allow pull source")
	}
	if CanWrite(SyncModePull, "push") {
		t.Error("pull mode should NOT allow push source to write ledger")
	}
	if !CanWrite(SyncModePull, "manual") {
		t.Error("pull mode should allow manual source")
	}

	// push 模式
	if !CanWrite(SyncModePush, "push") {
		t.Error("push mode should allow push source")
	}
	if CanWrite(SyncModePush, "pull") {
		t.Error("push mode should NOT allow pull source to write ledger")
	}

	// 未知模式
	if CanWrite("both", "pull") {
		t.Error("unknown sync_mode should deny all writes")
	}
}

func TestPushEventToWindow(t *testing.T) {
	// §4.1.5：事件级载荷 → UsageWindow（单租户单模型）；is_retry 归因（§6.3.4 路①）
	ts := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	win := pushEventToWindow(PushEvent{
		EventID: "evt-123", TenantID: "t1", Model: "m1",
		TokensIn: 100, TokensOut: 50, Result: "ok", TS: ts,
	})
	if win == nil {
		t.Fatal("win is nil")
	}
	if win.Source != "push" || win.EventKey != "evt-123" {
		t.Errorf("source/event_key = %q/%q, want push/evt-123", win.Source, win.EventKey)
	}
	if win.ToNs != time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC).UnixNano() {
		t.Errorf("ToNs = %d, want event ts", win.ToNs)
	}
	ta := win.Tenants["t1"]
	if ta == nil || len(ta.ByModel) != 1 {
		t.Fatalf("tenant/model missing: %+v", ta)
	}
	if ta.TokensIn != 100 || ta.TokensOut != 50 || ta.Requests != 1 {
		t.Errorf("agg = %+v, want in=100 out=50 req=1", ta)
	}

	// is_retry=true → retry_toks 归因，tokens_* 置零（M9）
	rw := pushEventToWindow(PushEvent{
		EventID: "evt-124", TenantID: "t1", Model: "m1",
		TokensIn: 100, TokensOut: 50, IsRetry: true, TS: ts,
	})
	rt := rw.Tenants["t1"]
	if rt.RetryToks != 150 || rt.TokensIn != 0 || rt.TokensOut != 0 {
		t.Errorf("retry agg = %+v, want retry=150 in/out=0", rt)
	}

	// 负 token → 不落账（B-6.3-4）
	if pushEventToWindow(PushEvent{EventID: "e", TenantID: "t1", Model: "m1", TokensIn: -1, TS: ts}) != nil {
		t.Error("negative tokens should yield nil (B-6.3-4)")
	}
	// ts 非法 → 不落账（无法归日）
	if pushEventToWindow(PushEvent{EventID: "e", TenantID: "t1", Model: "m1", TS: "not-a-time"}) != nil {
		t.Error("bad ts should yield nil")
	}
}

func TestAggToEntries_ZeroModelSkipped(t *testing.T) {
	// 零用量模型不生成条目
	win := &UsageWindow{
		FromNs: 1000,
		ToNs:   2000,
		Tenants: map[string]*TenantAgg{
			"t1": {
				TokensIn:  100,
				TokensOut: 50,
				Requests:  2,
				ByModel: map[string]*ModelAgg{
					"m1": {TokensIn: 100, TokensOut: 50, Requests: 2},
					"m2": {}, // 零用量
				},
			},
		},
		Source:   "pull",
		EventKey: "pull-0-1",
	}
	entries := AggToEntries(win)
	if len(entries) != 1 {
		t.Errorf("entries = %d, want 1 (zero model skipped)", len(entries))
	}
}

func TestAggToEntries_RetryOnlyModel(t *testing.T) {
	// 仅有 retry token 的模型也应写入（平台成本）
	win := &UsageWindow{
		FromNs: 1000,
		ToNs:   2000,
		Tenants: map[string]*TenantAgg{
			"t1": {
				RetryToks: 50,
				ByModel: map[string]*ModelAgg{
					"m1": {RetryToks: 50},
				},
			},
		},
		Source:   "push",
		EventKey: "push-evt-1",
	}
	entries := AggToEntries(win)
	// 0 tokens_in/out/requests + 50 retry → 不应跳过（retry 也是数据）
	if len(entries) != 1 {
		t.Errorf("entries = %d, want 1 (retry-only model kept)", len(entries))
	}
}

// ---------- 拉取源：净量字段消费（A-27/A-35 跨服务契约） ----------

func TestTEEPullSource_ConsumesNetFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenants": map[string]any{
				"t1": map[string]any{
					"tokens_in": 170, "tokens_out": 80, "requests": 2,
					"tokens_in_net": 100, "tokens_out_net": 50, "retry_tokens": 100,
					"by_model": map[string]any{
						"tee_gpu/qwen": map[string]any{
							"tokens_in": 170, "tokens_out": 80, "requests": 2,
							"tokens_in_net": 100, "tokens_out_net": 50, "retry_tokens": 100,
						},
					},
				},
			},
		})
	}))
	defer srv.Close()

	src := NewTEEPullSource(srv.URL, "tok", 5*time.Second)
	win, err := src.Pull(context.Background(), int64(1)*int64(time.Second), int64(2)*int64(time.Second))
	if err != nil {
		t.Fatalf("Pull err: %v", err)
	}
	ta := win.Tenants["t1"]
	if ta == nil {
		t.Fatal("tenant t1 missing")
	}
	// 入账消费净量（非含 retry 的原口径）
	if ta.TokensIn != 100 || ta.TokensOut != 50 {
		t.Errorf("net = (%d,%d), want (100,50)", ta.TokensIn, ta.TokensOut)
	}
	if ta.RetryToks != 100 {
		t.Errorf("retry = %d, want 100", ta.RetryToks)
	}
	mu := ta.ByModel["tee_gpu/qwen"]
	if mu == nil || mu.TokensIn != 100 || mu.TokensOut != 50 || mu.RetryToks != 100 {
		t.Errorf("per-model net/retry wrong: %+v", mu)
	}
}

func TestTEEPullSource_LegacyFallback(t *testing.T) {
	// 旧版对端（无 _net 字段）：回退为 tokens 全量净量，retry=0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenants": map[string]any{
				"t1": map[string]any{
					"tokens_in": 70, "tokens_out": 30, "requests": 1,
					"by_model": map[string]any{
						"m1": map[string]any{"tokens_in": 70, "tokens_out": 30, "requests": 1},
					},
				},
			},
		})
	}))
	defer srv.Close()

	src := NewTEEPullSource(srv.URL, "", 5*time.Second)
	win, err := src.Pull(context.Background(), int64(1)*int64(time.Second), int64(2)*int64(time.Second))
	if err != nil {
		t.Fatalf("Pull err: %v", err)
	}
	ta := win.Tenants["t1"]
	if ta.TokensIn != 70 || ta.TokensOut != 30 || ta.RetryToks != 0 {
		t.Errorf("legacy fallback = (%d,%d,retry=%d), want (70,30,0)",
			ta.TokensIn, ta.TokensOut, ta.RetryToks)
	}
}
