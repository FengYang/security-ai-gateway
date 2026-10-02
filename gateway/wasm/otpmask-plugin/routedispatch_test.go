package main

// routedispatch_test.go — 非流式重试（§6.5）纯逻辑单测。
// 仅覆盖无 hostcall 的部分：端点 URL 解析、可重试状态码判定、重试候选端点筛选、
// 引擎可用端点读方法；派发/回写路径依赖 wasm hostcall，不在宿主单测范围。

import (
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
	"security-ai-gateway/protocol/go"
)

func TestParseDispatchTarget(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		host     string
		port     int64
		path     string
		wantErr  bool
	}{
		{name: "显式端口+补推理路径", raw: "http://tee-infer.higress-system.svc.cluster.local:19090",
			host: "tee-infer.higress-system.svc.cluster.local", port: 19090, path: protocol.EndpointInfer},
		{name: "https 缺省端口", raw: "https://api.openai.com",
			host: "api.openai.com", port: 443, path: protocol.EndpointInfer},
		{name: "http 缺省端口", raw: "http://api.internal",
			host: "api.internal", port: 80, path: protocol.EndpointInfer},
		{name: "显式路径保留", raw: "http://a.internal:8080/v1/infer",
			host: "a.internal", port: 8080, path: "/v1/infer"},
		{name: "根路径补推理端点", raw: "http://a.internal:8080/",
			host: "a.internal", port: 8080, path: protocol.EndpointInfer},
		{name: "缺主机名", raw: "http://:19090", wantErr: true},
		{name: "非法 URL", raw: "http://[::1", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDispatchTarget(c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际得到 %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if got.host != c.host || got.port != c.port || got.path != c.path {
				t.Fatalf("解析结果不符: got=%+v want host=%s port=%d path=%s",
					got, c.host, c.port, c.path)
			}
			want := "http://" + c.host + ":" + itoa(c.port) + c.path
			if got.rawURL() != want {
				t.Fatalf("rawURL 不符: got=%q want=%q", got.rawURL(), want)
			}
		})
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestRetryableInferStatus(t *testing.T) {
	retryable := []int{500, 502, 503, 504, 429}
	for _, s := range retryable {
		if !retryableInferStatus(s) {
			t.Fatalf("状态码 %d 应可重试（§6.5.8）", s)
		}
	}
	// 不可重试：2xx/400/401/403/408（408 需"首字节未发出"前提，整包派发不满足）
	for _, s := range []int{200, 201, 204, 400, 401, 403, 404, 408} {
		if retryableInferStatus(s) {
			t.Fatalf("状态码 %d 不应可重试（§6.5.8）", s)
		}
	}
}

// newTestEntry 构造一个含两个端点的路由条目（供候选端点筛选测试）。
func newTestEntry(t *testing.T) *routingEntry {
	t.Helper()
	eng := routeengine.NewEngine(routeengine.Config{
		Strategy: routeengine.StrategyPriority,
		Endpoints: []routeengine.EndpointConfig{
			{Name: "ep-a", URL: "http://tee-a.internal:19090", Weight: 1, Priority: 1, Enabled: true},
			{Name: "ep-b", URL: "http://tee-b.internal:19090", Weight: 1, Priority: 2, Enabled: true},
		},
	})
	return &routingEntry{engine: eng}
}

func TestDispatchAvailableExcludesFailed(t *testing.T) {
	e := newTestEntry(t)
	d := &dispatchState{
		entry:  e,
		state:  routeengine.NewRetryState(),
		failed: map[string]bool{},
	}
	// 初始：两个端点都可用（升序）
	if got := d.available(); len(got) != 2 || got[0] != "ep-a" || got[1] != "ep-b" {
		t.Fatalf("初始候选端点不符: %v", got)
	}
	// 失败过的端点不再作为候选（§6.5.9 #9）
	d.failed["ep-a"] = true
	if got := d.available(); len(got) != 1 || got[0] != "ep-b" {
		t.Fatalf("排除失败端点后候选不符: %v", got)
	}
	// 全部失败 → 无候选（调用方不重试）
	d.failed["ep-b"] = true
	if got := d.available(); len(got) != 0 {
		t.Fatalf("全失败应无候选，实际: %v", got)
	}
}

// TestDispatchSingleEndpointNoRetry §6.5.9 #1：只有一个端点时不重试（无候选）。
func TestDispatchSingleEndpointNoRetry(t *testing.T) {
	eng := routeengine.NewEngine(routeengine.Config{
		Strategy:  routeengine.StrategyPriority,
		Endpoints: []routeengine.EndpointConfig{{Name: "only", URL: "http://only.internal:19090", Weight: 1, Enabled: true}},
	})
	d := &dispatchState{
		entry:  &routingEntry{engine: eng},
		state:  routeengine.NewRetryState(),
		failed: map[string]bool{"only": true},
	}
	if got := d.available(); len(got) != 0 {
		t.Fatalf("单端点失败后应无候选（不重试），实际: %v", got)
	}
}

// TestEngineUsableEndpointNamesSkipsDisabledAndOpenCircuit：
// 禁用端点与熔断打开端点不得进入重试候选（§6.5.4 / §6.8 硬约束）。
func TestEngineUsableEndpointNamesSkipsDisabledAndOpenCircuit(t *testing.T) {
	eng := routeengine.NewEngine(routeengine.Config{
		Strategy: routeengine.StrategyPriority,
		Endpoints: []routeengine.EndpointConfig{
			{Name: "ok", URL: "http://ok.internal:19090", Weight: 1, Enabled: true},
			{Name: "disabled", URL: "http://d.internal:19090", Weight: 1, Enabled: false},
		},
	})
	got := eng.UsableEndpointNames()
	if len(got) != 1 || got[0] != "ok" {
		t.Fatalf("禁用端点应被排除: %v", got)
	}
	if u, ok := eng.EndpointURL("ok"); !ok || u != "http://ok.internal:19090" {
		t.Fatalf("EndpointURL 读取不符: %q %v", u, ok)
	}
	if _, ok := eng.EndpointURL("missing"); ok {
		t.Fatal("未知端点应返回 ok=false")
	}
}

// TestDispatchPolicyRetryAcrossEndpoints 验证策略层：失败端点已在候选外时切换到另一端点。
func TestDispatchPolicyRetryAcrossEndpoints(t *testing.T) {
	st := routeengine.NewRetryState()
	dec := routeDispatchPolicy.ShouldRetry(st, "ep-a", []string{"ep-b"}, "ep-a", 0, true)
	if !dec.ShouldRetry || dec.RetryEndpoint != "ep-b" {
		t.Fatalf("应切换到 ep-b，实际: %+v", dec)
	}
	// 达到最大重试次数（默认 2）后不再重试
	_ = routeDispatchPolicy.ShouldRetry(st, "ep-b", []string{"ep-a"}, "ep-b", 0, true)
	dec = routeDispatchPolicy.ShouldRetry(st, "ep-a", []string{"ep-b"}, "ep-a", 0, true)
	if dec.ShouldRetry {
		t.Fatalf("达到最大重试次数后不应重试，实际: %+v", dec)
	}
}

// TestRetryAttemptHeaderValue GA-计费 P0-3（A-1/A-29）：
// 首次尝试（Attempt=1）不写归因头；重发（>=2）写十进制序号，供 tee-infer 判定 IsRetry。
func TestRetryAttemptHeaderValue(t *testing.T) {
	if v, ok := retryAttemptHeaderValue(1); ok || v != "" {
		t.Errorf("首次尝试不应写头，得到 (%q,%v)", v, ok)
	}
	if _, ok := retryAttemptHeaderValue(0); ok {
		t.Errorf("非法 attempt=0 不应写头")
	}
	if v, ok := retryAttemptHeaderValue(2); !ok || v != "2" {
		t.Errorf("重发应为 2，得到 (%q,%v)", v, ok)
	}
	if v, ok := retryAttemptHeaderValue(3); !ok || v != "3" {
		t.Errorf("二次重发应为 3，得到 (%q,%v)", v, ok)
	}
	if retryAttemptHeader != "X-Otpmask-Retry-Attempt" {
		t.Errorf("头名不符（须与 tee-infer 侧一致）: %q", retryAttemptHeader)
	}
}