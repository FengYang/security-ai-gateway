package main

// report_test.go — P1-7 T2b 数据面未达 TEE 流量上报通道单测（纯逻辑，hostcall 守卫下运行）。
//
// 覆盖：① 请求体签名求值经 cryptop sidecar 且与原直算口径**逐字节一致**（R-11 迁移证明，
// 2026-10-19）+ sidecar 不可用 ⇒ fail-closed 重入队；② 有界队列 FIFO/溢出丢弃计数（A3-14）；
// ③ 通道未启用=零行为变化（no-op）；④ 触发点判定（推理路径/非推理、缓存命中信号）；
// ⑤ 路径规范化与模式判定；⑥ 上报体 JSON 字段名与 §6.5 契约一致。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestAuditReportSignViaSidecarMatchesLegacy 迁移证明（R-11，2026-10-19）：签名求值经
// cryptop sidecar（/v1/hmac），与旧「插件内直算 HMAC-SHA256」**逐字节一致**
// ⇒ tee-infer 侧（D-13）验签口径零变化。
func TestAuditReportSignViaSidecarMatchesLegacy(t *testing.T) {
	installSeam(t) // in-process cryptop sidecar（cryptoseam_test.go；已登记 keyRefAuditReport=testSecret）
	body := []byte(`{"reports":[{"request_id":"r-1","result":"non_infer"}]}`)

	var got string
	var serr error
	symmetricHMAC(keyRefAuditReport, body, func(mac []byte, err error) {
		serr = err
		if mac != nil {
			got = hex.EncodeToString(mac)
		}
	})
	if serr != nil {
		t.Fatalf("sidecar 签名失败: %v", serr)
	}
	// 旧口径复算：HMAC-SHA256(key=令牌 UTF-8 字节, body)
	m := hmac.New(sha256.New, testSecret)
	m.Write(body)
	want := hex.EncodeToString(m.Sum(nil))
	if got != want {
		t.Fatalf("sidecar 签名与 D-13 旧口径不一致: want %s got %s", want, got)
	}
}

// TestAuditReportSignUnavailableRequeues sidecar 不可用 ⇒ 不签名不投递、批次重入队（fail-closed/C-4）。
func TestAuditReportSignUnavailableRequeues(t *testing.T) {
	savedQ, savedCfg := auditReportQ, auditReportCfg
	savedClient, savedReady := CryptoClient, cryptoReady
	defer func() {
		auditReportQ, auditReportCfg = savedQ, savedCfg
		CryptoClient, cryptoReady = savedClient, savedReady
	}()
	CryptoClient = nil
	cryptoReady = false
	auditReportQ = newAuditReportQueue(4)
	auditReportCfg = auditReportRuntime{token: "t", signRef: keyRefAuditReport, teeSvc: "tee.test", teePort: 19090}

	sendAuditReports([]auditReportItemDTO{{RequestID: "r-9", Result: resultNonInfer}})
	if auditReportQ.length() != 1 {
		t.Fatalf("sidecar 不可用时批次应重入队（fail-closed）：len=%d", auditReportQ.length())
	}
}

func TestAuditReportQueueFIFO(t *testing.T) {
	q := newAuditReportQueue(4)
	if d := q.push([]auditReportItemDTO{{RequestID: "a"}, {RequestID: "b"}}); d != 0 {
		t.Fatalf("未溢出不应丢弃: %d", d)
	}
	if q.length() != 2 {
		t.Fatalf("队列长度应为 2: %d", q.length())
	}
	out := q.takeAll()
	if len(out) != 2 || out[0].RequestID != "a" || out[1].RequestID != "b" {
		t.Fatalf("FIFO 顺序不符: %+v", out)
	}
	if q.length() != 0 {
		t.Fatalf("takeAll 后应清空: %d", q.length())
	}
	if q.takeAll() != nil {
		t.Fatal("空队列 takeAll 应返回 nil")
	}
}

func TestAuditReportQueueOverflowDropped(t *testing.T) {
	q := newAuditReportQueue(2)
	// 首次塞满（2 条）
	if d := q.push([]auditReportItemDTO{{RequestID: "1"}, {RequestID: "2"}}); d != 0 {
		t.Fatalf("填满不应丢弃: %d", d)
	}
	// 再塞 3 条 → 全部溢出丢弃（A3-14）
	d := q.push([]auditReportItemDTO{{RequestID: "3"}, {RequestID: "4"}, {RequestID: "5"}})
	if d != 3 {
		t.Fatalf("溢出应丢弃 3 条: %d", d)
	}
	if q.length() != 2 {
		t.Fatalf("队列长度应保持上限 2: %d", q.length())
	}
	// max<=0 → 回落缺省容量
	if def := newAuditReportQueue(0); def.max != defaultAuditReportQueueMax {
		t.Fatalf("缺省容量应为 %d: %d", defaultAuditReportQueueMax, def.max)
	}
}

func TestEnqueueDisabledIsNoop(t *testing.T) {
	// 保存并还原全局队列（避免测试间串扰）
	saved := auditReportQ
	auditReportQ = nil
	defer func() { auditReportQ = saved }()

	// 通道未启用 → 静默 no-op（不 panic、不建队列）
	enqueueDataPlaneReport(auditReportItemDTO{RequestID: "x", Result: resultNonInfer})
	onAuditReportFlushTick() // 未启用 → 直接返回
}

func TestEnqueueSetsTimestampAndPushes(t *testing.T) {
	saved := auditReportQ
	auditReportQ = newAuditReportQueue(4)
	defer func() { auditReportQ = saved }()

	enqueueDataPlaneReport(auditReportItemDTO{RequestID: "r-9", Result: resultNonInfer})
	if auditReportQ.length() != 1 {
		t.Fatalf("应入队 1 条: %d", auditReportQ.length())
	}
	out := auditReportQ.takeAll()
	if out[0].TimestampNS == 0 {
		t.Fatal("入队时应补 timestamp_ns（缺省落链时刻）")
	}
}

func TestMaybeReportDataPlaneDisabledIsNoop(t *testing.T) {
	saved := auditReportQ
	auditReportQ = nil
	defer func() { auditReportQ = saved }()

	// 通道未启用 → 在读取任何 hostcall 前返回；nil ctx 不得 panic
	maybeReportDataPlane(nil, PluginConfig{})
}

func TestIsInferencePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/v1/infer", true},
		{"/infer?x=1", true},
		{"/v1/recompute", true},
		{"/embed", true},
		{"/mcp-servers/secure-tools/foo", true}, // MCP 敏感轨（经 TEE 裁决）
		{"/provider/openai", false},             // S1 明文旅：非推理
		{"/healthz", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isInferencePath(c.path); got != c.want {
			t.Fatalf("isInferencePath(%q)=%v want %v", c.path, got, c.want)
		}
	}
}

func TestReportPathStripsQuery(t *testing.T) {
	if got := reportPath("/v1/infer?stream=1&m=qwen"); got != "/v1/infer" {
		t.Fatalf("应去 query: %q", got)
	}
	if got := reportPath("/healthz"); got != "/healthz" {
		t.Fatalf("无 query 应保持: %q", got)
	}
	if got := reportPath(""); got != "" {
		t.Fatalf("空路径应保持空: %q", got)
	}
}

func TestPathModeOf(t *testing.T) {
	if got := pathModeOf("/mcp-servers/secure-tools/x?y=1"); got != "encrypted" {
		t.Fatalf("MCP 敏感轨应记 encrypted: %q", got)
	}
	if got := pathModeOf("/provider/openai"); got != "plain" {
		t.Fatalf("普通路径应记 plain: %q", got)
	}
}

func TestAtoiSafe(t *testing.T) {
	if got := atoiSafe("429"); got != 429 {
		t.Fatalf("解析 429 失败: %d", got)
	}
	if got := atoiSafe(" 200 "); got != 200 {
		t.Fatalf("应容空白: %d", got)
	}
	if got := atoiSafe(""); got != 0 {
		t.Fatalf("空串应回退 0: %d", got)
	}
	if got := atoiSafe("abc"); got != 0 {
		t.Fatalf("非法应回退 0: %d", got)
	}
}

func TestAuditReportPayloadJSONShape(t *testing.T) {
	p := auditReportPayload{Reports: []auditReportItemDTO{{
		RequestID:   "req-1",
		TenantID:    "t-001",
		Path:        "/v1/infer",
		PathMode:    "encrypted",
		HTTPStatus:  200,
		Result:      resultCacheHitDataPlane,
		TimestampNS: 1700000000000000000,
		Model:       "qwen-max",
	}}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	// 契约字段名（§6.5 请求体）
	for _, k := range []string{"reports", "request_id", "tenant_id", "path", "path_mode", "http_status", "result", "timestamp_ns", "model"} {
		if !containsKey(b, k) {
			t.Fatalf("请求体缺字段 %q: %s", k, string(b))
		}
	}
	// omitempty：空字段不应出现
	empty, _ := json.Marshal(auditReportItemDTO{RequestID: "r", Result: resultNonInfer})
	if containsKey(empty, "tenant_id") || containsKey(empty, "dur_ms") {
		t.Fatalf("omitempty 字段不应序列化: %s", string(empty))
	}
}

// containsKey 粗略判断 JSON 对象是否含某键（值为字符串/数字键名，够用即可）。
func containsKey(b []byte, key string) bool {
	return json.Valid(b) && (len(b) > 0) && (jsonIndex(b, `"`+key+`":`) >= 0)
}

// jsonIndex 在字节序列中查找子串（避免引入 bytes 包命名冲突，保持测试自洽）。
func jsonIndex(haystack []byte, needle string) int {
	h := string(haystack)
	for i := 0; i+len(needle) <= len(h); i++ {
		if h[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestAuditLogHelpersNoSelfRecursion G-5 回归：auditInfof / auditWarnf 不得自递归。
//
// 历史缺陷：两函数在守卫放行分支内调用自身（自递归，无终止条件），生产态
// （metricsHostGuard=false）触达即无限递归栈溢出。本用例经日志宿接缝断言：
// 放行分支各调用日志宿恰一次（若自递归 → 栈溢出，测试进程崩溃即判失败）；
// 守卫分支为 no-op。
func TestAuditLogHelpersNoSelfRecursion(t *testing.T) {
	oldGuard := metricsHostGuard
	oldInfo, oldWarn := auditInfoLog, auditWarnLog
	t.Cleanup(func() {
		metricsHostGuard = oldGuard
		auditInfoLog, auditWarnLog = oldInfo, oldWarn
	})

	var info, warn int
	auditInfoLog = func(string, ...interface{}) { info++ }
	auditWarnLog = func(string, ...interface{}) { warn++ }

	// 放行分支（模拟生产 Wasm 运行态）：各调用一次。
	metricsHostGuard = false
	auditInfof("info x=%d", 1)
	auditWarnf("warn y=%d", 2)
	if info != 1 || warn != 1 {
		t.Fatalf("放行分支应各调用日志宿一次：info=%d warn=%d", info, warn)
	}

	// 守卫分支（单测/非 Wasm 运行态）：no-op，不调用日志宿。
	metricsHostGuard = true
	auditInfof("info")
	auditWarnf("warn")
	if info != 1 || warn != 1 {
		t.Fatalf("守卫分支不应调用日志宿：info=%d warn=%d", info, warn)
	}
}
