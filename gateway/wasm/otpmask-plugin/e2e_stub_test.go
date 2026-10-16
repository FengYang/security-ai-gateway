package main

// e2e_stub_test.go — P1-6 M6.3：插件端到端（E2E）桩驱动测试（本机可跑）。
//
// 与 e2e/ 目录（真实 K8s + Higress 环境，环境门控）互补：本文件在**本机**以真实插件
// 入口（`init()`/`wrapper.SetCtx` 注册）+ 真实 proxy-wasm hostcall 跑通
// 「桩控制面 ↔ 插件 ↔ 端点选择」全链路，落地 §9.1 E2E 层的验收项：
//   - 选路分布（latency-aware 加权路径确实按权重分配，非退化单端点）；
//   - `X-Otp-Endpoint` / `X-Otp-Strategy` 写入正确（R2-10 策略标签）；
//   - 统计通道故障 → 回退可复现、恢复后重新命中画像；
//   - 上报（POST /routes/ttft/report）契约 + 至少一次/ACK 语义。
//
// 组成（除控制面为桩外均为真实路径）：
//   - 宿主：proxy-wasm-go-sdk `proxytest` 宿主仿真器 + wasm-go `pkg/test` 测试宿主
//     （后者注册 `get_log_level` 等外部函数）；HTTP callout / 计数器 / 请求头读写 /
//     属性等 hostcall 均由仿真器实现，非 mock 我们的代码。
//   - 桩控制面：`/v1/capabilities`、`/routes`（HMAC 签名表）、`/v1/hmac`（验签）、
//     `/routes/ttft/stats`、`/routes/ttft/report`；由本文件按 `:path` 应答。
//   - 随机源：经同包接缝 `routeRand.buf` 直接充填，使加权抽样确定可复现。
//
// 边界（如实）：
//   - 宿主时钟为真实墙钟（`time.Now()`），周期任务按 `ttft_poll_interval_seconds` 门控；
//     本文件将该周期设为 1s（配置下限）并以真实 `host.Tick()` 驱动，避免直调 tick 函数
//     （直调发生在插件回调上下文之外，SDK 会因缺活动上下文而 panic）。
//   - Envoy tick 调度频率、真实上游端点落地由 e2e/ 真实环境覆盖；本层断言多端点决策
//     输出头（供 Envoy/TEE 消费），不牵动真实上游。

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	proxytest "github.com/higress-group/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/higress-group/wasm-go/pkg/test"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
)

// E2E 桩环境常量。
const (
	e2eVerifyKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	e2eTenant       = "t-e2e"
	e2eModel        = "m-e2e"
	e2eEpFast       = "tee-a" // 桩统计 p95=130ms
	e2eEpSlow       = "tee-b" // 桩统计 p95=1600ms

	// e2eTickWait 周期推进等待：> ttft_poll_interval_seconds（1s）以越过 wrapper 墙钟门控。
	e2eTickWait = 1200 * time.Millisecond
)

// e2eStubPluginConfig 桩驱动 E2E 的插件配置：启用路由（gateway_core + 验签密钥）与
// crypto sidecar（路由表验签走 sidecar 的 /v1/hmac；插件侧零密码）；TTFT 周期取配置下限 1s。
const e2eStubPluginConfig = `{
	"model": "` + e2eModel + `",
	"gateway_core_enabled": true,
	"gateway_core_service": "gateway-core.otpmask.svc.cluster.local",
	"gateway_core_port": 8085,
	"route_verify_key": "` + e2eVerifyKeyHex + `",
	"crypto_service": "cryptop.otpmask.svc.cluster.local",
	"crypto_service_port": 8086,
	"crypto_profile": "intl",
	"ttft_poll_interval_seconds": 1
}`

// e2ePlane 桩控制面/密码侧。按 `:path` 应答插件的 HTTP callout，并记录上报请求体。
type e2ePlane struct {
	t            *testing.T
	tableBody    string
	macB64       string
	statsStatus  int
	reportStatus int
	reportBody   string
	statsReqs    int
	reportReqs   []string
}

// e2eBasePath 去查询串的 `:path`。
func e2eBasePath(hdrs [][2]string) string {
	for _, h := range hdrs {
		if h[0] == ":path" {
			return strings.SplitN(h[1], "?", 2)[0]
		}
	}
	return ""
}

// e2eSignedRouteTable 构造（并签名）一张含多端点 + latency 段的规范路由表。
//
// 签名实现说明：插件侧验签经 cryptop sidecar `/v1/hmac`（K_rx，§5.4.5；插件零密码）。
// 桩环境里 sidecar 即信任锚，故此处取任意 32 字节桩签名 `S`，并令 `/v1/hmac` 回
// `base64(S)`；验签路径（canon 编码 → 常量时间比较）真实执行，签名与 canon 的字节
// 契约由 routecache 单测（canon fixture）锁定。
func e2eSignedRouteTable(t *testing.T) (tableJSON, macB64 string) {
	t.Helper()
	sig := []byte("0123456789abcdef0123456789abcdef")
	tbl := &routecache.RouteTable{
		Version:   1,
		UpdatedAt: time.Now().Unix(),
		Routes: []routecache.TableRoute{{
			Tenant:        e2eTenant,
			Model:         e2eModel,
			DefaultEngine: "tee",
			Strategy:      "latency-aware",
			Endpoints: []routecache.TableEndpoint{
				{Name: e2eEpFast, URL: "http://" + e2eEpFast + ":19090", Enabled: true, Weight: 1},
				{Name: e2eEpSlow, URL: "http://" + e2eEpSlow + ":19090", Enabled: true, Weight: 1},
			},
			Latency: &routecache.RouteLatency{Quantile: "p95"},
		}},
		Signature: sig,
	}
	b, err := json.Marshal(tbl)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), base64.StdEncoding.EncodeToString(sig)
}

// e2eNewHost 启动插件（真实 init 注册路径）并完成 capabilities 握手，隔离全局状态。
func e2eNewHost(t *testing.T) (test.TestHost, *e2ePlane) {
	t.Helper()
	// 隔离全局状态（随机源缓冲 / 上报队列 / 周期运行态 / 桶计数）。
	oldBuf := routeRand.buf
	oldQueue := ttftQueue
	oldRuntime := ttftRuntime
	routeRand.buf = nil
	ttftQueue = newTTFTReportQueue()
	ttftRuntime = ttftRuntimeState{}
	ttftStore.freeze() // 清空共享存储
	t.Cleanup(func() {
		routeRand.buf = oldBuf
		ttftQueue = oldQueue
		ttftRuntime = oldRuntime
	})

	tableJSON, macB64 := e2eSignedRouteTable(t)
	host, status := test.NewTestHost(json.RawMessage(e2eStubPluginConfig))
	if !status {
		t.Fatal("插件启动失败（OnPluginStartStatus != OK）")
	}
	t.Cleanup(host.Reset)

	p := &e2ePlane{t: t, tableBody: tableJSON, macB64: macB64, statsStatus: 200, reportStatus: 200, reportBody: `{"result":"ok"}`}
	p.drain(host) // capabilities
	return host, p
}

// respond 为单个 callout 产出应答（ok=false 表示未识别的路径）。
func (p *e2ePlane) respond(a proxytest.HttpCalloutAttribute) (int, string, bool) {
	switch e2eBasePath(a.Headers) {
	case "/v1/capabilities":
		return 200, `{"profile":"intl","suite":1,"mask_prg":"aes-ctr","compliance_note":"e2e-stub"}`, true
	case "/routes":
		return 200, p.tableBody, true
	case "/v1/hmac":
		return 200, `{"mac":"` + p.macB64 + `"}`, true
	case "/routes/ttft/stats":
		p.statsReqs++
		if p.statsStatus != 200 {
			return p.statsStatus, `{"error":"source_unavailable"}`, true
		}
		now := time.Now().Unix()
		return 200, fmt.Sprintf(
			`{"generated_at":%d,"stats":[`+
				`{"tenant":"%s","model":"%s","endpoint":"%s","cache":"miss","p50_ms":110,"p95_ms":130,"samples":400,"valid":true,"updated_at":%d},`+
				`{"tenant":"%s","model":"%s","endpoint":"%s","cache":"miss","p50_ms":1400,"p95_ms":1600,"samples":400,"valid":true,"updated_at":%d}]}`,
			now*1000, e2eTenant, e2eModel, e2eEpFast, now, e2eTenant, e2eModel, e2eEpSlow, now), true
	case "/routes/ttft/report":
		p.reportReqs = append(p.reportReqs, string(a.Body))
		return p.reportStatus, p.reportBody, true
	case "/v1/rand":
		return 200, `{"bytes":""}`, true
	}
	return 0, "", false
}

// drain 反复应答插件上下文中挂起的 HTTP callout，直到收敛。
func (p *e2ePlane) drain(host test.TestHost) {
	p.t.Helper()
	for round := 0; round < 32; round++ {
		attrs := host.GetCalloutAttributesFromContext(proxytest.PluginContextID)
		if len(attrs) == 0 {
			return
		}
		progressed := false
		for _, a := range attrs {
			if st, body, ok := p.respond(a); ok {
				host.CallOnHttpCallResponse(a.CalloutID, [][2]string{{":status", strconv.Itoa(st)}}, nil, []byte(body))
				progressed = true
			}
		}
		if !progressed {
			for _, a := range attrs {
				p.t.Logf("未识别 callout: path=%s upstream=%s", e2eBasePath(a.Headers), a.Upstream)
			}
			p.t.Fatal("存在无法应答的 callout")
		}
	}
	p.t.Fatal("callout 未收敛")
}

// routeIngest 首 tick（lastExecuted=0 → 立即触发全部周期任务）并完成路由表验签入缓存。
func (p *e2ePlane) routeIngest(host test.TestHost) {
	p.t.Helper()
	host.Tick()
	p.drain(host)
}

// nextCycle 推进一个真实 TTFT 周期（墙钟 >1s）后触发 tick，驱动拉取/上报。
func (p *e2ePlane) nextCycle(host test.TestHost) {
	p.t.Helper()
	time.Sleep(e2eTickWait)
	host.Tick()
	p.drain(host)
}

// e2eRequest 发起一次请求头阶段，返回插件写入的 X-Otp-Endpoint / X-Otp-Strategy。
func e2eRequest(t *testing.T, host test.TestHost, tenant string) (endpoint, strategy string) {
	t.Helper()
	host.CallOnHttpRequestHeaders([][2]string{
		{":method", "POST"}, {":path", "/infer"}, {":authority", "gw.example"},
		{"X-Tenant-ID", tenant},
	})
	for _, h := range host.GetRequestHeaders() {
		switch strings.ToLower(h[0]) {
		case "x-otp-endpoint":
			endpoint = h[1]
		case "x-otp-strategy":
			strategy = h[1]
		}
	}
	host.CompleteHttp() // 结束本请求上下文，下个请求新建
	return endpoint, strategy
}

// e2eSetRand 充填插件随机源缓冲（`routeRand`，同包接缝）：每次抽样消费 8 字节
// （BigEndian uint64 >> 11 / 2^53）。足够长以避免周期内触发 `/v1/rand` 充填。
func e2eSetRand(vals []float64) {
	buf := make([]byte, 0, len(vals)*8)
	for _, v := range vals {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v*(1<<53))<<11)
		buf = append(buf, b[:]...)
	}
	routeRand.buf = buf
}

// e2eRepeat 生成 count 个 v。
func e2eRepeat(v float64, count int) []float64 {
	out := make([]float64, count)
	for i := range out {
		out[i] = v
	}
	return out
}

// e2eCounter 读取宿主计数器（不存在 → 0）。
func e2eCounter(t *testing.T, host test.TestHost, name string) uint64 {
	t.Helper()
	v, err := host.GetCounterMetric(name)
	if err != nil {
		return 0
	}
	return v
}

// e2eEnableMetrics 开启真实指标 hostcall（默认为 TestMain 置位的单测守卫 no-op）。
//
// ⚠️ pwCounter 的 `defined`/指标 ID 为**包级一次性**缓存；跨宿主仿真器复用会指向失效 ID
// 并 panic。故仅允许「本进程内唯一开启者」调用（当前仅分布用例）；其余 E2E 用例保持守卫
// no-op，不读指标。
func e2eEnableMetrics(t *testing.T) {
	t.Helper()
	old := metricsHostGuard
	metricsHostGuard = false
	t.Cleanup(func() { metricsHostGuard = old })
}

// TestE2EStub_LatencyDistributionAndHeaders 选路分布 + 决策头正确性（§9.1 E2E 验收项）。
//
// 序：路由表入缓存 → 首请求建引擎 → 下发统计（fast p95=130ms / slow p95=1600ms）→
//   - 阶段 A（加权路径活性）：随机源充填混合值 → 快/慢端点均应被选中（分布非退化）；
//   - 阶段 B（偏好方向）：随机源充填 0.5 → 逐次命中更快端点（权函数方向正确）。
//
// 全程断言 X-Otp-Endpoint ∈ {fast,slow}、X-Otp-Strategy == "latency-aware"（R2-10），
// 且每次选路计入 `otpmask_route_latency_pick_weighted_total`。
func TestE2EStub_LatencyDistributionAndHeaders(t *testing.T) {
	e2eEnableMetrics(t) // 本进程唯一开启真实指标者（pwCounter 包级 Define 缓存约束）
	host, plane := e2eNewHost(t)
	plane.routeIngest(host)

	// 首请求：建立 tenant×model 引擎（无统计 → 全局回退）。
	if ep, st := e2eRequest(t, host, e2eTenant); ep == "" || st != "latency-aware" {
		t.Fatalf("首请求决策头不符：endpoint=%q strategy=%q", ep, st)
	}
	plane.drain(host)

	// 下发统计（真实 GET /routes/ttft/stats + 解析写入，经下一周期 tick 驱动）。
	plane.nextCycle(host)
	if plane.statsReqs == 0 {
		t.Fatal("未观察到统计拉取请求")
	}

	base := e2eCounter(t, host, "otpmask_route_latency_pick_weighted_total")

	// 阶段 A：混合随机源 → 加权路径活性（快/慢均出现）。
	// 模式 [0.99,0.99,0.10,0.10]：利用抽样 r=0.99W 越过 fast 端点累权（≈0.925W）→ 命中 slow；
	// r=0.10W → 命中 fast。周期 4 对抽样错位鲁棒。
	mixed := make([]float64, 0, 512)
	for i := 0; i < 128; i++ {
		mixed = append(mixed, 0.99, 0.99, 0.10, 0.10)
	}
	const nA = 64
	e2eSetRand(mixed)
	fastA, slowA := 0, 0
	for i := 0; i < nA; i++ {
		ep, st := e2eRequest(t, host, e2eTenant)
		if st != "latency-aware" {
			t.Fatalf("阶段 A 策略标签应恒为 latency-aware（R2-10）：%q", st)
		}
		switch ep {
		case e2eEpFast:
			fastA++
		case e2eEpSlow:
			slowA++
		default:
			t.Fatalf("阶段 A 端点越界：%q", ep)
		}
	}
	if slowA == 0 || fastA == 0 {
		t.Fatalf("阶段 A 选路分布退化（加权路径未生效）：fast=%d slow=%d", fastA, slowA)
	}

	// 阶段 B：固定 0.5 → 反复命中更快端点（偏好方向正确）。
	const nB = 64
	e2eSetRand(e2eRepeat(0.5, 512))
	for i := 0; i < nB; i++ {
		ep, st := e2eRequest(t, host, e2eTenant)
		if ep != e2eEpFast || st != "latency-aware" {
			t.Fatalf("阶段 B 应命中更快端点：endpoint=%q strategy=%q", ep, st)
		}
	}

	// 计数：全部 latency-aware 选路（含量化回退，R2-10）计入 weighted 拆名。
	if got := e2eCounter(t, host, "otpmask_route_latency_pick_weighted_total") - base; got != nA+nB {
		t.Fatalf("选路计数应 +%d：got %d", nA+nB, got)
	}
	t.Logf("阶段 A 分布 fast=%d slow=%d；阶段 B 全 fast=%d", fastA, slowA, nB)
}

// TestE2EStub_UnreachableFallbackAndRecovery 统计通道故障 → 回退可复现 + 恢复（§9.1）。
//
// 序：路由表入缓存 → 首请求建引擎 + 下发统计（命中画像）→ 统计通道返回 503
// → R2-19 序 1 不可达标记 + 确定性回退（策略标签仍 latency-aware）→ 通道恢复（200）
// → 标记清除、重新命中画像。
func TestE2EStub_UnreachableFallbackAndRecovery(t *testing.T) {
	host, plane := e2eNewHost(t)
	plane.routeIngest(host)
	e2eRequest(t, host, e2eTenant) // 建引擎
	plane.drain(host)

	plane.nextCycle(host)
	e2eSetRand(e2eRepeat(0.5, 512))
	if ep, st := e2eRequest(t, host, e2eTenant); ep != e2eEpFast || st != "latency-aware" {
		t.Fatalf("统计就绪后应命中更快端点：endpoint=%q strategy=%q", ep, st)
	}

	// 通道故障：503 → 不可达标记 + 确定性回退。
	plane.statsStatus = 503
	plane.nextCycle(host)
	eng := routingEngines.entries[e2eTenant+"\x00"+e2eModel].engine
	if !eng.TTFTStatsUnreachable() {
		t.Fatal("503 应置不可达标记（R2-19 序 1）")
	}
	if ep, st := e2eRequest(t, host, e2eTenant); ep == "" || st != "latency-aware" {
		t.Fatalf("不可达期间回退决策头不符：endpoint=%q strategy=%q", ep, st)
	}

	// 恢复：200 → 清除标记 + 重新命中画像。
	plane.statsStatus = 200
	plane.nextCycle(host)
	if eng.TTFTStatsUnreachable() {
		t.Fatal("成功下发应清除不可达标记")
	}
	e2eSetRand(e2eRepeat(0.5, 512))
	if ep, st := e2eRequest(t, host, e2eTenant); ep != e2eEpFast || st != "latency-aware" {
		t.Fatalf("恢复后应命中更快端点：endpoint=%q strategy=%q", ep, st)
	}
}

// TestE2EStub_ReportRoundTrip 上报契约 + 至少一次/ACK 语义（真实 POST /routes/ttft/report）。
//
// 序：观测样本 → 周期 tick 冻结成批并上报（断言 batch_id/reported_at/buckets 契约）→
// 200 → ACK 出队；再观测 → 503 → 保留；恢复 → 原样重发同一 batch_id → 清队。
func TestE2EStub_ReportRoundTrip(t *testing.T) {
	host, plane := e2eNewHost(t)

	for i := 0; i < 3; i++ {
		ttftStore.observe(ttftKey{e2eTenant, e2eModel, fmt.Sprintf("ep-%d", i), "miss"}, 100)
	}
	host.Tick() // 首 tick：立即触发上报
	plane.drain(host)
	if len(plane.reportReqs) != 1 {
		t.Fatalf("应上报 1 批：%d", len(plane.reportReqs))
	}

	// 上报体契约（对齐 gateway-core M3.4 解析结构）。
	var rep struct {
		BatchID    string `json:"batch_id"`
		ReportedAt int64  `json:"reported_at"`
		Samples    []struct {
			Tenant   string   `json:"tenant"`
			Model    string   `json:"model"`
			Endpoint string   `json:"endpoint"`
			Cache    string   `json:"cache"`
			Buckets  []uint64 `json:"buckets"`
		} `json:"samples"`
	}
	if err := json.Unmarshal([]byte(plane.reportReqs[0]), &rep); err != nil {
		t.Fatalf("上报体非法 JSON：%v", err)
	}
	if rep.ReportedAt%1000 != 0 || !strings.HasSuffix(rep.BatchID, "|"+strconv.FormatInt(rep.ReportedAt/1000, 10)) {
		t.Fatalf("batch_id/reported_at 契约不符：id=%q at=%d", rep.BatchID, rep.ReportedAt)
	}
	if len(rep.Samples) != 3 {
		t.Fatalf("样本数应 3：%d", len(rep.Samples))
	}
	for i, s := range rep.Samples {
		if s.Tenant != e2eTenant || s.Model != e2eModel || s.Cache != "miss" || len(s.Buckets) != TTFTBucketCount {
			t.Fatalf("samples[%d] 契约不符：%+v", i, s)
		}
	}
	if ttftQueue.len() != 0 {
		t.Fatalf("200 应答后应 ACK 清队：%d", ttftQueue.len())
	}

	// 至少一次：503 → 保留待确认；恢复后重发同一批次。
	plane.reportStatus = 503
	ttftStore.observe(ttftKey{e2eTenant, e2eModel, "ep-0", "miss"}, 120)
	plane.nextCycle(host)
	if ttftQueue.len() != 1 {
		t.Fatalf("503 应保留待确认：%d", ttftQueue.len())
	}
	head, ok := ttftQueue.head()
	if !ok {
		t.Fatal("队头批次缺失")
	}
	before := len(plane.reportReqs)

	plane.reportStatus = 200
	plane.reportBody = `{"result":"ok"}`
	plane.nextCycle(host)
	if len(plane.reportReqs) <= before {
		t.Fatal("恢复后应重发队头批次")
	}
	resend := plane.reportReqs[len(plane.reportReqs)-1]
	if !strings.Contains(resend, head.BatchID) {
		t.Fatalf("重发应保持同一 batch_id：want=%q body=%s", head.BatchID, resend)
	}
	if ttftQueue.len() != 0 {
		t.Fatalf("恢复应答后应清队：%d", ttftQueue.len())
	}
}
