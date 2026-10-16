package main

// integration_test.go — P1-6 M6.2：上报→聚合→下发→执行 契约级集成闭环（§9.1 集成层）。
//
// 边界（如实）：控制面网关（gateway-core 常驻服务）与数据面插件（wasm 主包）无法同进程
// 互调（internal 包可见性 + wasm 运行时限制），本套用例以**契约字节**为界、双侧语义真实：
//   - 数据面侧全部走真实实现：ttftStore.observe/freeze → ttftQueue.freezeCycle →
//     ttftBuildReports → json.Marshal（上报体）→ ttftOnReportResponse（ACK 语义）→
//     ttftApplyStatsResponse（下发解析）→ 引擎选路执行；
//   - 控制面侧载荷按 M3 实装结构逐字段构造：上报解析契约 = gateway-core internal/api
//     routes.go 的 {batch_id, reported_at, worker, samples{tenant,model,endpoint,cache,
//     buckets[11]}}（M3.4）；下发契约 = GET /routes/ttft/stats 的 {generated_at,
//     stats[{tenant,model,endpoint,cache,p50_ms,p95_ms,samples,valid,updated_at}]}（M3.5）。
//     两侧字段各自有 M3/M2 单测覆盖，本用例锁定跨边界字节面（字段名漂移将在本层暴露）。
//
// 覆盖（对齐 §9.1 集成测试行）：闭环可复现 / 控制面不可达回退可复现 / 多工作条目隔离
// （tenant/model 键）/ 至少一次重发与 batch_id 去重 ACK / 批量下发与 TT2-08 拆分。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

// swapTTFTQueue 替换全局待确认队列（隔离用例间状态；单线程测试包）。
func swapTTFTQueue(t *testing.T) *ttftReportQueue {
	t.Helper()
	old := ttftQueue
	ttftQueue = newTTFTReportQueue()
	t.Cleanup(func() { ttftQueue = old })
	return ttftQueue
}

// ttftSetStat 直写端点统计（latency-fastest 对照/夹具用）。
func ttftSetStat(t *testing.T, eng *routeengine.Engine, ep string, p95 int64, nowSec int64) {
	t.Helper()
	if ok := eng.SetEndpointTTFT(ep, routeengine.TTFTStat{
		P50Ms: p95 / 2, P95Ms: p95, Samples: 400, Valid: true,
		UpdatedAt: nowSec, Cache: "miss",
	}); !ok {
		t.Fatalf("SetEndpointTTFT(%s) 失败", ep)
	}
}

// ttftIntEngine 构造集成用双端点引擎（latency-aware 缺省 / strategy 可覆写）。
func ttftIntEngine(strategy routeengine.Strategy) *routeengine.Engine {
	return routeengine.NewEngine(routeengine.Config{
		Strategy: strategy,
		Endpoints: []routeengine.EndpointConfig{
			{Name: "tee-a", URL: "http://tee-a", Enabled: true, Weight: 1},
			{Name: "tee-b", URL: "http://tee-b", Enabled: true, Weight: 1},
		},
		Latency: routeengine.DefaultLatencyConfig(),
	})
}

// TestIntegration_ReportAggregateDispatchExecute：完整链路——
// 观测（真实桶）→ 冻结成批（batch_id/reported_at 契约）→ 上报体逐字段对照 M3.4 解析结构
// → ACK 出队 → 按 M3.5 响应字节下发 → 数据面真实解析写入 → 引擎执行偏好更快端点。
func TestIntegration_ReportAggregateDispatchExecute(t *testing.T) {
	q := swapTTFTQueue(t)
	ttftStore.freeze() // 清空全局存储（隔离他测残留）
	t.Cleanup(func() { ttftStore.freeze() })

	eng := ttftIntEngine(routeengine.StrategyLatencyAware)
	ttftSwapRegistry(t, map[string]*routingEntry{"t-int\x00m-int": {engine: eng}})

	// ① 数据面观测：tee-a 60 样本 @120ms；tee-b 60 样本 @1500ms（真实 ttftStore）
	for i := 0; i < 60; i++ {
		ttftStore.observe(ttftKey{"t-int", "m-int", "tee-a", "miss"}, 120)
		ttftStore.observe(ttftKey{"t-int", "m-int", "tee-b", "miss"}, 1500)
	}
	enq, dropped := q.freezeCycle(ttftIdentity{node: "node-1", vmID: "abc12345"}, 1760000000, ttftStore)
	if enq != 1 || dropped != 0 {
		t.Fatalf("冻结应入队 1 批：enq=%d dropped=%d", enq, dropped)
	}

	batch, ok := q.head()
	if !ok {
		t.Fatal("队头应有批次")
	}
	if batch.Node != "node-1" || batch.Worker != "abc12345" ||
		batch.BatchID != "node-1|abc12345|1760000000" || batch.ReportedAt != 1760000000000 {
		t.Fatalf("批次头不符（node|vm|周期起始秒；reported_at=起始秒×1000）：%+v", batch)
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}

	// ② 控制面契约边界（M3.4 解析结构：字段名/桶长 11/桶位）
	var parsed struct {
		Node       string `json:"node"`
		Worker     string `json:"worker"`
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
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.BatchID != batch.BatchID || parsed.ReportedAt != batch.ReportedAt {
		t.Fatalf("上报体契约字段丢失：%+v", parsed)
	}
	if len(parsed.Samples) != 2 {
		t.Fatalf("样本数应 2：%d", len(parsed.Samples))
	}
	// 构造顺序 = endpoint 字典序（tee-a → tee-b，§6.2 确定性顺序）
	if parsed.Samples[0].Endpoint != "tee-a" || parsed.Samples[1].Endpoint != "tee-b" {
		t.Fatalf("样本顺序不符（应 endpoint 字典序）：%+v", parsed.Samples)
	}
	// 桶位锁定（§3.4 边界）：120ms → 首个上界 ≥120 的桶 (100,250] = idx4；
	// 1500ms → (1000,2000] = idx7；桶为桶内计数（非累积），单桶满载、总和=样本数
	for i, wantIdx := range []int{4, 7} {
		s := parsed.Samples[i]
		if s.Tenant != "t-int" || s.Model != "m-int" || s.Cache != "miss" {
			t.Fatalf("samples[%d] 键不符：%+v", i, s)
		}
		if len(s.Buckets) != TTFTBucketCount {
			t.Fatalf("samples[%d] 桶数应 %d：%d", i, TTFTBucketCount, len(s.Buckets))
		}
		var sum uint64
		for j, c := range s.Buckets {
			sum += c
			if j != wantIdx && c != 0 {
				t.Fatalf("samples[%d] 桶 %d 不应有计数：%v", i, j, s.Buckets)
			}
		}
		if sum != 60 || s.Buckets[wantIdx] != 60 {
			t.Fatalf("samples[%d] 桶位不符：%v", i, s.Buckets)
		}
	}

	// ③ 传输确认（M3 契约 ACK 语义：200 result=ok → ackByID 出队）
	ttftOnReportResponse(200, []byte(`{"result":"ok"}`), batch.BatchID)
	if q.len() != 0 {
		t.Fatalf("确认后应清队：%d", q.len())
	}

	// ④ 下发（M3.5 响应字节）→ 数据面真实解析写入（一租户一批量：2 端点一次响应写入）
	nowSec := time.Now().Unix()
	statsBody := []byte(fmt.Sprintf(
		`{"generated_at":%d,"stats":[`+
			`{"tenant":"t-int","model":"m-int","endpoint":"tee-a","cache":"miss","p50_ms":110,"p95_ms":130,"samples":400,"valid":true,"updated_at":%d},`+
			`{"tenant":"t-int","model":"m-int","endpoint":"tee-b","cache":"miss","p50_ms":1400,"p95_ms":1600,"samples":400,"valid":true,"updated_at":%d}]}`,
		nowSec*1000, nowSec, nowSec))
	applied, rejected := ttftApplyStatsResponse("t-int", 200, statsBody, nowSec)
	if applied != 2 || rejected != 0 {
		t.Fatalf("下发应写入 2 条：applied=%d rejected=%d", applied, rejected)
	}
	states := ttftStatesByName(eng)
	if st := states["tee-a"].TTFT; !st.Valid || st.P95Ms != 130 {
		t.Fatalf("tee-a 下发写入不符：%+v", st)
	}
	if st := states["tee-b"].TTFT; !st.Valid || st.P95Ms != 1600 {
		t.Fatalf("tee-b 下发写入不符：%+v", st)
	}

	// ⑤ 执行：latency-aware 偏好更快端点（多次多数；R2-10 策略标签保持）
	fast := 0
	for i := 0; i < 200; i++ {
		d := eng.PickEndpointForTenant("t-int")
		if d.Strategy != routeengine.StrategyLatencyAware {
			t.Fatalf("策略标签应保持 latency-aware（R2-10）：%s", d.Strategy)
		}
		if d.EndpointName == "tee-a" {
			fast++
		}
	}
	if fast < 100 {
		t.Fatalf("更快端点应占多数：tee-a %d/200", fast)
	}

	// ⑥ 确定性策略对照：latency-fastest 单次即选 tee-a（γ→∞ 极限形式）
	engFast := ttftIntEngine(routeengine.StrategyLatencyFastest)
	ttftSetStat(t, engFast, "tee-a", 130, nowSec)
	ttftSetStat(t, engFast, "tee-b", 1600, nowSec)
	if d := engFast.PickEndpointForTenant("t-int"); d.EndpointName != "tee-a" {
		t.Fatalf("latency-fastest 应选 tee-a：%+v", d)
	}
}

// TestIntegration_AtLeastOnceAndDedupAckSemantics：至少一次重发与去重 ACK——
// 未确认批次原样重发（字节不变）；503/非契约载荷保留；ok/dropped/duplicate 均 ACK 出队
// （台账 G-6 语义）；队列上限丢最旧（R2-06/R2-18）。
func TestIntegration_AtLeastOnceAndDedupAckSemantics(t *testing.T) {
	q := swapTTFTQueue(t)
	ttftStore.freeze()
	t.Cleanup(func() { ttftStore.freeze() })

	id := ttftIdentity{node: "node-1", vmID: "abc12345"}
	for c := 0; c < 3; c++ {
		ttftStore.observe(ttftKey{"t-int", "m-int", "tee-a", "miss"}, 100+int64(c)*10)
		enq, _ := q.freezeCycle(id, 1760000000+int64(c)*10, ttftStore)
		if enq != 1 {
			t.Fatalf("周期 %d 应入队 1 批：%d", c, enq)
		}
	}
	if q.len() != 3 {
		t.Fatalf("三周期应累计 3 批：%d", q.len())
	}

	b0, _ := q.head()
	body0, err := json.Marshal(b0)
	if err != nil {
		t.Fatal(err)
	}
	// 未确认 → 下个 tick 原样重发：batch_id 与字节不变（去重前提）
	b0again, _ := q.head()
	body0again, _ := json.Marshal(b0again)
	if b0again.BatchID != b0.BatchID || !bytes.Equal(body0, body0again) {
		t.Fatal("未确认批次应原样重发（batch_id 与字节不变）")
	}

	// 503（source_unavailable，控制面不可达语义）→ 保留重发
	ttftOnReportResponse(503, []byte(`{"error":"source_unavailable"}`), b0.BatchID)
	if q.len() != 3 {
		t.Fatalf("503 应保留待确认：%d", q.len())
	}
	// 200 非契约载荷（版本错配/中间件页）→ 保留
	ttftOnReportResponse(200, []byte(`{}`), b0.BatchID)
	if q.len() != 3 {
		t.Fatalf("非契约 200 应保留：%d", q.len())
	}
	// 200 result=duplicate（控制面 batch_id 去重）→ ACK 出队
	ttftOnReportResponse(200, []byte(`{"result":"duplicate"}`), b0.BatchID)
	if q.len() != 2 {
		t.Fatalf("duplicate 应 ACK 出队：%d", q.len())
	}
	b1, _ := q.head()
	if b1.BatchID == b0.BatchID {
		t.Fatalf("队头应推进：%s", b1.BatchID)
	}
	// 200 result=dropped（旧世代弃发）→ ACK 出队
	ttftOnReportResponse(200, []byte(`{"result":"dropped"}`), b1.BatchID)
	if q.len() != 1 {
		t.Fatalf("dropped 应 ACK 出队：%d", q.len())
	}
	// 200 result=ok → ACK 出队，队列清空
	b2, _ := q.head()
	ttftOnReportResponse(200, []byte(`{"result":"ok"}`), b2.BatchID)
	if q.len() != 0 {
		t.Fatalf("ok 应清队：%d", q.len())
	}

	// 队列上限（R2-06/R2-18）：容量 4，追加 6 → 丢最旧 2 并计数
	reps := make([]ttftReport, 0, 6)
	for i := 0; i < 6; i++ {
		reps = append(reps, ttftReport{BatchID: fmt.Sprintf("b%d", i), ReportedAt: 1760000000000})
	}
	enqueued, dropped := q.appendAll(reps)
	if enqueued != 6 || dropped != 2 {
		t.Fatalf("追加 6 应丢 2：enq=%d dropped=%d", enqueued, dropped)
	}
	if q.len() != TTFTReportQueueCap || q.droppedTotal() != 2 {
		t.Fatalf("上限后应保 4 丢 2：len=%d dropped=%d", q.len(), q.droppedTotal())
	}
	if h, _ := q.head(); h.BatchID != "b2" {
		t.Fatalf("应丢最旧（b0/b1）：%s", h.BatchID)
	}
}

// TestIntegration_SplitBatchesOverLimit：TT2-08 超限拆分——单周期 1001 个键
// （> 单批 1000）拆 2 批，batch_id 追加 |1/|2，重发序号稳定。
func TestIntegration_SplitBatchesOverLimit(t *testing.T) {
	q := swapTTFTQueue(t)
	ttftStore.freeze()
	t.Cleanup(func() { ttftStore.freeze() })

	for i := 0; i < TTFTReportMaxSamples+1; i++ {
		ttftStore.observe(ttftKey{"t-int", "m-int", fmt.Sprintf("e%04d", i), "miss"}, 100)
	}
	enq, dropped := q.freezeCycle(ttftIdentity{node: "node-1", vmID: "abc12345"}, 1760000000, ttftStore)
	if enq != 2 || dropped != 0 {
		t.Fatalf("1001 键应拆 2 批：enq=%d dropped=%d", enq, dropped)
	}
	b1, _ := q.head()
	q.ack()
	b2, _ := q.head()
	if b1.BatchID != "node-1|abc12345|1760000000|1" || b2.BatchID != "node-1|abc12345|1760000000|2" {
		t.Fatalf("拆分批次号不符：%s / %s", b1.BatchID, b2.BatchID)
	}
	if len(b1.Samples) != TTFTReportMaxSamples || len(b2.Samples) != 1 {
		t.Fatalf("拆分样本数不符：%d / %d", len(b1.Samples), len(b2.Samples))
	}
	if b1.ReportedAt != b2.ReportedAt || b1.ReportedAt != 1760000000000 {
		t.Fatal("同周期拆分批次 reported_at 应一致")
	}
}

// TestIntegration_UnreachableFallbackAndRecovery：控制面统计通道故障闭环——
// 无统计 → 全局回退（策略标签保持）；统计就绪 → 命中延迟画像；拉取触发错误 → R2-19 序 1
// 不可达标记 + 确定性回退；成功下发 → 清除标记并恢复画像。
func TestIntegration_UnreachableFallbackAndRecovery(t *testing.T) {
	ttftStore.freeze()
	t.Cleanup(func() { ttftStore.freeze() })

	eng := ttftIntEngine(routeengine.StrategyLatencyAware)
	ttftSwapRegistry(t, map[string]*routingEntry{"t-int\x00m-int": {engine: eng}})

	// 初始无统计：全局回退（no_samples），决策有效且策略标签不变（R2-10）
	if d := eng.PickEndpointForTenant("t-int"); d.EndpointName == "" || d.Strategy != routeengine.StrategyLatencyAware {
		t.Fatalf("无统计全局回退不符：%+v", d)
	}

	nowSec := time.Now().Unix()
	applyStats := func() {
		t.Helper()
		body := []byte(fmt.Sprintf(
			`{"generated_at":%d,"stats":[`+
				`{"tenant":"t-int","model":"m-int","endpoint":"tee-a","cache":"miss","p50_ms":110,"p95_ms":130,"samples":400,"valid":true,"updated_at":%d},`+
				`{"tenant":"t-int","model":"m-int","endpoint":"tee-b","cache":"miss","p50_ms":1400,"p95_ms":1600,"samples":400,"valid":true,"updated_at":%d}]}`,
			nowSec*1000, nowSec, nowSec))
		if applied, rejected := ttftApplyStatsResponse("t-int", 200, body, nowSec); applied != 2 || rejected != 0 {
			t.Fatalf("下发应写入 2 条：applied=%d rejected=%d", applied, rejected)
		}
	}
	applyStats()
	preferRate := func() int {
		fast := 0
		for i := 0; i < 100; i++ {
			if eng.PickEndpointForTenant("t-int").EndpointName == "tee-a" {
				fast++
			}
		}
		return fast
	}
	if fast := preferRate(); fast < 50 {
		t.Fatalf("统计就绪后应偏好 tee-a：%d/100", fast)
	}

	// 通道故障（GET 发起即错）→ 不可达标记（R2-19 序 1）
	oldGet := ttftFetchGet
	ttftFetchGet = func(service string, port int64, path string, headers [][2]string,
		cb func(int, http.Header, []byte)) error {
		return fmt.Errorf("connection refused")
	}
	rt := &ttftRuntimeState{enabled: true, intervalMs: 10000}
	rt.fetchTenant("t-int", nowSec)
	ttftFetchGet = oldGet
	if !eng.TTFTStatsUnreachable() {
		t.Fatal("通道故障应标记不可达（R2-19 序 1）")
	}
	// 不可达期间：确定性回退且策略标签不变
	if d := eng.PickEndpointForTenant("t-int"); d.EndpointName == "" || d.Strategy != routeengine.StrategyLatencyAware {
		t.Fatalf("不可达回退不符：%+v", d)
	}

	// 恢复：成功下发清不可达 → 重新命中延迟画像
	applyStats()
	if eng.TTFTStatsUnreachable() {
		t.Fatal("成功下发应清除不可达标记")
	}
	if fast := preferRate(); fast < 50 {
		t.Fatalf("恢复后应偏好 tee-a：%d/100", fast)
	}
}
