package main

// OG-10 逐帧 e2e 断言工具（研发计划 OG-10；技术方案 §6.2「全链路测试资产」）。
//
// 判据：
//   - shadow：能对"命中内容确已下发"的流做**负向验证**——断言器必须报出违规，
//     否则说明工具空转（永远 PASS 的工具等于没有门禁）；
//   - enforcing：整流零命中（**逐帧 + 跨帧拼接**双重判定）+ 终止码 `content_filter`。
//
// 为什么必须做跨帧拼接判定：协议要求每帧一个 SSE event、逐帧 Flush，
// 命中片段被拆到相邻两帧下发时，逐帧判定全部落空而客户端拼接后可见——
// 这是最隐蔽的泄漏形态（§3.9 违禁词跨 delta 边界用例）。
//
// 输入形态（两态都收敛到同一 deliveredFrame 列表，断言器只有一份）：
//   - tee-infer wire SSE：`data: <hex 信封>` → 会话解密取内层 textStreamChunk（本地实链）；
//   - 客户端可见明文 SSE dump：`data: {json}`（schema 同内层分片；旧插件无 guard 字段）
//     ——K3S 真实链路（OG-11）抓包可直读（§6.2：两组升级前后对照）。
//
// 合规红线（§4.11）：违规明细只报「片段序号 + 帧序号」，**绝不写入片段原文**，
// 保证断言失败日志本身不落命中内容。

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"security-ai-gateway/gateway/tee-infer-service/model"
	"security-ai-gateway/protocol/go"
)

// deliveredFrame 一帧已下发内容（断言器的最小输入单元）。
type deliveredFrame struct {
	Seq    uint64
	Delta  string
	Finish string
	Guard  *chunkGuardMeta
}

// frameCheckOpts 断言选项。
type frameCheckOpts struct {
	// Forbidden 命中片段（仅内存比对；绝不进入违规明细，见文件头合规红线）。
	Forbidden []string
	// WantFinish 期望终止码：enforcing＝content_filter；shadow＝stop。空＝不校验。
	WantFinish string
	// WantMode 期望 guard.mode（shadow|enforcing）。空＝不校验（如升级前旧插件无 chunk-meta）。
	WantMode string
}

// 违规类别（断言失败的可机读归因）。
const (
	violationEmptyStream   = "empty_stream"    // 未捕获到任何帧（抓包链路问题）
	violationPerFrameHit   = "per_frame_hit"   // 单帧内出现命中片段
	violationCrossFrameHit = "cross_frame_hit" // 逐帧未命中但拼接命中（跨帧拆分泄漏）
	violationFinishCode    = "finish_code"     // 终止码不符（客户端无法识别审核终止）
	violationGuardMeta     = "guard_meta"      // chunk-meta 缺失或 mode 不符
)

// frameViolation 单条断言违规。
type frameViolation struct {
	Kind   string
	Detail string
}

// checkDeliveredFrames 对已下发帧序列做逐帧 + 跨帧 + 终止码 + chunk-meta 断言。
// 返回空切片 = 全部通过；非空 = 违规明细（调用方决定门禁与否：shadow 期命中属预期，enforcing 期零容忍）。
func checkDeliveredFrames(frames []deliveredFrame, opts frameCheckOpts) []frameViolation {
	if len(frames) == 0 {
		return []frameViolation{{Kind: violationEmptyStream, Detail: "未捕获到任何已下发帧"}}
	}
	var vs []frameViolation

	// ① 逐帧：任一帧的 delta 内不得出现命中片段。
	for i, f := range frames {
		for j, frag := range opts.Forbidden {
			if frag == "" {
				continue
			}
			if strings.Contains(f.Delta, frag) {
				vs = append(vs, frameViolation{Kind: violationPerFrameHit,
					Detail: fmt.Sprintf("片段#%d 出现在第 %d 帧（seq=%d）", j+1, i+1, f.Seq)})
			}
		}
	}

	// ② 跨帧：拼接后仍不得出现；仅当逐帧全部未命中才报（避免与①重复计数）。
	var all strings.Builder
	for _, f := range frames {
		all.WriteString(f.Delta)
	}
	joined := all.String()
	for j, frag := range opts.Forbidden {
		if frag == "" || !strings.Contains(joined, frag) {
			continue
		}
		if !containsInAnyFrame(frames, frag) {
			vs = append(vs, frameViolation{Kind: violationCrossFrameHit,
				Detail: fmt.Sprintf("片段#%d 跨帧拼接后出现（逐帧均未命中）", j+1)})
		}
	}

	// ③ 终止码：最后一帧（带 finish 的帧）必须是期望终止码。
	if opts.WantFinish != "" {
		if got := lastFinish(frames); got != opts.WantFinish {
			vs = append(vs, frameViolation{Kind: violationFinishCode,
				Detail: fmt.Sprintf("终止码=%q，期望 %q", got, opts.WantFinish)})
		}
	}

	// ④ chunk-meta：出现的 guard 必须 mode 一致；一个都没有则视为 meta 缺失。
	if opts.WantMode != "" {
		seen := false
		for i, f := range frames {
			if f.Guard == nil {
				continue
			}
			seen = true
			if f.Guard.Mode != opts.WantMode {
				vs = append(vs, frameViolation{Kind: violationGuardMeta,
					Detail: fmt.Sprintf("第 %d 帧 guard.mode=%q，期望 %q", i+1, f.Guard.Mode, opts.WantMode)})
			}
		}
		if !seen {
			vs = append(vs, frameViolation{Kind: violationGuardMeta, Detail: "未捕获到 guard chunk-meta"})
		}
	}
	return vs
}

// containsInAnyFrame 片段是否已完整出现在某一单帧内（用于区分①与②的责任归属）。
func containsInAnyFrame(frames []deliveredFrame, frag string) bool {
	for _, f := range frames {
		if strings.Contains(f.Delta, frag) {
			return true
		}
	}
	return false
}

// lastFinish 最后一帧的终止码（无 finish 的中间帧跳过）。
func lastFinish(frames []deliveredFrame) string {
	finish := ""
	for _, f := range frames {
		if f.Finish != "" {
			finish = f.Finish
		}
	}
	return finish
}

// hasViolation 违规明细中是否存在指定类别。
func hasViolation(vs []frameViolation, kind string) bool {
	for _, v := range vs {
		if v.Kind == kind {
			return true
		}
	}
	return false
}

// parseWireFrames 抓取 tee-infer wire SSE（`data: <hex 信封>`）→ 逐帧解密为内层明文帧。
// 缺 `[DONE]` = 流未正常收尾，属结构性失败（非内容断言），直接失败。
func parseWireFrames(t *testing.T, body []byte, sessionID string, kenc []byte) []deliveredFrame {
	t.Helper()
	var frames []deliveredFrame
	lastCounter := uint64(0)
	sawDone := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			sawDone = true
			continue
		}
		wire, err := hex.DecodeString(data)
		if err != nil {
			t.Fatalf("SSE 分片非 hex（逐帧断言须抓 wire 形态）: %v", err)
		}
		pt, counter, err := protocol.OpenEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionS2C, wire)
		if err != nil {
			t.Fatalf("SSE 分片解密失败: %v", err)
		}
		if counter != lastCounter+1 {
			t.Fatalf("s2c 计数器乱序: got=%d last=%d", counter, lastCounter)
		}
		lastCounter = counter
		var chunk textStreamChunk
		if err := json.Unmarshal(pt, &chunk); err != nil {
			t.Fatalf("分片 JSON 无效: %v", err)
		}
		frames = append(frames, deliveredFrame{Seq: chunk.Seq, Delta: chunk.Delta, Finish: chunk.Finish, Guard: chunk.Guard})
	}
	if !sawDone {
		t.Fatal("SSE 流缺 [DONE]（流未正常收尾）")
	}
	return frames
}

// parsePlaintextFrames 解析客户端可见明文 SSE dump（K3S 抓包形态，§6.2 两组对照）：
// 每行 `data: {"seq":..,"delta":..,"finish":..,"guard":{..}}`，schema 与内层分片一致；
// 升级前旧插件 dump 无 guard 字段（WantMode 留空即不校验）。
func parsePlaintextFrames(t *testing.T, dump []byte) []deliveredFrame {
	t.Helper()
	var frames []deliveredFrame
	sawDone := false
	for _, line := range strings.Split(string(dump), "\n") {
		line = strings.TrimRight(line, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			sawDone = true
			continue
		}
		var chunk textStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			t.Fatalf("明文 dump 分片 JSON 无效: %v", err)
		}
		frames = append(frames, deliveredFrame{Seq: chunk.Seq, Delta: chunk.Delta, Finish: chunk.Finish, Guard: chunk.Guard})
	}
	if !sawDone {
		t.Fatal("明文 dump 缺 [DONE]（流未正常收尾）")
	}
	return frames
}

// framewiseStubEngine 输出可控的测试引擎：让"引擎输出含命中片段"而不受输入侧 Guardrail 约束
// （输入侧与输出侧共用命中口径，直接回显命中文本会被输入侧 403 拦在门外）。
type framewiseStubEngine struct{ deltas []string }

func (framewiseStubEngine) Predict([]float64) int { return -1 }

func (e framewiseStubEngine) Generate(_ model.GenerateRequest, onDelta func(string) error) error {
	for _, d := range e.deltas {
		if err := onDelta(d); err != nil {
			return err
		}
	}
	return nil
}

// TestFramewiseCheckerDetectsPerFrameHit 负向验证①：单帧内的命中片段必被检出；
// 且未下发过的片段不得误报（防"永远报违规"的假阳性工具）。
func TestFramewiseCheckerDetectsPerFrameHit(t *testing.T) {
	const frag = "-- 命中片段在帧内。"
	frames := []deliveredFrame{
		{Seq: 1, Delta: "正常前缀。"},
		{Seq: 2, Delta: frag},
		{Seq: 3, Finish: "stop"},
	}
	vs := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: []string{frag}})
	if !hasViolation(vs, violationPerFrameHit) {
		t.Fatalf("帧内命中必须被检出，实际违规=%+v", vs)
	}
	if hasViolation(vs, violationCrossFrameHit) {
		t.Fatalf("命中完整落在单帧内，不应报跨帧违规：%+v", vs)
	}
	// 违规明细不含片段原文（合规红线：断言失败日志也不落命中内容）
	for _, v := range vs {
		if strings.Contains(v.Detail, "命中片段在帧内") {
			t.Fatalf("违规明细泄露片段原文：%q", v.Detail)
		}
	}
	// 未下发的片段 → 零违规
	if vs2 := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: []string{"从未下发的片段"}}); len(vs2) != 0 {
		t.Fatalf("未下发片段不得误报，实际违规=%+v", vs2)
	}
}

// TestFramewiseCheckerDetectsCrossFrameSplit 负向验证②：命中片段被拆到相邻两帧
// （逐帧全部未命中、客户端拼接后可见）必须被检出——这是最隐蔽的泄漏形态。
func TestFramewiseCheckerDetectsCrossFrameSplit(t *testing.T) {
	const frag = "-- 注释。"
	frames := []deliveredFrame{
		{Seq: 1, Delta: "前段--"},
		{Seq: 2, Delta: " 注释。"},
		{Seq: 3, Finish: "stop"},
	}
	vs := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: []string{frag}})
	if !hasViolation(vs, violationCrossFrameHit) {
		t.Fatalf("跨帧拆分泄漏必须被检出，实际违规=%+v", vs)
	}
	if hasViolation(vs, violationPerFrameHit) {
		t.Fatalf("单帧均不含完整片段，不应报逐帧违规：%+v", vs)
	}
}

// TestFramewiseCheckerTerminalContract 终止码与 chunk-meta 契约：
// enforcing 合法形态零违规；泄漏/终止码不符/meta 缺失均被检出。
// （合成流：enforcing 实链属 M4（OG-17），届时同一断言器直接复跑真实抓包。）
func TestFramewiseCheckerTerminalContract(t *testing.T) {
	enforcingMeta := &chunkGuardMeta{
		Detected: true, Filtered: true, Action: catActionBlock,
		Category: "A1-06", PolicyVersion: "pv2026.09.16", Mode: outputGuardEnforcing,
	}
	opts := frameCheckOpts{Forbidden: []string{"违规片段"}, WantFinish: "content_filter", WantMode: outputGuardEnforcing}

	// ① 合法 enforcing：命中在帧外被拦、以 content_filter 收尾 → 零违规
	ok := []deliveredFrame{
		{Seq: 1, Delta: "已判定通过的前缀。"},
		{Seq: 2, Finish: "content_filter", Guard: enforcingMeta},
	}
	if vs := checkDeliveredFrames(ok, opts); len(vs) != 0 {
		t.Fatalf("合法 enforcing 形态应零违规，实际=%+v", vs)
	}

	// ② 泄漏：命中片段随帧下发 → 逐帧违规
	leak := []deliveredFrame{
		{Seq: 1, Delta: "违规片段"},
		{Seq: 2, Finish: "content_filter", Guard: enforcingMeta},
	}
	if vs := checkDeliveredFrames(leak, opts); !hasViolation(vs, violationPerFrameHit) {
		t.Fatalf("enforcing 下命中下发必须被检出，实际=%+v", vs)
	}

	// ③ 终止码不符：已判定拦截却以 stop 收尾（客户端无法识别审核终止）→ finish_code
	stopEnd := []deliveredFrame{
		{Seq: 1, Delta: "已判定通过的前缀。"},
		{Seq: 2, Finish: "stop", Guard: enforcingMeta},
	}
	if vs := checkDeliveredFrames(stopEnd, opts); !hasViolation(vs, violationFinishCode) {
		t.Fatalf("终止码不符必须被检出，实际=%+v", vs)
	}

	// ④ chunk-meta 缺失：要求校验 mode 却一帧都没有 guard → guard_meta
	if vs := checkDeliveredFrames([]deliveredFrame{{Seq: 1, Delta: "x", Finish: "stop"}}, opts); !hasViolation(vs, violationGuardMeta) {
		t.Fatalf("chunk-meta 缺失必须被检出，实际=%+v", vs)
	}
}

// TestFramewisePlaintextDumpParsing 客户端可见明文 dump 形态可被工具消费
// （K3S 抓包直读；升级后形态带 guard 与 content_filter 终止码 → 零违规）。
func TestFramewisePlaintextDumpParsing(t *testing.T) {
	dump := "data: {\"seq\":1,\"delta\":\"已判定通过的前缀。\"}\n\n" +
		"data: {\"seq\":2,\"finish\":\"content_filter\",\"guard\":{\"detected\":true,\"filtered\":true," +
		"\"action\":\"block\",\"category\":\"A1-06\",\"policy_version\":\"pv2026.09.16\",\"mode\":\"enforcing\"}}\n\n" +
		"data: [DONE]\n\n"
	frames := parsePlaintextFrames(t, []byte(dump))
	if len(frames) != 2 {
		t.Fatalf("应解析出 2 帧，实际 %d", len(frames))
	}
	vs := checkDeliveredFrames(frames, frameCheckOpts{
		Forbidden: []string{"违规片段"}, WantFinish: "content_filter", WantMode: outputGuardEnforcing,
	})
	if len(vs) != 0 {
		t.Fatalf("升级后合法形态应零违规，实际=%+v", vs)
	}
}

// TestOutputGuardFramewiseE2EShadow 实链逐帧 e2e（shadow）：
// 真链路（httptest + 证明会话 + 信封 SSE）抓包 → 交付内容逐字节一致（只记不拦）→
// **负向验证**断言器确能检出已下发命中（工具非空转）→ chunk-meta 与审计落链一致。
func TestOutputGuardFramewiseE2EShadow(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.outputGuardMode = outputGuardShadow
	srv.outputGuardParams = defaultOutputGuardParams()
	// 输出含 SQL 注入口径命中（输入侧同口径，故用 stub 引擎绕过输入侧 403）
	srv.model = framewiseStubEngine{deltas: []string{"好的。", "-- 注释。", "结束。"}}

	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "请讲个笑话",
		protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("shadow 下推理应 200，got %d", resp.StatusCode)
	}
	frames := parseWireFrames(t, mustReadAll(t, resp.Body), sessionID, kenc)

	// 交付内容 = 引擎输出逐字节（shadow 只记不拦，不改变输出）
	var sb strings.Builder
	for _, f := range frames {
		sb.WriteString(f.Delta)
	}
	const want = "好的。-- 注释。结束。"
	if got := sb.String(); got != want {
		t.Fatalf("shadow 必须原样放行：got %q want %q", got, want)
	}

	// 命中片段取 L1 实际返回的 Match（不自造字符串，保证断言与检出同源）
	hit := newGuardrail().check("-- 注释。")
	if hit == nil || hit.Category != "sql_injection" {
		t.Fatalf("预期 sql_injection 命中，实际 %+v", hit)
	}
	forbidden := []string{hit.Match}

	// 负向验证：命中内容确已下发 → 断言器必须检出（否则工具空转、enforcing 门禁无意义）
	vs := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: forbidden, WantFinish: "stop", WantMode: outputGuardShadow})
	if !hasViolation(vs, violationPerFrameHit) {
		t.Fatalf("shadow 下命中内容已下发，逐帧断言器必须检出：%+v", vs)
	}
	// 同一流按 enforcing 语义判定 → 终止码违规亦须检出（M4 门禁语义就位）
	if vs2 := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: forbidden, WantFinish: "content_filter"}); !hasViolation(vs2, violationFinishCode) {
		t.Fatalf("enforcing 语义下终止码违规必须被检出：%+v", vs2)
	}
	// 未下发片段不得误报
	if vs3 := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: []string{"未下发的片段"}, WantFinish: "stop"}); len(vs3) != 0 {
		t.Fatalf("未下发片段不得误报：%+v", vs3)
	}

	// chunk-meta：shadow 只标记不拦截 + 内部类目 ID + action=flag（OG-5）
	last := frames[len(frames)-1]
	if last.Guard == nil {
		t.Fatal("终止帧应带 guard chunk-meta")
	}
	if !last.Guard.Detected || last.Guard.Filtered {
		t.Fatalf("shadow 命中应 detected=true/filtered=false，实际 %+v", last.Guard)
	}
	if last.Guard.Category != "A1-07" || last.Guard.Action != catActionFlag {
		t.Fatalf("chunk-meta 应为 A1-07/flag，实际 category=%q action=%q", last.Guard.Category, last.Guard.Action)
	}
	if last.Guard.Mode != outputGuardShadow || last.Guard.PolicyVersion == "" {
		t.Fatalf("chunk-meta mode/policy_version 不符：%+v", last.Guard)
	}

	// 审计：同一请求首个命中落 1 条 output_would_reject（OG-7 内部类目 ID）
	if n := srv.audit.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("应落 1 条 output_would_reject 审计，实际 %d", n)
	}
	for _, e := range srv.audit.query("") {
		if e.Action == "output_would_reject" && (e.OGCategory != "A1-07" || e.OGMode != outputGuardShadow) {
			t.Fatalf("审计类目/模式不符：%+v", e)
		}
	}
}