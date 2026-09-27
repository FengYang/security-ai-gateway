package main

// B1 强标标识（GB 45438-2025）测试（技术方案 B1 节；研发计划 B1 批次）。
//
// 覆盖（对照实施计划验收清单）：
//   - off：无标识帧无 label meta（现网行为由既有套件回归）；
//   - on：首帧 seq=1 且 meta.position=head；尾帧在 stop 前；stop 帧带 tail meta；
//   - repeat N=2、5 内容帧 → repeat 帧 2 个 + 首尾 2 个；
//   - seq 严格连续、帧总数 = 内容+标识+终止；
//   - 计量排除：标识文本不进 tokens_out（tokensOut == countTokens(引擎文本)）；
//   - 校验：文案缺"生成"/缺"人工智能"→ 拒绝；repeat 越界 → 拒绝；
//   - 热切换：POST on → 审计 content_label_change + 持久化 0600；重启恢复（loadContentLabelOverride）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"security-ai-gateway/protocol/go"
)

// TestContentLabelValidate 校验纪律（fail-closed；resolve 只派生不掩蔽非法）。
func TestContentLabelValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     contentLabelConfig
		wantErr string
	}{
		{"合规文案", contentLabelConfig{Enabled: true, Text: "内容由人工智能生成", Repeat: 0}, ""},
		{"自定义合规文案", contentLabelConfig{Enabled: true, Text: "本回答由人工智能生成，仅供参考", Repeat: 1000}, ""},
		{"缺「生成」", contentLabelConfig{Enabled: true, Text: "内容由人工智能产出"}, "生成"},
		{"缺「人工智能」", contentLabelConfig{Enabled: true, Text: "内容由 AI 生成"}, "人工智能"},
		{"repeat 负值", contentLabelConfig{Enabled: true, Text: "内容由人工智能生成", Repeat: -1}, "非法"},
		{"repeat 超上限", contentLabelConfig{Enabled: true, Text: "内容由人工智能生成", Repeat: maxContentLabelRepeat + 1}, "非法"},
		{"off 态文案不校验", contentLabelConfig{Enabled: false, Text: "任意文案", Repeat: 0}, ""},
		{"off 态 repeat 仍校验", contentLabelConfig{Enabled: false, Repeat: -1}, "非法"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateContentLabelConfig(c.cfg)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("应通过，实际 %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("应报含 %q 的错误，实际 %v", c.wantErr, err)
			}
		})
	}
}

// TestContentLabelResolveDefaults resolve 只派生：空文案/标准号兜底缺省。
func TestContentLabelResolveDefaults(t *testing.T) {
	c := resolveContentLabelConfig(contentLabelConfig{Enabled: true})
	if c.Text != defaultContentLabelText || c.Std != defaultContentLabelStd {
		t.Fatalf("缺省派生不符：%+v", c)
	}
	if !strings.Contains(c.Text, "人工智能") || !strings.Contains(c.Text, "生成") {
		t.Fatalf("缺省文案须同时含「人工智能」与「生成」：%q", c.Text)
	}
}

// runLabelInfer 跑一次 text 流式推理并解析 wire 帧（复用 framewise 工具链）。
func runLabelInfer(t *testing.T, srv *teeServer, ts *httptest.Server, deltas []string) []deliveredFrame {
	t.Helper()
	srv.model = framewiseStubEngine{deltas: deltas}
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "请讲个笑话",
		protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("推理应 200，got %d", resp.StatusCode)
	}
	return parseWireFrames(t, mustReadAll(t, resp.Body), sessionID, kenc)
}

// assertSeqStrict 帧 seq 严格连续（1 起逐帧 +1）——标识帧经 writeChunk 分配 seq 的合同。
func assertSeqStrict(t *testing.T, frames []deliveredFrame) {
	t.Helper()
	for i, f := range frames {
		if f.Seq != uint64(i+1) {
			t.Fatalf("seq 不连续：帧 %d seq=%d，期望 %d", i, f.Seq, i+1)
		}
	}
}

// labelFrames 过滤标识帧（Label != nil）。
func labelFrames(frames []deliveredFrame) []deliveredFrame {
	var out []deliveredFrame
	for _, f := range frames {
		if f.Label != nil {
			out = append(out, f)
		}
	}
	return out
}

// TestContentLabelOffNoLabelFrames off（缺省）：无任何标识帧与 label meta（零行为变化）。
func TestContentLabelOffNoLabelFrames(t *testing.T) {
	srv, ts := newM9Server(t) // contentLabelCfg 零值 = Enabled:false
	frames := runLabelInfer(t, srv, ts, []string{"好的。", "结束。"})
	if n := len(labelFrames(frames)); n != 0 {
		t.Fatalf("off 态不得出现标识帧，实际 %d 帧", n)
	}
	for i, f := range frames {
		if f.Label != nil {
			t.Fatalf("off 态第 %d 帧不得带 label meta：%+v", i, f.Label)
		}
	}
}

// TestContentLabelHeadTail on：首帧 seq=1 且 head；尾标帧在 stop 前；stop 帧恒带 tail meta。
func TestContentLabelHeadTail(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.contentLabelCfg = contentLabelConfig{Enabled: true} // resolve 兜底缺省文案
	deltas := []string{"好的。", "结束。"}
	frames := runLabelInfer(t, srv, ts, deltas)

	lbls := labelFrames(frames)
	// 期望帧序列：head, c1, c2, tail, stop → 3 个标识帧（head/tail/stop-tail-meta）
	if len(lbls) != 3 {
		t.Fatalf("应恰 3 帧带 label meta（head/tail/stop 兜底），实际 %d：%+v", len(lbls), lbls)
	}
	if frames[0].Seq != 1 || frames[0].Label == nil || frames[0].Label.Position != labelPositionHead {
		t.Fatalf("首帧应 seq=1 且 position=head，实际 seq=%d label=%+v", frames[0].Seq, frames[0].Label)
	}
	if frames[0].Delta != defaultContentLabelText {
		t.Fatalf("首帧 delta 应为标识文案，实际 %q", frames[0].Delta)
	}
	last := frames[len(frames)-1]
	if last.Finish != "stop" || last.Label == nil || last.Label.Position != labelPositionTail {
		t.Fatalf("终止帧应 finish=stop 且恒带 tail meta，实际 finish=%q label=%+v", last.Finish, last.Label)
	}
	// 尾标帧必须在 stop 帧之前（seq 连续：尾标 seq = last.Seq-1）
	tail := lbls[len(lbls)-2] // 最后一个标识帧前的尾标帧
	if tail.Label.Position != labelPositionTail {
		t.Fatalf("倒数第二个标识帧应为 tail，实际 %+v", tail.Label)
	}
	if tail.Seq+1 != last.Seq {
		t.Fatalf("尾标帧须紧邻 stop 帧之前（seq+1），实际 tail=%d stop=%d", tail.Seq, last.Seq)
	}
	// meta.Std 缺省兜底
	for _, f := range lbls {
		if f.Label.Std != defaultContentLabelStd {
			t.Fatalf("label.Std 缺省应为 %q，实际 %q", defaultContentLabelStd, f.Label.Std)
		}
	}
	assertSeqStrict(t, frames)
	// 帧总数 = 内容 2 + 标识 3（head/tail/stop meta）
	if len(frames) != 2+3 {
		t.Fatalf("帧总数不符：got %d want %d（frames=%+v）", len(frames), 5, frames)
	}
	// 内容口径（不含任何标识帧）拼接应为引擎原文——标识文本不得混入
	var content strings.Builder
	for _, f := range frames {
		if f.Label == nil {
			content.WriteString(f.Delta)
		}
	}
	if got, want := content.String(), strings.Join(deltas, ""); got != want {
		t.Fatalf("内容口径应恰为引擎文本：got %q want %q", got, want)
	}
}

// TestContentLabelRepeat repeat=2、5 内容帧 → repeat 帧 2 个（第 2/4 帧后）+ 首尾。
func TestContentLabelRepeat(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.contentLabelCfg = contentLabelConfig{Enabled: true, Repeat: 2}
	deltas := []string{"一。", "二。", "三。", "四。", "五。"}
	frames := runLabelInfer(t, srv, ts, deltas)

	lbls := labelFrames(frames)
	// head 1 + repeat 2 + tail 1 + stop meta 1 = 5 帧带 meta
	if len(lbls) != 5 {
		t.Fatalf("带 meta 帧数不符：got %d want 5（%+.v）", len(lbls), lbls)
	}
	var positions []string
	for _, f := range lbls {
		positions = append(positions, f.Label.Position)
	}
	want := []string{labelPositionHead, labelPositionRepeat, labelPositionRepeat, labelPositionTail, labelPositionTail}
	if strings.Join(positions, ",") != strings.Join(want, ",") {
		t.Fatalf("标识帧序应为 %v，实际 %v（frames=%+v）", want, positions, frames)
	}
	assertSeqStrict(t, frames)
	// 帧总数 = 内容 5 + head 1 + repeat 2 + tail 1 + stop 1
	if len(frames) != 5+1+2+1+1 {
		t.Fatalf("帧总数不符：got %d want 10（frames=%+v）", len(frames), frames)
	}
	// repeat 帧必须跟在每第 2 个内容帧之后（帧序：head,一,rep,二,rep? 不对——计数口径为内容帧序）
	// 内容帧序 2 后插第 1 个 repeat，内容帧序 4 后插第 2 个 repeat：
	// 序列为 head,一,二,rep,三,四,rep,五,tail,stop
	seq := make([]string, 0, len(frames))
	for _, f := range frames {
		switch {
		case f.Finish == "stop":
			seq = append(seq, "stop")
		case f.Label != nil:
			seq = append(seq, "label:"+f.Label.Position)
		default:
			seq = append(seq, "content:"+f.Delta)
		}
	}
	wantSeq := "label:head,content:一。,content:二。,label:repeat,content:三。,content:四。,label:repeat,content:五。,label:tail,stop"
	if strings.Join(seq, ",") != wantSeq {
		t.Fatalf("帧序列不符：\n got %s\nwant %s", strings.Join(seq, ","), wantSeq)
	}
}

// TestContentLabelMeteringExcluded 计量排除：标识文本不进 tokens_out / filtered_tokens 口径。
// tokensOut == countTokens(引擎文本)——标识帧经 emitLabel（count=false）不累计 emittedBuilder/agg。
func TestContentLabelMeteringExcluded(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.contentLabelCfg = contentLabelConfig{Enabled: true, Repeat: 1} // 最密重复：每内容帧后都插
	deltas := []string{"好的。", "结束。"}
	frames := runLabelInfer(t, srv, ts, deltas)

	// 内容帧数与标识帧数核对（repeat=1 → 每内容帧后 1 个 repeat）
	lbls := labelFrames(frames)
	if len(lbls) != 1+2+1+1 { // head + repeat×2 + tail + stop meta
		t.Fatalf("标识帧数不符：got %d", len(lbls))
	}
	// 计量口径：usage 记录 tokensOut 应等于 countTokens(引擎 deltas 拼接)，不含任何标识文本
	rec := srv.usage[defaultTenant]
	if rec == nil {
		t.Fatal("缺用量记录")
	}
	engineText := strings.Join(deltas, "")
	want := srv.countTokens(engineText)
	if rec.TokensOut != want {
		t.Fatalf("tokensOut 计量排除失败：got %d want %d（引擎文本 %q；标识文本不得计入）",
			rec.TokensOut, want, engineText)
	}
	if strings.Contains(engineText, defaultContentLabelText) {
		t.Fatal("测试构造错误：引擎文本不应含标识文案")
	}
}

// postContentLabel 直接调 handler（newM9Server 未挂 /config 路由；handler 语义与路由无关）。
func postContentLabel(t *testing.T, srv *teeServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/config/content-label", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handleContentLabelConfig(rec, req)
	return rec
}

// TestContentLabelConfigAPI 热切换：校验 fail-closed（400）→ 合法生效 → 审计 + 持久化 → 重启恢复。
func TestContentLabelConfigAPI(t *testing.T) {
	srv, _ := newM9Server(t)
	dir := t.TempDir()
	srv.contentLabelCfgPath = filepath.Join(dir, "content-label.json")

	// ① 不合规文案 → 400（fail-closed，不得静默生效）
	rec := postContentLabel(t, srv, `{"enabled":true,"text":"内容由人工智能产出"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("不合规文案应 400，got %d", rec.Code)
	}
	if srv.currentContentLabelConfig().Enabled {
		t.Fatal("400 后不得生效")
	}
	// ② repeat 越界 → 400
	if rec := postContentLabel(t, srv, `{"enabled":true,"repeat":1001}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("repeat 越界应 400，got %d", rec.Code)
	}
	// ③ 合法开启 → 200 + 审计 + 持久化（0600 单行 JSON）
	rec = postContentLabel(t, srv, `{"enabled":true,"repeat":3}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法切换应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	if !srv.currentContentLabelConfig().Enabled || srv.currentContentLabelConfig().Repeat != 3 {
		t.Fatalf("切换未生效：%+v", srv.currentContentLabelConfig())
	}
	if n := srv.audit.countByAction("content_label_change"); n != 1 {
		t.Fatalf("应落 1 条 content_label_change 审计，实际 %d", n)
	}
	raw, err := os.ReadFile(srv.contentLabelCfgPath)
	if err != nil {
		t.Fatalf("持久化文件缺失：%v", err)
	}
	fi, err := os.Stat(srv.contentLabelCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Windows 不实现 POSIX 权限位（0600 落盘为 0666），权限断言仅限类 Unix。
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("持久化文件权限应为 0600，实际 %v", fi.Mode().Perm())
	}
	var persisted contentLabelConfigRecord
	if err := json.Unmarshal(bytes.TrimSpace(raw), &persisted); err != nil {
		t.Fatalf("持久化记录非单行 JSON：%v", err)
	}
	if !persisted.Enabled || persisted.Repeat != 3 || persisted.Text == "" || persisted.Std == "" {
		t.Fatalf("持久化记录不符：%+v", persisted)
	}
	// ④ 重启恢复：新 server（同一路径）load 后生效——on/off 双向可切，无单向闸门
	srv2, _ := newM9Server(t)
	srv2.contentLabelCfgPath = srv.contentLabelCfgPath
	srv2.loadContentLabelOverride()
	if !srv2.currentContentLabelConfig().Enabled || srv2.currentContentLabelConfig().Repeat != 3 {
		t.Fatalf("重启恢复失败：%+v", srv2.currentContentLabelConfig())
	}
	if src := srv2.contentLabelSource(); src != "runtime" {
		t.Fatalf("来源应为 runtime，实际 %q", src)
	}
	// ⑤ 运行时关 → 恢复 off（双向）
	if rec := postContentLabel(t, srv, `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("关闭应 200，got %d", rec.Code)
	}
	if srv.currentContentLabelConfig().Enabled {
		t.Fatal("关闭未生效")
	}
}

// TestContentLabelSnapshot /config 只读快照字段（enabled/source/text/repeat/std 与生效配置同源）。
func TestContentLabelSnapshot(t *testing.T) {
	srv, _ := newM9Server(t)
	srv.contentLabelCfg = contentLabelConfig{Enabled: true, Repeat: 5}
	rec := httptest.NewRecorder()
	srv.handleConfig(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/config 应 200，got %d", rec.Code)
	}
	var view struct {
		ContentLabel contentLabelSnapshot `json:"content_label"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.ContentLabel.Enabled || view.ContentLabel.Source != "startup" ||
		view.ContentLabel.Repeat != 5 || view.ContentLabel.Text != defaultContentLabelText ||
		view.ContentLabel.Std != defaultContentLabelStd {
		t.Fatalf("快照不符：%+v", view.ContentLabel)
	}
}

// TestContentLabelFramewiseWithShadowOG framewise e2e：label on + shadow og 共存——
// 首帧 head、尾标帧在 stop 前、stop 帧恒带 tail meta；shadow 命中照常检出；帧序断言零违规。
func TestContentLabelFramewiseWithShadowOG(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.outputGuardMode = outputGuardShadow
	srv.outputGuardParams = defaultOutputGuardParams()
	srv.contentLabelCfg = contentLabelConfig{Enabled: true}
	// 输出含 SQL 注入口径命中（shadow 只记不拦；stub 引擎绕过输入侧 403）
	frames := runLabelInfer(t, srv, ts, []string{"好的。", ";-- 注释。", "结束。"})

	if len(frames) == 0 {
		t.Fatal("未捕获帧")
	}
	// 首帧 head
	if frames[0].Label == nil || frames[0].Label.Position != labelPositionHead {
		t.Fatalf("首帧应 head 标识，实际 %+v", frames[0].Label)
	}
	// 终止帧：finish=stop + 恒带 tail meta + guard meta（shadow 命中）
	last := frames[len(frames)-1]
	if last.Finish != "stop" {
		t.Fatalf("终止码应为 stop，实际 %q", last.Finish)
	}
	if last.Label == nil || last.Label.Position != labelPositionTail {
		t.Fatalf("终止帧应恒带 tail meta，实际 %+v", last.Label)
	}
	if last.Guard == nil || !last.Guard.Detected {
		t.Fatalf("shadow 命中终止帧应带 guard meta：%+v", last.Guard)
	}
	assertSeqStrict(t, frames)

	// 内容完整性：shadow 原样放行（标识帧不计入内容比对）
	var content strings.Builder
	for _, f := range frames {
		if f.Label == nil {
			content.WriteString(f.Delta)
		}
	}
	if got, want := content.String(), "好的。;-- 注释。结束。"; got != want {
		t.Fatalf("shadow 内容应原样：got %q want %q", got, want)
	}
	// 逐帧断言器：shadow 命中已下发必须检出（工具非空转）；按 stop 语义零 finish 违规
	hit := newGuardrail().check(";-- 注释。")
	if hit == nil {
		t.Fatal("预期 sql_injection 命中")
	}
	vs := checkDeliveredFrames(frames, frameCheckOpts{Forbidden: []string{hit.Match}, WantFinish: "stop", WantMode: outputGuardShadow})
	if !hasViolation(vs, violationPerFrameHit) {
		t.Fatalf("shadow 命中已下发必须检出：%+v", vs)
	}
	if hasViolation(vs, violationFinishCode) || hasViolation(vs, violationGuardMeta) {
		t.Fatalf("终止码/guard meta 不应违规：%+v", vs)
	}
}
