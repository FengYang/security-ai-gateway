package main

// B1 强标标识（GB 45438-2025）qwen3guard 插件侧测试（明文审核路径）：
//   - buildStreamLabelBody 帧形态（单 delta 帧 + label meta，无 [DONE]）；
//   - buildStreamDenyBodyWithLabel on_deny 变体（默认关：无 meta；开：拒答首帧带 meta）；
//   - maybeInjectStreamLabel 每流至多一次（off 零行为、置位语义）；
//   - parseConfig 文案校验 fail-closed（仅 enabled 时校验；snake/camel 双键）。

import (
	"os"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// TestBuildStreamLabelBody 标识帧形态：标准 OpenAI chunk + 顶层 label 注解，单帧无 [DONE]。
func TestBuildStreamLabelBody(t *testing.T) {
	body := string(buildStreamLabelBody(defaultContentLabelText))
	if !strings.HasPrefix(body, "data: ") || !strings.HasSuffix(body, "\n\n") {
		t.Fatalf("SSE 帧形态不符：%q", body)
	}
	payloads := extractSSEDataPayloads(body)
	if len(payloads) != 1 {
		t.Fatalf("应恰 1 帧（无 [DONE]），实际 %d：%q", len(payloads), body)
	}
	p := gjson.Parse(payloads[0])
	if got := p.Get("choices.0.delta.content").String(); got != defaultContentLabelText {
		t.Fatalf("delta.content 应为标识文案，实际 %q", got)
	}
	if got := p.Get("content_label.std").String(); got != defaultContentLabelStd {
		t.Fatalf("label.std 不符：%q", got)
	}
	if got := p.Get("content_label.position").String(); got != labelPositionHead {
		t.Fatalf("label.position 不符：%q", got)
	}
}

// TestBuildStreamDenyBodyWithLabel on_deny 变体：nil（默认）无 label meta；非 nil 拒答首帧带 meta。
func TestBuildStreamDenyBodyWithLabel(t *testing.T) {
	// 默认形态（buildStreamDenyBody 委托）：无 label 键
	plain := string(buildStreamDenyBody("blocked"))
	if strings.Contains(plain, `"content_label"`) {
		t.Fatalf("默认拒答帧不得带 label meta：%q", plain)
	}
	payloads := extractSSEDataPayloads(plain)
	if len(payloads) != 3 {
		t.Fatalf("默认拒答应 3 帧（delta/stop/[DONE]），实际 %d", len(payloads))
	}

	// on_deny 变体：首帧带 label meta，其余帧序不变
	labelled := string(buildStreamDenyBodyWithLabel("blocked", &labelMeta{Std: defaultContentLabelStd, Position: labelPositionHead}))
	payloads = extractSSEDataPayloads(labelled)
	if len(payloads) != 3 {
		t.Fatalf("on_deny 拒答应 3 帧，实际 %d", len(payloads))
	}
	if got := gjson.Get(payloads[0], "content_label.position").String(); got != labelPositionHead {
		t.Fatalf("on_deny 首帧应带 head meta，实际 %q（payload=%s）", got, payloads[0])
	}
	if gjson.Get(payloads[1], "content_label").Exists() {
		t.Fatalf("stop 帧不应带 label meta：%s", payloads[1])
	}
	if got := gjson.Get(payloads[1], "choices.0.finish_reason").String(); got != "stop" {
		t.Fatalf("终止帧 finish_reason 应为 stop，实际 %q", got)
	}
}

// TestMaybeInjectStreamLabel 每流至多一次：off 零行为；enabled 首次 true 后续 false（已置位）。
func TestMaybeInjectStreamLabel(t *testing.T) {
	// off（默认）：恒 false，不置位
	ctx := newTestHTTPContext()
	if maybeInjectStreamLabel(ctx, pluginConfig{}) {
		t.Fatal("off 态不得注入")
	}
	if ctx.GetBoolContext(ctxStreamLabelled, false) {
		t.Fatal("off 态不得置位")
	}

	// enabled：首次 true（置位），后续 false（每流至多一次）
	cfg := pluginConfig{contentLabelEnabled: true, contentLabelText: defaultContentLabelText}
	if !maybeInjectStreamLabel(ctx, cfg) {
		t.Fatal("enabled 首次应注入")
	}
	if !ctx.GetBoolContext(ctxStreamLabelled, false) {
		t.Fatal("首次注入后应置位")
	}
	if maybeInjectStreamLabel(ctx, cfg) {
		t.Fatal("每流至多注入一次")
	}
}

// TestParseConfigContentLabel B1 配置解析：双键、缺省文案、文案校验 fail-closed。
func TestParseConfigContentLabel(t *testing.T) {
	base := `{"serviceSource":"k8s","serviceName":"qwen3guard","servicePort":8000`

	// 默认：全关、文案兜底缺省
	var c pluginConfig
	if err := parseConfig(gjson.Parse(base+"}"), &c, nil); err != nil {
		t.Fatal(err)
	}
	if c.contentLabelEnabled || c.contentLabelOnDeny {
		t.Fatal("默认应全关（off/on_deny=false）")
	}
	if c.contentLabelText != defaultContentLabelText {
		t.Fatalf("文案应兜底缺省，实际 %q", c.contentLabelText)
	}

	// snake 键开启 + 自定义文案
	c = pluginConfig{}
	if err := parseConfig(gjson.Parse(base+`,"content_label_enabled":true,"content_label_text":"本回答由人工智能生成，仅供参考"}`), &c, nil); err != nil {
		t.Fatal(err)
	}
	if !c.contentLabelEnabled || c.contentLabelText != "本回答由人工智能生成，仅供参考" {
		t.Fatalf("snake 键解析不符：%+v", c)
	}

	// camel 键 on_deny
	c = pluginConfig{}
	if err := parseConfig(gjson.Parse(base+`,"contentLabelEnabled":true,"contentLabelOnDeny":true}`), &c, nil); err != nil {
		t.Fatal(err)
	}
	if !c.contentLabelEnabled || !c.contentLabelOnDeny {
		t.Fatalf("camel 键解析不符：%+v", c)
	}

	// 文案缺「生成」→ fail-closed（仅 enabled 时校验）
	for _, bad := range []string{`{"content_label_enabled":true,"content_label_text":"内容由人工智能产出"}`,
		`{"content_label_enabled":true,"content_label_text":"内容由 AI 生成"}`} {
		c = pluginConfig{}
		if err := parseConfig(gjson.Parse(base+","+bad[1:]), &c, nil); err == nil {
			t.Fatalf("不合规文案应拒绝：%s", bad)
		}
	}

	// off 态文案不校验（配置留口）
	c = pluginConfig{}
	if err := parseConfig(gjson.Parse(base+`,"content_label_text":"任意文案"}`), &c, nil); err != nil {
		t.Fatalf("off 态文案不应校验：%v", err)
	}
}

// TestLabelJSONTextAtPath 非流式整包标识注入（S4-1 补口）：head＋tail 双锚点改写、幂等、
// 路径缺失/空文本/空标签一律原样返回（调用方不得替换响应体）。
func TestLabelJSONTextAtPath(t *testing.T) {
	const path = "choices.0.message.content"
	label := defaultContentLabelText
	body := []byte(`{"choices":[{"message":{"role":"assistant","content":"正文内容"}}]}`)

	out, ok := labelJSONTextAtPath(body, path, label)
	if !ok {
		t.Fatalf("应发生改写")
	}
	want := label + "\n" + "正文内容" + "\n" + label
	if got := gjson.GetBytes(out, path).String(); got != want {
		t.Fatalf("双锚点改写不符：want %q got %q", want, got)
	}
	if role := gjson.GetBytes(out, "choices.0.message.role").String(); role != "assistant" {
		t.Fatalf("相邻字段被污染：role=%q", role)
	}

	// 幂等：已注入的 body 再注入 → 不改写、原样返回
	again, ok2 := labelJSONTextAtPath(out, path, label)
	if ok2 || string(again) != string(out) {
		t.Fatalf("应幂等（不重复注入）")
	}

	// 非改写场景 → 原样返回 false
	for _, tc := range []struct {
		name string
		b    []byte
		p    string
		l    string
	}{
		{"路径不存在", body, "choices.0.message.missing", label},
		{"空文本", []byte(`{"choices":[{"message":{"content":""}}]}`), path, label},
		{"空标签", body, path, ""},
	} {
		o, okk := labelJSONTextAtPath(tc.b, tc.p, tc.l)
		if okk || string(o) != string(tc.b) {
			t.Fatalf("%s：应原样返回且 ok=false", tc.name)
		}
	}
}

// TestSourceInvariant_NonStreamLabelInject S4-1 源码不变量锁：非流式放行路径必须同时存在
// "按路径注入"与"替换响应体"，且不得新增 ResumeHttpResponse 调用点
// （既有 failclosed 测试已锁 `ResumeHttpResponse()` 出现 2 次；注入复用原调用点）。
func TestSourceInvariant_NonStreamLabelInject(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读取 main.go 失败：%v", err)
	}
	s := string(src)
	for _, want := range []string{
		"labelJSONTextAtPath(body, c.responseContentJSONPath, c.contentLabelText)",
		"proxywasm.ReplaceHttpResponseBody(labelled)",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("main.go 缺少非流式标识注入关键行：%s", want)
		}
	}
	if n := strings.Count(s, "ResumeHttpResponse()"); n != 2 {
		t.Fatalf("ResumeHttpResponse() 调用点应为 2（不得新增），实际 %d", n)
	}
}
