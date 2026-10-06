package main

// B1 强标标识（GB 45438-2025）插件侧测试：
//   - label meta roundtrip（streamChunk 编解码 + sseLine 透传）；
//   - SSEStreamDecoder.SawLabel 去重依据；
//   - buildLabelSSELine 标准 OpenAI 帧形态；
//   - maybeInjectContentLabel 去重注入（上游已带不注入、每流至多一次、off 零行为）。

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestChunkLabelRoundtrip label meta 编解码 roundtrip（omitempty：nil 时不出现在 JSON）。
func TestChunkLabelRoundtrip(t *testing.T) {
	in := streamChunk{Seq: 1, Delta: "内容由人工智能生成", Label: &chunkLabel{Std: "GB45438-2025", Position: labelPositionHead}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out streamChunk
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Label == nil || out.Label.Std != "GB45438-2025" || out.Label.Position != labelPositionHead {
		t.Fatalf("label roundtrip 不符：%+v", out.Label)
	}
	// nil label → JSON 不含 "content_label" 键（旧插件前向兼容 / off 态零变化）
	rawNil, err := json.Marshal(streamChunk{Seq: 1, Delta: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawNil), `"content_label"`) {
		t.Fatalf("nil label 不得出现在 JSON：%s", rawNil)
	}
}

// TestSSELineLabelPassthrough sseLine 透传 label meta 到客户端 OpenAI 帧。
func TestSSELineLabelPassthrough(t *testing.T) {
	line, err := sseLine("req1", "mock", &streamChunk{
		Seq:   1,
		Delta: "内容由人工智能生成",
		Label: &chunkLabel{Std: "GB45438-2025", Position: labelPositionHead},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(line)
	for _, want := range []string{`"content":"内容由人工智能生成"`, `"content_label":{"std":"GB45438-2025","position":"head"}`} {
		if !strings.Contains(s, want) {
			t.Fatalf("sseLine 缺 %q：%q", want, s)
		}
	}
	if !strings.HasSuffix(s, "\n\n") {
		t.Fatal("SSE 帧须以空行收尾")
	}
}

// TestSSEDecoderSawLabel SawLabel 语义：任一上游帧带 label meta → true（去重注入依据）。
func TestSSEDecoderSawLabel(t *testing.T) {
	newSessionForTest(t)
	// ① 上游带 head 标识（tee-infer 注入点形态：head 帧 + 内容帧 + tail meta 终止帧）
	body := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "内容由人工智能生成", Label: &chunkLabel{Std: "GB45438-2025", Position: labelPositionHead}},
		{Seq: 2, Delta: "正文"},
		{Seq: 3, Finish: "stop", Label: &chunkLabel{Std: "GB45438-2025", Position: labelPositionTail}},
	}, []uint64{1, 2, 3})
	dec := NewSSEStreamDecoder("req1", "mock")
	var derr error
	dec.Feed(body, true, func(_ []byte, err error) { derr = err })
	if derr != nil {
		t.Fatal(derr)
	}
	if !dec.SawLabel() {
		t.Fatal("上游带 label meta 时 SawLabel 应为 true")
	}
	// ② 上游无标识（旧版 tee-infer / label off）——计数器须续用（全局反重放窗口）
	body2 := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "正文"},
		{Seq: 2, Finish: "stop"},
	}, []uint64{4, 5})
	dec2 := NewSSEStreamDecoder("req1", "mock")
	var derr2 error
	dec2.Feed(body2, true, func(_ []byte, err error) { derr2 = err })
	if derr2 != nil {
		t.Fatal(derr2)
	}
	if dec2.SawLabel() {
		t.Fatal("上游无 label meta 时 SawLabel 应为 false")
	}
}

// TestBuildLabelSSELine 兜底注入帧形态：标准 OpenAI chunk + 顶层 label 注解。
func TestBuildLabelSSELine(t *testing.T) {
	line := buildLabelSSELine("内容由人工智能生成", labelPositionHead, "req1", "mock")
	s := string(line)
	for _, want := range []string{
		`"object":"chat.completion.chunk"`,
		`"delta":{"content":"内容由人工智能生成"}`,
		`"content_label":{"std":"GB45438-2025","position":"head"}`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("buildLabelSSELine 缺 %q：%q", want, s)
		}
	}
	if !strings.HasPrefix(s, "data: ") || !strings.HasSuffix(s, "\n\n") {
		t.Fatalf("SSE 帧形态不符：%q", s)
	}
}

// TestMaybeInjectContentLabelDedup 去重注入：上游已带不注入；未带注入一次且仅一次；off 零行为。
func TestMaybeInjectContentLabelDedup(t *testing.T) {
	cfg := PluginConfig{ContentLabelEnabled: true, ContentLabelText: "内容由人工智能生成"}
	contentOut := []byte("data: {\"x\":1}\n\n")

	// ① 上游未带标识 → 注入 head，且置于内容帧之前
	st := &respStreamState{dec: &SSEStreamDecoder{}}
	got := maybeInjectContentLabel(st, cfg, contentOut)
	if !st.labelInjected {
		t.Fatal("应标记已注入")
	}
	if !strings.HasPrefix(string(got), "data: ") ||
		!strings.Contains(string(got[:bytesIndex(got, "\n\n")+2]), "内容由人工智能生成") {
		t.Fatalf("注入帧应前置：%q", got)
	}
	if !strings.HasSuffix(string(got), string(contentOut)) {
		t.Fatalf("内容帧应保留在注入帧之后：%q", got)
	}
	// ② 第二次调用 → 不再注入（每流至多一次）
	got2 := maybeInjectContentLabel(st, cfg, contentOut)
	if string(got2) != string(contentOut) {
		t.Fatalf("每流至多注入一次：%q", got2)
	}

	// ③ 上游已带标识（SawLabel=true）→ 不注入（单一注入点规则兜底）
	st2 := &respStreamState{dec: &SSEStreamDecoder{labelSeen: true}}
	if got := maybeInjectContentLabel(st2, cfg, contentOut); string(got) != string(contentOut) {
		t.Fatalf("上游已带标识时不得重复注入：%q", got)
	}

	// ④ off（默认）→ 零行为
	st3 := &respStreamState{dec: &SSEStreamDecoder{}}
	if got := maybeInjectContentLabel(st3, PluginConfig{}, contentOut); string(got) != string(contentOut) {
		t.Fatalf("off 态不得注入：%q", got)
	}

	// ⑤ 空输出帧不注入（无上内容可前置）
	st4 := &respStreamState{dec: &SSEStreamDecoder{}}
	if got := maybeInjectContentLabel(st4, cfg, nil); len(got) != 0 {
		t.Fatalf("空输出不得注入：%q", got)
	}
	if st4.labelInjected {
		t.Fatal("空输出不得标记已注入（等待首个内容帧）")
	}
}

// bytesIndex 小工具：bytes.Index 的简写（避免引 bytes 包仅为一次调用）。
func bytesIndex(b []byte, sub string) int {
	return strings.Index(string(b), sub)
}
