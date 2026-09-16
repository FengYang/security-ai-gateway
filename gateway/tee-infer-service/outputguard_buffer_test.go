package main

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// OG-4（缓冲/滑窗算法）验收单测：§4.3.1 句子分割 8 类边界情形、首句强切阈值、
// B/C 滑窗窗长派生与 P-WINDOW-MARGIN=0 非法、跨 delta、断连释放、有界内存（无增长）。

// bgParams 构造指定单元上限的句模式参数（其余走默认派生）。
func bgParams(maxUnit, firstUnit int) outputGuardParams {
	return resolveOutputGuardParams(outputGuardParams{
		Unit:              unitSentence,
		MaxUnitRunes:      maxUnit,
		FirstUnitMaxRunes: firstUnit,
		MaxBufferBytes:    paramUnset,
		WindowMargin:      paramUnset,
	})
}

// newTestBuf 构造句模式缓冲（强切原因收集到 ret）。
func newTestBuf(p outputGuardParams, forced *[]string) *unitBuffer {
	return newUnitBuffer(p, func(reason string) { *forced = append(*forced, reason) })
}

// pushAll 逐 delta 下发并把所有单元拼接返回。
func pushAll(b *unitBuffer, deltas []string) []string {
	var units []string
	for _, d := range deltas {
		units = append(units, b.Push(d)...)
	}
	return append(units, b.Flush()...)
}

// TestBufferSentenceSplitBoundaryCases §4.3.1 8 类边界情形（golden set 核心）。
func TestBufferSentenceSplitBoundaryCases(t *testing.T) {
	cases := []struct {
		name  string
		in    []string
		units []string
	}{
		// ① 小数点/版本号不切
		{"decimal", []string{"说 3.14 很好。"}, []string{"说 3.14 很好。"}},
		{"version", []string{"v1.2.3 发布了。"}, []string{"v1.2.3 发布了。"}},
		// ② 英文缩写：白名单内不切；白名单外按点切
		{"abbrev-eg", []string{"e.g. 这样。"}, []string{"e.g. 这样。"}},
		{"abbrev-ie-mr", []string{"Mr. Smith likes it, i.e. 就这样。"}, []string{"Mr. Smith likes it, i.e. 就这样。"}},
		{"abbrev-outside", []string{"Hello. World."}, []string{"Hello.", " World."}},
		// ③ 引号/括号闭合归前句
		{"closing-quote", []string{"他说\"好。\"然后走了。"}, []string{"他说\"好。\"", "然后走了。"}},
		{"closing-bracket", []string{"（真的吗？）对。"}, []string{"（真的吗？）", "对。"}},
		// ④ URL/邮箱内部点号不切
		{"url", []string{"见 https://a.b.c/x。然后回家。"}, []string{"见 https://a.b.c/x。", "然后回家。"}},
		{"email", []string{"联系 a.b@c.com。谢谢。"}, []string{"联系 a.b@c.com。", "谢谢。"}},
		// ⑤ 代码块/JSON：成对花括号内点号不切
		{"json-brace", []string{`{"url":"a.b.c"} 好了。`}, []string{`{"url":"a.b.c"} 好了。`}},
		{"fenced-code", []string{"```\nfoo.bar\n```\n完。"}, []string{"```\n", "foo.bar\n", "```\n", "完。"}},
		// ⑥ 连续终止符合并为一边界，不产生空句
		{"multi-term", []string{"真的吗？！"}, []string{"真的吗？！"}},
		{"bang-run", []string{"走！！！好。"}, []string{"走！！！", "好。"}},
		{"ellipsis-run", []string{"等等……好。"}, []string{"等等……", "好。"}},
		// ⑧ 超长无标点 → 强切（阈值见下个用例）
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var forced []string
			got := pushAll(newTestBuf(bgParams(paramUnset, paramUnset), &forced), tc.in)
			if strings.Join(got, "|") != strings.Join(tc.units, "|") {
				t.Fatalf("单元不符：got %q want %q", got, tc.units)
			}
		})
	}
}

// TestBufferNoEmptyUnits 空句不下发、不判定、不占 seq（§4.3.1 情形⑦）。
func TestBufferNoEmptyUnits(t *testing.T) {
	var forced []string
	got := pushAll(newTestBuf(bgParams(paramUnset, paramUnset), &forced), []string{"。\n\n。\n"})
	for i, u := range got {
		if strings.TrimSpace(u) == "" {
			t.Fatalf("第 %d 个单元为空串（空句不得下发）: %q", i, u)
		}
	}
	if len(got) == 0 {
		t.Fatalf("应至少切出非空单元")
	}
}

// TestBufferCrossDelta 跨 delta 拼接后切句（同一句被拆成多个 delta 下发）。
func TestBufferCrossDelta(t *testing.T) {
	var forced []string
	b := newTestBuf(bgParams(paramUnset, paramUnset), &forced)
	units := pushAll(b, []string{"你好", "，世界", "。再见", "。"})
	if want := "你好，世界。|再见。"; strings.Join(units, "|") != want {
		t.Fatalf("跨 delta 切句不符：got %q want %q", units, want)
	}
}

// TestBufferRuneSafeEmojiZWJ emoji ZWJ 序列不被切断（rune 安全 + 强切安全边界）。
func TestBufferRuneSafeEmojiZWJ(t *testing.T) {
	// 限长 4 rune：家庭 emoji 为 5 rune（👨 ZWJ 👩 ZWJ 👧），强切点必须避开 ZWJ。
	// 以码位显式构造，避免源文件编码差异影响测试前置。
	family := string([]rune{0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467})
	if n := len([]rune(family)); n != 5 {
		t.Fatalf("测试前置假设失效：家庭 emoji rune 数 %d != 5", n)
	}
	var forced []string
	b := newTestBuf(bgParams(4, 4), &forced)
	units := pushAll(b, []string{family + family})
	joined := strings.Join(units, "")
	if joined != family+family {
		t.Fatalf("强切改变了文本内容：got %q", joined)
	}
	for i, u := range units {
		rs := []rune(u)
		if len(rs) > 0 && rs[len(rs)-1] == 0x200D {
			t.Fatalf("第 %d 个单元以 ZWJ 结尾（切断了 emoji 序列）: %q", i, u)
		}
		if len(rs) > 0 && isGraphemeExtend(rs[0]) {
			t.Fatalf("第 %d 个单元以延伸码位开头（切断了 emoji 序列）: %q", i, u)
		}
	}
	if len(forced) == 0 {
		t.Fatalf("超长应触发强切")
	}
}

// TestBufferForcedSplitMaxUnit 超长无标点 → 按 P-MAX-UNIT-RUNES 强切并计数（§4.3.1 情形⑧）。
func TestBufferForcedSplitMaxUnit(t *testing.T) {
	var forced []string
	b := newTestBuf(bgParams(10, paramUnset), &forced) // firstUnit 派生 = 4
	got := pushAll(b, []string{strings.Repeat("a", 25)})
	if len(got) == 0 {
		t.Fatalf("超长无标点必须强切出单元")
	}
	total := 0
	for _, u := range got {
		if n := len([]rune(u)); n > 10 {
			t.Fatalf("单元超过 P-MAX-UNIT-RUNES=10: %d", n)
		}
		total += len([]rune(u))
	}
	if total != 25 {
		t.Fatalf("强切后内容总量不符：got %d want 25", total)
	}
	if len(forced) == 0 {
		t.Fatalf("应记录强切原因")
	}
	for _, r := range forced {
		if r != forcedReasonMaxUnit && r != forcedReasonFirstUnit {
			t.Fatalf("强切原因非法：%q", r)
		}
	}
}

// TestBufferFirstUnitForcedSplit 首句强切阈值生效（P-FIRST-UNIT-MAX-RUNES 仅约束首个单元）。
func TestBufferFirstUnitForcedSplit(t *testing.T) {
	var forced []string
	b := newTestBuf(bgParams(100, 5), &forced)
	// 首句 12 rune 无终止符：应在 5 处强切（first_unit），随后按 max=100 继续累积。
	got := pushAll(b, []string{strings.Repeat("x", 12)})
	if len(got) != 2 {
		t.Fatalf("期望首句强切出 2 个单元（5 + 7），实际 %d: %q", len(got), got)
	}
	if n := len([]rune(got[0])); n != 5 {
		t.Fatalf("首单元应等于 P-FIRST-UNIT-MAX-RUNES=5，实际 %d", n)
	}
	if len(forced) != 1 || forced[0] != forcedReasonFirstUnit {
		t.Fatalf("首个强切原因应为 first_unit，实际 %q", forced)
	}
	// 后续累积不再受首句阈值（5）约束，而按 max=100 累积：首单元 5、余下 35 单元一个。
	var forced2 []string
	b2 := newTestBuf(bgParams(100, 5), &forced2)
	got2 := pushAll(b2, []string{strings.Repeat("y", 40)})
	if len(got2) != 2 || len([]rune(got2[1])) != 35 {
		t.Fatalf("非首单元应按 max=100 累积（首 5 + 余 35），实际 %q", got2)
	}
}

// TestBufferFlushJudgesTail 尾部无终止符：Finish(Flush) 时作为最后一个单元送判（不逃逸审查）。
func TestBufferFlushJudgesTail(t *testing.T) {
	var forced []string
	b := newTestBuf(bgParams(paramUnset, paramUnset), &forced)
	if units := b.Push("没终止符的尾巴"); len(units) != 0 {
		t.Fatalf("未终止尾部不应构成判定单元，实际 %d", len(units))
	}
	units := b.Flush()
	if len(units) != 1 || units[0] != "没终止符的尾巴" {
		t.Fatalf("Flush 应把尾部作为最后一个单元，实际 %q", units)
	}
}

// TestBufferWindowRunesDerivation B/C 滑窗窗长 = 词库最长命中长度 + P-WINDOW-MARGIN（§5.4）。
func TestBufferWindowRunesDerivation(t *testing.T) {
	if got, err := windowRunesFromLexicon(10, 5); err != nil || got != 15 {
		t.Fatalf("窗长派生不符：got %d err %v (want 15)", got, err)
	}
	// P-WINDOW-MARGIN=0 非法
	if _, err := windowRunesFromLexicon(10, 0); err == nil {
		t.Fatalf("P-WINDOW-MARGIN=0 应视为非法")
	}
	// 未配置 → 派生默认（词库最长词 × 1.5，下限 1）
	p := resolveOutputGuardParams(outputGuardParams{MaxKeywordRunes: 10})
	if p.WindowMargin < 15 {
		t.Fatalf("未配置余量应按 ≥ 词库最长词 × 1.5 派生，实际 %d", p.WindowMargin)
	}
	if p.WindowRunes != 10+p.WindowMargin {
		t.Fatalf("P-WINDOW-CHARS 应为最长词 + 余量：%d", p.WindowRunes)
	}
}

// TestBufferFixedWindow 固定窗模式：按 P-WINDOW-CHARS（= 最长词 2 + 余量 4 = 6）等长切窗，不做句子分割。
func TestBufferFixedWindow(t *testing.T) {
	p := resolveOutputGuardParams(outputGuardParams{Unit: unitFixedWindow, MaxKeywordRunes: 2, WindowMargin: 4})
	if p.WindowRunes != 6 {
		t.Fatalf("前置假设：窗长应为 6，实际 %d", p.WindowRunes)
	}
	var forced []string
	b := newTestBuf(p, &forced)
	units := pushAll(b, []string{"abcdef", "ghij"})
	if len(units) != 2 || units[0] != "abcdef" || units[1] != "ghij" {
		t.Fatalf("固定窗切分不符：%q", units)
	}
}

// TestValidateOutputGuardParams P-WINDOW-MARGIN=0 等非法值拒绝启动（§5.4）。
func TestValidateOutputGuardParams(t *testing.T) {
	// 未配置（哨兵）→ 合法
	if err := validateOutputGuardParams(defaultOutputGuardParams()); err != nil {
		t.Fatalf("默认未配置态应合法，实际 %v", err)
	}
	// 显式 0 → 非法
	bad := []outputGuardParams{
		{WindowMargin: 0},
		{MaxUnitRunes: 0},
		{MaxBufferBytes: 0},
		{MaxUnitRunes: -5},
		{Unit: "bogus"},
		{MaxKeywordRunes: -1},
	}
	for i, p := range bad {
		if err := validateOutputGuardParams(p); err == nil {
			t.Fatalf("第 %d 组非法参数未被拒绝：%+v", i, p)
		}
	}
	// 合法显式值
	ok := outputGuardParams{Unit: unitSentence, MaxUnitRunes: 500, MaxBufferBytes: 4096, WindowMargin: 12}
	if err := validateOutputGuardParams(ok); err != nil {
		t.Fatalf("合法参数被拒：%v", err)
	}
}

// TestOutputGuardProcessDisconnectReleases 慢客户端：emit 失败 → 立即 Close 并上抛（§4.3 断连行）。
func TestOutputGuardProcessDisconnectReleases(t *testing.T) {
	og, _, _ := newTestOutputGuard(t, outputGuardShadow, "acme", "req-dc-1")
	og.buf.Push("一些内容") // 制造未判定的在飞缓冲
	if og.buf.pendingRunes() == 0 {
		t.Fatalf("前置条件：应有在飞缓冲")
	}
	emit := func(delta, finish string) error { return errors.New("client gone") }
	if err := og.Process("更多内容", emit); err == nil {
		t.Fatalf("emit 失败应上抛错误（终止引擎）")
	}
	if !og.closed {
		t.Fatalf("emit 失败应置 closed")
	}
	if og.buf.pendingRunes() != 0 {
		t.Fatalf("断连后缓冲应已释放，实际 %d rune", og.buf.pendingRunes())
	}
	// Close 幂等；关闭后不再缓冲/下发。
	og.Close()
	og.Close()
	if err := og.Process("再来", func(string, string) error { return nil }); err != nil {
		t.Fatalf("已关闭后 Process 应空操作，实际 %v", err)
	}
}

// TestBufferBoundedMemory 有界内存（无增长）：长流不乱涨，总量守恒。
func TestBufferBoundedMemory(t *testing.T) {
	const limit = 32
	var forced []string
	b := newTestBuf(bgParams(limit, limit), &forced)
	total := 0
	chunk := strings.Repeat("z", 7) // 无终止符，逼迫持续强切
	for i := 0; i < 5000; i++ {
		for _, u := range b.Push(chunk) {
			total += len([]rune(u))
		}
		if n := b.pendingRunes(); n > limit {
			t.Fatalf("第 %d 轮 pending=%d 超过上限 %d（内存无界增长）", i, n, limit)
		}
	}
	for _, u := range b.Flush() {
		total += len([]rune(u))
	}
	if want := 5000 * len([]rune(chunk)); total != want {
		t.Fatalf("强切后内容总量不守恒：got %d want %d", total, want)
	}
}

// TestOutputGuardForcedSplitMetric 强切计数进 /metrics（§4.3.1 forced_split_total{reason}）。
func TestOutputGuardForcedSplitMetric(t *testing.T) {
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	p := resolveOutputGuardParams(outputGuardParams{MaxUnitRunes: 5, FirstUnitMaxRunes: 3})
	og, err := newOutputGuard(outputGuardConfig{Mode: outputGuardShadow, Params: p},
		l1Classifier{g: newGuardrail()}, nil, m, a, "acme", "req-force-1")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	_ = collectThrough(t, og, []string{strings.Repeat("w", 17)})
	var buf bytes.Buffer
	m.render(&buf, a.len())
	if !strings.Contains(buf.String(), `otpmask_output_guard_forced_split_total{reason="first_unit"} 1`) {
		t.Fatalf("首个强切应记 first_unit\n---\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `otpmask_output_guard_forced_split_total{reason="max_unit"} 2`) {
		t.Fatalf("后续强切应记 max_unit×2\n---\n%s", buf.String())
	}
}

// TestBufferProtectedSpansIncremental R7② 差分等价性：增量维护的 b.protSpans
// 必须与 protectedRuneRanges(b.pending) 全量重算逐区间相等——每个 delta 之后、
// 成句消费导致坐标左移之后、Flush 释放之后均断言。覆盖：URL/邮箱跨 delta 拼接、
// 同一 URL 跨边界延长、':'/'@' 存在但非匹配、双 URL、无标记纯中文、逐 rune 下发。
func TestBufferProtectedSpansIncremental(t *testing.T) {
	splitRunes := func(s string) []string {
		rs := []rune(s)
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = string(r)
		}
		return out
	}
	cases := []struct {
		name   string
		deltas []string
	}{
		{"url-cross-delta", []string{"见 ht", "tp://a.b.c/x", "。回家。"}},
		{"url-extends-across-boundary", []string{"https://a.com/", "x 后续。"}},
		{"email-cross-delta", []string{"联系 a", ".b@c", ".com。谢谢。"}},
		{"colon-no-match", []string{"比例 3:4 与 5:6。"}},
		{"at-no-match", []string{"用户@ 提到了。"}},
		{"two-urls", []string{"https://a.com 与 https://b.com。完。"}},
		{"url-tail-no-terminator", []string{"链接 http://x.y/z", " 尾部暂不成句"}},
		{"no-mark-cjk", []string{"甲乙丙丁戊己庚辛壬癸。"}},
		{"rune-by-rune", splitRunes("访问 https://t.co/abc 收件 a@b.com 好。")},
		{"rune-by-rune-nomark", splitRunes("甲乙。")},
	}
	sameSpans := func(a, b [][2]int) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var forced []string
			b := newTestBuf(bgParams(500, 200), &forced)
			assertOracle := func(stage string) {
				t.Helper()
				want := protectedRuneRanges(b.pending)
				if !sameSpans(b.protSpans, want) {
					t.Fatalf("%s：增量区间 %v != 全量重算 %v（pending=%q）",
						stage, b.protSpans, want, string(b.pending))
				}
			}
			for i, d := range tc.deltas {
				b.Push(d)
				assertOracle("第 " + strconv.Itoa(i+1) + " 个 delta 后")
			}
			b.Flush()
			assertOracle("Flush 后")
			if len(b.protSpans) != 0 || b.lastSep != -1 || len(b.marks) != 0 {
				t.Fatalf("Flush 后增量状态未释放：spans=%v lastSep=%d marks=%v",
					b.protSpans, b.lastSep, b.marks)
			}
		})
	}
}
