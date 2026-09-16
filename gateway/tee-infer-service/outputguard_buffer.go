// 缓冲/滑窗算法（GA-输出侧内容审查-技术实现方案 §4.3、§4.3.1；§3.2 文件清单 outputguard_buffer.go）。
//
// 职责：把引擎逐 delta 下发的文本**按判定单元**聚合，交给分类器判定。
//   - sentence（A 模式）：按句切分（§4.3.1 全规则），尾部未终止不构成判定单元，继续累积；
//     累积超过 P-MAX-UNIT-RUNES（首句为 P-FIRST-UNIT-MAX-RUNES）→ 在最近安全边界强切并立即判定；
//   - fixed-window（B/C 模式）：不做句子分割，窗长 = P-WINDOW-CHARS（词库最长命中长度 + 余量）。
//
// 硬边界：
//   - rune 安全：一律按 []rune 索引，禁止按字节切（emoji ZWJ/组合字符/代理对不得切断）；
//   - 有界：pending 长度受 P-MAX-UNIT-RUNES 与 P-MAX-BUFFER-BYTES 双重约束，不随输出无限增长；
//   - 幂等：Reset 可重复调用（Close 语义，见 outputguard.go）。
//
// 简化声明（与 §4.3.1 一致，诚实标注）：不做句法分析、不处理嵌套引号、不做语言检测；
// 中英标点混合按同一规则集；fenced/brace 保护只针对**点号**（`\n` 仍是终止符，与 §4.3.1 字面一致）。
package main

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 判定单元模式（P-UNIT）。
const (
	unitSentence    = "sentence"
	unitFixedWindow = "fixed-window"
)

// 强切原因（`forced_split_total{reason}`，§4.3.1）。
const (
	forcedReasonMaxUnit   = "max_unit"   // 累积超过 P-MAX-UNIT-RUNES
	forcedReasonFirstUnit = "first_unit" // 首句累积超过 P-FIRST-UNIT-MAX-RUNES
)

// unitBuffer 判定单元缓冲（请求级）。
type unitBuffer struct {
	unit          string // sentence｜fixed-window
	maxRunes      int    // 单元上限（sentence：P-MAX-UNIT-RUNES；fixed-window：P-WINDOW-CHARS）
	firstMax      int    // 首句强切阈值（P-FIRST-UNIT-MAX-RUNES；仅 sentence 生效）
	maxBufRunes   int    // P-MAX-BUFFER-BYTES 折算的 rune 硬顶（保守：字节数 / UTFMax）
	pending       []rune // 未判定累积（始终由本文件内的方法维护）
	sawUnit       bool   // 是否已产出过判定单元（首句阈值只对首个单元生效）
	state         scanState
	onForcedSplit func(reason string) // 强切计数回调（可为 nil）

	// URL/邮箱保护区间的增量维护（M1 性能优化 R7②），坐标始终相对当前 pending。
	// 不变式：protSpans 与 protectedRuneRanges(pending) 全量重算结果逐区间相等。
	protSpans [][2]int // 当前保护区间（左闭右开 rune 下标）
	lastSep   int      // pending 中最后一个硬分隔符下标（无则 -1）
	marks     []int    // pending 中 ':' 与 '@' 的全部下标（有序；URL/邮箱的必要字符）
}

// newUnitBuffer 构造判定单元缓冲。params 须为 resolve 后的取值。
func newUnitBuffer(params outputGuardParams, onForcedSplit func(reason string)) *unitBuffer {
	b := &unitBuffer{
		unit:          params.Unit,
		firstMax:      params.FirstUnitMaxRunes,
		onForcedSplit: onForcedSplit,
		lastSep:       -1,
	}
	if params.Unit == unitFixedWindow {
		b.maxRunes = params.WindowRunes // 滑窗窗长＝P-WINDOW-CHARS（词库最长词 + 余量）
	} else {
		b.maxRunes = params.MaxUnitRunes
	}
	if params.MaxBufferBytes > 0 {
		// 保守折算：UTF-8 单 rune 最多 4 字节 → 以此保证实际字节数不超过上限。
		b.maxBufRunes = params.MaxBufferBytes / utf8.UTFMax
	}
	if b.maxRunes < 1 {
		b.maxRunes = 1
	}
	return b
}

// Push 追加一个 delta，返回本次可判定的完整单元（0 个或多个）。
func (b *unitBuffer) Push(delta string) []string {
	if delta == "" {
		return nil
	}
	dr := []rune(delta)
	oldN := len(b.pending)
	b.pending = append(b.pending, dr...)
	if b.unit == unitFixedWindow {
		return b.drainWindow()
	}
	b.extendProtected(oldN, dr)
	return b.drain(false)
}

// Flush 收尾（流结束）：把剩余尾部作为最后一个判定单元交给分类器——
// 否则"最后一句无终止符"的输出将逃逸审查（fail-open，不可接受）。
func (b *unitBuffer) Flush() []string {
	if b.unit == unitFixedWindow {
		if len(b.pending) == 0 {
			return nil
		}
		unit := string(b.pending)
		b.pending = b.pending[:0]
		return []string{unit}
	}
	return b.drain(true)
}

// Reset 丢弃缓冲与状态（Close 语义；幂等，可重复调用）。
func (b *unitBuffer) Reset() {
	b.pending = b.pending[:0]
	b.sawUnit = false
	b.state = scanState{}
	b.resetProtected()
}

// pendingRunes 当前未判定累积长度（可观测/测试用）。
func (b *unitBuffer) pendingRunes() int { return len(b.pending) }

// drain 抽取已就绪的判定单元；flush=true 时把尾部一并作为最后一个单元。
func (b *unitBuffer) drain(flush bool) []string {
	var units []string
	for len(b.pending) > 0 {
		limit, reason := b.limitAndReason()
		end := b.findBoundary(limit)
		forced := false
		if end == 0 && len(b.pending) > limit {
			end = b.safeCut(limit)
			forced = true
		}
		if end == 0 {
			break // 尾部未终止：不构成判定单元，继续累积（§4.3.1）
		}
		unit := string(b.pending[:end])
		b.consume(end)
		b.sawUnit = true
		if forced && b.onForcedSplit != nil {
			b.onForcedSplit(reason)
		}
		// 空句（切出的 rune 数 0 单元）不下发、不判定（§4.3.1）。
		if strings.TrimSpace(unit) != "" {
			units = append(units, unit)
		}
	}
	if flush && len(b.pending) > 0 {
		unit := string(b.pending)
		b.pending = b.pending[:0]
		b.resetProtected()
		if strings.TrimSpace(unit) != "" {
			units = append(units, unit)
		}
	}
	return units
}

// drainWindow（fixed-window 模式）按窗长切出非重叠固定窗。
func (b *unitBuffer) drainWindow() []string {
	var units []string
	for len(b.pending) >= b.maxRunes {
		units = append(units, string(b.pending[:b.maxRunes]))
		b.pending = append(b.pending[:0], b.pending[b.maxRunes:]...)
		b.sawUnit = true
	}
	return units
}

// limitAndReason 返回本次强制切分的阈值与原因（取单元上限、首句阈值、字节硬顶三者最小值）。
func (b *unitBuffer) limitAndReason() (int, string) {
	limit, reason := b.maxRunes, forcedReasonMaxUnit
	if !b.sawUnit && b.firstMax > 0 && b.firstMax < limit {
		limit, reason = b.firstMax, forcedReasonFirstUnit
	}
	if b.maxBufRunes > 0 && b.maxBufRunes < limit {
		limit, reason = b.maxBufRunes, forcedReasonMaxUnit
	}
	if limit < 1 {
		limit = 1
	}
	return limit, reason
}

// findBoundary 在 pending[0:limit) 内查找第一个句子边界，返回切点（含终止符与后续闭合标点）；
// 无边界返回 0。window 模式下由 drainWindow 处理，不走本函数。
func (b *unitBuffer) findBoundary(limit int) int {
	st := b.state
	spans := b.protSpans
	for i := 0; i < len(b.pending) && i < limit; i++ {
		r := b.pending[i]
		if !inRuneSpans(spans, i) && b.isTerminatorAt(i, st) {
			j := i + 1
			for j < len(b.pending) && isAbsorbableRune(b.pending[j]) {
				j++ // 连续终止符与闭合标点归前句（§4.3.1）
			}
			return j
		}
		st = advanceState(st, r)
	}
	return 0
}

// safeCut 取最近的安全切点：先自 limit 向前回退，找不到再向后推进
// （回转是为了不切断 emoji ZWJ/组合字符/变体选择符，且不落在 URL/邮箱内部）；
// 都找不到时退回 len(pending)——宁可单元略超限，也不切断字符序列。
func (b *unitBuffer) safeCut(limit int) int {
	n := len(b.pending)
	if limit > n {
		limit = n
	}
	spans := b.protSpans
	for cut := limit; cut >= 1; cut-- {
		if isGraphemeSafeBoundary(b.pending, cut) && !inRuneSpans(spans, cut-1) {
			return cut
		}
	}
	for cut := limit + 1; cut <= n; cut++ {
		if isGraphemeSafeBoundary(b.pending, cut) && !inRuneSpans(spans, cut-1) {
			return cut
		}
	}
	return n
}

// consume 消费前 n 个 rune 并提交扫描状态（fence/brace/反引号计数）。
func (b *unitBuffer) consume(n int) {
	b.state = b.stateAfter(n)
	b.pending = append(b.pending[:0], b.pending[n:]...)
	b.shiftProtected(n)
}

// resetProtected 清空 URL/邮箱保护的增量状态（pending 被整体释放时调用）。
func (b *unitBuffer) resetProtected() {
	b.protSpans = nil
	b.lastSep = -1
	b.marks = nil
}

// extendProtected 在追加 dr（旧 pending 长 oldN）后增量更新保护区间（R7②）。
// 任何 URL/邮箱匹配都不可能跨过 isHardSplitRune 字符，故只需对「旧 pending
// 最后一个硬分隔符之后」的后缀窗口重跑正则；窗口内无 ':'/'@' 时正则零调用。
func (b *unitBuffer) extendProtected(oldN int, dr []rune) {
	w := b.lastSep + 1 // lastSep=-1 → 0；分隔符只在旧 pending 中取，保证 w ≤ oldN
	for i, r := range dr {
		pos := oldN + i
		if isHardSplitRune(r) {
			b.lastSep = pos
		}
		if r == ':' || r == '@' {
			b.marks = append(b.marks, pos)
		}
	}
	// 保留完全落在窗口之前的旧区间；其余由窗口重算结果取代。
	kept := b.protSpans[:0]
	for _, sp := range b.protSpans {
		if sp[1] <= w {
			kept = append(kept, sp)
		}
	}
	hasMark := false
	for _, p := range b.marks {
		if p >= w {
			hasMark = true
			break
		}
	}
	if !hasMark {
		b.protSpans = kept
		return
	}
	// 仅对窗口后缀跑两条正则（正则顺序与 FindAll 口径与 protectedRuneRanges 完全一致）。
	ws := string(b.pending[w:])
	for _, re := range []*regexp.Regexp{splitURLRe, splitEmailRe} {
		for _, loc := range re.FindAllStringIndex(ws, -1) {
			start := w + utf8.RuneCountInString(ws[:loc[0]])
			kept = append(kept, [2]int{start, start + utf8.RuneCountInString(ws[loc[0]:loc[1]])})
		}
	}
	b.protSpans = kept
}

// shiftProtected 在 consume 消费前 n 个 rune 后把保护坐标整体左移 n。
// findBoundary/safeCut 保证切点不落在保护区间内，故跨切点区间理论上不出现；
// 万一观察到则回退全量重算（正确性优先于性能）。
func (b *unitBuffer) shiftProtected(n int) {
	if b.lastSep >= n {
		b.lastSep -= n
	} else {
		b.lastSep = -1
	}
	mm := b.marks[:0]
	for _, p := range b.marks {
		if p >= n {
			mm = append(mm, p-n)
		}
	}
	b.marks = mm
	sp := b.protSpans[:0]
	fallback := false
	for _, s := range b.protSpans {
		switch {
		case s[1] <= n: // 整个区间随本单元消费
		case s[0] < n: // 跨切点：不应发生 → 全量重算
			fallback = true
		default:
			sp = append(sp, [2]int{s[0] - n, s[1] - n})
		}
	}
	if fallback {
		b.protSpans = protectedRuneRanges(b.pending)
	} else {
		b.protSpans = sp
	}
}

// stateAfter 从当前已提交状态出发，重放 pending[:n] 得到下标 n 处的扫描状态。
func (b *unitBuffer) stateAfter(n int) scanState {
	st := b.state
	for i := 0; i < n && i < len(b.pending); i++ {
		st = advanceState(st, b.pending[i])
	}
	return st
}

// isTerminatorAt 判断下标 i 是否为合法句子边界（§4.3.1 主/次级终止符 + 点号例外）。
func (b *unitBuffer) isTerminatorAt(i int, st scanState) bool {
	r := b.pending[i]
	switch {
	case isMainTerminator(r):
		return true
	case isSecondaryTerminator(r):
		return b.unit == unitSentence // 次级终止符仅按句缓冲模式启用
	case r == '.':
		if st.inFence || st.braces > 0 {
			return false // 围栏/成对花括号内的点号不切
		}
		return b.dotIsBoundary(i)
	}
	return false
}

// dotIsBoundary ASCII 点号是否构成句子边界（小数点/版本号、英文缩写白名单除外）。
func (b *unitBuffer) dotIsBoundary(i int) bool {
	rs := b.pending
	if i > 0 && i+1 < len(rs) && unicode.IsDigit(rs[i-1]) && unicode.IsDigit(rs[i+1]) {
		return false // 小数点/版本号：3.14 / v1.2.3
	}
	// 英文缩写白名单：取包含本点号的字母/点 token（限长 12），
	// e.g. / i.e. 含内部点 → 整个 token 保护；其余按"以本点号结尾"匹配。
	start, end := i, i+1
	for start > 0 && i-start < 12 && (isLatinLetter(rs[start-1]) || rs[start-1] == '.') {
		start--
	}
	for end < len(rs) && end-i < 12 && (isLatinLetter(rs[end]) || rs[end] == '.') {
		end++
	}
	tok := strings.ToLower(string(rs[start:end]))
	if strings.Contains(tok, "e.g.") || strings.Contains(tok, "i.e.") {
		return false
	}
	prefix := strings.ToLower(string(rs[start : i+1]))
	for _, w := range []string{"etc.", "mr.", "ms.", "dr."} {
		if strings.HasSuffix(prefix, w) {
			return false
		}
	}
	return true
}

// isMainTerminator 主终止符（§4.3.1）：。！？!?…（连续省略号视作一个）＋ \n。
func isMainTerminator(r rune) bool {
	switch r {
	case '。', '！', '？', '!', '?', '…', '\n':
		return true
	}
	return false
}

// isSecondaryTerminator 次级终止符：；。
func isSecondaryTerminator(r rune) bool { return r == '；' }

// isClosingPunct 终止符后归前句的闭合标点（§4.3.1 字面清单）。
func isClosingPunct(r rune) bool {
	switch r {
	case '"', '\'', '）', '】', '」':
		return true
	}
	return false
}

// isAbsorbableRune 可被前一终止符吸收的 rune（连续终止符 / 闭合标点）。
func isAbsorbableRune(r rune) bool {
	return isMainTerminator(r) || isSecondaryTerminator(r) || isClosingPunct(r)
}

// isLatinLetter ASCII 字母（缩写 token 识别用）。
func isLatinLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

// isGraphemeSafeBoundary 判断在下标 i 处断开是否安全（不切断 emoji ZWJ 序列 /
// 组合字符 / 变体选择符 / 肤色修饰符；Go 的 []rune 已保证代理对不被拆开）。
func isGraphemeSafeBoundary(rs []rune, i int) bool {
	if i <= 0 {
		return false
	}
	if i >= len(rs) {
		return true
	}
	if rs[i-1] == 0x200D { // 前一个是 ZWJ：断开会把 ZWJ 悬在句尾
		return false
	}
	return !isGraphemeExtend(rs[i])
}

// isGraphemeExtend 是否为"附加在前一字符上"的延伸码位。
func isGraphemeExtend(r rune) bool {
	switch {
	case r == 0x200D: // ZWJ
		return true
	case r >= 0xFE00 && r <= 0xFE0F: // 变体选择符
		return true
	case r >= 0x1F3FB && r <= 0x1F3FF: // 肤色修饰符
		return true
	case r == 0x20E3: // 组合围合键帽
		return true
	case unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r): // 组合标记
		return true
	}
	return false
}

// scanState 扫描态（跨 delta 保持）：代码围栏与成对花括号内的点号不切（§4.3.1）。
type scanState struct {
	inFence bool
	braces  int
	ticks   int // 连续反引号计数（三个＝围栏分隔符）
}

// advanceState 按一个 rune 推进扫描态。
func advanceState(st scanState, r rune) scanState {
	if r == '`' {
		st.ticks++
		if st.ticks == 3 {
			st.inFence = !st.inFence
			st.ticks = 0
		}
		return st
	}
	st.ticks = 0
	if st.inFence {
		return st
	}
	switch r {
	case '{':
		st.braces++
	case '}':
		if st.braces > 0 {
			st.braces--
		}
	}
	return st
}

// URL/邮箱识别（复用 PII 正则口径：邮箱与 guardrail.piiPatterns 中的邮箱模式一致；
// guardrail.go 目前未编译 URL 模式，故此处显式声明 URL 模式，供"内部点号不切"使用）。
var (
	splitURLRe   = regexp.MustCompile(`(?i)(?:https?|ftp)://[^\s。！？；，、）】」"'!?…]+`)
	splitEmailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

// protectedRuneRanges 返回 pending 中 URL/邮箱覆盖的 rune 区间（左闭右开）。
// 注意：本函数为全量重算的「正确性基准」（oracle），生产路径由 protSpans 增量
// 维护（R7②），差分等价性测试 TestBufferProtectedSpansIncremental 锁定两者一致。
func protectedRuneRanges(rs []rune) [][2]int {
	if len(rs) == 0 {
		return nil
	}
	s := string(rs)
	var out [][2]int
	for _, re := range []*regexp.Regexp{splitURLRe, splitEmailRe} {
		for _, loc := range re.FindAllStringIndex(s, -1) {
			start := utf8.RuneCountInString(s[:loc[0]])
			out = append(out, [2]int{start, start + utf8.RuneCountInString(s[loc[0]:loc[1]])})
		}
	}
	return out
}

// inRuneSpans 下标 i 是否落在任一区间内。
func inRuneSpans(spans [][2]int, i int) bool {
	for _, sp := range spans {
		if i >= sp[0] && i < sp[1] {
			return true
		}
	}
	return false
}

// isHardSplitRune 判定该 rune 是否不可能出现在 URL/邮箱匹配内部。
// 集合严格对齐 splitURLRe 的排除字符集 [\s。！？；，、）】」"'!?…]；
// 邮箱可出现字符（字母数字._%+-@）是其真子集，故同一分隔符对两条正则都成立（R7② 依据）。
func isHardSplitRune(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '。', '！', '？', '；', '，', '、', '）', '】', '」', '"', '\'', '!', '?', '…':
		return true
	}
	return false
}

// windowRunesFromLexicon 派生 P-WINDOW-CHARS（§5.4）：词库最长命中长度 + P-WINDOW-MARGIN。
// margin ≤ 0 视为非法（P-WINDOW-MARGIN=0 启动失败）。
func windowRunesFromLexicon(maxKeywordRunes, margin int) (int, error) {
	if margin <= 0 {
		return 0, validatePositiveRunes("P-WINDOW-MARGIN", margin)
	}
	if maxKeywordRunes < 0 {
		return 0, validatePositiveRunes("词库最长命中长度", maxKeywordRunes)
	}
	return maxKeywordRunes + margin, nil
}
