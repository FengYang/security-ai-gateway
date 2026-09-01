// tokenizer.go — 计量口径可插拔（GF.2.4，决策点 D-3=B）。
//
// 现状：配额/计量用估算口径（estimateTokensCJK，CJK 感知上界估算）。
// D-3 结论 = 真机 tokenizer 就绪后校准（偏差 <5%）。本文件把计量口径抽为接口，
// 作为真机 tokenizer 的正式接入点——替换实现即完成校准，不改动调用方。
//
// 过渡口径（真机到位前，GF.2.4 评审 P1-4）：
// 原提案"字符/4 × 1.5 中文加权"经核算不成立——字符/4 对中文估算 0.25 token/字，
// 实际 cl100k_base 中文 ≈ 0.6-1 token/字；×1.5 后仅 0.375 token/字，仍系统性
// 低估 1.6-2.7 倍，无法达成"避免系统性放行"的目标。故采用 CJK 感知上界口径：
// CJK 字符按 1 token/字（cl100k 上界，宁保守拒绝、不放行超额），非 CJK 字符
// 按 4 字符/token（英文近似准确）。估算期间审计事件标记 metering_mode=estimate
// （未校准）；生产配额以真机 tokenizer 校准为准。
//
// 安全约束：计量口径只影响配额/计费，不影响段① 加密链与 fail-closed 语义；
// 接入真机 tokenizer 时须保证与阿里计费对账口径一致（见 GA-计费接口设计.md）。
package main

// Tokenizer 计量 token 计数接口。
type Tokenizer interface {
	// Count 返回 text 的 token 数（计量/配额统一口径）。
	Count(text string) int
}

// charDiv4Tokenizer 字符/4 估算口径（原过渡实现，保留供内部预览/对照）。
// 局限（记录于 GA-AI网关能力补齐方案 D-3）：中文每字≈1 token，估算偏差 3-4 倍；
// 配额默认口径已切换为 CJK 感知估算（estimateTokensCJK），本实现不再作为默认。
type charDiv4Tokenizer struct{}

// Count 字符/4 估算（与既有 estimateTokens 完全一致，向后兼容）。
func (charDiv4Tokenizer) Count(text string) int {
	return estimateTokens(text)
}

// countTokens 计量入口：tokenizer 未注入（nil，过渡期缺省）时回退 CJK 感知估算，
// 生产注入真机 tokenizer 后自动切换为精确口径。
func (s *teeServer) countTokens(text string) int {
	if s.tokenizer != nil {
		return s.tokenizer.Count(text)
	}
	return estimateTokensCJK(text)
}

// meteringMode 计量口径标记（GF.2.4：审计证据字段）：
// "estimate" = 估算未校准（真机 tokenizer 未注入）；"tokenizer" = 真机已校准。
func (s *teeServer) meteringMode() string {
	if s.tokenizer != nil {
		return "tokenizer"
	}
	return "estimate"
}

// isCJKRune 判断 r 是否为 CJK 表意文字/标点/全角形式（按 1 token/字计的字符集）。
func isCJKRune(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF: // CJK 统一表意文字
		return true
	case r >= 0x3400 && r <= 0x4DBF: // 扩展 A
		return true
	case r >= 0xF900 && r <= 0xFAFF: // 兼容表意文字
		return true
	case r >= 0x3000 && r <= 0x303F: // CJK 标点符号（，。、等）
		return true
	case r >= 0xFF00 && r <= 0xFFEF: // 全角形式（！？：等）
		return true
	case r >= 0x3040 && r <= 0x30FF: // 平假名/片假名（日文混排）
		return true
	}
	return false
}

// estimateTokensCJK CJK 感知估算（GF.2.4 过渡口径，配额/计量默认）：
// CJK 字符 1 token/字（cl100k_base 上界）+ 非 CJK 字符 4 字符/token。
// 对中文为保守上界（避免配额系统性放行），对英文与字符/4 口径一致。
func estimateTokensCJK(text string) int {
	cjk, other := 0, 0
	for _, r := range text {
		if isCJKRune(r) {
			cjk++
		} else {
			other++
		}
	}
	return cjk + (other+3)/4
}
