// 输出侧内容审查 — PII mask 改写（OG-18）。
//
// 对 A4-06（PII 个人信息）命中的文本做等长/近等长脱敏替换，
// 供 enforcing + mask 启用时在流式下发前执行。
//
// 设计约束（与 L1 判定一致性）：
//   - 数字类（手机/身份证/银行卡）：等长替换（数字 → '*'），跨 delta 位置不变，
//     回填时可按原 rune 长度精确切分，无错位。
//   - 邮箱：近等长（用户名长度可能变短 1 字符，单字符用户名为 3 个 '*'），
//     跨 delta 场景罕见且影响极小（仅用户名后半），登记为已知限制。
//   - 正则与 L1 判定复用同一套（pii_patterns.json），确保"判得到才改得到"。
package main

import (
	"regexp"
	"strings"
)

// piiMaskRules PII 改写规则表（与 pii_patterns.json 的 4 条正则一一对应）。
// 每条规则负责：匹配 → 提取本体 → 改写 → 返回改写后的完整匹配。
//
// 注意：正则顺序与 pii_patterns.json 一致（手机号 / 身份证 / 邮箱 / 银行卡），
// 由调用方按相同顺序传入已编译的正则切片，确保一一对应。
type piiMaskFunc func(match string, groups []string) string

// maskPhone 手机号脱敏：前 3 + **** + 后 4（11 位等长）。
func maskPhone(_ string, groups []string) string {
	// groups[0]=全匹配 groups[1]=前边界 groups[2]=手机号 groups[3]=后边界
	phone := groups[2]
	if len(phone) < 7 {
		return groups[1] + strings.Repeat("*", len(phone)) + groups[3]
	}
	masked := phone[:3] + "****" + phone[len(phone)-4:]
	return groups[1] + masked + groups[3]
}

// maskIDCard 身份证脱敏：前 6 + ******** + 后 4（18 位等长）。
// 15 位老身份证不在正则覆盖范围（正则要求 17 + 1 位校验），但做兼容。
func maskIDCard(_ string, groups []string) string {
	id := groups[2]
	n := len(id)
	if n < 10 {
		return groups[1] + strings.Repeat("*", n) + groups[3]
	}
	keepHead := 6
	keepTail := 4
	if n < keepHead+keepTail {
		keepHead = n / 2
		keepTail = n - keepHead - 1
		if keepTail < 1 {
			keepTail = 1
			keepHead = n - keepTail
		}
	}
	masked := id[:keepHead] + strings.Repeat("*", n-keepHead-keepTail) + id[n-keepTail:]
	return groups[1] + masked + groups[3]
}

// maskEmail 邮箱脱敏：用户名保留首字符 + 星号，域名全保留。
// 用户名长度 = 1 时，替换为 "***"（无明文可保）。
func maskEmail(match string, _ []string) string {
	at := strings.Index(match, "@")
	if at < 0 {
		return match
	}
	user := match[:at]
	domain := match[at:]
	if len(user) <= 1 {
		return "***" + domain
	}
	// 保留首字符，其余替换为等数量星号（近等长，长度不变）
	maskedUser := string(user[0]) + strings.Repeat("*", len(user)-1)
	return maskedUser + domain
}

// maskBankCard 银行卡脱敏：前 6 + ****... + 后 4（等长，16~19 位）。
func maskBankCard(_ string, groups []string) string {
	card := groups[2]
	n := len(card)
	if n < 10 {
		return groups[1] + strings.Repeat("*", n) + groups[3]
	}
	masked := card[:6] + strings.Repeat("*", n-10) + card[n-4:]
	return groups[1] + masked + groups[3]
}

// piiMaskRuleTable 改写规则表（与 pii_patterns.json 的 4 条按索引一一对应）。
// 调用方按相同顺序传入 regexps，这里按索引取对应改写函数。
var piiMaskRuleTable = []piiMaskFunc{
	maskPhone,    // kw-a4-06-0001 手机号
	maskIDCard,   // kw-a4-06-0002 身份证
	maskEmail,    // kw-a4-06-0003 邮箱
	maskBankCard, // kw-a4-06-0004 银行卡
}

// maskTextPII 对文本做 PII 脱敏改写。
//
// res：与 pii_patterns.json 一一对应的已编译正则切片（顺序必须一致）。
// 返回改写后的文本与命中次数；命中文本按规则表对应索引的改写函数处理。
//
// 一致性保证：使用与 L1 判定完全相同的正则与扫描逻辑，
// "L1 判得到的，改写一定能找到"（反之亦然）。
func maskTextPII(text string, res []*regexp.Regexp) (string, int) {
	if len(res) == 0 || text == "" {
		return text, 0
	}
	hits := 0
	result := text
	for i, re := range res {
		if i >= len(piiMaskRuleTable) {
			break // 防御：规则表少于正则数（不应发生）
		}
		fn := piiMaskRuleTable[i]
		result = re.ReplaceAllStringFunc(result, func(m string) string {
			groups := re.FindStringSubmatch(m)
			hits++
			return fn(m, groups)
		})
	}
	return result, hits
}
