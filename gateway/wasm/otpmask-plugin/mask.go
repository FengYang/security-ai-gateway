// 段① 插件侧 PII mask 改写（OG-16 扩展，两形态第二形态）。
//
// 与 tee-infer 侧 OG-18 的 maskTextPII 复用同一套改写规则（等长替换、邮箱首字符保留），
// 保证两形态输出字节级一致。PII 正则编译进 wasm（builtin），首版无热加载。
//
// 默认 off（piiMaskConfig.Enabled=false），零行为变化。
package main

import (
	"regexp"
	"strings"
)

// builtinPIIPatterns 内置 PII 正则表达式（与 tee-infer 侧 pii_patterns.json 一一对应）。
// 顺序：手机号 / 身份证号 / 邮箱 / 银行卡号。
//
// 保持与 OG-18 完全一致，保证两形态输出可对账。
var builtinPIIPatterns = []string{
	// 0: 手机号（1[3-9] 开头的 11 位数字，前后非数字边界）
	`(^|[^0-9])(1[3-9][0-9]{9})([^0-9]|$)`,
	// 1: 身份证号（17 位数字 + 1 位校验位/数字/X/x，前后非数字边界）
	`(^|[^0-9])([0-9]{17}[0-9Xx])([^0-9]|$)`,
	// 2: 邮箱（简化版：用户名@域名.后缀，覆盖主流场景）
	`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`,
	// 3: 银行卡号（16-19 位数字，前后非数字边界）
	`(^|[^0-9])([0-9]{16,19})([^0-9]|$)`,
}

// piiMaskFunc PII 改写函数类型：输入完整匹配 + 子组，返回改写后的完整匹配。
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

// piiMaskRuleTable 改写规则表（与 builtinPIIPatterns 按索引一一对应）。
var piiMaskRuleTable = []piiMaskFunc{
	maskPhone,    // 0: 手机号
	maskIDCard,   // 1: 身份证
	maskEmail,    // 2: 邮箱
	maskBankCard, // 3: 银行卡
}

// compiledPIIRegexps 编译后的 PII 正则（init 时一次性编译，运行时只读）。
var compiledPIIRegexps []*regexp.Regexp

// piiMaskEnabled PII mask 总开关（由 parseConfig 设置；默认 false = off）。
// 单实例插件，全局变量即可；配置热更新时由配置 goroutine 写、请求 goroutine 读，
// bool 类型读写在 Go 中是原子的，无需额外同步。
var piiMaskEnabled bool

func init() {
	compiledPIIRegexps = make([]*regexp.Regexp, 0, len(builtinPIIPatterns))
	for _, pat := range builtinPIIPatterns {
		compiledPIIRegexps = append(compiledPIIRegexps, regexp.MustCompile(pat))
	}
}

// maskTextPII 对文本做 PII 脱敏改写（与 tee-infer 侧 OG-18 完全一致的逻辑）。
//
// 使用内置 compiledPIIRegexps（与 pii_patterns.json 同源）。
// 返回改写后的文本与命中次数。
func maskTextPII(text string) (string, int) {
	if text == "" {
		return text, 0
	}
	hits := 0
	result := text
	for i, re := range compiledPIIRegexps {
		if i >= len(piiMaskRuleTable) {
			break
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
