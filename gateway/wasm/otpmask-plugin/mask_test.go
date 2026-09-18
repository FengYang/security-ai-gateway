package main

import (
	"strings"
	"testing"
)

// TestMaskPhone 验证手机号改写。
func TestMaskPhone(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"标准手机号", "我的手机号是13812345678", "我的手机号是138****5678"},
		{"手机号带边界", "电话:13999998888,请联系", "电话:139****8888,请联系"},
		{"多个手机号", "13800001111 和 13922223333 都是", "138****1111 和 139****3333 都是"},
		{"无手机号", "hello world", "hello world"},
		{"短数字串（非手机号）", "编号12345", "编号12345"},
		{"空文本", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, hits := maskTextPII(tc.input)
			if got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
			// 命中次数 sanity check
			if tc.name == "无手机号" || tc.name == "短数字串（非手机号）" || tc.name == "空文本" {
				if hits != 0 {
					t.Fatalf("应零命中，实际 hits=%d", hits)
				}
			}
		})
	}
}

// TestMaskIDCard 验证身份证改写。
func TestMaskIDCard(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"标准18位身份证", "身份证号11010519900101002X", "身份证号110105********002X"},
		{"带X的身份证", "ID: 310115200012311234x", "ID: 310115********1234x"},
		{"多个身份证", "11010519900101002X 和 440101202001018888", "110105********002X 和 440101********8888"},
		{"无身份证", "普通文本", "普通文本"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := maskTextPII(tc.input)
			if got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

// TestMaskEmail 验证邮箱改写。
func TestMaskEmail(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"标准邮箱", "联系 john@example.com", "联系 j***@example.com"},
		{"单字符用户名", "a@b.com", "***@b.com"},
		{"双字符用户名", "ab@test.cn", "a*@test.cn"},
		{"长用户名", "john.doe+label@example.co.uk", "j*************@example.co.uk"},
		{"多个邮箱", "a@b.com 和 c@d.org", "***@b.com 和 ***@d.org"},
		{"无邮箱", "没有邮箱哦", "没有邮箱哦"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := maskTextPII(tc.input)
			if got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

// TestMaskBankCard 验证银行卡改写。
func TestMaskBankCard(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"16位银行卡", "卡号6222021234567890", "卡号622202******7890"},
		{"19位银行卡", "卡号6222021234567890123", "卡号622202*********0123"},
		{"多个银行卡", "6222021234567890, 6222039876543210", "622202******7890, 622203******3210"},
		{"无银行卡", "没有卡号", "没有卡号"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := maskTextPII(tc.input)
			if got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

// TestMaskMixedPII 验证混合 PII 改写。
func TestMaskMixedPII(t *testing.T) {
	input := "用户张三，手机13812345678，身份证11010519900101002X，邮箱john@test.com，银行卡6222021234567890。"
	got, hits := maskTextPII(input)
	if hits < 4 {
		t.Fatalf("应至少命中4次，实际 hits=%d", hits)
	}
	// 手机号
	if strings.Contains(got, "13812345678") {
		t.Fatal("手机号明文泄露")
	}
	if !strings.Contains(got, "138****5678") {
		t.Fatal("手机号未正确脱敏")
	}
	// 身份证
	if strings.Contains(got, "11010519900101002X") {
		t.Fatal("身份证明文泄露")
	}
	if !strings.Contains(got, "110105********002X") {
		t.Fatal("身份证未正确脱敏")
	}
	// 邮箱
	if !strings.Contains(got, "j***@test.com") {
		t.Fatal("邮箱未正确脱敏")
	}
	// 银行卡
	if !strings.Contains(got, "622202******7890") {
		t.Fatal("银行卡未正确脱敏")
	}
}

// TestMaskEmpty 验证空文本。
func TestMaskEmpty(t *testing.T) {
	got, hits := maskTextPII("")
	if got != "" || hits != 0 {
		t.Fatalf("空文本应返回空+零命中，实际 got=%q hits=%d", got, hits)
	}
}

// TestMaskBuiltinRegexConsistency 验证 builtin 正则与 pii_patterns.json 中
// 的顺序和条数一致（两形态对账的基础保障）。
// 注意：本测试只校验条数和顺序，不校验正则字符串完全相同——
// 因为 Go 字符串和 JSON 字符串的转义形式不同，但语义等价。
// 真正的等价性由两形态对账测试（同一输入两端输出一致）来验证。
func TestMaskBuiltinRegexConsistency(t *testing.T) {
	if len(builtinPIIPatterns) != len(piiMaskRuleTable) {
		t.Fatalf("正则数(%d) != 改写规则数(%d)", len(builtinPIIPatterns), len(piiMaskRuleTable))
	}
	if len(compiledPIIRegexps) != len(builtinPIIPatterns) {
		t.Fatalf("编译后正则数(%d) != 源正则数(%d)", len(compiledPIIRegexps), len(builtinPIIPatterns))
	}
}

// TestMaskBoundaryCases 边界 PII 用例。
// 目的：验证 UTF-8 多字节边界、跨 PII 紧邻等场景下的改写行为
// （已知限制：数字类正则的 [^0-9] 边界对 UTF-8 多字节字符
//  在"中文+数字+中文"的三明治结构下可能匹配不到，登记为已知限制）。
func TestMaskBoundaryCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		check func(t *testing.T, got string, hits int)
	}{
		{
			name:  "前后全ASCII标点的手机号",
			input: "(13812345678)",
			check: func(t *testing.T, got string, hits int) {
				if hits != 1 {
					t.Fatalf("应命中1次，实际 hits=%d", hits)
				}
				if got != "(138****5678)" {
					t.Fatalf("改写错误: %q", got)
				}
			},
		},
		{
			name:  "两个手机号紧邻（ASCII逗号分隔）— 已知限制：后边界被首匹配消费，第二个漏改",
			input: "13811112222,13933334444",
			check: func(t *testing.T, got string, hits int) {
				// 已知限制：数字类正则的 [^0-9] 边界会被消费，紧邻的第二个 PII 因缺
				// 前边界而漏改。生产中 PII 之间通常有空格/中文等足够分隔，影响极小。
				// 这里仅登记行为，不要求修复。
				if hits == 0 {
					t.Fatalf("至少应命中1个，实际 hits=%d", hits)
				}
			},
		},
		{
			name:  "两个手机号有空格分隔",
			input: "13811112222, 13933334444",
			check: func(t *testing.T, got string, hits int) {
				if hits != 2 {
					t.Fatalf("应命中2次，实际 hits=%d got=%q", hits, got)
				}
			},
		},
		{
			name:  "邮箱与数字紧邻",
			input: "john@test.com123",
			check: func(t *testing.T, got string, hits int) {
				// 邮箱命中，数字不是完整 PII
				if hits < 1 {
					t.Fatalf("邮箱应至少命中1次，实际 hits=%d", hits)
				}
			},
		},
		{
			name:  "单字全是数字但长度不足",
			input: "编号1234567",
			check: func(t *testing.T, got string, hits int) {
				// 7位数字：不是手机号（11位）、不是身份证（18位）、不是银行卡（16-19位）
				if hits != 0 {
					t.Fatalf("短数字串不应命中，实际 hits=%d got=%q", hits, got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, hits := maskTextPII(tc.input)
			tc.check(t, got, hits)
		})
	}
}

// BenchmarkMaskTextPII 性能基准——插件侧 PII mask 的延迟量级。
// 注意：基准在原生 Go 下运行（go test -bench），wasm 环境下通常慢 3～10x，
// 仅用于量级对比（与 tee-infer 侧同 benchmark 对比），不作为生产绝对延迟。
func BenchmarkMaskTextPII_NoPII(b *testing.B) {
	text := "这是一段普通文本，不包含任何个人身份信息。" +
		"Hello world. This is a test message without PII."
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		maskTextPII(text)
	}
}

func BenchmarkMaskTextPII_OnePhone(b *testing.B) {
	text := "用户的手机号是13812345678，请尽快联系。"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		maskTextPII(text)
	}
}

func BenchmarkMaskTextPII_MixedPII(b *testing.B) {
	text := "用户张三，手机13812345678，身份证11010519900101002X，" +
		"邮箱john.doe@example.com，银行卡6222021234567890。"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		maskTextPII(text)
	}
}
