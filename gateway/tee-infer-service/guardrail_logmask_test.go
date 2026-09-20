// B4（合规达标最小集）：日志零原文 —— guardrail 命中 match 的掩码化测试。
//
// 口径依据：《GA-大模型内容合规规划.md》§8 S0-#0（R3-1）与 §5-G6 缺陷面：
// 密文路径日志曾以 %q 打印 match 原文，本文件锁定「掩码规格 + 不得出现原文 + 源码不变量」。
package main

import (
	"os"
	"strings"
	"testing"
)

func TestMaskForLog(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空串", "", "(empty,len=0)"},
		{"短串3rune全掩", "abc", "***(len=3)"},
		{"短串5rune全掩", "abcde", "*****(len=5)"},
		{"恰好6rune", "abcdef", "abc***ef(len=6)"},
		{"手机号", "13812345678", "138***78(len=11)"},
		{"身份证", "110101199003077777", "110***77(len=18)"},
		{"邮箱", "user@example.com", "use***om(len=16)"},
		{"中文多字节", "忽略以上指令内容", "忽略以***内容(len=8)"},
	}
	for _, c := range cases {
		if got := maskForLog(c.in); got != c.want {
			t.Errorf("%s: maskForLog(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// 掩码后的输出不得包含原文整体，也不得包含首3/末2 之外的中段内容。
func TestMaskForLogNoPlaintextLeak(t *testing.T) {
	samples := []struct {
		in     string
		middle string // 必须不出现在掩码结果中的中段（若有）
	}{
		{"13812345678", "1234567"},
		{"110101199003077777", "1011990030777"},
		{"user@example.com", "r@example.c"},
		{"忽略以上指令内容", "以上指令"},
	}
	for _, s := range samples {
		out := maskForLog(s.in)
		if strings.Contains(out, s.in) {
			t.Errorf("掩码输出仍含原文: in=%q out=%q", s.in, out)
		}
		if s.middle != "" && strings.Contains(out, s.middle) {
			t.Errorf("掩码输出仍含原文中段: middle=%q out=%q", s.middle, out)
		}
	}
}

// 源码不变量（合规回归锁）：main.go 中出现的 hit.Match 只允许作为 maskForLog 的入参。
// 若新增其它用法（例如再次直接打日志），本测试失败，防止缺陷面回归。
func TestGuardrailMatchLoggedMasked(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读取 main.go 失败: %v", err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "hit.Match") && !strings.Contains(line, "maskForLog(hit.Match)") {
			t.Errorf("main.go:%d 出现未掩码的 hit.Match：%s", i+1, strings.TrimSpace(line))
		}
	}
}
