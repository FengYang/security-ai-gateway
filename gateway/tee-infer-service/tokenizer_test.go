package main

// GF.2.4 计量口径可插拔测试：
// - charDiv4Tokenizer.Count 与 estimateTokens 一致（向后兼容）
// - estimateTokensCJK：CJK 1 token/字 + 非 CJK 字符/4（过渡口径上界）
// - countTokens 在 tokenizer 为 nil 时回退 CJK 感知估算
// - countTokens 注入自定义 tokenizer 后切换为精确口径
// - meteringMode：nil = estimate（未校准），注入 = tokenizer（已校准）

import "testing"

// TestCharDiv4Tokenizer charDiv4 与 estimateTokens 口径一致（保留实现向后兼容）。
func TestCharDiv4Tokenizer(t *testing.T) {
	tok := charDiv4Tokenizer{}
	for _, s := range []string{"", "a", "hello", "你好世界", "中文字符串测试abcdef"} {
		if got, want := tok.Count(s), estimateTokens(s); got != want {
			t.Fatalf("charDiv4.Count(%q)=%d want %d", s, got, want)
		}
	}
}

// TestEstimateTokensCJK CJK 感知估算：CJK 按 1 token/字，非 CJK 按 4 字符/token。
func TestEstimateTokensCJK(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"空串", "", 0},
		{"纯英文", "hello", 2},   // 5 字符 → (5+3)/4 = 2
		{"纯中文", "你好世界", 4},    // 4 CJK × 1
		{"中文标点", "你好，世界。", 6}, // 4 汉字 + 2 全角标点
		{"混合", "你好abc", 3},    // 2 CJK + 3 ASCII → 2 + (3+3)/4 = 2+1
		{"英文标点", "hi!", 1},    // 3 字符 → (3+3)/4 = 1
		{"日文假名", "あいう", 3},    // 假名按 CJK 计
	}
	for _, c := range cases {
		if got := estimateTokensCJK(c.in); got != c.want {
			t.Fatalf("%s: estimateTokensCJK(%q)=%d want %d", c.name, c.in, got, c.want)
		}
	}
}

// TestEstimateTokensCJKConservative 对中文不低估（保守上界，避免配额系统性放行）。
func TestEstimateTokensCJKConservative(t *testing.T) {
	for _, s := range []string{"你好世界", "机密推理网关", "这是一段较长的中文提示词用于计量口径验证"} {
		// CJK 口径须严格大于字符/4 口径（后者对中文低估 2.4-4 倍）
		if estimateTokensCJK(s) <= estimateTokens(s) {
			t.Fatalf("CJK 口径对中文应高于字符/4: %q cjk=%d div4=%d",
				s, estimateTokensCJK(s), estimateTokens(s))
		}
	}
}

// TestCountTokensFallback tokenizer 未注入（nil）时回退 CJK 感知估算（过渡口径）。
func TestCountTokensFallback(t *testing.T) {
	srv := &teeServer{} // tokenizer = nil
	if got, want := srv.countTokens("hello"), estimateTokensCJK("hello"); got != want {
		t.Fatalf("nil tokenizer 应回退 CJK 估算: got %d want %d", got, want)
	}
	if got, want := srv.countTokens("你好世界"), 4; got != want {
		t.Fatalf("nil tokenizer 中文按 1 token/字: got %d want %d", got, want)
	}
}

// byteTokenizer 精确 tokenizer（测试注入用）：每字节计 1 token。
type byteTokenizer struct{}

func (byteTokenizer) Count(text string) int { return len(text) }

// TestCountTokensInjected 注入自定义 tokenizer 后切换为精确口径。
func TestCountTokensInjected(t *testing.T) {
	srv := &teeServer{tokenizer: byteTokenizer{}}
	if got, want := srv.countTokens("hello"), 5; got != want {
		t.Fatalf("注入 tokenizer 应精确计数: got %d want %d", got, want)
	}
	// 过渡估算为 2，精确为 5，证明已切换口径
	if srv.countTokens("hello") == estimateTokensCJK("hello") {
		t.Fatal("注入 tokenizer 后口径未切换")
	}
}

// TestMeteringMode 计量口径标记：nil = estimate（未校准），注入 = tokenizer。
func TestMeteringMode(t *testing.T) {
	srv := &teeServer{}
	if got := srv.meteringMode(); got != "estimate" {
		t.Fatalf("nil tokenizer 应标记 estimate（未校准）: got %q", got)
	}
	srv2 := &teeServer{tokenizer: byteTokenizer{}}
	if got := srv2.meteringMode(); got != "tokenizer" {
		t.Fatalf("注入 tokenizer 应标记 tokenizer: got %q", got)
	}
}
