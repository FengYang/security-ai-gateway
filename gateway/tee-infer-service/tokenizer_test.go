package main

// GF.2.4 计量口径可插拔测试：
// - charDiv4Tokenizer.Count 与 estimateTokens 一致（向后兼容）
// - countTokens 在 tokenizer 为 nil 时回退字符/4
// - countTokens 注入自定义 tokenizer 后切换为精确口径

import "testing"

// TestCharDiv4Tokenizer charDiv4 与 estimateTokens 口径一致。
func TestCharDiv4Tokenizer(t *testing.T) {
	tok := charDiv4Tokenizer{}
	for _, s := range []string{"", "a", "hello", "你好世界", "中文字符串测试abcdef"} {
		if got, want := tok.Count(s), estimateTokens(s); got != want {
			t.Fatalf("charDiv4.Count(%q)=%d want %d", s, got, want)
		}
	}
}

// TestCountTokensFallback tokenizer 未注入（nil）时回退字符/4。
func TestCountTokensFallback(t *testing.T) {
	srv := &teeServer{} // tokenizer = nil
	if got, want := srv.countTokens("hello"), estimateTokens("hello"); got != want {
		t.Fatalf("nil tokenizer 应回退字符/4: got %d want %d", got, want)
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
	// 字符/4 估算为 2，精确为 5，证明已切换口径
	if srv.countTokens("hello") == estimateTokens("hello") {
		t.Fatal("注入 tokenizer 后口径未切换")
	}
}
