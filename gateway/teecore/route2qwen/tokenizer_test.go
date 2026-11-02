package route2qwen

import (
	"os"
	"reflect"
	"testing"
)

// loadTestTokenizer 载入 testdata 内的小型合成 BPE，用于确定性单元测试。
func loadTestTokenizer(t *testing.T) *Tokenizer {
	t.Helper()
	tok, err := LoadTokenizer("testdata/tokenizer.json")
	if err != nil {
		t.Fatalf("载入测试 tokenizer 失败: %v", err)
	}
	return tok
}

func TestTokenizerKnown(t *testing.T) {
	tok := loadTestTokenizer(t)
	// "the" -> 单 token "the"(id 11)
	if got := tok.Encode("the"); !reflect.DeepEqual(got, []int{11}) {
		t.Fatalf("Encode(\"the\") = %v, want [11]", got)
	}
	// " the"（前导空格）-> "Ġthe"(id 12)
	if got := tok.Encode(" the"); !reflect.DeepEqual(got, []int{12}) {
		t.Fatalf("Encode(\" the\") = %v, want [12]", got)
	}
	// "cat" -> "cat"(id 14)
	if got := tok.Encode("cat"); !reflect.DeepEqual(got, []int{14}) {
		t.Fatalf("Encode(\"cat\") = %v, want [14]", got)
	}
	// 解码回原文
	if got := tok.Decode([]int{12, 4, 14}); got != " the cat" {
		t.Fatalf("Decode([12,4,14]) = %q, want %q", got, " the cat")
	}
}

func TestTokenizerRoundTrip(t *testing.T) {
	tok := loadTestTokenizer(t)
	// 注意：testdata 为最小词表（仅含 the/cat 及单字 t,h,e,Ġ,a,c），
	// 仅覆盖下列字符串；"hello world" 等超纲字符串请用 TestTokenizerRealRoundTrip（全词表）。
	cases := []string{"the", " the", "the cat", "cat", " a cat"}
	for _, s := range cases {
		ids := tok.Encode(s)
		if len(ids) == 0 {
			t.Fatalf("Encode(%q) 为空", s)
		}
		if got := tok.Decode(ids); got != s {
			t.Fatalf("RoundTrip %q -> %v -> %q", s, ids, got)
		}
	}
}

// TestTokenizerRealRoundTrip 用完整 Qwen tokenizer.json 做 round-trip 校验（BPE 天然可逆）。
// 设置环境变量 ROUTE2_REAL_TOK 指向 Qwen2.5-*.json 后运行；未设置则跳过。
func TestTokenizerRealRoundTrip(t *testing.T) {
	p := os.Getenv("ROUTE2_REAL_TOK")
	if p == "" {
		t.Skip("设置 ROUTE2_REAL_TOK 指向 Qwen tokenizer.json 以运行真实 round-trip 校验")
	}
	tok, err := LoadTokenizer(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"Hello world",
		"你好，世界",
		"The capital of France is",
		"def add(a, b):\n    return a + b",
	}
	for _, s := range cases {
		ids := tok.Encode(s)
		if len(ids) == 0 {
			t.Fatalf("Encode(%q) 为空", s)
		}
		if got := tok.Decode(ids); got != s {
			t.Fatalf("RoundTrip %q -> %v -> %q", s, ids, got)
		}
	}
}
