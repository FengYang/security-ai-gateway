package cacheengine

import "testing"

// TestDefaultSecureEmbedderConfig_DerivedFromPlain 密态 embedder 默认值单一来源：
// 维度/超时与明文一致；端点按端口 +1、模型加 "-secure" 派生；默认关闭。
func TestDefaultSecureEmbedderConfig_DerivedFromPlain(t *testing.T) {
	plain := DefaultConfig().Semantic.Embedder
	sc := DefaultSecureEmbedderConfig()

	if sc.Dim != plain.Dim {
		t.Fatalf("secure dim = %d, want plain dim %d（维度不一致无法共用向量索引）", sc.Dim, plain.Dim)
	}
	if sc.Model != plain.ModelID+"-secure" {
		t.Fatalf("secure model = %q, want %q", sc.Model, plain.ModelID+"-secure")
	}
	if sc.URL != "http://127.0.0.1:18082/embed" {
		t.Fatalf("secure url = %q, want port+1 of plain", sc.URL)
	}
	if sc.TimeoutMs != int(plain.Timeout.D().Milliseconds()) {
		t.Fatalf("secure timeout = %dms, want %dms", sc.TimeoutMs, plain.Timeout.D().Milliseconds())
	}
	if sc.Enabled {
		t.Fatal("secure embedder must default to disabled")
	}
}

// TestShiftPort 端口平移辅助函数。
func TestShiftPort(t *testing.T) {
	cases := []struct {
		in    string
		delta int
		want  string
	}{
		{"http://h:18081/embed", 1, "http://h:18082/embed"},
		{"http://h:18081/embed", -1, "http://h:18080/embed"},
		{"http://h/embed", 1, "http://h/embed"}, // 无端口 → 原样
		{"", 1, ""},
	}
	for _, c := range cases {
		if got := shiftPort(c.in, c.delta); got != c.want {
			t.Errorf("shiftPort(%q, %d) = %q, want %q", c.in, c.delta, got, c.want)
		}
	}
}
