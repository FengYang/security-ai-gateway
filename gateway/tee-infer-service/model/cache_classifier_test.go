package model

import "testing"

// TestNullCache 空缓存恒 miss、put 无副作用。
func TestNullCache(t *testing.T) {
	c := NullCache{}
	c.Put("k", "v")
	if _, hit := c.Get("k"); hit {
		t.Fatal("NullCache 应恒 miss")
	}
}

// TestKeywordClassifier 顺序命中 + 大小写不敏感 + 未命中空类别。
func TestKeywordClassifier(t *testing.T) {
	c := NewKeywordClassifier([2]string{"sql", "select"}, [2]string{"pii", "身份证"})
	if cat, m := c.Classify("请帮我执行 SELECT * FROM users"); cat != "sql" || m != "select" {
		t.Fatalf("sql 命中失败: cat=%q match=%q", cat, m)
	}
	if cat, m := c.Classify("SELECT 之后有身份证号"); cat != "sql" || m != "select" {
		t.Fatalf("应按顺序先命中 sql, got %q", cat)
	}
	if cat, m := c.Classify("我的身份证号是110101"); cat != "pii" || m != "身份证" {
		t.Fatalf("pii 命中失败: cat=%q match=%q", cat, m)
	}
	if cat, _ := c.Classify("普通问候"); cat != "" {
		t.Fatalf("未命中应空类别, got %q", cat)
	}
}
