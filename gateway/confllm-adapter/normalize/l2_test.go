package normalize

import "testing"

// TestMergeVendorOptionsEmptyAllowlist 白名单为空（未声明任何 vendor key）→ 丢弃全部 vendor 字段（fail-closed）。
func TestMergeVendorOptionsEmptyAllowlist(t *testing.T) {
	base := map[string]any{"model": "m", "messages": "x"}
	vendor := map[string]any{"enable_thinking": true, "leak": "y"}
	out := MergeVendorOptions(base, vendor, nil)
	if _, ok := out["enable_thinking"]; ok {
		t.Fatal("白名单为空时应丢弃所有 vendor 字段（含声明过的 key）")
	}
	if _, ok := out["leak"]; ok {
		t.Fatal("白名单为空时应丢弃所有 vendor 字段")
	}
	if out["model"] != "m" {
		t.Fatal("base 标准字段必须保留")
	}
}

// TestMergeVendorOptionsAllowlistPassThrough 白名单命中透传、未命中丢弃。
func TestMergeVendorOptionsAllowlistPassThrough(t *testing.T) {
	base := map[string]any{"model": "m"}
	vendor := map[string]any{"enable_thinking": true, "thinking": 1, "leak": "y"}
	out := MergeVendorOptions(base, vendor, []string{"enable_thinking", "thinking"})
	if _, ok := out["enable_thinking"]; !ok {
		t.Fatal("白名单 key 应透传")
	}
	if _, ok := out["thinking"]; !ok {
		t.Fatal("白名单 key 应透传")
	}
	if _, ok := out["leak"]; ok {
		t.Fatal("非白名单 key 不应透传（否则污染统一契约）")
	}
}

// TestMergeVendorOptionsBasePreserved base 标准字段在合并后保留（vendor 不触碰 base 未声明为白名单的 key）。
func TestMergeVendorOptionsBasePreserved(t *testing.T) {
	base := map[string]any{"model": "m", "stream": false}
	vendor := map[string]any{"enable_thinking": true}
	allowed := []string{"enable_thinking"}
	out := MergeVendorOptions(base, vendor, allowed)
	if out["model"] != "m" {
		t.Fatalf("base model 应保留，实际 %v", out["model"])
	}
	if out["stream"] != false {
		t.Fatalf("base stream 应保留，实际 %v", out["stream"])
	}
	if _, ok := out["enable_thinking"]; !ok {
		t.Fatal("白名单 vendor key 应透传")
	}
}
