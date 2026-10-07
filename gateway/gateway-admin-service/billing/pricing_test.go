package billing

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------- 价格表加载测试（T4） ----------

func TestLoadPriceTable_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pricing.json")
	content := `{
	  "version": "v1",
	  "currency": "CNY",
	  "models": {
	    "a/b": {"in_coef": 2.0, "out_coef": 3.0,
	      "tiers": [{"up_to_tokens": 1000, "in_per_1k": 1.0, "out_per_1k": 2.0},
	                {"up_to_tokens": 0, "in_per_1k": 0.5, "out_per_1k": 1.0}]}
	  }
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	tbl, err := LoadPriceTable(path)
	if err != nil {
		t.Fatalf("LoadPriceTable err: %v", err)
	}
	if tbl.Version != "v1" {
		t.Errorf("version = %q, want v1", tbl.Version)
	}
	mp, ok := tbl.ModelPriceOf("a/b")
	if !ok {
		t.Fatal("model a/b not found")
	}
	if mp.InCoef != 2.0 || mp.OutCoef != 3.0 {
		t.Errorf("coef = (%v,%v), want (2,3)", mp.InCoef, mp.OutCoef)
	}
	if len(mp.Tiers) != 2 {
		t.Errorf("tiers = %d, want 2", len(mp.Tiers))
	}
}

func TestLoadPriceTable_MissingVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	os.WriteFile(path, []byte(`{"models":{}}`), 0o644)
	if _, err := LoadPriceTable(path); err == nil {
		t.Error("expected error for missing version")
	}
}

func TestLoadPriceTable_BadTiers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	// 阶梯非递增（第二档上界 < 第一档）
	os.WriteFile(path, []byte(`{"version":"v1","models":{"m":{"tiers":[
	  {"up_to_tokens":1000,"in_per_1k":1,"out_per_1k":1},
	  {"up_to_tokens":500,"in_per_1k":1,"out_per_1k":1}]}}}`), 0o644)
	if _, err := LoadPriceTable(path); err == nil {
		t.Error("expected error for non-increasing tiers")
	}
}

// BUG-004：空阶梯（模型侧）→ 拒载（fail-closed），避免静默按 0 金额计价
func TestLoadPriceTable_EmptyTiersRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	os.WriteFile(path, []byte(`{"version":"v1","models":{"m":{"in_coef":1,"out_coef":1,"tiers":[]}}}`), 0o644)
	if _, err := LoadPriceTable(path); err == nil {
		t.Error("expected error for empty tiers (BUG-004 fail-closed)")
	}
}

// BUG-004：空阶梯（defaults 侧）→ 拒载
func TestLoadPriceTable_DefaultsEmptyTiersRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	os.WriteFile(path, []byte(`{"version":"v1","models":{},"defaults":{"tiers":[]}}`), 0o644)
	if _, err := LoadPriceTable(path); err == nil {
		t.Error("expected error for empty defaults.tiers (BUG-004 fail-closed)")
	}
}

func TestLoadPriceTable_DefaultCoefApplied(t *testing.T) {
	// coef 缺省（0）→ 归一为 1.0（R-14 缺省）
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	os.WriteFile(path, []byte(`{"version":"v1","models":{"m":{"tiers":[
	  {"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`), 0o644)
	tbl, err := LoadPriceTable(path)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	mp := tbl.Models["m"]
	if mp.InCoef != 1.0 || mp.OutCoef != 1.0 {
		t.Errorf("default coef = (%v,%v), want (1,1)", mp.InCoef, mp.OutCoef)
	}
}

func TestLoadPriceTable_SampleFile(t *testing.T) {
	// 校验仓库样例文件可加载（deploy/billing/pricing.sample.json）
	path := filepath.Join("..", "..", "..", "deploy", "billing", "pricing.sample.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("sample file not present: %v", err)
	}
	tbl, err := LoadPriceTable(path)
	if err != nil {
		t.Fatalf("sample LoadPriceTable err: %v", err)
	}
	if tbl.Version == "" {
		t.Error("sample version empty")
	}
	if len(tbl.Models) == 0 {
		t.Error("sample has no models")
	}
}
