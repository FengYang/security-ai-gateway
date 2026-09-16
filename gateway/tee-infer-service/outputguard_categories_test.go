package main

import "testing"

// OG-2（类目体系与映射）验收单测：31 类完整清单 + L1 映射表合法 + 未映射类目返回 false。

// TestOutputCategoriesCount：类目总数 = 31（附录 A 约定数）。
func TestOutputCategoriesCount(t *testing.T) {
	if got := categoryCount(); got != 31 {
		t.Fatalf("类目总数期望 31（附录 A），实际 %d", got)
	}
}

// TestOutputCategoriesUniqueAndValid：每个 ID 唯一、非空、格式合法（A<1-5>-<2位数字>）。
func TestOutputCategoriesUniqueAndValid(t *testing.T) {
	seen := make(map[string]bool, 31)
	for _, c := range outputCategories {
		if c.ID == "" {
			t.Fatal("存在空 ID")
		}
		if seen[c.ID] {
			t.Fatalf("重复 ID: %s", c.ID)
		}
		seen[c.ID] = true
		// 格式：A<1-5>-<两位数字>
		if len(c.ID) != 5 || c.ID[0] != 'A' || c.ID[1] < '1' || c.ID[1] > '5' || c.ID[2] != '-' ||
			c.ID[3] < '0' || c.ID[3] > '9' || c.ID[4] < '0' || c.ID[4] > '9' {
			t.Fatalf("ID 格式非法: %q（期望 A<1-5>-<NN>）", c.ID)
		}
		if c.Name == "" {
			t.Fatalf("%s: 类目名称为空", c.ID)
		}
		if c.Family == "" {
			t.Fatalf("%s: 族为空", c.ID)
		}
		if c.DefaultLevel == "" {
			t.Fatalf("%s: 默认级别为空", c.ID)
		}
		if c.DefaultAction == "" {
			t.Fatalf("%s: 默认动作为空", c.ID)
		}
	}
}

// TestOutputCategoriesFamilyCount：各族条目数与附录 A 一致
// （A1=8 / A2=9 / A3=5 / A4=7 / A5=2）。
func TestOutputCategoriesFamilyCount(t *testing.T) {
	counts := map[string]int{}
	for _, c := range outputCategories {
		counts[c.Family]++
	}
	expect := map[string]int{
		"A1": 8, "A2": 9, "A3": 5, "A4": 7, "A5": 2,
	}
	for fam, want := range expect {
		if counts[fam] != want {
			t.Fatalf("族 %s 条目数期望 %d，实际 %d", fam, want, counts[fam])
		}
	}
}

// TestIsValidCategory：isValidCategory 正反向都正确。
func TestIsValidCategory(t *testing.T) {
	if !isValidCategory("A1-06") {
		t.Fatal("A1-06 应合法")
	}
	if isValidCategory("A9-99") {
		t.Fatal("A9-99 应非法")
	}
	if isValidCategory("") {
		t.Fatal("空串应非法")
	}
	if isValidCategory("a1-06") {
		t.Fatal("小写 ID 应非法（值使用时必须大写）")
	}
}

// TestGetCategory：getCategory 返回正确的类目定义。
func TestGetCategory(t *testing.T) {
	c, ok := getCategory("A4-06")
	if !ok {
		t.Fatal("A4-06 应存在")
	}
	if c.DefaultAction != catActionMask {
		t.Fatalf("A4-06 默认动作期望 mask，实际 %s", c.DefaultAction)
	}
	if c.Family != "A4" {
		t.Fatalf("A4-06 族期望 A4，实际 %s", c.Family)
	}
	_, ok = getCategory("A5-02")
	if !ok {
		t.Fatal("A5-02 应存在")
	}
}

// TestL1CategoryMap：L1 三个原生类目都有合法映射。
func TestL1CategoryMap(t *testing.T) {
	for _, l1Cat := range []string{"pii", "sql_injection", "prompt_injection"} {
		id, ok := mapL1Category(l1Cat)
		if !ok {
			t.Fatalf("L1 类目 %q 无映射", l1Cat)
		}
		if !isValidCategory(id) {
			t.Fatalf("L1 类目 %q 映射到非法 ID: %s", l1Cat, id)
		}
	}
	// PII 应该映射到 A4-06（个人信息）。
	if id, _ := mapL1Category("pii"); id != "A4-06" {
		t.Fatalf("pii 期望映射到 A4-06，实际 %s", id)
	}
}

// TestL1CategoryMapUnmapped：未映射类目返回 false（P-DEGRADE 语义）。
func TestL1CategoryMapUnmapped(t *testing.T) {
	if _, ok := mapL1Category("nonexistent"); ok {
		t.Fatal("未映射类目应返回 false（P-DEGRADE）")
	}
	if _, ok := mapL1Category(""); ok {
		t.Fatal("空类目应返回 false")
	}
}
