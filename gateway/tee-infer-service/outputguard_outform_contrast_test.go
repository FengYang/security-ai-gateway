package main

// 输出形态良性对照集（testdata/outform-contrast/）校验与禁令锁。
//
// 用途：S0-⑨「输出侧误杀基线取数」的**输出形态**对照语料（Markdown/代码/长编号/emoji/跨 delta）。
// 本测试**只做数据校验 + 计数报告**，不设误杀阈值——阈值属产品定线（S0-⑨ / D-LLM-8）。
//
// 禁令锁（防误用，硬约束）：本集**不得**作为备案抽检集、不得写入对外材料、不得替代 OG-25 真实黄金集；
// 故测试断言：① 语料不在 testdata/golden/（交付物目录）下；② README 必须仍载明禁令原文。
//
// fail-closed：语料缺失即 Fail（缺语料 = 校验未执行，不应静默变绿；与 guardrail-bench 同纪律）。

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	outformContrastRelPath = "testdata/outform-contrast/corpus.jsonl"
	outformContrastReadme  = "testdata/outform-contrast/README"
)

func TestOutformContrast(t *testing.T) {
	raw, err := os.ReadFile(outformContrastRelPath)
	if err != nil {
		t.Fatalf("对照集语料缺失（%s）：%v —— 缺语料即 Fail（不得静默变绿）", outformContrastRelPath, err)
	}
	if strings.Contains(outformContrastRelPath, "testdata/golden/") {
		t.Fatal("禁令锁：对照集不得位于 testdata/golden/（交付物目录）")
	}

	type contrastCase struct {
		ID      string `json:"id"`
		Source  string `json:"source"`
		Scope   string `json:"scope"`
		Expect  string `json:"expect"`
		Variant string `json:"variant"`
		Text    string `json:"text"`
		Note    string `json:"note"`
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	seenID := make(map[string]bool, len(lines))
	byVariant := make(map[string]int)
	cases := 0
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c contrastCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("第 %d 行 JSON 非法：%v", i+1, err)
		}
		switch {
		case c.ID == "" || c.Text == "" || c.Variant == "" || c.Note == "":
			t.Fatalf("第 %d 行字段不完整：%+v", i+1, c)
		case c.Source != "synthetic":
			t.Fatalf("第 %d 行 source=%q，本集必须全为 synthetic（不含第三方数据集内容）", i+1, c.Source)
		case c.Scope != "benign_outform":
			t.Fatalf("第 %d 行 scope=%q，本集只承载 benign_outform（对照用；不得混入应拦样本）", i+1, c.Scope)
		case c.Expect != "allow":
			t.Fatalf("第 %d 行 expect=%q，本集只承载 allow（良性对照）", i+1, c.Expect)
		case seenID[c.ID]:
			t.Fatalf("第 %d 行 id 重复：%s", i+1, c.ID)
		}
		seenID[c.ID] = true
		byVariant[c.Variant]++
		cases++
	}
	if cases < 40 {
		t.Fatalf("对照集样本量不足：%d（应 ≥40，覆盖 Markdown/代码/长编号/emoji/跨 delta 等输出形态）", cases)
	}

	// 禁令锁②：README 必须仍载明"不得用于备案抽检 / 不得替代 OG-25"两条禁令（防禁令被误删）。
	rm, err := os.ReadFile(outformContrastReadme)
	if err != nil {
		t.Fatalf("对照集 README 缺失：%v", err)
	}
	r := string(rm)
	for _, must := range []string{"不得**作为备案抽检集", "不得**替代 OG-25 真实黄金集"} {
		if !strings.Contains(r, must) {
			t.Fatalf("禁令锁：README 缺失禁令条款 %q", must)
		}
	}

	// 仅报告（不设阈值）：样本量与 variant 分布。
	t.Logf("输出形态对照集：%d 条（仅对照，不作达标口径）", cases)
	for _, v := range []string{"md-table", "long-num", "ignore", "sql", "code", "crit", "mixed", "emoji", "halfsent", "md", "json", "log", "quote", "url", "pii-like", "math", "cn-en", "list"} {
		if n := byVariant[v]; n > 0 {
			t.Logf("  variant=%-12s %d", v, n)
		}
	}
}
