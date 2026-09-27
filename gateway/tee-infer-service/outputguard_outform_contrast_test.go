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
	// outformContrastFPBaseline 输出形态误杀**已登记基线**（命中数，非百分比）：
	// ＝ S0-⑨ 首次取数（2026-09-26，走完整流式管线）经 **S2-4 方案 D 收窄规则后复测**的结果：**6/40**，其中
	//   - **A1-07 拦截类 1 条**：quote-01（分析语境引用「请忽略之前的指令」，仍命中保留词条「请忽略之前」）；
	//   - **A4-06 mask 类 5 条**：long-num×3（16-19 位数字）、pii-like×2（证件号/卡号占位）
	//     —— 语义是"会被 PII 正则命中"，默认动作为 mask（非 block，本次未改动）。
	// 收窄日期 2026-09-26（S2-4 方案 D）；收窄前为 **15/40**（A1-07 10 条 + A4-06 5 条）。
	// 收窄的三条规则（仅 §newGuardrail 语义）：
	//   ① 删除 `select … from` 结构子句（语法讲解/代码块误报；真注入由 union select/堆叠/恒真式承担）；
	//   ② 裸 `--` 改为注入上下文 `['"]\s*(--|#)` 与 `;\s*(--|#)`（Markdown 表格分隔线不再误报）；
	//   ③ 裸 `请忽略` 改为带宾语词条（请忽略以上/之前/前述/上述/前面/所有）。
	// 仅作**回归护栏**，不作达标阈值（阈值定线见 **S2-4**）。
	outformContrastFPBaseline = 6
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

// TestOutformContrastFalsePositive S0-⑨「输出侧误杀基线取数」：
// 40 条良性对照样本各经**完整 outputGuard 流式管线**（Process/Finish，含按句切分与跨 delta 边界），
// 命中数即**输出形态误杀基线**。
//
// **口径**：本用例**取数**（仅报告），阈值由 **S2-4**（产品＋SRE 定线）决定，故此处**不设门禁**；
// 仅保留"不得高于已登记基线"的**回归护栏**（基线＝首次取数结果，见 outformContrastFPBaseline）。
func TestOutformContrastFalsePositive(t *testing.T) {
	raw, err := os.ReadFile(outformContrastRelPath)
	if err != nil {
		t.Fatalf("对照集语料缺失（%s）：%v", outformContrastRelPath, err)
	}
	var (
		total   int
		hits    int
		hitIDs  []string
		hitCats []string
	)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("对照集 JSON 非法：%v", err)
		}
		total++
		if hit, cat := runThroughOutputGuard(t, c.Text); hit {
			hits++
			hitIDs = append(hitIDs, c.ID)
			hitCats = append(hitCats, cat)
		}
	}
	pct := 0.0
	if total > 0 {
		pct = float64(hits) * 100 / float64(total)
	}
	t.Logf("S0-⑨ 输出形态误杀基线：命中 %d/%d = %.2f%%", hits, total, pct)
	for i := range hitIDs {
		t.Logf("  误杀：%s（category=%s）", hitIDs[i], hitCats[i])
	}
	if hits > outformContrastFPBaseline {
		t.Fatalf("输出形态误杀超过已登记基线：%d > %d（基线取数见 S0-⑨；阈值定线见 S2-4）",
			hits, outformContrastFPBaseline)
	}
}
