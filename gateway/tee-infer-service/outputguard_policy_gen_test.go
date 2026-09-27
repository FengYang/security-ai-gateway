// 输出侧内容审查 — policy/ 内容资产生成器（研发计划 OG-24）。
//
// 定位：**不是常规单测**，而是内容资产的**可复现生成器**——默认跳过，
// 仅当 `POLICY_GEN=1` 时执行写盘。放在 _test.go 内的原因：
// 可直接引用 outputCategories（31 类单一事实源）与 newGuardrail()（PII/SQL/注入
// 现行规则集），避免"生成器内复制一份类目表/正则"造成双源漂移。
//
// 生成内容（技术方案 §4.2.4 词库结构）：
//
//	policy/categories.json        31 类定义（引用附录 A 的 ID/名称/族/级别/动作）
//	policy/keywords/<id>.json     28 类关键词词库（文件名 = 内部类目 ID 小写）
//	policy/regex/pii_patterns.json  A4-06 PII 正则（**迁移**自输入侧 guardrail，同口径）
//	policy/regex/injection.json     A1-07 SQL 注入正则 + 提示注入词（**迁移**自输入侧 guardrail）
//	policy/manifest.json          聚合版本号 + 逐文件 sha256
//
// 例外清单（与源文档一致，非偷懒）：
//   - A1-08「其他法律、行政法规禁止的内容」：类目定义注明为**兜底类，
//     不单独建词库，仅作映射落点**（outputguard_categories.go），故不生成文件；
//   - A1-07 / A4-06：规则形态为正则，文件置于 regex/ 下（§4.2.4 目录树），
//     故 keywords/ 下不重复生成（同类目两文件会被加载器判为重复登记而拒加载）。
//
// 词面口径（2026-09-26 起为**真料**，必须显式声明量级边界）：
//   - A1-07 / A4-06 为**真实可用规则**（迁移自输入侧现行 guardrail，可直接参与判定）；
//   - 其余 28 类 = 基词（每类 ≥5 条人工真料，取自 `testdata/lexicon-seed/seed.json`）
//     ∪ 扩量组合（`testdata/lexicon-seed/expand.json` 左×右拼接）：
//     政治类用【行为/类型表述】、歧视/商业/民事/服务类用【元表述＋常见对抗形态词】，
//     **不含具体违法内容细节、不含污名化具体群体的词条**；
//   - **已达官方建设规模档下限**（2026-09-27）：词库 ≥10000 条、A.1 每类 ≥200、A.2 每类 ≥100 ——
//     由「基词 `seed.json` ∪ 组合展开 `expand.json`」达成；**组合部分为机器生成、未经人工审核**
//     （对外提交前须逐条人工复核；逐类目量级见 TestPolicyLexiconScaleReport 报告项）；
//   - `source` 标注为 `lexicon-seed`（区别于 `lexicon-placeholder`）；D8 复核留痕见
//     `policy/review-ledger.json`（S3-2：一类目一批，条数须与词条一致，加载器强校验）。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 生成器常量。
const (
	genPolicyVersion   = "pv2026.09.27.10"
	genKeywordVersion  = "v2026.09.27.10"
	genPlaceholderEach = 5 // 每类条目下限（L0 档：每类 ≥5 正例）
	genAddedAt         = "2026-09-16"
	genReviewedAt      = "2026-09-27" // D8 复核日期（台账 reviewed_at）
	genPolicyENV       = "POLICY_GEN"
	genSeedRelPath     = "testdata/lexicon-seed/seed.json"
	genExpandRelPath   = "testdata/lexicon-seed/expand.json" // 扩量档：左×右 受控组合展开库
	genSeedSource      = "lexicon-seed"
	genSeedSubmitter   = "ai-assisted-lexicon-gen"
	// genReviewerRole D8 复核方：开发单位角色级留痕（须 ≠ submitter）。**对外具名复核由部署单位签署**
	// （见 docs/GA-部署指南.md §7 S1）——开发单位不代签、不承担其法定责任。
	genReviewerRole = "security-team"
	// genReviewLevelRole 复核级别＝角色级（对外报备须改 named，见 review_level 说明）。
	genReviewLevelRole = reviewLevelRole
	genSeedReviewerTag  = genReviewerRole
	// genRegexSubmitter 正则类目（A1-07 / A4-06）条目留痕：规则**迁移**自输入侧 guardrail，非生成。
	genRegexSubmitter = "guardrail-rule-migration"
	// 以下两个仅供测试夹具（genPlaceholderLexicon）使用，不参与 policy/ 落盘交付。
	genSubmitter = "policy-gen（占位留痕）"
	genReviewer  = "security-team（占位留痕）"
)

// policyCategoryView categories.json 的单条结构（字段名与文档一致）。
type policyCategoryView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Family        string `json:"family"`
	DefaultLevel  string `json:"default_level"`
	DefaultAction string `json:"default_action"`
	Note          string `json:"note,omitempty"`
}

// genFile 待写盘文件（path 用斜杠相对路径，与 manifest 登记一致）。
type genFile struct {
	path string
	data []byte
}

// TestGeneratePolicyAssets 生成 policy/ 内容资产（POLICY_GEN=1 时执行）。
func TestGeneratePolicyAssets(t *testing.T) {
	if os.Getenv(genPolicyENV) != "1" {
		t.Skipf("内容资产生成器：设置 %s=1 才执行（会写盘 policy/，默认跳过）", genPolicyENV)
	}
	root := "policy"

	var files []genFile

	// 1. categories.json
	files = append(files, genFile{"categories.json", mustJSON(t, genCategoriesView())})

	// 2. keywords/<id>.json（28 类真料词库：基词 seed.json ∪ 扩量展开 expand.json）
	seed := loadSeedLexicon(t)
	banks := loadExpandBanks(t)
	lex := expandLexicon(t, seed, banks)
	for _, c := range outputCategories {
		if c.ID == "A1-08" || c.ID == "A1-07" || c.ID == "A4-06" {
			continue // 例外清单：兜底类不建库 / 正则类目置于 regex/
		}
		files = append(files, genFile{
			"keywords/" + categoryFileStem(c.ID) + ".json",
			mustJSON(t, genSeedLexicon(t, lex[c.ID], c)),
		})
	}

	// 3. regex/pii_patterns.json（A4-06，迁移自输入侧 guardrail）
	files = append(files, genFile{"regex/pii_patterns.json", mustJSON(t, genPIILexicon())})

	// 4. regex/injection.json（A1-07，迁移自输入侧 guardrail）
	files = append(files, genFile{"regex/injection.json", mustJSON(t, genInjectionLexicon())})

	// 5. review-ledger.json（D8 复核台账，S3-2：一类目一批，条数须与词条一致——加载器强校验）
	files = append(files, genFile{policyReviewLedgerName, mustJSON(t, genReviewLedger(t, lex))})

	// 6. 写盘（先写资产，再算哈希写 manifest）
	for _, f := range files {
		full := filepath.Join(root, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, f.data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", full, err)
		}
	}

	// 7. manifest.json（逐文件 sha256 + 聚合版本；SelfSHA256 为"置空后字节"的摘要）
	mf := policyManifest{PolicyVersion: genPolicyVersion, SchemaVersion: lexiconSchemaVersion}
	for _, f := range files {
		mf.Files = append(mf.Files, policyManifestFile{Path: f.path, SHA256: lexiconSHA256(f.data)})
	}
	// 复算规则：将 manifest.json 的 sha256 字段置空后按 2 空格缩进重新序列化，
	// 取该字节序列的 sha256（同此处的计算方式）。
	mfPath := filepath.Join(root, policyManifestName)
	mf.SelfSHA256 = lexiconSHA256(mustJSON(t, mf))
	if err := os.WriteFile(mfPath, mustJSON(t, mf), 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", mfPath, err)
	}

	t.Logf("已生成 %d 个词库/规则文件 + %s（policy_version=%s）",
		len(files), policyManifestName, genPolicyVersion)
}

// genCategoriesView 31 类定义视图（顺序与 outputCategories 一致 = 附录 A 顺序）。
func genCategoriesView() []policyCategoryView {
	out := make([]policyCategoryView, 0, len(outputCategories))
	for _, c := range outputCategories {
		out = append(out, policyCategoryView{
			ID: c.ID, Name: c.Name, Family: c.Family,
			DefaultLevel: c.DefaultLevel, DefaultAction: c.DefaultAction, Note: c.Note,
		})
	}
	return out
}

// loadSeedLexicon 读取词库真料种子（testdata/lexicon-seed/seed.json）。
// **fail-closed**：种子缺失/解析失败即失败（不得回落到占位词面——那会让"真料"静默变回占位）。
func loadSeedLexicon(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(genSeedRelPath)
	if err != nil {
		t.Fatalf("词库真料种子缺失（%s）：%v —— 生成器不得回落到占位词面", genSeedRelPath, err)
	}
	var raw2 map[string]json.RawMessage
	if err := json.Unmarshal(raw, &raw2); err != nil {
		t.Fatalf("词库真料种子解析失败（%s）：%v", genSeedRelPath, err)
	}
	all := make(map[string][]string, len(raw2))
	for k, v := range raw2 {
		if len(k) > 0 && k[0] == '_' {
			continue // 元信息键（_note/_notGenerated 等），非类目
		}
		var words []string
		if err := json.Unmarshal(v, &words); err != nil {
			t.Fatalf("词库真料种子类目 %s 解析失败：%v", k, err)
		}
		all[k] = words
	}
	return all
}

// expandBank 单类目的组合展开库。
//
// 组合式（2026-09-27 六角色评审后扩展，用于纠正"无语法/极性校验的盲目左×右"）：
//
//	final = 基词(seed) ∪ Terms ∪ {Left×Right} ∪ {VerbRight×Left} − Drop
//
//   - Right    **名词化形态**，按 left+right 组合（如「民族」+「歧视」→「民族歧视」）；
//   - VerbRight **及物动词形态**，按 verb+left 组合（如「贬低」+「民族」→「贬低民族」）——
//     汉语及物动词须前置宾语，机器若按 left+verb 拼出「民族贬低」即为反向不成词；
//   - Terms    逐条显式词面（不参与组合；用于无法用"左×右"表达的类目，
//     如 A3-04 反垄断法定术语「滥用市场支配地位」「限定转售价格」）。
//
// 轴级排除（评审结论落地：整列被判定不成词/极性错误/纯冗余 → 删一列即生效，不必逐条删）：
//
//   - ExcludeLeft / ExcludeRight 从组合轴中剔除（**不删除任何基词**）；
//   - Drop 词面级排除（用于零散的单元格缺陷）。**不得用于删除基词**——违反即生成失败。
type expandBank struct {
	Left      []string `json:"left"`
	Right     []string `json:"right"`
	VerbRight []string `json:"verb_right,omitempty"`
	Terms     []string `json:"terms,omitempty"`
	// LeftObjects 动宾搭配**白名单**（键=左列项，值=其可搭配的右列项子集）。
	// 用于纠正"盲目左×右"造成的动宾失配：如「洗稿」只适用于文字稿件类客体，
	// 「取保候审」式乱搭即由本表禁止。缺省（无键）= 该左列可与全部右列组合。
	LeftObjects map[string][]string `json:"left_objects,omitempty"`
	// RightLefts 反向**白名单**（键=右列项，值=可与它组合的左列项子集）。
	// 用于"权利类客体只受特定动词支配"：如「隐私权」是**权利**，仅「侵害/侵犯」可带，
	// 「窃取隐私权」「出售隐私权」均不成词。缺省（无键）= 可与全部左列组合。
	RightLefts map[string][]string `json:"right_lefts,omitempty"`
	// ExcludeLeft/ExcludeRight 轴级排除（2026-09-27 六角色评审结论）。
	ExcludeLeft  []string `json:"exclude_left,omitempty"`
	ExcludeRight []string `json:"exclude_right,omitempty"`
	// Drop 词面级排除清单：把评审判定"不成词/越界/冗余"的**派生词面**逐条剔除。
	// **不得用于删除基词**（基词属人工真料，须在 seed.json 中显式处理）——违反即生成失败（fail-closed）。
	Drop []string `json:"drop,omitempty"`
}

// loadExpandBanks 读取扩量展开库（testdata/lexicon-seed/expand.json）。
// **fail-closed**：缺失/解析失败即失败（展开库缺席会让 A.1/A.2 静默退回 L0 档量级）。
func loadExpandBanks(t *testing.T) map[string]expandBank {
	t.Helper()
	raw, err := os.ReadFile(genExpandRelPath)
	if err != nil {
		t.Fatalf("扩量展开库缺失（%s）：%v", genExpandRelPath, err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("扩量展开库解析失败（%s）：%v", genExpandRelPath, err)
	}
	out := make(map[string]expandBank, len(all))
	for k, v := range all {
		if len(k) > 0 && k[0] == '_' {
			continue // 元信息键（_note/_A2note 等）
		}
		var b expandBank
		if err := json.Unmarshal(v, &b); err != nil {
			t.Fatalf("扩量展开库类目 %s 解析失败：%v", k, err)
		}
		out[k] = b
	}
	return out
}

// expandLexicon 合成各类目**最终词面**：先为全部类目**预留基词**（基词优先，派生不得抢占），
// 再按类目 ID 升序做「左×右」组合展开，全局去重（一个词面只归一个类目）。
// 目的：既满足"基词 ∪ 派生"，又不产生跨类目同名词面（跨类目重名会让 §6.1.2 分类目召回失真）。
func expandLexicon(t *testing.T, seed map[string][]string, banks map[string]expandBank) map[string][]string {
	t.Helper()
	cats := make([]string, 0, len(seed))
	for cat := range seed {
		cats = append(cats, cat)
	}
	sort.Strings(cats)

	claimed := make(map[string]string) // 词面 → 归属类目（基词先占，派生先到先得）
	for _, cat := range cats {
		for _, w := range seed[cat] {
			claimed[w] = cat
		}
	}

	out := make(map[string][]string, len(seed))
	for _, cat := range cats {
		words := append([]string(nil), seed[cat]...)
		seen := make(map[string]bool, len(words))
		for _, w := range words {
			seen[w] = true
		}
		b := banks[cat]
		drop := make(map[string]bool, len(b.Drop))
		for _, w := range b.Drop {
			if seen[w] {
				t.Fatalf("drop 清单不得删除**基词**（%s: %q）：基词属人工真料，须在 %s 中显式处理",
					cat, w, genSeedRelPath)
			}
			drop[w] = true
		}
		left := excludeAxis(b.Left, b.ExcludeLeft)
		right := excludeAxis(b.Right, b.ExcludeRight)
		if n := len(b.Left) - len(left); n > 0 || len(b.Right)-len(right) > 0 {
			t.Logf("轴级排除（评审结论）：%s 左列 −%d 项、右列 −%d 项",
				cat, n, len(b.Right)-len(right))
		}
		if len(drop) > 0 {
			t.Logf("drop 排除：%s 剔除 %d 条派生词面（评审判定不成词/越界/冗余）", cat, len(drop))
		}
		add := func(w string) {
			if w == "" || seen[w] || drop[w] {
				return
			}
			if owner, ok := claimed[w]; ok && owner != cat {
				return // 已被他类基词/派生占用：不抢（保跨类目唯一）
			}
			claimed[w] = cat
			seen[w] = true
			words = append(words, w)
		}
		// 1) 显式词面（法定术语等，不参与组合）
		for _, w := range b.Terms {
			add(w)
		}
		// 2) 名词化形态：left+right（「民族」+「歧视」→「民族歧视」）
		//    受两向搭配白名单约束：
		//      LeftObjects[l] 限定该左列可搭配的客体（「洗稿」只接文字稿件类）；
		//      RightLefts[r]  限定该权利类客体可被哪些左列支配（「侵害隐私权」✓／「窃取隐私权」✗）。
		for _, l := range left {
			allowed := asSet(b.LeftObjects[l])
			for _, r := range right {
				// 过滤"左/右互相包含"的拼接：会产生机械叠词（如「违规宣传」+「宣传」→「违规宣传宣传」、
				// 「无资质」+「资质」→「无资质资质」），无采集价值且损清单可辩护性。
				if strings.Contains(l, r) || strings.Contains(r, l) {
					continue
				}
				if allowed != nil && !allowed[r] {
					continue
				}
				if lv := asSet(b.RightLefts[r]); lv != nil && !lv[l] {
					continue
				}
				add(l + r)
			}
		}
		// 3) 及物动词形态：verb+left（「贬低」+「民族」→「贬低民族」）——纠正机器反向语序
		for _, v := range b.VerbRight {
			for _, l := range left {
				if strings.Contains(v, l) || strings.Contains(l, v) {
					continue
				}
				add(v + l)
			}
		}
		out[cat] = words
	}
	return out
}

// asSet 把字符串切片转为集合；nil/空切片返回 nil（语义为"未限定"，与"空集禁止一切"区分）。
func asSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]bool, len(items))
	for _, it := range items {
		s[it] = true
	}
	return s
}

// excludeAxis 从组合轴剔除被评审判定"整列不成词/极性错误/纯冗余"的项（保持原序，便于复现与审计）。
func excludeAxis(axis, exclude []string) []string {
	if len(exclude) == 0 {
		return axis
	}
	ex := make(map[string]bool, len(exclude))
	for _, s := range exclude {
		ex[s] = true
	}
	out := make([]string, 0, len(axis))
	for _, s := range axis {
		if !ex[s] {
			out = append(out, s)
		}
	}
	return out
}

// lexWords 类目 → 最终词面（基词 seed ∪ 扩量展开 expand），供题库生成消费（与词库生成同源）。
func lexWords(t *testing.T) map[string][]string {
	t.Helper()
	return expandLexicon(t, loadSeedLexicon(t), loadExpandBanks(t))
}

// genSeedLexicon 由类目**最终词面**生成单类词库（每类 ≥genPlaceholderEach 条；不足即失败）。
func genSeedLexicon(t *testing.T, words []string, c outputCategory) lexiconFile {
	t.Helper()
	if len(words) < genPlaceholderEach {
		t.Fatalf("类目 %s 真料词面不足：%d（应 ≥%d，来源 %s ∪ %s）",
			c.ID, len(words), genPlaceholderEach, genSeedRelPath, genExpandRelPath)
	}
	f := lexiconFile{
		SchemaVersion: lexiconSchemaVersion,
		Category:      c.ID,
		Version:       genKeywordVersion,
		Level:         mapLevelEnToZh(c.DefaultLevel),
	}
	for i, w := range words {
		f.Rules = append(f.Rules, lexiconRule{
			ID:        "kw-" + categoryFileStem(c.ID) + "-" + pad4(i+1),
			Keyword:   w,
			Type:      ruleTypeContains,
			Weight:    0.7, // contains（无边界子串）默认权重，§4.2.6
			AddedAt:   genAddedAt,
			Submitter: genSeedSubmitter,
			Reviewer:  genSeedReviewerTag,
			Comment:   "基词 " + genSeedRelPath + " ∪ 扩量组合 " + genExpandRelPath + "；**组合部分为机器生成、未经人工审核**（对外提交前须逐条人工复核）",
		})
	}
	return f
}

// genReviewLedger 生成 D8 复核台账（S3-2）：**一类目一批**，条数须与词库实际条目数一致。
// 计数与词库生成同源（类目最终词面数 / 正则迁移条数），避免"台账与词条漂移"（漂移＝加载期拒加载）。
func genReviewLedger(t *testing.T, lex map[string][]string) reviewLedger {
	t.Helper()
	g := newGuardrail()
	lg := reviewLedger{
		SchemaVersion: lexiconSchemaVersion,
		PolicyVersion: genPolicyVersion,
		// 复核级别：当前为**角色级**（reviewer = 角色名）；补具名复核后改为 named，
		// 报备形态导出（export-blocklist.ps1）仅在 named 时生成。
		ReviewLevel: genReviewLevelRole,
	}
	for _, c := range outputCategories {
		var count int
		var submitter string
		switch c.ID {
		case "A1-08":
			continue // 兜底类：不建词库（无条目），故不建台账条目
		case "A1-07":
			count, submitter = len(g.sqlPatterns)+len(g.injTerms), genRegexSubmitter
		case "A4-06":
			count, submitter = len(g.piiPatterns), genRegexSubmitter
		default:
			count, submitter = len(lex[c.ID]), genSeedSubmitter
		}
		lg.Entries = append(lg.Entries, reviewLedgerEntry{
			BatchID:      "D8-OG-" + genReviewedAt + "-" + c.ID,
			Category:     c.ID,
			EntriesCount: count,
			Submitter:    submitter,
			Reviewer:     genReviewerRole,
			ReviewedAt:   genReviewedAt,
			Conclusion:   reviewLedgerApproved,
			Note:         "开发单位内部质量活动（角色级留痕）；**对外具名复核由部署单位签署**（见 docs/GA-部署指南.md §7 S1）",
		})
	}
	return lg
}

// genPlaceholderLexicon **仅供测试夹具**使用（outputguard_policy_test.go 构造合法词库文件用）。
// 注意：内容资产生成器 TestGeneratePolicyAssets 已改走**真料种子**（见 genSeedLexicon），
// 本函数不再参与 policy/ 落盘——保留它是为了让既有夹具测试继续复用同一 schema 构造方式。
func genPlaceholderLexicon(c outputCategory) lexiconFile {
	f := lexiconFile{
		SchemaVersion: lexiconSchemaVersion,
		Category:      c.ID,
		Version:       genKeywordVersion,
		Level:         mapLevelEnToZh(c.DefaultLevel),
	}
	for i := 1; i <= genPlaceholderEach; i++ {
		f.Rules = append(f.Rules, lexiconRule{
			ID:        "kw-" + categoryFileStem(c.ID) + "-" + pad4(i),
			Keyword:   "【" + c.ID + "-示例-" + pad4(i) + "】",
			Type:      ruleTypeContains,
			Weight:    0.7,
			AddedAt:   genAddedAt,
			Submitter: genSubmitter,
			Reviewer:  genReviewer,
			Comment:   "测试夹具条目（非交付内容）",
		})
	}
	return f
}

// genPIILexicon 生成 A4-06 PII 词库（**迁移**输入侧 guardrail 的 PII 正则，同口径）。
func genPIILexicon() lexiconFile {
	g := newGuardrail()
	f := lexiconFile{
		SchemaVersion: lexiconSchemaVersion,
		Category:      "A4-06",
		Version:       genKeywordVersion,
		Level:         mustLevelZh("A4-06"),
	}
	for i, re := range g.piiPatterns {
		f.Rules = append(f.Rules, lexiconRule{
			ID:      "kw-a4-06-" + pad4(i+1),
			Keyword: re.String(), // 迁移：正则源码原文，与输入侧逐字节一致
			Type:    ruleTypeRegex,
			Weight:  1.0, // §4.2.6：PII 正则命中置信度 1.0
			// 与输入侧同口径：输入侧 PII 先半角化（normalize）再叠去空白/连字符（compactText），
			// 故此处声明 compact 档；否则全角/空格分隔的 PII 在输出侧漏检（2026-09-27 评审修复）。
			Normalize: regexNormCompact,
			AddedAt:   genAddedAt, Submitter: genRegexSubmitter, Reviewer: genReviewerRole,
			Comment: "迁移自输入侧 guardrail（同实现、同口径，normalize=compact）；命中走 maskPII 路径，非 block",
		})
	}
	return f
}

// genInjectionLexicon 生成 A1-07 注入/攻击词库（迁移 SQL 正则 + 提示注入词）。
func genInjectionLexicon() lexiconFile {
	g := newGuardrail()
	f := lexiconFile{
		SchemaVersion: lexiconSchemaVersion,
		Category:      "A1-07",
		Version:       genKeywordVersion,
		Level:         mustLevelZh("A1-07"),
	}
	n := 0
	for _, re := range g.sqlPatterns {
		n++
		f.Rules = append(f.Rules, lexiconRule{
			ID: "kw-a1-07-" + pad4(n), Keyword: re.String(), Type: ruleTypeRegex,
			Weight: 0.95, // §4.2.6：正则规则命中
			// 与输入侧同口径：输入侧先半角化（normalize）再匹配；此处声明 fold 档
			// （保留空白——SQL 规则依赖 `\s+`，不可用去空白的档位）。
			Normalize: regexNormFold,
			AddedAt:   genAddedAt, Submitter: genRegexSubmitter, Reviewer: genReviewerRole,
			Comment: "迁移自输入侧 guardrail sql_injection 规则集（normalize=fold）",
		})
	}
	for _, term := range g.injTerms {
		n++
		f.Rules = append(f.Rules, lexiconRule{
			ID: "kw-a1-07-" + pad4(n), Keyword: term, Type: ruleTypeContains,
			Weight: 0.7, // §4.2.6：关键词包含匹配
			AddedAt: genAddedAt, Submitter: genRegexSubmitter, Reviewer: genReviewerRole,
			Comment: "迁移自输入侧 guardrail prompt_injection 词表",
		})
	}
	return f
}

// mustLevelZh 取类目默认级别的中文名（词库 level 字段口径）。
func mustLevelZh(id string) string {
	c, ok := getCategory(id)
	if !ok {
		panic("词库生成器：未知类目 " + id)
	}
	return mapLevelEnToZh(c.DefaultLevel)
}

// categoryFileStem 内部 ID → 文件名词干（小写，§4.2.4 命名纪律）。
func categoryFileStem(id string) string {
	return toLowerASCII(id)
}

// toLowerASCII 仅折叠 ASCII 大写（类目 ID 形如 A1-06，避免引入 unicode 依赖）。
func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// pad4 序号补零到 4 位（条目 ID 形如 kw-a2-04-0001）。
func pad4(n int) string {
	s := ""
	for _, d := range []int{1000, 100, 10, 1} {
		s += string(rune('0' + (n/d)%10))
	}
	return s
}

// mustJSON 序列化（2 空格缩进 + 末尾换行；sha256 即对此字节计算）。
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	return append(data, '\n')
}