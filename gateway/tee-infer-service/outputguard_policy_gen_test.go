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
// 词面口径（必须显式声明，勿误读为"已完成真实词库"）：
//   - A1-07 / A4-06 为**真实可用规则**（迁移自输入侧现行 guardrail，可直接参与判定）；
//   - 其余 28 类为**结构完整的占位条目**（词面形如「【A2-04-示例-01】」），
//     schema / manifest / 签名校验 / 质量门禁全链可跑通，**真实词面待安全团队
//     按 §4.2.4 schema 填充**（词库变更属高敏变更，须走 D8 双审，故占位条目
//     的 submitter/reviewer 亦为占位留痕，填充时须整体替换）。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 生成器常量。
const (
	genPolicyVersion   = "pv2026.09.16"
	genKeywordVersion  = "v2026.09.16"
	genPlaceholderEach = 5 // 每类占位条目数（OG-24：每类 ≥5 正例）
	genAddedAt         = "2026-09-16"
	genSubmitter       = "policy-gen（占位留痕）"
	genReviewer        = "security-team（占位留痕）"
	genPolicyENV       = "POLICY_GEN"
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

	// 2. keywords/<id>.json（28 类占位词库）
	for _, c := range outputCategories {
		if c.ID == "A1-08" || c.ID == "A1-07" || c.ID == "A4-06" {
			continue // 例外清单：兜底类不建库 / 正则类目置于 regex/
		}
		files = append(files, genFile{
			"keywords/" + categoryFileStem(c.ID) + ".json",
			mustJSON(t, genPlaceholderLexicon(c)),
		})
	}

	// 3. regex/pii_patterns.json（A4-06，迁移自输入侧 guardrail）
	files = append(files, genFile{"regex/pii_patterns.json", mustJSON(t, genPIILexicon())})

	// 4. regex/injection.json（A1-07，迁移自输入侧 guardrail）
	files = append(files, genFile{"regex/injection.json", mustJSON(t, genInjectionLexicon())})

	// 5. 写盘（先写资产，再算哈希写 manifest）
	for _, f := range files {
		full := filepath.Join(root, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, f.data, 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", full, err)
		}
	}

	// 6. manifest.json（逐文件 sha256 + 聚合版本；SelfSHA256 为"置空后字节"的摘要）
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

// genPlaceholderLexicon 生成单类占位词库（词面 = 「【<ID>-示例-<n>】」，结构完整）。
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
			Weight:    0.7, // contains（无边界子串）默认权重，§4.2.6
			AddedAt:   genAddedAt,
			Submitter: genSubmitter,
			Reviewer:  genReviewer,
			Comment:   "占位条目：待安全团队按 §4.2.4 schema 填充真实词面（变更走 D8 双审）",
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
			AddedAt: genAddedAt, Submitter: genSubmitter, Reviewer: genReviewer,
			Comment: "迁移自输入侧 guardrail（同实现、同口径）；命中走 maskPII 路径，非 block",
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
			AddedAt: genAddedAt, Submitter: genSubmitter, Reviewer: genReviewer,
			Comment: "迁移自输入侧 guardrail sql_injection 规则集",
		})
	}
	for _, term := range g.injTerms {
		n++
		f.Rules = append(f.Rules, lexiconRule{
			ID: "kw-a1-07-" + pad4(n), Keyword: term, Type: ruleTypeContains,
			Weight: 0.7, // §4.2.6：关键词包含匹配
			AddedAt: genAddedAt, Submitter: genSubmitter, Reviewer: genReviewer,
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