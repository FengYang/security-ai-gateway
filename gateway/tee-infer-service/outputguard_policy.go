// 输出侧内容审查 — 策略/词库供应链（OG-9 补完：manifest + 多类目注册表 + sha256 校验）。
//
// 对齐技术方案 §4.2.4 词库结构与 §4.8 策略/词库供应链：
//
//	policy/
//	├── manifest.json          # 聚合版本号 + 逐文件 sha256（哈希唯一出处）
//	├── keywords/a1-06.json    # 31 个类目词库（文件名 = 内部类目 ID，禁俗名）
//	└── regex/pii_patterns.json
//
// 加载期强校验（违反即拒加载，fail-closed——"正则编译失败即拒启动"纪律同源）：
//  1. manifest 可解析、schema_version 匹配、policy_version 非空、files 非空；
//  2. 每个登记文件的 sha256 与实际字节一致（**先校验后解析**：篡改文件不进解析器）；
//  3. 文件路径不得为绝对路径或含 ".."（防目录穿越）；
//  4. 每个词库文件过 §4.2.4 六条校验（由 newLexiconClassifierFromJSON 承担）；
//  5. 同一类目不得重复登记（重复＝拒加载，防"同一类目两套规则"歧义）。
//
// 未登记文件不参与加载（manifest 是**唯一出处**，避免"加了文件忘了登记"的静默生效）。
//
// 与 manifest 自身哈希：`sha256` 字段为 manifest 自身摘要，供**外部**锚定使用，
// 启动期无法自校验（自身哈希不可能内嵌于自身），故仅校验非空/格式。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// policyManifestName manifest 文件名（policy 根目录下）。
const policyManifestName = "manifest.json"

// policyCategoriesName 类目索引文档名（31 类定义，与代码内 outputCategories 同源）。
// 加载器只对其做哈希校验，**不解析为词库**（形态为数组，非 lexiconFile）。
const policyCategoriesName = "categories.json"

// policyManifest policy/manifest.json 结构（§4.2.4，M1 冻结项）。
type policyManifest struct {
	PolicyVersion string               `json:"policy_version"`
	SchemaVersion string               `json:"schema_version"`
	Files         []policyManifestFile `json:"files"`
	SelfSHA256    string               `json:"sha256,omitempty"`
}

// policyManifestFile 单文件登记项（路径 + 期望 sha256）。
type policyManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// 热加载失败原因（otpmask_output_guard_policy_rollback_total{reason=...} 与
// output_guard_policy_reload/rolled_back 审计归因；§3.6.4、§4.10 指标目录）。
const (
	policyErrHashMismatch     = "hash_mismatch"     // 登记 sha256 与文件字节不一致（篡改/未同步）
	policyErrInvalidJSON      = "invalid_json"      // manifest/词库 JSON 不可解析
	policyErrSchemaInvalid    = "schema_invalid"    // schema_version/字段/level 等不合规
	policyErrCategoryInvalid  = "category_invalid"  // category 不在附录 A 31 类内
	policyErrUnsafePath       = "unsafe_path"       // 登记路径为绝对路径/含 ".."/盘符
	policyErrDuplicateCategory = "duplicate_category" // 同一类目重复登记
	policyErrRegexInvalid     = "regex_invalid"     // 正则规则不可编译
	policyErrReadError        = "read_error"        // 文件不可读
)

// policyLoadError 携带归类原因的加载错误（供热加载回退的指标/审计归因）。
type policyLoadError struct {
	Kind string
	Err  error
}

func (e *policyLoadError) Error() string { return e.Err.Error() }
func (e *policyLoadError) Unwrap() error { return e.Err }

// plErr 构造带原因分类的加载错误。
func plErr(kind, format string, a ...any) error {
	return &policyLoadError{Kind: kind, Err: fmt.Errorf(format, a...)}
}

// PolicyLoadErrorKind 提取加载错误的原因分类（非策略加载错误统一归 invalid_json 之外的未知类，
// 以 "unknown" 显式暴露而非伪造原因）。
func PolicyLoadErrorKind(err error) string {
	var ple *policyLoadError
	if errors.As(err, &ple) {
		return ple.Kind
	}
	return "unknown"
}

// classifyLexiconLoadErr 把词库解析器（newLexiconClassifierFromJSON）产生的错误归因到
// 回退原因枚举。归因标记串全部为本仓库加载器自己产出的固定中文文案，故按包含关系归类是封闭的。
func classifyLexiconLoadErr(err error) string {
	var ple *policyLoadError
	if errors.As(err, &ple) {
		return ple.Kind
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "JSON 解析失败"):
		return policyErrInvalidJSON
	case strings.Contains(msg, "正则"):
		return policyErrRegexInvalid
	case strings.Contains(msg, "category") || strings.Contains(msg, "类目"):
		return policyErrCategoryInvalid
	default:
		// schema_version / level / version / rules 为空等结构合规问题
		return policyErrSchemaInvalid
	}
}

// lexiconRegistry 多类目词库注册表（实现 OutputClassifier）。
//
// 匹配优先级（§6.1.1「多类目交叉：返回优先级最高的类目（PII > 正则 > 关键词）」）：
// 含 regex 规则的类目（PII / 注入 / SQL 等结构化强证据）排在纯关键词类目之前；
// 同优先级内按内部类目 ID 升序（顺序确定，可复现）。
type lexiconRegistry struct {
	policyVersion string
	manifestSHA   string // manifest.json 自锚定摘要（§4.2.4；进热加载审计 sha256 附字段）
	classifiers   []*lexiconClassifier // 已按优先级排序
	byCategory    map[string]*lexiconClassifier
}

// loadPolicyDir 从 policy 根目录加载全量词库（manifest 驱动）。
// 任何一步失败即返回错误（调用方 fail-closed：不得静默降级为"无词库"）。
func loadPolicyDir(dir string) (*lexiconRegistry, error) {
	if dir == "" {
		return nil, fmt.Errorf("policy 目录为空")
	}
	manifestPath := filepath.Join(dir, policyManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, plErr(policyErrReadError, "读取 %s 失败: %v", policyManifestName, err)
	}
	var mf policyManifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		return nil, plErr(policyErrInvalidJSON, "%s JSON 解析失败: %v", policyManifestName, err)
	}
	if mf.SchemaVersion != lexiconSchemaVersion {
		return nil, plErr(policyErrSchemaInvalid, "%s schema_version=%q 不匹配（期望 %q）",
			policyManifestName, mf.SchemaVersion, lexiconSchemaVersion)
	}
	if mf.PolicyVersion == "" {
		return nil, plErr(policyErrSchemaInvalid, "%s policy_version 为空", policyManifestName)
	}
	if len(mf.Files) == 0 {
		return nil, plErr(policyErrSchemaInvalid, "%s files 为空（聚合清单不得为空）", policyManifestName)
	}

	reg := &lexiconRegistry{
		policyVersion: mf.PolicyVersion,
		manifestSHA:   mf.SelfSHA256,
		byCategory:    make(map[string]*lexiconClassifier, len(mf.Files)),
	}

	for i, f := range mf.Files {
		if err := checkPolicyRelPath(f.Path); err != nil {
			return nil, plErr(policyErrUnsafePath, "%s files[%d]: %v", policyManifestName, i, err)
		}
		if len(f.SHA256) != 64 {
			return nil, plErr(policyErrSchemaInvalid, "%s files[%d] (%s): sha256 长度非法（期望 64 hex）",
				policyManifestName, i, f.Path)
		}
		// 先校验哈希，再解析：篡改文件不进解析器。
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			return nil, plErr(policyErrReadError, "读取词库文件 %s 失败: %v", f.Path, err)
		}
		if got := lexiconSHA256(data); !strings.EqualFold(got, f.SHA256) {
			return nil, plErr(policyErrHashMismatch, "词库文件 %s sha256 不匹配（期望 %s，实际 %s）：文件被篡改或 manifest 未同步",
				f.Path, f.SHA256, got)
		}
		// 类目索引文档：哈希已校验（防篡改），不参与词库解析。
		if f.Path == policyCategoriesName {
			continue
		}
		lc, err := newLexiconClassifierFromJSON(data)
		if err != nil {
			return nil, plErr(classifyLexiconLoadErr(err), "词库文件 %s 加载失败: %v", f.Path, err)
		}
		if _, dup := reg.byCategory[lc.Category()]; dup {
			return nil, plErr(policyErrDuplicateCategory, "类目 %s 重复登记（%s）：同一类目不得两套规则",
				lc.Category(), f.Path)
		}
		reg.byCategory[lc.Category()] = lc
		reg.classifiers = append(reg.classifiers, lc)
	}

	// 优先级排序：含 regex 的类目（结构化强证据）在前；同类按类目 ID 升序。
	sort.SliceStable(reg.classifiers, func(i, j int) bool {
		ri, rj := reg.classifiers[i].hasRegexRules(), reg.classifiers[j].hasRegexRules()
		if ri != rj {
			return ri
		}
		return reg.classifiers[i].Category() < reg.classifiers[j].Category()
	})

	return reg, nil
}

// checkPolicyRelPath 校验 manifest 登记路径为相对路径且不含上跳（防目录穿越）。
func checkPolicyRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("path 为空")
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.Contains(p, ":") {
		return fmt.Errorf("path=%q 必须为相对路径", p)
	}
	for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
		if seg == ".." {
			return fmt.Errorf("path=%q 不得含 \"..\"", p)
		}
	}
	return nil
}

// Classify 实现 OutputClassifier：按优先级顺序取首个命中类目。
func (r *lexiconRegistry) Classify(text string) (string, float64, string) {
	for _, lc := range r.classifiers {
		if cat, conf, match := lc.Classify(text); cat != "" {
			return cat, conf, match
		}
	}
	return "", 0, ""
}

// PolicyVersion 返回聚合策略版本（进审计与 chunk-meta）。
func (r *lexiconRegistry) PolicyVersion() string { return r.policyVersion }

// ManifestSHA 返回加载时 manifest.json 的自锚定摘要（热加载审计 sha256 附字段）。
func (r *lexiconRegistry) ManifestSHA() string { return r.manifestSHA }

// readPolicyManifestSelfSHA 尽力读取指定策略目录 manifest.json 的自锚定摘要。
// 仅供**加载失败**回退留痕使用：读取/解析失败一律返回空串（不掩盖真正的加载错误）。
func readPolicyManifestSelfSHA(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, policyManifestName))
	if err != nil {
		return ""
	}
	var mf policyManifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		return ""
	}
	return mf.SelfSHA256
}

// CategoryCount 返回已加载类目数（供 /config 快照 l1_categories_loaded）。
func (r *lexiconRegistry) CategoryCount() int { return len(r.classifiers) }

// RuleCount 返回已加载规则总条数（供 /config 快照 l1_rules_total）。
func (r *lexiconRegistry) RuleCount() int {
	n := 0
	for _, lc := range r.classifiers {
		n += lc.RuleCount()
	}
	return n
}

// MaxKeywordRunes 返回全词库最长关键词 rune 数（供派生 P-WINDOW-CHARS，§5.4）。
func (r *lexiconRegistry) MaxKeywordRunes() int {
	max := 0
	for _, lc := range r.classifiers {
		if n := lc.MaxKeywordRunes(); n > max {
			max = n
		}
	}
	return max
}

// Categories 返回已加载类目 ID 列表（有序，供测试与运维核对）。
func (r *lexiconRegistry) Categories() []string {
	out := make([]string, 0, len(r.classifiers))
	for _, lc := range r.classifiers {
		out = append(out, lc.Category())
	}
	return out
}