// 输出侧内容审查 — D8 高敏复核台账（S3-2：词库/策略发布的复核留痕）。
//
// 定位（与 outputguard_lexicon.go 的分工）：
//
//	条目级：每条词条自带 submitter/reviewer，由 newLexiconClassifierFromJSON 强校验
//	        「非空且 submitter≠reviewer」（谁提交、谁复核，逐条可查）；
//	批次级：本文件补**复核台账**——谁在何时复核了哪个类目、多少条、结论为何，
//	        并要求台账覆盖数与该类目**实际词条数一致**（台账未随词条同步即拒加载）。
//
// 纪律（与 §4.2.4「先校验后解析」同源）：
//   - 台账经 manifest.files 登记 → 与词库一同被 sha256 锚定（篡改即 hash_mismatch）；
//   - **已登记则强校验**：结构不合规 / 结论非 approved / 发起人=复核人 / 覆盖数不符 → 拒加载（fail-closed）；
//   - **未登记则不校验**：兼容最小夹具与历史资产；发布门禁（scripts/policy-publish.ps1）
//     强制要求登记台账，故任何**已发布版本**必然携带并已过本校验。
//
// 角色级留痕说明：reviewer 允许为**角色名**（如 security-team），此时应在 note 中标注
// 「角色级留痕、具名待补」——不得把角色名当作具名复核人对外举证。
package main

import (
	"encoding/json"
	"fmt"
)

// policyReviewLedgerName 复核台账文件名（policy 根目录下）。
const policyReviewLedgerName = "review-ledger.json"

// reviewLedgerApproved 复核结论唯一放行取值（未通过复核不得发布）。
const reviewLedgerApproved = "approved"

// 复核级别（台账级）：
//   - role  = 开发单位**角色级留痕**（reviewer 为角色名，如 security-team）→ **不得用于对外报备**；
//   - named = **部署单位具名复核**（reviewer 为部署单位指定的具名责任人）；
//   - 缺省（历史台账未携带该字段）= 按 role 处理（保守降级：不视为已具名）。
//
// 责任边界（2026-09-27 定）：具名复核属**部署单位**职责，开发单位只做开发/测试/内部审查，
// 不代签、不承担其法定责任；需具名/签署的事项清单见 docs/GA-部署指南.md §7（原独立清单已并入该章）。
// 用途：报备形态导出（scripts/export-blocklist.ps1）仅在 named 时生成；
// 加载与版本发布不因此受阻断（**对外物**须具名，内部版本管理不必）。
const (
	reviewLevelRole  = "role"
	reviewLevelNamed = "named"
)

// reviewLedger 复核台账顶层结构。
type reviewLedger struct {
	SchemaVersion string              `json:"schema_version"`
	PolicyVersion string              `json:"policy_version"`
	ReviewLevel   string              `json:"review_level,omitempty"` // role | named（缺省 = role）
	Entries       []reviewLedgerEntry `json:"entries"`
}

// reviewLedgerEntry 单批复核记录（**一类目一批**，避免"条数归属多类目"的歧义）。
type reviewLedgerEntry struct {
	BatchID      string `json:"batch_id"`      // 复核批次号（唯一，供追溯）
	Category     string `json:"category"`      // 内部类目 ID（大写，如 A1-01）
	EntriesCount int    `json:"entries_count"` // 本批覆盖条数（须 = 该类目实际词条数）
	Submitter    string `json:"submitter"`     // 提交方（角色名）
	Reviewer     string `json:"reviewer"`      // 复核方（角色名；须 ≠ submitter）
	ReviewedAt   string `json:"reviewed_at"`   // 复核日期（YYYY-MM-DD）
	Conclusion   string `json:"conclusion"`    // 结论（仅 approved 放行）
	Note         string `json:"note,omitempty"`
}

// parseAndValidateReviewLedger 解析台账并校验其对本注册表的覆盖完整性。
// 返回 nil 表示台账合规且覆盖全部已加载类目（逐类目条数一致）。
func parseAndValidateReviewLedger(data []byte, reg *lexiconRegistry) error {
	var lg reviewLedger
	if err := json.Unmarshal(data, &lg); err != nil {
		return plErr(policyErrInvalidJSON, "%s JSON 解析失败: %v", policyReviewLedgerName, err)
	}
	if lg.SchemaVersion != lexiconSchemaVersion {
		return plErr(policyErrSchemaInvalid, "%s schema_version=%q 不匹配（期望 %q）",
			policyReviewLedgerName, lg.SchemaVersion, lexiconSchemaVersion)
	}
	if lg.PolicyVersion != reg.policyVersion {
		return plErr(policyErrSchemaInvalid, "%s policy_version=%q 与 manifest 的 %q 不一致",
			policyReviewLedgerName, lg.PolicyVersion, reg.policyVersion)
	}
	if len(lg.Entries) == 0 {
		return plErr(policyErrReviewLedgerInvalid, "%s entries 为空（复核台账不得为空）", policyReviewLedgerName)
	}
	if lg.ReviewLevel != "" && lg.ReviewLevel != reviewLevelRole && lg.ReviewLevel != reviewLevelNamed {
		return plErr(policyErrReviewLedgerInvalid,
			"%s review_level=%q 非法（取值：%s | %s，或留空＝按 %s 处理）",
			policyReviewLedgerName, lg.ReviewLevel, reviewLevelRole, reviewLevelNamed, reviewLevelRole)
	}

	covered := make(map[string]int, len(lg.Entries))
	for i, e := range lg.Entries {
		tag := fmt.Sprintf("%s entries[%d]", policyReviewLedgerName, i)
		if e.BatchID == "" || e.Category == "" || e.ReviewedAt == "" {
			return plErr(policyErrReviewLedgerInvalid, "%s: batch_id/category/reviewed_at 不能为空", tag)
		}
		if e.Submitter == "" || e.Reviewer == "" {
			return plErr(policyErrReviewLedgerInvalid, "%s (%s): submitter/reviewer 不能为空", tag, e.Category)
		}
		if e.Submitter == e.Reviewer {
			return plErr(policyErrReviewLedgerInvalid, "%s (%s): submitter=reviewer=%q（必须不同）",
				tag, e.Category, e.Submitter)
		}
		if e.Conclusion != reviewLedgerApproved {
			return plErr(policyErrReviewLedgerInvalid, "%s (%s): conclusion=%q 非 %q（未通过复核不得随版本发布）",
				tag, e.Category, e.Conclusion, reviewLedgerApproved)
		}
		if e.EntriesCount <= 0 {
			return plErr(policyErrReviewLedgerInvalid, "%s (%s): entries_count=%d 须 > 0",
				tag, e.Category, e.EntriesCount)
		}
		if _, ok := reg.byCategory[e.Category]; !ok {
			return plErr(policyErrReviewLedgerInvalid,
				"%s: category=%q 不在本次加载的类目内（台账与词库不同步）", tag, e.Category)
		}
		covered[e.Category] += e.EntriesCount
	}

	for _, lc := range reg.classifiers {
		cat := lc.Category()
		if got, want := covered[cat], lc.RuleCount(); got != want {
			return plErr(policyErrReviewLedgerInvalid,
				"类目 %s 台账覆盖 %d 条 ≠ 词库实际 %d 条（复核台账未随词条同步）", cat, got, want)
		}
	}
	return nil
}
