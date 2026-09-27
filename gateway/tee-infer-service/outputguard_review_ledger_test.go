// 输出侧内容审查 — D8 复核台账加载期校验（S3-2）单测。
//
// 覆盖：
//   - 已登记台账：结构/结论/发起人≠复核人/覆盖完整性 → 不合规即拒加载（fail-closed）；
//   - 未登记台账：不校验（兼容最小夹具与历史资产，沿用改造前行为）；
//   - 仓库真实资产：必须已登记台账且可加载（跑量随词条同步）。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withLedger 把台账登记进最小资产集（写入文件 + 追加 manifest 登记项）。
func withLedger(t *testing.T, files map[string][]byte, entries []reviewLedgerEntry) map[string][]byte {
	t.Helper()
	data := mustJSON(t, reviewLedger{
		SchemaVersion: lexiconSchemaVersion,
		PolicyVersion: "pv-test",
		Entries:       entries,
	})
	var mf policyManifest
	if err := json.Unmarshal(files[policyManifestName], &mf); err != nil {
		t.Fatalf("解析 manifest: %v", err)
	}
	mf.Files = append(mf.Files, policyManifestFile{Path: policyReviewLedgerName, SHA256: lexiconSHA256(data)})
	files[policyReviewLedgerName] = data
	files[policyManifestName] = mustJSON(t, mf)
	return files
}

// okLedgerEntry 合规台账条目（最小资产集 A1-06 = 5 条）。
func okLedgerEntry() reviewLedgerEntry {
	return reviewLedgerEntry{
		BatchID:      "D8-OG-test-01",
		Category:     "A1-06",
		EntriesCount: 5,
		Submitter:    "ai-assisted-lexicon-gen",
		Reviewer:     "security-team",
		ReviewedAt:   "2026-09-27",
		Conclusion:   reviewLedgerApproved,
	}
}

// TestReviewLedgerLoadGate 台账登记后的各类拒加载场景与放行场景。
func TestReviewLedgerLoadGate(t *testing.T) {
	t.Run("合规台账可加载", func(t *testing.T) {
		files := withLedger(t, minimalPolicyFiles(t), []reviewLedgerEntry{okLedgerEntry()})
		if _, err := loadPolicyDir(writeTempPolicy(t, files)); err != nil {
			t.Fatalf("合规台账不应拒加载: %v", err)
		}
	})

	t.Run("覆盖数不符（台账未随词条同步）", func(t *testing.T) {
		e := okLedgerEntry()
		e.EntriesCount = 4
		files := withLedger(t, minimalPolicyFiles(t), []reviewLedgerEntry{e})
		_, err := loadPolicyDir(writeTempPolicy(t, files))
		if err == nil || !strings.Contains(err.Error(), "台账覆盖") {
			t.Fatalf("覆盖数不符应被拒，实际: %v", err)
		}
		if got := PolicyLoadErrorKind(err); got != policyErrReviewLedgerInvalid {
			t.Fatalf("原因分类应为 %s，实际 %s", policyErrReviewLedgerInvalid, got)
		}
	})

	t.Run("发起人=复核人", func(t *testing.T) {
		e := okLedgerEntry()
		e.Reviewer = e.Submitter
		files := withLedger(t, minimalPolicyFiles(t), []reviewLedgerEntry{e})
		_, err := loadPolicyDir(writeTempPolicy(t, files))
		if err == nil || !strings.Contains(err.Error(), "必须不同") {
			t.Fatalf("发起人=复核人应被拒，实际: %v", err)
		}
	})

	t.Run("结论非 approved", func(t *testing.T) {
		e := okLedgerEntry()
		e.Conclusion = "pending"
		files := withLedger(t, minimalPolicyFiles(t), []reviewLedgerEntry{e})
		_, err := loadPolicyDir(writeTempPolicy(t, files))
		if err == nil || !strings.Contains(err.Error(), "conclusion") {
			t.Fatalf("未通过复核应被拒，实际: %v", err)
		}
	})

	t.Run("台账引用未加载类目", func(t *testing.T) {
		e := okLedgerEntry()
		e.Category = "A2-01"
		files := withLedger(t, minimalPolicyFiles(t), []reviewLedgerEntry{e})
		_, err := loadPolicyDir(writeTempPolicy(t, files))
		if err == nil || !strings.Contains(err.Error(), "不在本次加载的类目内") {
			t.Fatalf("台账与词库不同步应被拒，实际: %v", err)
		}
	})

	t.Run("policy_version 不一致", func(t *testing.T) {
		lg := reviewLedger{
			SchemaVersion: lexiconSchemaVersion,
			PolicyVersion: "pv-other",
			Entries:       []reviewLedgerEntry{okLedgerEntry()},
		}
		files := withLedger(t, minimalPolicyFiles(t), lg.Entries)
		// withLedger 固定写 pv-test，此处改为不一致版本并同步 manifest 哈希。
		files[policyReviewLedgerName] = mustJSON(t, lg)
		var mf policyManifest
		_ = json.Unmarshal(files[policyManifestName], &mf)
		for i := range mf.Files {
			if mf.Files[i].Path == policyReviewLedgerName {
				mf.Files[i].SHA256 = lexiconSHA256(files[policyReviewLedgerName])
			}
		}
		files[policyManifestName] = mustJSON(t, mf)
		_, err := loadPolicyDir(writeTempPolicy(t, files))
		if err == nil || !strings.Contains(err.Error(), "policy_version") {
			t.Fatalf("版本不一致应被拒，实际: %v", err)
		}
	})

	t.Run("未登记台账则不校验", func(t *testing.T) {
		if _, err := loadPolicyDir(writeTempPolicy(t, minimalPolicyFiles(t))); err != nil {
			t.Fatalf("未登记台账应沿用改造前行为（不校验）: %v", err)
		}
	})
}

// TestPolicyReviewLedgerRegistered 仓库真实资产必须已登记复核台账（S3-2：
// 发布门禁要求携带留痕；真实目录加载即触发台账覆盖校验）。
func TestPolicyReviewLedgerRegistered(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(policyDirReal, policyManifestName))
	if err != nil {
		t.Fatalf("读取 manifest: %v", err)
	}
	var mf policyManifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		t.Fatalf("解析 manifest: %v", err)
	}
	registered := false
	for _, f := range mf.Files {
		if f.Path == policyReviewLedgerName {
			registered = true
		}
	}
	if !registered {
		t.Fatalf("真实资产 manifest 未登记 %s（D8 复核留痕缺失）", policyReviewLedgerName)
	}
	// 加载即校验台账覆盖（覆盖不全/结论非 approved 会在此失败）。
	if _, err := loadPolicyDir(policyDirReal); err != nil {
		t.Fatalf("真实资产台账校验失败: %v", err)
	}
}
