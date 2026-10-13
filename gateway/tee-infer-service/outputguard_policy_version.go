// 输出侧内容审查 — 策略/词库**版本库**（S1-4 / G21：版本快照 · bench 硬门禁 · 显式引用 · 可回滚）。
//
// 定位（与 OG-9 的分工）：
//
//	OG-9（outputguard_policy.go + POST /config/policy/reload）解决"**重读**当前目录"；
//	本文件解决"**用哪个版本**"——版本库是**只读输入**，运行时只做
//	「发现 / 门禁校验 / 显式引用 / 回滚」，**不写盘**。
//
// 只读约束（为什么"草稿→发布"的写入不在本进程内）：
//
//	tee-infer 运行于 readOnlyRootFilesystem，policy 由镜像/只读卷分发；
//	故快照写入属**离线**步骤（scripts/policy-publish.ps1），本进程只消费其产物。
//
// 目录结构（与现有 policy/ 同处一个只读分发单元，**不新增挂载**）：
//
//	policy/
//	├── manifest.json + categories.json + keywords/ + regex/   ← 当前生效版本入口（既有路径不变）
//	└── versions/
//	    ├── index.json            ← 版本索引（唯一出处：版本条目 + 门禁基线）
//	    └── <policy_version>/     ← 每版本一份完整快照（manifest + 词库 + bench.json）
//
// 向后兼容（**零行为变更**）：**无 versions/index.json ⇒ 本文件全部能力不启用**，
//
//	启动加载、/config/policy/reload、数据面审查行为均与改造前完全一致。
//
// bench 硬门禁口径（2026-09-26 裁定）：「**不低于已登记基线且不可回退**」——
//
//	逐维比较：rule_detect ≥ 基线、semantic_detect ≥ 基线、fp ≤ 基线，且**语料指纹须与基线一致**
//	（语料不同即不可比 → 拒绝，避免"换套题库显得更好"）。
//	**不套用 Phase 2 门禁 #1 的 ≥95% 目标线**：该线属语义后端选型（S3-4）后的目标，
//	现状 semantic 水位为 12%（选型未落地），直接套用将使任何版本都无法发布。
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// 版本库文件名（policy/versions/ 下）。
const (
	policyVersionsDirName   = "versions"
	policyVersionsIndexName = "index.json"
	policyBenchName         = "bench.json"
)

// 版本状态：**仅 published 允许被引用**（draft = 草稿，可归档但不可 activate）。
const (
	policyStatusPublished = "published"
	policyStatusDraft     = "draft"
)

// 版本库加载/门禁失败原因（进 policy_rollback_total / policy_activate_total 指标与审计归因）。
// 与 outputguard_policy.go 的 policyErr* 同属一套原因词汇表。
const (
	policyErrVersionsNotConfigured = "versions_not_configured" // 无 versions/index.json（能力未启用）
	policyErrVersionNotFound       = "version_not_found"       // 索引未登记该版本
	policyErrVersionNotPublished   = "version_not_published"   // 版本为 draft
	policyErrBaselineNotRegistered = "baseline_not_registered" // 索引未登记基线（须由发布脚本自举）
	policyErrBenchMissing          = "bench_missing"           // 快照缺 bench.json（未过评测）
	policyErrBenchNotPassed        = "bench_not_passed"        // bench.passed=false
	policyErrBenchCorpusMismatch   = "bench_corpus_mismatch"   // 语料指纹与基线不一致（不可比）
	policyErrBenchRegression       = "bench_regression"        // 指标低于基线（检出↓ 或 误报↑）
	policyErrNoPreviousVersion     = "no_previous_version"     // 无可回滚的上一版本
)

// policyVersionIndex versions/index.json：版本索引（唯一出处）。
type policyVersionIndex struct {
	SchemaVersion string               `json:"schema_version"`
	Baseline      *policyBenchBaseline `json:"baseline,omitempty"`
	Versions      []policyVersionEntry `json:"versions"`
}

// policyVersionEntry 单个版本条目。
type policyVersionEntry struct {
	Version   string `json:"version"`
	Dir       string `json:"dir,omitempty"` // 快照目录名（缺省 = Version）
	Status    string `json:"status"`        // published | draft
	Note      string `json:"note,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// policyBenchBaseline 门禁基线（"不可回退"的比较基准；由发布脚本首次自举写入）。
type policyBenchBaseline struct {
	RuleDetect     float64 `json:"rule_detect"`     // 确定性攻击族检出率（不得下降）
	SemanticDetect float64 `json:"semantic_detect"` // 语义族检出率（不得下降）
	FP             float64 `json:"fp"`              // 误报率（不得上升）
	CorpusSHA256   string  `json:"corpus_sha256"`   // 基线语料指纹（不一致即不可比）
	// 输出侧维度（2026-09-27 新增，可选）：取自**输出侧词库 + 题库**自身，与上面三维
	// （输入侧 guardrail 口径）互补——上面三维度量的是输入侧分类器，不覆盖 policy/ 词库内容。
	// 缺省（null）= 未登记，此时由 TestPolicyOutputSideGateNotRegress 以"不劣于登记值"口径约束。
	OutputDetect *float64 `json:"output_detect,omitempty"` // 黄金正例归入自身类目的比例（不得下降）
	OutputFP     *float64 `json:"output_fp,omitempty"`     // 黄金负例被任一类目命中的比例（不得上升）
}

// policyBenchRecord 版本快照内的评测记录（versions/<v>/bench.json，由评测跑道产出）。
type policyBenchRecord struct {
	Version        string  `json:"version"`
	CorpusSHA256   string  `json:"corpus_sha256"`
	RuleDetect     float64 `json:"rule_detect"`
	SemanticDetect float64 `json:"semantic_detect"`
	FP             float64 `json:"fp"`
	Passed         bool    `json:"passed"`
	GeneratedAt    string  `json:"generated_at,omitempty"`
	Source         string  `json:"source,omitempty"` // 记录来源（如 keyword-baseline.json），供追溯
}

// loadPolicyVersionIndex 读取版本索引。
// 返回 (nil, versions_not_configured) 表示**版本库未启用**——调用方据此保持既有行为（零变更）。
func loadPolicyVersionIndex(policyDir string) (*policyVersionIndex, error) {
	if policyDir == "" {
		return nil, plErr(policyErrVersionsNotConfigured, "未配置策略目录")
	}
	path := filepath.Join(policyDir, policyVersionsDirName, policyVersionsIndexName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, plErr(policyErrVersionsNotConfigured,
				"未找到 %s/%s（版本库未启用，行为不变）", policyVersionsDirName, policyVersionsIndexName)
		}
		return nil, plErr(policyErrReadError, "读取 %s 失败: %v", policyVersionsIndexName, err)
	}
	var idx policyVersionIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, plErr(policyErrInvalidJSON, "%s JSON 解析失败: %v", policyVersionsIndexName, err)
	}
	if idx.SchemaVersion != lexiconSchemaVersion {
		return nil, plErr(policyErrSchemaInvalid, "%s schema_version=%q 不匹配（期望 %q）",
			policyVersionsIndexName, idx.SchemaVersion, lexiconSchemaVersion)
	}
	return &idx, nil
}

// entryOf 在索引中查版本条目（未登记 → version_not_found）。
func (idx *policyVersionIndex) entryOf(version string) (*policyVersionEntry, error) {
	if version == "" {
		return nil, plErr(policyErrVersionNotFound, "版本号为空")
	}
	for i := range idx.Versions {
		if idx.Versions[i].Version == version {
			return &idx.Versions[i], nil
		}
	}
	return nil, plErr(policyErrVersionNotFound, "索引未登记版本 %q", version)
}

// policyVersionNames 返回索引中登记的版本号（有序，供 /config 快照与列表端点）。
func (idx *policyVersionIndex) policyVersionNames() []string {
	out := make([]string, 0, len(idx.Versions))
	for i := range idx.Versions {
		out = append(out, idx.Versions[i].Version)
	}
	return out
}

// policySnapshotDir 解析版本快照目录（含路径安全校验，防目录穿越）。
func (s *teeServer) policySnapshotDir(version string) (string, error) {
	idx, err := loadPolicyVersionIndex(s.outputGuardPolicyDir)
	if err != nil {
		return "", err
	}
	e, err := idx.entryOf(version)
	if err != nil {
		return "", err
	}
	if e.Status != policyStatusPublished {
		return "", plErr(policyErrVersionNotPublished,
			"版本 %q 状态为 %q（仅 %s 可被引用）", version, e.Status, policyStatusPublished)
	}
	dir := e.Dir
	if dir == "" {
		dir = version
	}
	if filepath.IsAbs(dir) || strings.Contains(dir, ":") {
		return "", plErr(policyErrUnsafePath, "版本 %q 快照目录 %q 须为相对路径", version, dir)
	}
	rel := policyVersionsDirName + "/" + dir
	if err := checkPolicyRelPath(rel); err != nil {
		return "", plErr(policyErrUnsafePath, "版本 %q 快照路径非法: %v", version, err)
	}
	return filepath.Join(s.outputGuardPolicyDir, policyVersionsDirName, filepath.FromSlash(dir)), nil
}

// checkPolicyBenchGate 执行 bench 硬门禁（**只读校验**；不在生产路径跑评测框架）。
//
// 检查顺序（先"能不能比"，再"比得过"）：基线已登记 → 语料可比 → 记录存在且自洽 → 未回退。
func checkPolicyBenchGate(idx *policyVersionIndex, snapshotDir, version string) error {
	if idx.Baseline == nil {
		return plErr(policyErrBaselineNotRegistered,
			"版本库未登记门禁基线：须先由 scripts/policy-publish.ps1 -InitBaseline 自举（基线为「不可回退」的比较基准）")
	}
	if idx.Baseline.CorpusSHA256 == "" {
		return plErr(policyErrBaselineNotRegistered, "基线未登记语料指纹 corpus_sha256（无法保证与基线可比）")
	}
	raw, err := os.ReadFile(filepath.Join(snapshotDir, policyBenchName))
	if err != nil {
		if os.IsNotExist(err) {
			return plErr(policyErrBenchMissing, "版本 %s 缺 %s（未过评测 → 不得发布）", version, policyBenchName)
		}
		return plErr(policyErrReadError, "读取 %s 失败: %v", policyBenchName, err)
	}
	var rec policyBenchRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return plErr(policyErrInvalidJSON, "%s JSON 解析失败: %v", policyBenchName, err)
	}
	if rec.Version != version {
		return plErr(policyErrSchemaInvalid, "%s version=%q 与索引登记 %q 不一致", policyBenchName, rec.Version, version)
	}
	if rec.CorpusSHA256 == "" {
		return plErr(policyErrSchemaInvalid, "%s 缺 corpus_sha256", policyBenchName)
	}
	if !rec.Passed {
		return plErr(policyErrBenchNotPassed, "版本 %s 评测未通过（passed=false）", version)
	}
	if !strings.EqualFold(rec.CorpusSHA256, idx.Baseline.CorpusSHA256) {
		return plErr(policyErrBenchCorpusMismatch,
			"版本 %s 语料指纹与基线不一致（不可比；须先更新基线）：实测 %s / 基线 %s",
			version, rec.CorpusSHA256, idx.Baseline.CorpusSHA256)
	}
	b := idx.Baseline
	if rec.RuleDetect < b.RuleDetect || rec.SemanticDetect < b.SemanticDetect || rec.FP > b.FP {
		return plErr(policyErrBenchRegression,
			"版本 %s 指标回退（要求 rule_detect≥%.4f、semantic_detect≥%.4f、fp≤%.4f；实测 rule_detect=%.4f、semantic_detect=%.4f、fp=%.4f）",
			version, b.RuleDetect, b.SemanticDetect, b.FP, rec.RuleDetect, rec.SemanticDetect, rec.FP)
	}
	return nil
}

// ---- 显式引用与回滚 ----

// policyActivateRequest POST /config/policy/activate|rollback 请求体。
// rollback 可带 version（= 回任意历史版本）；不带则回"上一 active"。
type policyActivateRequest struct {
	Version string `json:"version"`
}

// applyPolicyVersion 显式引用某版本：索引校验 → bench 硬门禁 → 全量加载校验 → 原子换版
// → gauge/指标/审计/持久化。失败一律**保留旧注册表继续服务**（与 OG-9 热加载同纪律）。
//
// action ∈ activate | rollback（仅影响审计 Action 与指标标签，语义同一）。
// 返回值：响应体 + HTTP 状态码（成功 200；各类拒绝 409；未配置版本库 400）。
func (s *teeServer) applyPolicyVersion(version, action, actor, reqID string) (policyReloadResponse, int) {
	oldVersion := s.policyVersion()

	// 版本库未启用 → 端点不适用（与 /config/policy/reload 未配置目录时同语义：400）。
	idx, err := loadPolicyVersionIndex(s.outputGuardPolicyDir)
	if err != nil {
		kind := PolicyLoadErrorKind(err)
		status := 409
		if kind == policyErrVersionsNotConfigured {
			status = 400
		}
		s.recordPolicyActivate(action, "rejected", kind)
		return policyReloadResponse{Status: "not_configured", OldVersion: oldVersion, Reason: kind}, status
	}

	fail := func(err error) (policyReloadResponse, int) {
		kind := PolicyLoadErrorKind(err)
		if s.metrics != nil {
			// 未生效即保留旧版：同时计入既有"回退"计数族（口径与热加载失败一致）。
			s.metrics.incOGPolicyRollback(kind)
		}
		s.recordPolicyActivate(action, "rejected", kind)
		log.Printf("[output-guard] 策略版本 %s（%s）未生效（保留版本 %s 继续服务）：reason=%s",
			version, action, oldVersion, kind)
		if s.audit != nil {
			s.audit.append(AuditEvent{
				TenantID:        "-",
				UserID:          actor,
				RequestID:       reqID,
				Action:          "output_guard_policy_" + action,
				Result:          "rejected",
				OGOldVersion:    oldVersion,
				OGPolicySHA256:  readPolicyManifestSelfSHA(s.policyDirForVersion(idx, version)),
				OGPolicyVersion: version,
			})
		}
		return policyReloadResponse{Status: "rejected", OldVersion: oldVersion, Reason: kind}, 409
	}

	dir, err := s.policySnapshotDir(version)
	if err != nil {
		return fail(err)
	}
	if err := checkPolicyBenchGate(idx, dir, version); err != nil {
		return fail(err)
	}
	reg, err := loadPolicyDir(dir)
	if err != nil {
		return fail(err)
	}

	// 生效：原子换版 → 引用状态机 → gauge → 审计 → 持久化。
	st := s.shiftPolicyRef(version)
	s.setPolicy(reg)
	s.setPolicyRef(st)
	if s.metrics != nil {
		s.metrics.setOutputGuardMode(s.currentOutputGuardMode(), reg.PolicyVersion())
		s.recordPolicyActivate(action, "applied", "")
	}
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID:        "-",
			UserID:          actor,
			RequestID:       reqID,
			Action:          "output_guard_policy_" + action,
			Result:          "applied",
			OGPolicyVersion: reg.PolicyVersion(),
			OGOldVersion:    oldVersion,
			OGPolicySHA256:  reg.ManifestSHA(),
		})
	}
	// 持久化（跨重启保持显式引用）；未配置 -output-guard-config 则仅进程内生效（既有语义）。
	if err := s.saveOutputGuardRefRecord(st, actor, reqID); err != nil {
		log.Printf("[output-guard] 版本引用持久化失败（仅进程内生效）：%v", err)
	}
	log.Printf("[output-guard] 策略版本已生效（%s）：%s → %s 类目=%d 规则=%d",
		action, oldVersion, reg.PolicyVersion(), reg.CategoryCount(), reg.RuleCount())
	return policyReloadResponse{
		Status:        "applied",
		PolicyVersion: reg.PolicyVersion(),
		OldVersion:    oldVersion,
		Categories:    reg.CategoryCount(),
		Rules:         reg.RuleCount(),
	}, 200
}

// applyRootPolicy 回到 policy 根目录 manifest（清除显式引用）。
//
// 为什么必须有这条路径：未引用态本身是一个可回滚目标——否则一旦 activate，持久化记录会把某版本
// "锁死"（重启后仍被恢复），运维将失去回到镜像默认策略的手段。
// 语义：加载根目录（仍走既有全量校验；不套 bench 门禁——根目录属镜像内既有资产，非新发布版本）。
func (s *teeServer) applyRootPolicy(action, actor, reqID string) (policyReloadResponse, int) {
	oldVersion := s.policyVersion()
	old := s.policyRef()
	if old.Version == "" {
		// 已是未引用态：不构成换版（调用方应先行判断；此处兜底拒绝，避免"假成功"）。
		s.recordPolicyActivate(action, "rejected", policyErrNoPreviousVersion)
		return policyReloadResponse{Status: "rejected", OldVersion: oldVersion, Reason: policyErrNoPreviousVersion}, 409
	}
	reg, err := loadPolicyDir(s.outputGuardPolicyDir)
	if err != nil {
		kind := PolicyLoadErrorKind(err)
		if s.metrics != nil {
			s.metrics.incOGPolicyRollback(kind)
		}
		s.recordPolicyActivate(action, "rejected", kind)
		log.Printf("[output-guard] 回到根目录未生效（保留版本 %s 继续服务）：reason=%s", oldVersion, kind)
		return policyReloadResponse{Status: "rejected", OldVersion: oldVersion, Reason: kind}, 409
	}
	st := s.shiftPolicyRefToRoot()
	s.setPolicy(reg)
	s.setPolicyRef(st)
	if s.metrics != nil {
		s.metrics.setOutputGuardMode(s.currentOutputGuardMode(), reg.PolicyVersion())
		s.recordPolicyActivate(action, "applied", "")
	}
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID:        "-",
			UserID:          actor,
			RequestID:       reqID,
			Action:          "output_guard_policy_" + action,
			Result:          "applied",
			OGPolicyVersion: reg.PolicyVersion(),
			OGOldVersion:    oldVersion,
			OGPolicySHA256:  reg.ManifestSHA(),
		})
	}
	if err := s.saveOutputGuardRefRecord(st, actor, reqID); err != nil {
		log.Printf("[output-guard] 版本引用持久化失败（仅进程内生效）：%v", err)
	}
	log.Printf("[output-guard] 已回到 policy 根目录（%s）：%s → %s 类目=%d 规则=%d",
		action, oldVersion, reg.PolicyVersion(), reg.CategoryCount(), reg.RuleCount())
	return policyReloadResponse{
		Status:        "applied",
		PolicyVersion: reg.PolicyVersion(),
		OldVersion:    oldVersion,
		Categories:    reg.CategoryCount(),
		Rules:         reg.RuleCount(),
	}, 200
}

// policyDirForVersion 尽力解析版本快照目录（仅供**拒绝路径**留痕：解析失败返回根目录，不掩盖原错误）。
func (s *teeServer) policyDirForVersion(idx *policyVersionIndex, version string) string {
	if e, err := idx.entryOf(version); err == nil {
		dir := e.Dir
		if dir == "" {
			dir = version
		}
		if !filepath.IsAbs(dir) && !strings.Contains(dir, ":") {
			return filepath.Join(s.outputGuardPolicyDir, policyVersionsDirName, filepath.FromSlash(dir))
		}
	}
	return s.outputGuardPolicyDir
}

// recordPolicyActivate 记录一次版本引用事件（指标；nil 安全）。
func (s *teeServer) recordPolicyActivate(action, result, reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.incOGPolicyActivate(action, result, reason)
}

// ---- 引用版本运行态 ----
//
// 状态机（为什么不能只用"当前版本号"两个字符串）：
//   未引用态（用 policy 根目录 manifest）也是**一种可回滚目标**——首次 activate 后必须能回到它，
//   否则一旦引用某版本，持久化记录会把它"锁死"，重启也无法回到镜像默认策略。

// policyRefState 版本引用运行态（不可变快照；整体原子替换，请求路径无锁读）。
type policyRefState struct {
	Version  string // 当前显式引用版本；空 ＝ 未引用（用 policy 根目录 manifest）
	Prev     string // 上一 active 的版本号（PrevRoot=false 时有效）
	PrevRoot bool   // 上一 active 为"未引用态"（回滚 = 回到 policy 根目录）
	HasPrev  bool   // 是否存在可回滚的上一状态
}

// policyRef 当前引用运行态（无状态时返回零值）。
func (s *teeServer) policyRef() policyRefState {
	if v, ok := s.outputGuardPolicyRef.Load().(*policyRefState); ok && v != nil {
		return *v
	}
	return policyRefState{}
}

// setPolicyRef 原子替换引用运行态（唯一写入点）。
func (s *teeServer) setPolicyRef(st policyRefState) { s.outputGuardPolicyRef.Store(&st) }

// loadCurrentPolicySource 加载"当前应生效"的策略源：
//   - 已显式引用版本 ⇒ 该版本快照目录；
//   - 未引用 ⇒ policy 根目录（**行为与改造前一致**）。
//
// 热加载（/config/policy/reload）与启动解析共用同一口径，避免"两处指向不同目录"的漂移。
// 注：本函数不再跑 bench 门禁——门禁属**换版**动作（activate/rollback/启动显式引用）的准入条件，
// 重读同一版本不构成换版；引用版本解析失败则如实报错（不静默回落到根目录）。
func (s *teeServer) loadCurrentPolicySource() (*lexiconRegistry, error) {
	dir := s.outputGuardPolicyDir
	if v := s.referencedPolicyVersion(); v != "" {
		d, err := s.policySnapshotDir(v)
		if err != nil {
			return nil, err
		}
		dir = d
	}
	return loadPolicyDir(dir)
}

// referencedPolicyVersion 当前显式引用的版本（空 = 沿用 policy 根目录 manifest，行为不变）。
func (s *teeServer) referencedPolicyVersion() string { return s.policyRef().Version }

// previousPolicyVersion 上一 active 版本号（PrevRoot=true 时无意义）。
func (s *teeServer) previousPolicyVersion() string { return s.policyRef().Prev }

// shiftPolicyRef 计算"切换到某引用版本后"的新运行态。
// 规则：上一状态 = 换版前的引用状态（未引用态记为 PrevRoot）；重复引用同一版本保持原上一状态。
func (s *teeServer) shiftPolicyRef(version string) policyRefState {
	old := s.policyRef()
	if old.Version == version {
		return old
	}
	next := policyRefState{Version: version, HasPrev: true}
	if old.Version == "" {
		next.PrevRoot = true
	} else {
		next.Prev = old.Version
	}
	return next
}

// shiftPolicyRefToRoot 计算"回到根目录（清除引用）后"的新运行态：上一状态 = 刚引用的版本。
func (s *teeServer) shiftPolicyRefToRoot() policyRefState {
	old := s.policyRef()
	if old.Version == "" {
		return old // 已是未引用态：不构成换版（调用方应先行拒绝）
	}
	return policyRefState{Version: "", Prev: old.Version, HasPrev: true}
}

// saveOutputGuardRefRecord 持久化版本引用状态（**读改写合并**：不覆盖同文件的 mode 字段）。
// 引用三字段整体写入（含置空）——回到根目录时 st.Version 为空，即视为"清除引用"。
func (s *teeServer) saveOutputGuardRefRecord(st policyRefState, actor, reqID string) error {
	if s.outputGuardCfgPath == "" {
		return nil
	}
	return writeOutputGuardConfigRecord(s.outputGuardCfgPath, outputGuardConfigRecord{
		PolicyVersion:   st.Version,
		PreviousVersion: st.Prev,
		PreviousIsRoot:  st.PrevRoot,
		Actor:           actor,
		RequestID:       reqID,
	}, true, false)
}

// ---- 版本列表视图（/config/policy/versions 与 /config 快照共用）----

// policyVersionView 单版本只读视图。
// Bench 为 nil 表示**无评测记录**（该版本不可被引用），避免用零值伪装"已评测且全 0"。
type policyVersionView struct {
	Version   string            `json:"version"`
	Status    string            `json:"status"`
	Note      string            `json:"note,omitempty"`
	CreatedAt string            `json:"created_at,omitempty"`
	Bench     *policyBenchBrief `json:"bench,omitempty"`
}

// policyBenchBrief 评测记录摘要（列表视图用；完整记录见 versions/<v>/bench.json）。
type policyBenchBrief struct {
	Passed         bool    `json:"passed"`
	CorpusSHA256   string  `json:"corpus_sha256,omitempty"`
	RuleDetect     float64 `json:"rule_detect"`
	SemanticDetect float64 `json:"semantic_detect"`
	FP             float64 `json:"fp"`
	GeneratedAt    string  `json:"generated_at,omitempty"`
	Source         string  `json:"source,omitempty"`
}

// policyVersionsView 版本列表响应体（只读发现）。
type policyVersionsView struct {
	Enabled           bool                 `json:"enabled"`
	Reason            string               `json:"reason,omitempty"` // 未启用时的原因枚举
	ReferencedVersion string               `json:"referenced_version,omitempty"`
	PreviousVersion   string               `json:"previous_version,omitempty"`
	Baseline          *policyBenchBaseline `json:"baseline,omitempty"`
	Versions          []policyVersionView  `json:"versions,omitempty"`
}

// buildPolicyVersionsView 组装版本列表视图（**只读、不因缺 bench 记录而报错**——如实呈现）。
func (s *teeServer) buildPolicyVersionsView() policyVersionsView {
	view := policyVersionsView{
		ReferencedVersion: s.referencedPolicyVersion(),
		PreviousVersion:   s.previousPolicyVersion(),
	}
	idx, err := loadPolicyVersionIndex(s.outputGuardPolicyDir)
	if err != nil {
		view.Reason = PolicyLoadErrorKind(err)
		return view
	}
	view.Enabled = true
	view.Baseline = idx.Baseline
	for i := range idx.Versions {
		e := &idx.Versions[i]
		item := policyVersionView{Version: e.Version, Status: e.Status, Note: e.Note, CreatedAt: e.CreatedAt}
		dir := e.Dir
		if dir == "" {
			dir = e.Version
		}
		if raw, err := os.ReadFile(filepath.Join(s.outputGuardPolicyDir, policyVersionsDirName, filepath.FromSlash(dir), policyBenchName)); err == nil {
			var rec policyBenchRecord
			if json.Unmarshal(raw, &rec) == nil {
				item.Bench = &policyBenchBrief{
					Passed: rec.Passed, CorpusSHA256: rec.CorpusSHA256,
					RuleDetect: rec.RuleDetect, SemanticDetect: rec.SemanticDetect, FP: rec.FP,
					GeneratedAt: rec.GeneratedAt, Source: rec.Source,
				}
			}
		}
		view.Versions = append(view.Versions, item)
	}
	return view
}

// ---- HTTP 端点 ----

// policyErrVersionRequired activate 未提供版本号（请求体缺字段）。
const policyErrVersionRequired = "version_required"

// handlePolicyVersions GET /config/policy/versions：版本库只读发现。
//
// 语义：**未启用版本库不是错误**——200 + enabled=false + reason（能力未启用属正常态，
// 便于"没配版本库"与"配了但读坏了"区分呈现）；非 GET → 405；鉴权同其它管理端点。
func (s *teeServer) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		recordExemptExit("handlePolicyVersions", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		s.auditAdminExit(r, "output_guard_policy_activate", "rejected_admin_auth", http.StatusUnauthorized)
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, s.buildPolicyVersionsView())
}

// handlePolicyActivate POST /config/policy/activate：**显式引用**某版本（须过 bench 硬门禁）。
func (s *teeServer) handlePolicyActivate(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodePolicyVersionRequest(w, r)
	if !ok {
		return
	}
	if req.Version == "" {
		writeJSON(w, http.StatusBadRequest, policyReloadResponse{
			Status: "rejected", OldVersion: s.policyVersion(), Reason: policyErrVersionRequired,
		})
		return
	}
	resp, status := s.applyPolicyVersion(req.Version, "activate",
		r.Header.Get("X-Admin-Actor"), r.Header.Get("X-Request-ID"))
	writeJSON(w, status, resp)
}

// handlePolicyRollback POST /config/policy/rollback：回滚。
//   - 带 version ⇒ **回任意历史版本**（与 activate 同一路径，仅审计 Action 不同）；
//   - 不带 version ⇒ **回上一 active**——上一 active 可能是某版本，也可能是"未引用态（policy 根目录）"；
//     无可回滚对象 → 409 no_previous_version。
func (s *teeServer) handlePolicyRollback(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodePolicyVersionRequest(w, r)
	if !ok {
		return
	}
	actor, reqID := r.Header.Get("X-Admin-Actor"), r.Header.Get("X-Request-ID")
	if req.Version != "" {
		resp, status := s.applyPolicyVersion(req.Version, "rollback", actor, reqID)
		writeJSON(w, status, resp)
		return
	}
	st := s.policyRef()
	if !st.HasPrev {
		s.recordPolicyActivate("rollback", "rejected", policyErrNoPreviousVersion)
		writeJSON(w, http.StatusConflict, policyReloadResponse{
			Status: "rejected", OldVersion: s.policyVersion(), Reason: policyErrNoPreviousVersion,
		})
		return
	}
	if st.PrevRoot {
		resp, status := s.applyRootPolicy("rollback", actor, reqID)
		writeJSON(w, status, resp)
		return
	}
	resp, status := s.applyPolicyVersion(st.Prev, "rollback", actor, reqID)
	writeJSON(w, status, resp)
}

// decodePolicyVersionRequest 统一方法/鉴权/请求体解析（请求体可为空 = 缺省语义）。
func (s *teeServer) decodePolicyVersionRequest(w http.ResponseWriter, r *http.Request) (policyActivateRequest, bool) {
	var req policyActivateRequest
	if r.Method != http.MethodPost {
		recordExemptExit("decodePolicyVersionRequest", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return req, false
	}
	if !s.checkAdmin(r) {
		s.auditAdminExit(r, "output_guard_policy_activate", "rejected_admin_auth", http.StatusUnauthorized)
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return req, false
	}
	if r.Body != nil {
		// 空体合法（rollback 缺省回上一 active）；非 JSON 则 400。
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil && err != io.EOF {
			s.auditAdminExit(r, "output_guard_policy_activate", "rejected_bad_request", http.StatusBadRequest)
			http.Error(w, `请求体须为 JSON（{"version":"..."}，可为空）`, http.StatusBadRequest)
			return req, false
		}
	}
	return req, true
}

// writeJSON 统一 JSON 响应（含状态码）。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	recordExemptExit("writeJSON", "common_writer")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
