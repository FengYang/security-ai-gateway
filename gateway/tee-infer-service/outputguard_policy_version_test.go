// S1-4（G21）策略/词库版本库单测：版本发现 / bench 硬门禁 / 显式引用 / 回滚 / 持久化 / 零行为变更。
//
// 门禁口径（2026-09-26 裁定）：「不低于已登记基线且不可回退」——rule_detect/semantic_detect ≥ 基线、
// fp ≤ 基线，且语料指纹须与基线一致（不可比即拒绝）。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// testBenchCorpus 基线语料指纹（与快照 bench.json 一致时才可比）。
	testBenchCorpus = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// testOtherCorpus 与基线不一致的语料指纹（用于 bench_corpus_mismatch）。
	testOtherCorpus = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// writeInto 把数据写入 root 下的相对路径（自动建父目录）。
func writeInto(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatalf("WriteFile %s: %v", rel, err)
	}
}

// benchJSON 构造版本快照内的 bench.json（评测记录）。
func benchJSON(t *testing.T, version, corpus string, rule, sem, fp float64, passed bool) []byte {
	t.Helper()
	return mustJSON(t, policyBenchRecord{
		Version: version, CorpusSHA256: corpus,
		RuleDetect: rule, SemanticDetect: sem, FP: fp,
		Passed: passed, GeneratedAt: "2026-09-26T00:00:00Z", Source: "test",
	})
}

// snapshot 构造某版本的完整快照文件集（policy 资产 + bench.json）。
func snapshot(t *testing.T, version, corpus string, rule, sem, fp float64, passed bool, extraCats ...string) map[string][]byte {
	t.Helper()
	files := policyReloadFiles(t, version, strings.Repeat("d", 64), extraCats...)
	files[policyBenchName] = benchJSON(t, version, corpus, rule, sem, fp, passed)
	return files
}

// buildVersionLib 构造测试夹具：policy 根目录（未引用态的当前生效版本）＋ versions/ 版本库。
func buildVersionLib(t *testing.T, baseline *policyBenchBaseline,
	entries []policyVersionEntry, snapshots map[string]map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	// 根目录＝未引用态（行为与改造前一致）：沿用既有最小资产集，版本号固定 pv-root。
	for rel, data := range policyReloadFiles(t, "pv-root", strings.Repeat("c", 64)) {
		writeInto(t, root, rel, data)
	}
	writeInto(t, root, policyVersionsDirName+"/"+policyVersionsIndexName, mustJSON(t, policyVersionIndex{
		SchemaVersion: lexiconSchemaVersion, Baseline: baseline, Versions: entries,
	}))
	for v, files := range snapshots {
		for rel, data := range files {
			writeInto(t, root, policyVersionsDirName+"/"+v+"/"+rel, data)
		}
	}
	return root
}

// okBaseline 已登记基线（rule 100% / semantic 12% / fp 0%，对应现状实测水位）。
func okBaseline() *policyBenchBaseline {
	return &policyBenchBaseline{RuleDetect: 1.0, SemanticDetect: 0.12, FP: 0.0, CorpusSHA256: testBenchCorpus}
}

// activateReq 直接调用版本库 handler（不经 mux）。方法由路径决定：
// versions 为只读发现（GET），activate/rollback 为写动作（POST）；body 为空串表示空请求体。
func activateReq(srv *teeServer, path, body string, authed bool) *httptest.ResponseRecorder {
	method := http.MethodPost
	if path == "/config/policy/versions" {
		method = http.MethodGet
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Request-ID", "req-ver")
	req.Header.Set("X-Admin-Actor", "tester")
	if authed {
		req.Header.Set(adminHeader, "secret-token")
	}
	switch path {
	case "/config/policy/activate":
		srv.handlePolicyActivate(rec, req)
	case "/config/policy/rollback":
		srv.handlePolicyRollback(rec, req)
	default:
		srv.handlePolicyVersions(rec, req)
	}
	return rec
}

// decodeReloadResp 解析响应体。
func decodeReloadResp(t *testing.T, rec *httptest.ResponseRecorder) policyReloadResponse {
	t.Helper()
	var resp policyReloadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v（body=%s）", err, rec.Body.String())
	}
	return resp
}

// policyActivateCount 读取 policy_activate_total 中 action|result|reason 的计数。
func policyActivateCount(srv *teeServer, action, result, reason string) int64 {
	if reason == "" {
		reason = "-"
	}
	return srv.metrics.ogPolicyActivate[action+"|"+result+"|"+reason]
}

// findPolicyAudit 收集版本库端点的审计事件。
func findPolicyAudit(srv *teeServer, action string) []AuditEvent {
	var out []AuditEvent
	for _, e := range srv.audit.query("") {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// ---- 1. 零行为变更：无 versions/ 目录 ----

// TestPolicyVersionNotConfiguredZeroChange 未配置版本库时：能力不启用（enabled=false），
// 且既有热加载路径**行为完全不变**（这是本改造的第一纪律）。
func TestPolicyVersionNotConfiguredZeroChange(t *testing.T) {
	srv, _ := newM9Server(t)
	dir := writeTempPolicy(t, policyReloadFiles(t, "pv-root", strings.Repeat("c", 64)))
	srv.outputGuardPolicyDir = dir
	reg, err := loadPolicyDir(dir)
	if err != nil {
		t.Fatalf("根目录加载失败: %v", err)
	}
	srv.setPolicy(reg)

	// 版本库视图：未启用（不是错误）。
	view := srv.buildPolicyVersionsView()
	if view.Enabled || view.Reason != policyErrVersionsNotConfigured {
		t.Fatalf("应 enabled=false 且 reason=%s，实际 %+v", policyErrVersionsNotConfigured, view)
	}
	if rec := activateReq(srv, "/config/policy/versions", "", true); rec.Code != http.StatusOK {
		t.Fatalf("列表端点未启用时也应 200（能力未启用属正常态），got %d", rec.Code)
	}

	// 既有热加载：行为与改造前一致（成功换版）。
	if rec := doPolicyReload(srv, http.MethodPost, false); rec.Code != http.StatusOK {
		t.Fatalf("热加载应 200，got %d body=%s", rec.Code, rec.Body.String())
	}

	// activate：版本库未启用 → 400 + not_configured（端点不适用）。
	rec := activateReq(srv, "/config/policy/activate", `{"version":"pv-x"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未启用版本库时 activate 应 400，got %d", rec.Code)
	}
	if resp := decodeReloadResp(t, rec); resp.Reason != policyErrVersionsNotConfigured {
		t.Fatalf("reason 应 %s，实际 %q", policyErrVersionsNotConfigured, resp.Reason)
	}
}

// ---- 2. bench 硬门禁与版本校验的各拒绝原因 ----

// TestPolicyVersionGateReasons 逐项覆盖拒绝原因：门禁"先能不能比，再比得过"，
// 且任何拒绝都必须**保留旧注册表**（fail-closed，不静默降级）。
func TestPolicyVersionGateReasons(t *testing.T) {
	pub := func(dir string) policyVersionEntry {
		return policyVersionEntry{Version: "pv-v2", Dir: dir, Status: policyStatusPublished}
	}
	cases := []struct {
		name     string
		baseline *policyBenchBaseline
		entry    policyVersionEntry
		snap     map[string]map[string][]byte
		want     string
	}{
		{
			name: "基线未登记", baseline: nil, entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0, true)},
			want: policyErrBaselineNotRegistered,
		},
		{
			name:     "基线缺语料指纹",
			baseline: &policyBenchBaseline{RuleDetect: 1.0, SemanticDetect: 0.12, FP: 0},
			entry:    pub("pv-v2"),
			snap:     map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0, true)},
			want:     policyErrBaselineNotRegistered,
		},
		{
			name: "缺 bench.json", baseline: okBaseline(), entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": policyReloadFiles(t, "pv-v2", strings.Repeat("d", 64))},
			want: policyErrBenchMissing,
		},
		{
			name: "评测未通过", baseline: okBaseline(), entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0, false)},
			want: policyErrBenchNotPassed,
		},
		{
			name: "语料指纹不一致", baseline: okBaseline(), entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testOtherCorpus, 1.0, 0.12, 0, true)},
			want: policyErrBenchCorpusMismatch,
		},
		{
			name: "检出率回退", baseline: okBaseline(), entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 0.99, 0.12, 0, true)},
			want: policyErrBenchRegression,
		},
		{
			name: "语义族回退", baseline: okBaseline(), entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.11, 0, true)},
			want: policyErrBenchRegression,
		},
		{
			name: "误报率上升", baseline: okBaseline(), entry: pub("pv-v2"),
			snap: map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0.01, true)},
			want: policyErrBenchRegression,
		},
		{
			name: "草稿不可引用", baseline: okBaseline(),
			entry: policyVersionEntry{Version: "pv-v2", Status: policyStatusDraft},
			snap:  map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0, true)},
			want:  policyErrVersionNotPublished,
		},
		{
			name: "快照目录穿越", baseline: okBaseline(),
			entry: policyVersionEntry{Version: "pv-v2", Dir: "../escape", Status: policyStatusPublished},
			snap:  map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0, true)},
			want:  policyErrUnsafePath,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newM9Server(t)
			root := buildVersionLib(t, tc.baseline, []policyVersionEntry{tc.entry}, tc.snap)
			srv.outputGuardPolicyDir = root
			rootReg, err := loadPolicyDir(root)
			if err != nil {
				t.Fatalf("根目录加载失败: %v", err)
			}
			srv.setPolicy(rootReg)

			rec := activateReq(srv, "/config/policy/activate", `{"version":"pv-v2"}`, true)
			if rec.Code != http.StatusConflict {
				t.Fatalf("应 409，got %d body=%s", rec.Code, rec.Body.String())
			}
			if resp := decodeReloadResp(t, rec); resp.Reason != tc.want {
				t.Fatalf("reason 应 %q，实际 %q", tc.want, resp.Reason)
			}
			// fail-closed：旧注册表保留（未换版）。
			if v := srv.policyVersion(); v != "pv-root" {
				t.Fatalf("拒绝后应仍为 pv-root，实际 %q", v)
			}
			if srv.referencedPolicyVersion() != "" {
				t.Fatalf("拒绝后不应产生引用，实际 %q", srv.referencedPolicyVersion())
			}
			// 指标：回退计数 + activate 拒绝计数。
			if n := srv.metrics.ogPolicyRollback[tc.want]; n != 1 {
				t.Fatalf("rollback_total{%s} 应 1，实际 %d", tc.want, n)
			}
			if n := policyActivateCount(srv, "activate", "rejected", tc.want); n != 1 {
				t.Fatalf("activate_total{activate|rejected|%s} 应 1，实际 %d", tc.want, n)
			}
		})
	}

	// 未登记版本：索引内无该条目。
	t.Run("版本未登记", func(t *testing.T) {
		srv, _ := newM9Server(t)
		root := buildVersionLib(t, okBaseline(), nil,
			map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.12, 0, true)})
		srv.outputGuardPolicyDir = root
		rec := activateReq(srv, "/config/policy/activate", `{"version":"pv-v2"}`, true)
		if resp := decodeReloadResp(t, rec); resp.Reason != policyErrVersionNotFound {
			t.Fatalf("reason 应 %q，实际 %q", policyErrVersionNotFound, resp.Reason)
		}
	})
}

// ---- 3. 显式引用成功路径 + 回滚 + 持久化 ----

// TestPolicyVersionActivateRollback 成功引用：换版生效、引用/上一状态正确、审计与指标留痕、
// 持久化不丢 mode 字段；回滚缺省先回根目录（未引用态）再回该版本。
func TestPolicyVersionActivateRollback(t *testing.T) {
	srv, _ := newM9Server(t)
	root := buildVersionLib(t, okBaseline(),
		[]policyVersionEntry{{Version: "pv-v2", Status: policyStatusPublished}},
		map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.2, 0, true, "A1-07")})
	srv.outputGuardPolicyDir = root
	// 持久化文件：先写入 mode=shadow，验证引用写入不会抹掉它。
	cfgPath := filepath.Join(t.TempDir(), "og-config.json")
	if err := writeOutputGuardConfigRecord(cfgPath, outputGuardConfigRecord{Mode: outputGuardShadow, Actor: "op"}, false, false); err != nil {
		t.Fatalf("预置配置失败: %v", err)
	}
	srv.outputGuardCfgPath = cfgPath
	rootReg, err := loadPolicyDir(root)
	if err != nil {
		t.Fatalf("根目录加载失败: %v", err)
	}
	srv.setPolicy(rootReg)
	srv.loadOutputGuardOverride() // 恢复 mode=shadow（引用态仍为空）

	// 引用前：A1-07 不命中（根目录仅 A1-06）。
	if cat, _, _ := srv.l1Classifier().Classify("【A1-07-示例-0001】"); cat != "" {
		t.Fatalf("引用前 A1-07 不应命中，实际 %q", cat)
	}

	rec := activateReq(srv, "/config/policy/activate", `{"version":"pv-v2"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeReloadResp(t, rec)
	if resp.Status != "applied" || resp.PolicyVersion != "pv-v2" || resp.OldVersion != "pv-root" {
		t.Fatalf("响应不符: %+v", resp)
	}
	if v := srv.policyVersion(); v != "pv-v2" {
		t.Fatalf("换版后版本应 pv-v2，实际 %q", v)
	}
	if cat, _, _ := srv.l1Classifier().Classify("【A1-07-示例-0001】"); cat != "A1-07" {
		t.Fatalf("换版后 A1-07 应命中，实际 %q", cat)
	}
	if st := srv.policyRef(); st.Version != "pv-v2" || !st.PrevRoot || !st.HasPrev {
		t.Fatalf("引用状态应为 引用 v2 + 上一=根目录，实际 %+v", st)
	}
	// 审计与指标。
	if evs := findPolicyAudit(srv, "output_guard_policy_activate"); len(evs) != 1 || evs[0].Result != "applied" {
		t.Fatalf("应有 1 条 activate applied 审计，实际 %+v", evs)
	}
	if n := policyActivateCount(srv, "activate", "applied", ""); n != 1 {
		t.Fatalf("activate applied 计数应 1，实际 %d", n)
	}
	// 持久化：mode 未被抹掉，且写入引用与"上一=根目录"。
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved outputGuardConfigRecord
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Mode != outputGuardShadow || saved.PolicyVersion != "pv-v2" || !saved.PreviousIsRoot {
		t.Fatalf("持久化记录不符（mode 不应丢）: %+v", saved)
	}

	// 回滚缺省：上一状态为"未引用态"→ 回到根目录。
	rec = activateReq(srv, "/config/policy/rollback", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("回滚应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	if v := srv.policyVersion(); v != "pv-root" {
		t.Fatalf("回滚后应 pv-root，实际 %q", v)
	}
	if st := srv.policyRef(); st.Version != "" || st.Prev != "pv-v2" {
		t.Fatalf("回滚后状态应 未引用 + 上一=v2，实际 %+v", st)
	}
	if cat, _, _ := srv.l1Classifier().Classify("【A1-07-示例-0001】"); cat != "" {
		t.Fatalf("回到根目录后 A1-07 不应命中，实际 %q", cat)
	}
	// 回滚缺省再走一次：上一状态为 v2 → 回到 v2（可来回切换，不锁死）。
	rec = activateReq(srv, "/config/policy/rollback", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("再次回滚应 200，got %d", rec.Code)
	}
	if v := srv.policyVersion(); v != "pv-v2" {
		t.Fatalf("再次回滚后应 pv-v2，实际 %q", v)
	}
	// 持久化：三元组整体一致——当前引用 v2，上一状态为"未引用态（根目录）"，且不含陈旧的 previous_version。
	raw, _ = os.ReadFile(cfgPath)
	_ = json.Unmarshal(raw, &saved)
	if saved.PolicyVersion != "pv-v2" || !saved.PreviousIsRoot || saved.PreviousVersion != "" {
		t.Fatalf("再次引用后持久化记录不符（三元组须整体一致）: %+v", saved)
	}
	if ok, broken := srv.audit.verify(); !ok {
		t.Fatalf("版本库审计入链后链断裂于 %d", broken)
	}
}

// TestPolicyVersionRollbackNoPrevious 无任何引用历史时回滚 → 409 no_previous_version（不假成功）。
func TestPolicyVersionRollbackNoPrevious(t *testing.T) {
	srv, _ := newM9Server(t)
	root := buildVersionLib(t, okBaseline(), nil, nil)
	srv.outputGuardPolicyDir = root
	rec := activateReq(srv, "/config/policy/rollback", "", true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("应 409，got %d body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeReloadResp(t, rec); resp.Reason != policyErrNoPreviousVersion {
		t.Fatalf("reason 应 %q，实际 %q", policyErrNoPreviousVersion, resp.Reason)
	}
}

// TestPolicyVersionRollbackExplicitVersion 带 version 的回滚 = 回任意历史版本（与 activate 同路径）。
func TestPolicyVersionRollbackExplicitVersion(t *testing.T) {
	srv, _ := newM9Server(t)
	root := buildVersionLib(t, okBaseline(),
		[]policyVersionEntry{
			{Version: "pv-v2", Status: policyStatusPublished},
			{Version: "pv-v3", Status: policyStatusPublished},
		},
		map[string]map[string][]byte{
			"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.2, 0, true),
			"pv-v3": snapshot(t, "pv-v3", testBenchCorpus, 1.0, 0.3, 0, true),
		})
	srv.outputGuardPolicyDir = root
	rootReg, err := loadPolicyDir(root)
	if err != nil {
		t.Fatal(err)
	}
	srv.setPolicy(rootReg)

	if rec := activateReq(srv, "/config/policy/activate", `{"version":"pv-v3"}`, true); rec.Code != http.StatusOK {
		t.Fatalf("引用 v3 应 200，got %d", rec.Code)
	}
	// 回滚到更早的历史版本 v2（非"上一 active"）。
	rec := activateReq(srv, "/config/policy/rollback", `{"version":"pv-v2"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("回滚到 v2 应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	if v := srv.policyVersion(); v != "pv-v2" {
		t.Fatalf("应 v2，实际 %q", v)
	}
	if n := policyActivateCount(srv, "rollback", "applied", ""); n != 1 {
		t.Fatalf("rollback applied 计数应 1，实际 %d", n)
	}
	if evs := findPolicyAudit(srv, "output_guard_policy_rollback"); len(evs) != 1 {
		t.Fatalf("应有 1 条 rollback 审计，实际 %d", len(evs))
	}
}

// ---- 4. 快照被篡改（哈希不匹配）→ 复用既有归因且旧版保留 ----

// TestPolicyVersionTamperedSnapshot 快照内词库被改动 → 409 hash_mismatch，旧注册表保留。
func TestPolicyVersionTamperedSnapshot(t *testing.T) {
	srv, _ := newM9Server(t)
	root := buildVersionLib(t, okBaseline(),
		[]policyVersionEntry{{Version: "pv-v2", Status: policyStatusPublished}},
		map[string]map[string][]byte{"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.2, 0, true)})
	srv.outputGuardPolicyDir = root
	rootReg, err := loadPolicyDir(root)
	if err != nil {
		t.Fatal(err)
	}
	srv.setPolicy(rootReg)
	// 篡改快照内词库（manifest 登记的 sha256 不再匹配）。
	tampered := []byte(`{"category":"A1-06","version":"pv-v2","level":"block","rules":[{"type":"keyword","value":"篡改"}]}`)
	if err := os.WriteFile(filepath.Join(root, policyVersionsDirName, "pv-v2", "keywords", "a1-06.json"), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := activateReq(srv, "/config/policy/activate", `{"version":"pv-v2"}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("应 409，got %d body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeReloadResp(t, rec); resp.Reason != policyErrHashMismatch {
		t.Fatalf("reason 应 %q，实际 %q", policyErrHashMismatch, resp.Reason)
	}
	if v := srv.policyVersion(); v != "pv-root" {
		t.Fatalf("旧版应保留，实际 %q", v)
	}
}

// ---- 5. 端点契约（方法/鉴权/缺参） ----

// TestPolicyVersionEndpointContract 方法、鉴权、缺 version 的响应契约。
func TestPolicyVersionEndpointContract(t *testing.T) {
	srv, _ := newM9Server(t)
	root := buildVersionLib(t, okBaseline(), nil, nil)
	srv.outputGuardPolicyDir = root

	// GET activate → 405。
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/config/policy/activate", nil)
	srv.handlePolicyActivate(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET activate 应 405，got %d", rec.Code)
	}
	// POST versions → 405。
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/config/policy/versions", nil)
	srv.handlePolicyVersions(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST versions 应 405，got %d", rec.Code)
	}
	// 鉴权失败 → 401（需显式配置管理令牌）。
	srvAuth, _ := newM9Server(t)
	srvAuth.outputGuardPolicyDir = root
	srvAuth.adminToken = "secret-token"
	if rec := activateReq(srvAuth, "/config/policy/activate", `{"version":"pv-v2"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("缺管理令牌应 401，got %d", rec.Code)
	}
	// 缺 version → 400 version_required。
	rec = activateReq(srv, "/config/policy/activate", `{}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 version 应 400，got %d", rec.Code)
	}
	if resp := decodeReloadResp(t, rec); resp.Reason != policyErrVersionRequired {
		t.Fatalf("reason 应 %q，实际 %q", policyErrVersionRequired, resp.Reason)
	}
}

// ---- 6. 版本列表视图如实呈现（含无评测记录的版本） ----

// TestPolicyVersionListView 列表视图：draft 与已发布版本并列，bench 缺失者 Bench=nil（不用零值伪装）。
func TestPolicyVersionListView(t *testing.T) {
	srv, _ := newM9Server(t)
	root := buildVersionLib(t, okBaseline(),
		[]policyVersionEntry{
			{Version: "pv-v2", Status: policyStatusPublished},
			{Version: "pv-v3", Status: policyStatusDraft},
		},
		map[string]map[string][]byte{
			"pv-v2": snapshot(t, "pv-v2", testBenchCorpus, 1.0, 0.2, 0, true),
			"pv-v3": policyReloadFiles(t, "pv-v3", strings.Repeat("e", 64)), // 无 bench.json
		})
	srv.outputGuardPolicyDir = root

	view := srv.buildPolicyVersionsView()
	if !view.Enabled || view.Baseline == nil || len(view.Versions) != 2 {
		t.Fatalf("视图不符: %+v", view)
	}
	byVer := map[string]policyVersionView{}
	for _, v := range view.Versions {
		byVer[v.Version] = v
	}
	if b := byVer["pv-v2"].Bench; b == nil || !b.Passed || b.SemanticDetect != 0.2 {
		t.Fatalf("v2 bench 摘要不符: %+v", byVer["pv-v2"].Bench)
	}
	if b := byVer["pv-v3"].Bench; b != nil {
		t.Fatalf("v3 无评测记录，Bench 应为 nil（不得用零值伪装），实际 %+v", b)
	}
	if byVer["pv-v3"].Status != policyStatusDraft {
		t.Fatalf("v3 状态应 draft，实际 %q", byVer["pv-v3"].Status)
	}
}

// ---- 7. 发布物门禁（发布脚本与 CI 共用）：逐个真实版本快照复算哈希 + bench 门禁 ----

// TestPolicyVersionArtifactsVerify 校验仓库内**真实**版本库发布物（policy/versions/*）。
//   - 无版本库 ⇒ 跳过（能力未启用，不阻断：零行为变更纪律）；
//   - 每个已发布版本：快照全量哈希/结构校验（loadPolicyDir）＋ bench 硬门禁；
//   - draft 版本：只跳过门禁（允许"先归档、待评测"），但仍校验快照结构。
//
// 发布脚本（scripts/policy-publish.ps1）与 CI 以本测试作为**发布门禁**。
func TestPolicyVersionArtifactsVerify(t *testing.T) {
	root := "policy"
	idx, err := loadPolicyVersionIndex(root)
	if err != nil {
		if PolicyLoadErrorKind(err) == policyErrVersionsNotConfigured {
			t.Skipf("版本库未启用（无 %s/%s），跳过发布物校验", policyVersionsDirName, policyVersionsIndexName)
		}
		t.Fatalf("读取版本索引失败: %v", err)
	}
	if len(idx.Versions) == 0 {
		t.Skip("版本库为空（尚无已发布版本），跳过发布物校验")
	}
	srv := &teeServer{outputGuardPolicyDir: root}
	for i := range idx.Versions {
		e := &idx.Versions[i]
		if e.Status == policyStatusDraft {
			continue // 草稿不适用 bench 门禁（但不可被引用）
		}
		dir, err := srv.policySnapshotDir(e.Version)
		if err != nil {
			t.Fatalf("版本 %s 快照目录解析失败: %v", e.Version, err)
		}
		if _, err := loadPolicyDir(dir); err != nil {
			t.Fatalf("版本 %s 快照哈希/结构校验失败: %v", e.Version, err)
		}
		if err := checkPolicyBenchGate(idx, dir, e.Version); err != nil {
			t.Fatalf("版本 %s 未过 bench 硬门禁: %v", e.Version, err)
		}
		t.Logf("✅ 版本 %s：快照哈希与 bench 硬门禁均通过", e.Version)
	}
}
