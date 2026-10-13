// Package main — P1-7 T8/T9 单测：温/冷层检索·导出 与 留存声明读写。
//
// 覆盖：参数解析/校验（§6.2 首错 400）、跨度上限、多维过滤/排序/分页、确定性降采样、
// 本地归档后端按日期分区扫描、端点 RBAC/租户隔离、导出链尾摘要头、留存 GET/PUT
// 往返 + G1 链落链 + 校验 fail-closed。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- 归档夹具 ----

// writeArchiveFixture 写一个归档分区文件 <root>/<tier>/<tenant>/<date>/part-*.jsonl。
func writeArchiveFixture(t *testing.T, root, tier, tenant, date string, recs []auditRecord) {
	t.Helper()
	dir := filepath.Join(root, tier, tenant, date)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("建归档目录失败: %v", err)
	}
	f, err := os.Create(filepath.Join(dir, "part-"+date+"-0.jsonl"))
	if err != nil {
		t.Fatalf("建归档文件失败: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatalf("写归档记录失败: %v", err)
		}
	}
}

// newAuditFullTestMux 以指定归档根/链构造管理面 mux（设置 env 后组装）。
func newAuditFullTestMux(t *testing.T, cfg *config, chain *adminAuditChain, archiveRoot string) *http.ServeMux {
	t.Helper()
	t.Setenv(envArchiveRoot, archiveRoot)
	us := &usageSettings{url: "", token: "tee-tok"}
	return buildAdminMux(cfg, nil, nil, nil, nil, nil, newSecCenterHandler(chain, us), nil, nil, false)
}

// secDo 以指定角色/租户发起请求（body 可空）。
func auditDo(t *testing.T, mux *http.ServeMux, cfg *config, method, sub, role, tenant, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader = strings.NewReader(body)
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, cfg.jwtSecret, claims{
		Sub: sub, Role: role, Tenant: tenant, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// ---- 参数解析/校验 ----

func TestParseAuditQueryValidation(t *testing.T) {
	base := map[string][]string{"tenant": {"t1"}, "from": {"1000"}, "to": {"2000"}}
	if _, err := parseAuditQuery(base, false); err != nil {
		t.Fatalf("合法参数应通过: %v", err)
	}
	bad := func(k, v string) map[string][]string {
		m := map[string][]string{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = []string{v}
		return m
	}
	cases := []struct {
		k, v string
	}{
		{"tier", "bogus"},
		{"path_mode", "weird"},
		{"hit", "maybe"},
		{"status", "999"},
		{"status", "abc"},
		{"sort", "bogus"},
		{"sort", "timestamp:sideways"},
	}
	for _, c := range cases {
		if _, err := parseAuditQuery(bad(c.k, c.v), false); err == nil {
			t.Fatalf("%s=%s 应校验失败", c.k, c.v)
		}
	}
	// from > to → 400
	if _, err := parseAuditQuery(map[string][]string{"from": {"3000"}, "to": {"1000"}}, false); err == nil {
		t.Fatal("from>to 应校验失败")
	}
	// status 多值超上限（6 个）→ 400
	if _, err := parseAuditQuery(map[string][]string{"status": {"400,401,402,403,404,405"}}, false); err == nil {
		t.Fatal("status 多值超上限应失败")
	}
	// 合法多值 + 去重
	q, err := parseAuditQuery(map[string][]string{"status": {"429, 503,429"}, "action": {"infer,deny"}}, false)
	if err != nil || len(q.Statuses) != 2 || len(q.Actions) != 2 {
		t.Fatalf("多值解析错误: %+v err=%v", q, err)
	}
	// 导出模式 sample_miss_rate 越界
	if _, err := parseAuditQuery(map[string][]string{"sample_miss_rate": {"101"}}, true); err == nil {
		t.Fatal("sample_miss_rate=101 应失败")
	}
}

func TestMaxSpanFor(t *testing.T) {
	if maxSpanFor("search", "warm") != 30*24*time.Hour {
		t.Fatal("search warm 应 30d")
	}
	if maxSpanFor("search", "cold") != 90*24*time.Hour {
		t.Fatal("search cold 应 90d")
	}
	if maxSpanFor("search", "hot") != -1 {
		t.Fatal("search 不支持 hot")
	}
	if maxSpanFor("export", "hot") != 7*24*time.Hour {
		t.Fatal("export hot 应 7d")
	}
	if maxSpanFor("export", "cold") != -1 {
		t.Fatal("export 不支持 cold")
	}
}

// ---- 过滤 / 排序 / 分页 / 采样 ----

func TestFilterRecords(t *testing.T) {
	recs := []auditRecord{
		{RequestID: "a", Timestamp: 1500, Result: "ok", HTTPStatus: 200, Action: "infer", Model: "qwen", PathMode: "plain"},
		{RequestID: "b", Timestamp: 1600, Result: "rate_limited", HTTPStatus: 429, Action: "request", HitPolicies: "rpm_limit", PathMode: "encrypted"},
		{RequestID: "c", Timestamp: 1700, Result: "ok", HTTPStatus: 200, Action: "deny", PathMode: "plain"},
	}
	q := &auditQuery{FromNano: 1000, ToNano: 2000, Hit: "hit"}
	got := filterRecords(recs, q)
	if len(got) != 1 || got[0].RequestID != "b" {
		t.Fatalf("hit 过滤应仅 b: %+v", got)
	}
	q = &auditQuery{FromNano: 1000, ToNano: 2000, Hit: "miss"}
	if got := filterRecords(recs, q); len(got) != 2 {
		t.Fatalf("miss 过滤应 2 条: %d", len(got))
	}
	q = &auditQuery{FromNano: 1000, ToNano: 2000, Statuses: []int{429, 503}}
	if got := filterRecords(recs, q); len(got) != 1 || got[0].RequestID != "b" {
		t.Fatalf("status OR 过滤错误: %+v", got)
	}
	q = &auditQuery{FromNano: 1000, ToNano: 2000, Actions: []string{"infer", "deny"}}
	if got := filterRecords(recs, q); len(got) != 2 {
		t.Fatalf("action OR 过滤应 2 条: %d", len(got))
	}
	// 时间窗裁剪
	q = &auditQuery{FromNano: 1000, ToNano: 1550}
	if got := filterRecords(recs, q); len(got) != 1 {
		t.Fatalf("时间窗过滤应 1 条: %d", len(got))
	}
}

func TestSortAndPaginate(t *testing.T) {
	recs := []auditRecord{
		{RequestID: "a", Timestamp: 1000, DurMS: 30},
		{RequestID: "b", Timestamp: 3000, DurMS: 10},
		{RequestID: "c", Timestamp: 2000, DurMS: 20},
	}
	q := &auditQuery{Sort: "timestamp", SortDesc: true}
	sortRecords(recs, q)
	if recs[0].RequestID != "b" || recs[2].RequestID != "a" {
		t.Fatalf("timestamp desc 排序错误: %+v", recs)
	}
	q = &auditQuery{Sort: "dur_ms", SortDesc: false}
	sortRecords(recs, q)
	if recs[0].RequestID != "b" {
		t.Fatalf("dur_ms asc 排序错误: %+v", recs)
	}
	page := paginate(recs, 1, 1)
	if len(page) != 1 || page[0].RequestID != "c" {
		t.Fatalf("分页错误: %+v", page)
	}
	if got := paginate(recs, 9, 1); len(got) != 0 {
		t.Fatalf("越界分页应空: %+v", got)
	}
}

func TestSampleShouldKeepDeterministic(t *testing.T) {
	// 同 request_id 多次执行结果一致（可重现，A3-08）。
	first := sampleShouldKeep("req-stable", 50)
	for i := 0; i < 5; i++ {
		if sampleShouldKeep("req-stable", 50) != first {
			t.Fatal("确定性采样应可重现")
		}
	}
	if !sampleShouldKeep("x", 100) {
		t.Fatal("rate=100 应全采样")
	}
	// 命中事件恒保留（sampleMiss）
	recs := []auditRecord{
		{RequestID: "m1", Result: "ok"},            // miss
		{RequestID: "hit", Result: "rate_limited"}, // hit → 恒保留
	}
	out := sampleMiss(recs, 1) // 极低采样率
	foundHit := false
	for _, r := range out {
		if r.RequestID == "hit" {
			foundHit = true
		}
	}
	if !foundHit {
		t.Fatal("命中事件应恒保留（D-16）")
	}
}

// ---- 留存校验 ----

func TestValidateRetention(t *testing.T) {
	ok := auditRetentionRequest{DeclaredDays: 365, HotDays: 7, WarmDays: 30, ColdDays: 180, SampleMissRate: 0}
	if err := validateRetention(ok); err != nil {
		t.Fatalf("合法声明应通过: %v", err)
	}
	if err := validateRetention(auditRetentionRequest{DeclaredDays: 90, HotDays: 7, WarmDays: 30, ColdDays: 180}); err == nil {
		t.Fatal("declared_days=90 应拒绝（(0,180)）")
	}
	if err := validateRetention(auditRetentionRequest{DeclaredDays: 0, HotDays: 7, WarmDays: 30, ColdDays: 180}); err != nil {
		t.Fatalf("declared_days=0（不声明）应通过: %v", err)
	}
	if err := validateRetention(auditRetentionRequest{DeclaredDays: 365, HotDays: 30, WarmDays: 30, ColdDays: 180}); err == nil {
		t.Fatal("warm<=hot 应拒绝")
	}
	if err := validateRetention(auditRetentionRequest{DeclaredDays: 365, HotDays: 1, WarmDays: 2, ColdDays: 3}); err == nil {
		t.Fatal("合计 <180 应拒绝")
	}
	if err := validateRetention(auditRetentionRequest{DeclaredDays: 365, HotDays: 7, WarmDays: 30, ColdDays: 180, SampleMissRate: 150}); err == nil {
		t.Fatal("sample_miss_rate=150 应拒绝")
	}
}

// ---- 本地归档后端 ----

func TestLocalArchiveStoreReadEvents(t *testing.T) {
	root := t.TempDir()
	writeArchiveFixture(t, root, "warm", "t1", "2026-01-01", []auditRecord{{RequestID: "r1", Timestamp: 1}})
	writeArchiveFixture(t, root, "warm", "t1", "2026-01-05", []auditRecord{{RequestID: "r2", Timestamp: 2}})
	writeArchiveFixture(t, root, "warm", "t1", "2026-02-01", []auditRecord{{RequestID: "r3", Timestamp: 3}})

	store := &localArchiveStore{root: root}
	got, err := store.readEvents(nil, "warm", "t1", "2026-01-01", "2026-01-31")
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("日期分区裁剪应 2 条: %d", len(got))
	}
	// 缺失租户 → 空（非错误）
	got, err = store.readEvents(nil, "warm", "nope", "2026-01-01", "2026-01-31")
	if err != nil || len(got) != 0 {
		t.Fatalf("缺失分区应返回空且无错误: %v %d", err, len(got))
	}
	// 路径穿越防护
	if _, err := store.readEvents(nil, "warm", "../evil", "2026-01-01", "2026-01-31"); err == nil {
		t.Fatal("非法分段应报错")
	}
}

// ---- 端点：检索 ----

func TestAuditFullSearchEndpoint(t *testing.T) {
	cfg := testCfg()
	root := t.TempDir()
	writeArchiveFixture(t, root, "warm", "t1", "2026-01-02", []auditRecord{
		{RequestID: "r1", TenantID: "t1", Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC).UnixNano(), Result: "ok", Action: "infer"},
		{RequestID: "r2", TenantID: "t1", Timestamp: time.Date(2026, 1, 2, 1, 0, 0, 0, time.UTC).UnixNano(), Result: "rate_limited", Action: "request", HitPolicies: "rpm_limit"},
	})
	mux := newAuditFullTestMux(t, cfg, newAuditTestChain(t, false), root)

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	to := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	target := auditFullSearchPath + "?tenant=t1&from=" + from + "&to=" + to + "&tier=warm"

	rec := auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1", target, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("检索应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []auditRecord     `json:"items"`
		Page  auditPage         `json:"page"`
		Chain auditChainSummary `json:"chain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非法 JSON: %v", err)
	}
	if resp.Page.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("应返回 2 条: %+v", resp.Page)
	}
	if resp.Chain.Schema != "tee" || resp.Chain.Tier != "warm" || resp.Chain.Events != 2 {
		t.Fatalf("chain 摘要错误: %+v", resp.Chain)
	}

	// hit 过滤
	rec = auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1", target+"&hit=hit", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Page.Total != 1 || resp.Items[0].RequestID != "r2" {
		t.Fatalf("hit 过滤错误: %+v", resp)
	}

	// 跨租户 → 403（audit_admin 非 unrestricted，请求他租户）
	rec = auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1", auditFullSearchPath+"?tenant=other&from="+from+"&to="+to, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨租户应 403，实际 %d", rec.Code)
	}

	// 缺 tenant → 400
	rec = auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1", auditFullSearchPath+"?from="+from+"&to="+to, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 tenant 应 400，实际 %d", rec.Code)
	}

	// 超跨度（cold 上限 90d，构造 100d）→ 400
	rec = auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1",
		auditFullSearchPath+"?tenant=t1&tier=cold&from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超跨度应 400，实际 %d", rec.Code)
	}
}

func TestAuditFullSearchArchiveNotConfigured503(t *testing.T) {
	cfg := testCfg()
	mux := newAuditFullTestMux(t, cfg, newAuditTestChain(t, false), "") // 归档根未配置
	rec := auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1",
		auditFullSearchPath+"?tenant=t1&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("归档未配置应 503（不静默返回空），实际 %d", rec.Code)
	}
}

// ---- 端点：导出 ----

func TestAuditFullExportEndpoint(t *testing.T) {
	cfg := testCfg()
	root := t.TempDir()
	writeArchiveFixture(t, root, "warm", "t1", "2026-01-02", []auditRecord{
		{RequestID: "r1", Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC).UnixNano(), Result: "ok", PrevHash: "abc"},
	})
	mux := newAuditFullTestMux(t, cfg, newAuditTestChain(t, false), root)

	target := auditFullExportPath + "?tenant=t1&tier=warm&from=2026-01-01T00:00:00Z&to=2026-01-03T00:00:00Z&sample_miss_rate=100"
	rec := auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "t1", target, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("导出应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "ndjson") {
		t.Fatalf("导出 Content-Type 应为 ndjson，实际 %q", ct)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("导出应带 attachment 头")
	}
	if rec.Header().Get("X-Audit-Chain-Events") != "1" {
		t.Fatalf("X-Audit-Chain-Events 应为 1，实际 %q", rec.Header().Get("X-Audit-Chain-Events"))
	}
	if rec.Header().Get("X-Audit-Chain-Last-Hash") != "abc" {
		t.Fatalf("链尾摘要头应为窗口锚 abc，实际 %q", rec.Header().Get("X-Audit-Chain-Last-Hash"))
	}
	if rec.Header().Get("X-Audit-Sample-Rate") != "100" {
		t.Fatalf("启用采样应附 X-Audit-Sample-Rate=100，实际 %q", rec.Header().Get("X-Audit-Sample-Rate"))
	}
	if !strings.Contains(rec.Body.String(), "sample_notice") {
		t.Fatal("抽样包内应有 sample_notice 说明")
	}
	if !strings.Contains(rec.Body.String(), `"request_id":"r1"`) {
		t.Fatal("导出行应含事件")
	}
}

// ---- 端点：留存 ----

func TestAuditRetentionRoundTrip(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	mux := newAuditFullTestMux(t, cfg, chain, t.TempDir())

	// GET 缺省声明
	rec := auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "", auditRetentionPath, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET 留存应 200，实际 %d", rec.Code)
	}
	var st retentionState
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st.DeclaredDays != 365 || st.ColdDays != 180 {
		t.Fatalf("缺省声明不符: %+v", st)
	}

	// PUT 合法声明 → 200 且落 G1 链（audit_retention_change）
	body := `{"declared_days":365,"hot_days":7,"warm_days":30,"cold_days":200,"sample_miss_rate":10}`
	rec = auditDo(t, mux, cfg, http.MethodPut, "alice", roleAdmin, "", auditRetentionPath, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT 应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var updated retentionState
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.ColdDays != 200 || updated.SampleMissRate != 10 {
		t.Fatalf("更新未生效: %+v", updated)
	}
	events, _ := chain.list(10, 0)
	found := false
	for _, e := range events {
		if e.Action == auditActionAuditRetentionChange {
			found = true
		}
	}
	if !found {
		t.Fatal("留存变更应落 G1 链（audit_retention_change）")
	}

	// PUT 非法（declared_days 90）→ 400 且配置未变更
	rec = auditDo(t, mux, cfg, http.MethodPut, "alice", roleAdmin, "", auditRetentionPath,
		`{"declared_days":90,"hot_days":7,"warm_days":30,"cold_days":200}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法声明应 400，实际 %d", rec.Code)
	}
	rec = auditDo(t, mux, cfg, http.MethodGet, "audit-user", roleAuditAdmin, "", auditRetentionPath, "")
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.DeclaredDays != 365 {
		t.Fatalf("非法 PUT 后配置不应变更: %+v", updated)
	}
}

func TestAuditRetentionWriteForbiddenForAuditor(t *testing.T) {
	cfg := testCfg()
	mux := newAuditFullTestMux(t, cfg, newAuditTestChain(t, false), t.TempDir())
	rec := auditDo(t, mux, cfg, http.MethodPut, "bob", roleAuditor, "", auditRetentionPath,
		`{"declared_days":365,"hot_days":7,"warm_days":30,"cold_days":200}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor 写留存应 403，实际 %d", rec.Code)
	}
}

// ---- G1 链落 audit_retention_change（事件格式回归） ----

func TestRetentionChainEventHashes(t *testing.T) {
	chain := newAuditTestChain(t, false)
	if err := chain.append(adminAuditEvent{
		Actor: "alice", Action: auditActionAuditRetentionChange, Result: "ok",
		Detail: `{"declared_days":365}`, RequestID: "req-1",
	}); err != nil {
		t.Fatalf("落链失败: %v", err)
	}
	ok, n := chain.verify()
	if !ok || n != 1 {
		t.Fatalf("链校验应 ok 且 1 条: ok=%v n=%d", ok, n)
	}
}
