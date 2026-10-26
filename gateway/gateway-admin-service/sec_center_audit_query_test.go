// Package main — P2-4 T-4.1 审计跨集群聚合查询（只读分卷）单测。
//
// 覆盖：admin 链直查（缺省 schema / 未启用）、core/tee 按集群拉取（成功/离线/错误/
// 注册表禁用/集群不存在）、单卷失败不影响其他卷（V-4 故障注入）、鉴权（无令牌 401 /
// 越权 403）、方法契约（仅 GET）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// newAuditQueryMux 装配含聚合查询端点的 mux（复用 buildAdminMux + 显式注册 query 路由）。
func newAuditQueryMux(t *testing.T, cfg *config, chain *adminAuditChain, cs ClusterStore, token string) (*http.ServeMux, *secCenterHandler) {
	t.Helper()
	us := &usageSettings{url: "", token: "tee-tok"}
	sch := newSecCenterHandler(chain, us)
	if cs != nil {
		sch.setClusterStore(cs)
	}
	if token != "" {
		sch.setDispatchToken(token)
	}
	mux := buildAdminMux(cfg, nil, nil, nil, nil, nil, sch, nil, nil, false)
	sch.registerAuditChainQuery(mux, cfg)
	return mux, sch
}

// auditQueryVolume 聚合查询单卷解码结构。
type auditQueryVolume struct {
	ClusterID   string            `json:"cluster_id"`
	ClusterName string            `json:"cluster_name"`
	Schema      string            `json:"schema"`
	Status      string            `json:"status"`
	Error       string            `json:"error"`
	EventCount  int               `json:"event_count"`
	Total       int               `json:"total"`
	LastHash    string            `json:"last_hash"`
	Events      []json.RawMessage `json:"events"`
}

// auditQueryResp 聚合查询响应解码结构。
type auditQueryResp struct {
	Schema                 string             `json:"schema"`
	ClusterRegistryEnabled bool               `json:"cluster_registry_enabled"`
	Volumes                []auditQueryVolume `json:"volumes"`
}

// queryGet 以指定角色发起聚合查询 GET。
func queryGet(t *testing.T, mux *http.ServeMux, cfg *config, sub, role, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if role != "" {
		req.Header.Set("Authorization", "Bearer "+testSignToken(t, cfg.jwtSecret, claims{
			Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
		}))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// newExportStub 构造 core/tee 导出端点假上游（返回 NDJSON + 元信息响应头；校验 Bearer 令牌）。
func newExportStub(t *testing.T, schema string, lines []string, tailHash string, status int, expectToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/internal/audit/chain/export", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("schema") != schema {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if expectToken != "" && r.Header.Get("Authorization") != "Bearer "+expectToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "application/x-ndjson")
		h.Set("X-Audit-Export-Schema", schema)
		h.Set("X-Audit-Export-Events", strconv.Itoa(len(lines)))
		h.Set("X-Audit-Export-Total", strconv.Itoa(len(lines)))
		h.Set("X-Audit-Export-Tail-Hash", tailHash)
		w.WriteHeader(http.StatusOK)
		for _, l := range lines {
			_, _ = io.WriteString(w, l+"\n")
		}
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// stubClusterFetcher 注入式假拉取（离线/错误路径用，避免真实网络）。
type stubClusterFetcher struct {
	vol *auditChainVolume
	err error
}

func (s stubClusterFetcher) FetchClusterChain(_ context.Context, _ string, schema, _ string, _ int) (*auditChainVolume, error) {
	if s.err != nil {
		return nil, s.err
	}
	v := *s.vol
	v.Schema = schema
	return &v, nil
}

func clusterWithEndpoint(id, endpoint string) *ClusterRecord {
	c := sampleCluster(id)
	if endpoint != "" {
		c.Endpoint = endpoint
	}
	return c
}

// ---- admin 链（只读，不重算哈希）----

func TestAuditChainQuery_AdminDefaultSchema(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	seedChain(t, chain, 3)
	mux, _ := newAuditQueryMux(t, cfg, chain, nil, "")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("查询应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp auditQueryResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非合法 JSON：%v", err)
	}
	if resp.Schema != "admin" || resp.ClusterRegistryEnabled {
		t.Fatalf("schema/registry 不符：%+v", resp)
	}
	if len(resp.Volumes) != 1 {
		t.Fatalf("admin 应仅 1 卷，实际 %d", len(resp.Volumes))
	}
	v := resp.Volumes[0]
	if v.ClusterID != "" || v.Schema != "admin" || v.Status != auditVolOK {
		t.Fatalf("admin 卷头部不符：%+v", v)
	}
	if v.EventCount != 3 || v.Total != 3 || len(v.Events) != 3 {
		t.Fatalf("admin 卷应含 3 条事件，实际 count=%d total=%d len=%d", v.EventCount, v.Total, len(v.Events))
	}
	if v.LastHash != chain.lastHash() {
		t.Fatalf("last_hash 应为链尾哈希 %s，实际 %q", chain.lastHash(), v.LastHash)
	}
}

func TestAuditChainQuery_AdminDisabled(t *testing.T) {
	cfg := testCfg()
	mux, _ := newAuditQueryMux(t, cfg, nil, nil, "") // 审计链未启用

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("聚合查询未启用审计链应 200（逐卷 status=disabled，不整响应 503），实际 %d", rec.Code)
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 1 || resp.Volumes[0].Status != auditVolDisabled {
		t.Fatalf("admin 未启用应单卷 disabled，实际 %+v", resp.Volumes)
	}
	if len(resp.Volumes[0].Events) != 0 {
		t.Fatal("disabled 卷不应含事件")
	}
}

// ---- core/tee 按集群拉取（真实 httptest 端点，验证 URL/令牌/NDJSON 透传）----

func TestAuditChainQuery_CoreAllClustersSuccess(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	ctx := context.Background()
	tsA := newExportStub(t, "core", []string{`{"event_id":"a1"}`, `{"event_id":"a2"}`}, "hashA", http.StatusOK, "tk")
	tsB := newExportStub(t, "core", []string{`{"event_id":"b1"}`}, "hashB", http.StatusOK, "tk")
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-a", tsA.URL)); err != nil {
		t.Fatal(err)
	}
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-b", tsB.URL)); err != nil {
		t.Fatal(err)
	}
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core")
	if rec.Code != http.StatusOK {
		t.Fatalf("查询应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Schema != "core" || !resp.ClusterRegistryEnabled {
		t.Fatalf("schema/registry 不符：%+v", resp)
	}
	if len(resp.Volumes) != 2 {
		t.Fatalf("应 2 卷（两集群），实际 %d：%+v", len(resp.Volumes), resp.Volumes)
	}
	byID := map[string]auditQueryVolume{}
	for _, v := range resp.Volumes {
		byID[v.ClusterID] = v
	}
	va, okA := byID["cluster-a"]
	vb, okB := byID["cluster-b"]
	if !okA || !okB {
		t.Fatalf("缺集群卷：%+v", byID)
	}
	if va.Status != auditVolOK || va.EventCount != 2 || va.LastHash != "hashA" {
		t.Fatalf("cluster-a 卷不符：%+v", va)
	}
	if vb.Status != auditVolOK || vb.EventCount != 1 || vb.LastHash != "hashB" {
		t.Fatalf("cluster-b 卷不符：%+v", vb)
	}
}

func TestAuditChainQuery_CoreSingleClusterSuccess(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	ctx := context.Background()
	ts := newExportStub(t, "core", []string{`{"event_id":"x1"}`}, "hashX", http.StatusOK, "tk")
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-x", ts.URL)); err != nil {
		t.Fatal(err)
	}
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core&cluster=cluster-x")
	if rec.Code != http.StatusOK {
		t.Fatalf("查询应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 1 || resp.Volumes[0].ClusterID != "cluster-x" || resp.Volumes[0].Status != auditVolOK {
		t.Fatalf("单集群卷不符：%+v", resp.Volumes)
	}
}

func TestAuditChainQuery_TeeSuccess(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	ctx := context.Background()
	ts := newExportStub(t, "tee", []string{`{"event_id":"t1"}`, `{"event_id":"t2"}`, `{"event_id":"t3"}`}, "hashT", http.StatusOK, "tk")
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-t", ts.URL)); err != nil {
		t.Fatal(err)
	}
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=tee&cluster=cluster-t")
	if rec.Code != http.StatusOK {
		t.Fatalf("查询应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 1 || resp.Volumes[0].Schema != "tee" || resp.Volumes[0].EventCount != 3 {
		t.Fatalf("tee 卷不符：%+v", resp.Volumes)
	}
}

// ---- 降级语义：单卷失败不影响其他卷（V-4 故障注入）----

func TestAuditChainQuery_CoreOneOfflineOthersOK(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	ctx := context.Background()
	tsOK := newExportStub(t, "core", []string{`{"event_id":"ok1"}`}, "hashOK", http.StatusOK, "tk")
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-ok", tsOK.URL)); err != nil {
		t.Fatal(err)
	}
	// 离线集群：端点指向已关闭的监听（连接被拒 ⇒ offline）。
	closed := httptest.NewServer(http.NewServeMux())
	closedURL := closed.URL
	closed.Close()
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-down", closedURL)); err != nil {
		t.Fatal(err)
	}
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core")
	if rec.Code != http.StatusOK {
		t.Fatalf("聚合查询应 200（不因单集群离线而失败），实际 %d", rec.Code)
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 2 {
		t.Fatalf("应 2 卷（一在线一离线），实际 %d：%+v", len(resp.Volumes), resp.Volumes)
	}
	var ok, down auditQueryVolume
	for _, v := range resp.Volumes {
		switch v.ClusterID {
		case "cluster-ok":
			ok = v
		case "cluster-down":
			down = v
		}
	}
	if ok.Status != auditVolOK || ok.EventCount != 1 {
		t.Fatalf("在线集群应 ok 且含 1 事件，实际 %+v", ok)
	}
	if down.Status != auditVolOffline {
		t.Fatalf("离线集群应标 offline，实际 %+v", down)
	}
	if len(down.Events) != 0 {
		t.Fatal("offline 卷不应含事件（不为空链，但无数据）")
	}
}

func TestAuditChainQuery_CoreClusterError(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	ctx := context.Background()
	ts := newExportStub(t, "core", nil, "", http.StatusInternalServerError, "tk")
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-err", ts.URL)); err != nil {
		t.Fatal(err)
	}
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core&cluster=cluster-err")
	if rec.Code != http.StatusOK {
		t.Fatalf("聚合查询应 200，实际 %d", rec.Code)
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 1 || resp.Volumes[0].Status != auditVolError {
		t.Fatalf("错误集群应标 error，实际 %+v", resp.Volumes)
	}
	if !strings.Contains(resp.Volumes[0].Error, "HTTP 500") {
		t.Fatalf("error 文案应包含 HTTP 状态码，实际 %q", resp.Volumes[0].Error)
	}
}

func TestAuditChainQuery_CoreRegistryDisabled(t *testing.T) {
	cfg := testCfg()
	// 不注入集群注册表（cs=nil）。
	mux, _ := newAuditQueryMux(t, cfg, nil, nil, "")

	// 指定 cluster ⇒ 单卷 disabled。
	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core&cluster=anything")
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", rec.Code)
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ClusterRegistryEnabled {
		t.Fatal("cluster_registry_enabled 应为 false")
	}
	if len(resp.Volumes) != 1 || resp.Volumes[0].Status != auditVolDisabled {
		t.Fatalf("指定集群但注册表禁用应单卷 disabled，实际 %+v", resp.Volumes)
	}

	// 不指定 cluster ⇒ 空卷集（仍 200）。
	rec = queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 0 {
		t.Fatalf("注册表禁用且无指定集群应无卷，实际 %+v", resp.Volumes)
	}
}

func TestAuditChainQuery_CoreClusterNotFound(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core&cluster=ghost")
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", rec.Code)
	}
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 1 || resp.Volumes[0].Status != auditVolNotFound {
		t.Fatalf("不存在集群应标 not_found，实际 %+v", resp.Volumes)
	}
}

func TestAuditChainQuery_CoreRemovedClusterSkipped(t *testing.T) {
	cfg := testCfg()
	cs := openTestClusterStore(t)
	ctx := context.Background()
	tsOK := newExportStub(t, "core", []string{`{"event_id":"ok1"}`}, "hashOK", http.StatusOK, "tk")
	if err := cs.Register(ctx, clusterWithEndpoint("cluster-ok", tsOK.URL)); err != nil {
		t.Fatal(err)
	}
	removed := clusterWithEndpoint("cluster-rm", tsOK.URL)
	removed.Status = ClusterStatusRemoved
	if err := cs.Register(ctx, removed); err != nil {
		t.Fatal(err)
	}
	mux, _ := newAuditQueryMux(t, cfg, nil, cs, "tk")

	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=core")
	var resp auditQueryResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Volumes) != 1 || resp.Volumes[0].ClusterID != "cluster-ok" {
		t.Fatalf("已摘除集群应被跳过，实际 %+v", resp.Volumes)
	}
}

// ---- 契约/鉴权 ----

func TestAuditChainQuery_BadSchema(t *testing.T) {
	cfg := testCfg()
	mux, _ := newAuditQueryMux(t, cfg, nil, nil, "")
	rec := queryGet(t, mux, cfg, "audit-user", roleAuditAdmin, auditChainQueryPath+"?schema=foo")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 schema 应 400，实际 %d", rec.Code)
	}
}

func TestAuditChainQuery_RequiresAuth(t *testing.T) {
	cfg := testCfg()
	mux, _ := newAuditQueryMux(t, cfg, nil, nil, "")
	// 无令牌 ⇒ 401。
	rec := queryGet(t, mux, cfg, "", "", auditChainQueryPath)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实际 %d", rec.Code)
	}
	// 越权角色（system_admin 不在 audit:read 列表，且非 legacy admin 映射）⇒ 403。
	rec = queryGet(t, mux, cfg, "sys", roleSystemAdmin, auditChainQueryPath)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rec.Code)
	}
	// auditor 可读（与 audit-chain 同口径）。
	rec = queryGet(t, mux, cfg, "bob", roleAuditor, auditChainQueryPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("auditor 应可读，实际 %d", rec.Code)
	}
}

func TestAuditChainQuery_RejectsNonGet(t *testing.T) {
	cfg := testCfg()
	mux, _ := newAuditQueryMux(t, cfg, nil, nil, "")
	req := httptest.NewRequest(http.MethodPost, auditChainQueryPath, nil)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, cfg.jwtSecret, claims{
		Sub: "audit-user", Role: roleAuditAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST 应 405（只读端点），实际 %d", rec.Code)
	}
}

// 校验 fetchOne 对注入式 stub 的 error/offline 映射（离线/错误路径确定性覆盖）。
func TestAuditChainQuery_fetchOneMapping(t *testing.T) {
	cs := openTestClusterStore(t)
	ctx := context.Background()
	if err := cs.Register(ctx, clusterWithEndpoint("c1", "https://c1.example.com")); err != nil {
		t.Fatal(err)
	}
	rec, _ := cs.Get(ctx, "c1")

	h := newSecCenterHandler(nil, &usageSettings{})
	// 离线（非 HTTP 错误）。
	h.fetcher = stubClusterFetcher{err: errors.New("dial tcp: connection refused")}
	vOff := h.fetchOne(ctx, rec, "core", 0)
	if vOff.Status != auditVolOffline {
		t.Fatalf("非 HTTP 错误应映射 offline，实际 %s/%s", vOff.Status, vOff.Error)
	}
	// 导出端点错误（HTTP 500）。
	h.fetcher = stubClusterFetcher{err: &fetchHTTPError{Code: 500}}
	vErr := h.fetchOne(ctx, rec, "core", 0)
	if vErr.Status != auditVolError || !strings.Contains(vErr.Error, "HTTP 500") {
		t.Fatalf("HTTP 错误应映射 error，实际 %s/%s", vErr.Status, vErr.Error)
	}
	// 成功。
	h.fetcher = stubClusterFetcher{vol: &auditChainVolume{Status: auditVolOK, Events: []json.RawMessage{json.RawMessage(`{"e":1}`)}, EventCount: 1}}
	vOK := h.fetchOne(ctx, rec, "core", 0)
	if vOK.Status != auditVolOK || vOK.ClusterID != "c1" || vOK.ClusterName != rec.Name {
		t.Fatalf("成功卷应回填集群标识，实际 %+v", vOK)
	}
}
