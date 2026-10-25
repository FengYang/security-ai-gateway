package api

// P2-4 T-3.5（V-3）：core 侧串扰/隔离用例。
//
// 隔离面（core 侧，§6.2 + V-3）：**每集群只见本集群配置**。
// admin 侧隔离（"下发计划不串扰"：cluster-a 的策略不得出现在 cluster-b 的下发计划里）
// 由工程师 1 在 T-3.1/T-3.2 实现；本文件覆盖 **core 侧**三面：
//
//  1. 快照隔离：快照路径按集群维度唯一 ⇒ A 集群的快照变更不影响 B 集群快照；
//  2. 凭证/身份隔离：applied 版本上报**按 source 分槽**、**不跨实例混用**；
//     心跳凭证与 cluster ID 绑定（缺任一 ⇒ fail-closed），上报只携带**本实例**凭证；
//  3. 插件拉取面隔离：/routes 与 /prescriptions 只暴露**本集群**内容。
//
// ⚠️ **负向用例必须同时断言"本集群数据可见"**：只断言"取不到"会被"全 nil / 空表"
// 造成假阴性，故每条负向断言都配一条正向断言。
//
// 形态口径：core 是**单集群形态**（一个 core 实例 = 一个集群）；跨集群隔离由
// "每集群独立实例 + 独立快照路径 + 独立集群凭证"三要素保证，本组用例验证三要素
// 互不串扰（而非验证"单实例内多集群视图"，后者属 admin 侧职责）。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/configversion"
	"security-ai-gateway/gateway/gateway-core/internal/heartbeat"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// isolationServer 构造一个**独立**的 core 实例（独立 store ⇒ 独立集群形态）。
func isolationServer(t *testing.T, st store.Store) *Server {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sig, err := route.NewSigner(key)
	if err != nil {
		t.Fatalf("构造路由签名器失败: %v", err)
	}
	msig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatalf("构造 MCP 签名器失败: %v", err)
	}
	rlsig, err := ratelimit.NewSigner(key)
	if err != nil {
		t.Fatalf("构造限流签名器失败: %v", err)
	}
	return New(sig, msig, rlsig, nil, st, "tok",
		route.NewRouteTable(1, 1725500000), ratelimit.NewTable(1, time.Unix(1725500000, 0)))
}

// TestIsolationSnapshotPerClusterPath **隔离面 1：快照隔离**。
//
// 快照路径由部署按**集群维度**唯一确定（env GATEWAY_CORE_STORE_SNAPSHOT_PATH，
// 每集群一份 PVC/文件）⇒ A 集群的快照变更**不得**影响 B 集群快照。
//
// 负向：A 的处方/路由表不得出现在 B 的快照里；
// 正向：A 的快照恢复后**本集群数据可见**（防"全 nil"假阴性）。
func TestIsolationSnapshotPerClusterPath(t *testing.T) {
	pathA := filepath.Join(t.TempDir(), "cluster-a", "snap.json")
	pathB := filepath.Join(t.TempDir(), "cluster-b", "snap.json")

	// —— 集群 A：写入本集群状态 ——
	memA := store.NewMemory()
	ssA := store.NewSnapshotStore(memA, pathA, nil)
	ssA.SetFlushInterval(0) // 同步写：便于断言落盘结果
	if err := ssA.Prepare(); err != nil {
		t.Fatalf("A 集群快照准备失败: %v", err)
	}
	_ = ssA.Save(&route.RoutePrescription{PrescriptionID: "rx-a", Tenant: "tenant-a"})
	rtA := route.NewRouteTable(7, 1234)
	rtA.Routes = []route.TableRoute{{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas"}}
	ssA.SaveRouteTable(rtA)

	// —— 集群 B：独立路径，独立状态 ——
	memB := store.NewMemory()
	ssB := store.NewSnapshotStore(memB, pathB, nil)
	ssB.SetFlushInterval(0)
	if err := ssB.Prepare(); err != nil {
		t.Fatalf("B 集群快照准备失败: %v", err)
	}
	_ = ssB.Save(&route.RoutePrescription{PrescriptionID: "rx-b", Tenant: "tenant-b"})
	bytesB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatalf("读 B 集群快照失败: %v", err)
	}

	// —— 隔离断言 1（字节级）：A 的快照变更**不得**改动 B 的快照文件 ——
	bytesAAfter, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("读 A 集群快照失败: %v", err)
	}
	bytesBAfter, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatalf("读 B 集群快照失败: %v", err)
	}
	if !bytes.Equal(bytesB, bytesBAfter) {
		t.Fatalf("A 集群的快照变更改动了 B 集群的快照文件（串扰）")
	}
	if bytes.Contains(bytesBAfter, []byte("rx-a")) {
		t.Fatalf("B 集群快照文件含 A 集群的处方（串扰）")
	}
	if !bytes.Contains(bytesAAfter, []byte("rx-a")) {
		t.Fatalf("A 集群快照文件应含本集群处方 rx-a")
	}
	if bytes.Contains(bytesAAfter, []byte("rx-b")) {
		t.Fatalf("A 集群快照文件含 B 集群的处方（串扰）")
	}

	// 负向：B 恢复后**不得**含 A 的数据。
	memB2 := store.NewMemory()
	ssB2 := store.NewSnapshotStore(memB2, pathB, nil)
	if err := ssB2.LoadSnapshot(); err != nil {
		t.Fatalf("B 集群快照恢复失败: %v", err)
	}
	if _, ok := memB2.Get("rx-a"); ok {
		t.Fatalf("B 集群快照出现了 A 集群的处方（串扰）")
	}
	if rt := memB2.GetRouteTable(); rt != nil {
		t.Fatalf("B 集群快照出现了 A 集群的路由表（串扰）")
	}
	// 正向：B 恢复后**本集群**数据可见（防"全 nil"假阴性）。
	if _, ok := memB2.Get("rx-b"); !ok {
		t.Fatalf("B 集群快照应含本集群处方 rx-b")
	}

	// 正向：A 恢复后**本集群**数据可见（防"全 nil"假阴性）。
	memA2 := store.NewMemory()
	ssA2 := store.NewSnapshotStore(memA2, pathA, nil)
	if err := ssA2.LoadSnapshot(); err != nil {
		t.Fatalf("A 集群快照恢复失败: %v", err)
	}
	if _, ok := memA2.Get("rx-a"); !ok {
		t.Fatalf("A 集群快照应含本集群处方 rx-a")
	}
	rt := memA2.GetRouteTable()
	if rt == nil || rt.Version != 7 || len(rt.Routes) != 1 || rt.Routes[0].Tenant != "tenant-a" {
		t.Fatalf("A 集群快照应含本集群路由表 v7（tenant-a），got %+v", rt)
	}
	// 负向：A 的恢复结果不得含 B 的数据。
	if _, ok := memA2.Get("rx-b"); ok {
		t.Fatalf("A 集群快照出现了 B 集群的处方（串扰）")
	}
}

// TestIsolationAppliedVersionSlotAndCredential **隔离面 2：凭证/身份隔离**。
//
// core 侧目前没有"多集群共存于单实例"的形态，故按派单口径验证四件事：
// (a) **上报内容按 source 分槽**：同实例内不同 source 互不覆盖；
// (b) **不跨实例混用**：另一实例（另一集群进程）看不到本实例的记录；
// (c) **凭证与 cluster ID 绑定**：缺任一 ⇒ fail-closed（不构造上报器）；
// (d) 每个上报器**只携带本实例**的凭证与集群 ID（不串用他集群凭证）。
func TestIsolationAppliedVersionSlotAndCredential(t *testing.T) {
	// —— (a) 按 source 分槽 ——
	cache := configversion.New()
	if _, ok := cache.Report("cluster-a/routes", "v7", time.Now()); !ok {
		t.Fatalf("cluster-a 的上报应被采纳")
	}
	if _, ok := cache.Report("cluster-b/routes", "v9", time.Now()); !ok {
		t.Fatalf("cluster-b 的上报应被采纳")
	}
	gotA, okA := cache.Get("cluster-a/routes")
	gotB, okB := cache.Get("cluster-b/routes")
	if !okA || !okB {
		t.Fatalf("两个 source 的槽位都应存在: okA=%v okB=%v", okA, okB)
	}
	if gotA.Version != "v7" || gotB.Version != "v9" {
		t.Fatalf("按 source 分槽被串扰: a=%q b=%q", gotA.Version, gotB.Version)
	}

	// —— (b) 不跨实例混用 ——
	other := configversion.New()
	if _, ok := other.Get("cluster-a/routes"); ok {
		t.Fatalf("另一实例不应看到本实例的上报记录（跨实例混用）")
	}
	// 正向：本实例读回自己的记录（防"全 nil"假阴性）。
	if rec, ok := cache.Get("cluster-a/routes"); !ok || rec.Version != "v7" {
		t.Fatalf("本实例应能读回本实例的上报记录: %+v ok=%v", rec, ok)
	}

	// —— (c) 凭证与 cluster ID 绑定：缺任一 ⇒ fail-closed ——
	if _, err := heartbeat.NewReporter(heartbeat.Config{
		Endpoint: "http://admin.invalid/v1/heartbeat", ClusterID: "cluster-a",
	}); err == nil {
		t.Fatalf("缺集群凭证必须 fail-closed（不得构造上报器）")
	}
	if _, err := heartbeat.NewReporter(heartbeat.Config{
		Endpoint: "http://admin.invalid/v1/heartbeat", Credential: "cred-a",
	}); err == nil {
		t.Fatalf("缺 cluster ID 必须 fail-closed（不得构造上报器）")
	}

	// —— (d) 每个上报器只携带本实例凭证（不串用他集群凭证） ——
	type captured struct {
		credential string
		body       string
	}
	capture := func(version string) (*captured, *heartbeat.Reporter) {
		t.Helper()
		got := &captured{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.credential = r.Header.Get("X-Cluster-Credential")
			b, _ := io.ReadAll(r.Body)
			got.body = string(b)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		rep, err := heartbeat.NewReporter(heartbeat.Config{
			Endpoint: srv.URL, ClusterID: "cluster-" + version, Credential: "cred-" + version,
		})
		if err != nil {
			t.Fatalf("构造上报器失败: %v", err)
		}
		return got, rep
	}
	gotA2, repA := capture("a")
	gotB2, repB := capture("b")
	if err := repA.ReportOnce(context.Background(), "v7"); err != nil {
		t.Fatalf("A 上报失败: %v", err)
	}
	if err := repB.ReportOnce(context.Background(), "v9"); err != nil {
		t.Fatalf("B 上报失败: %v", err)
	}
	if gotA2.credential != "cred-a" || gotB2.credential != "cred-b" {
		t.Fatalf("上报凭证串用: a=%q b=%q", gotA2.credential, gotB2.credential)
	}
	if !strings.Contains(gotA2.body, `"v7"`) || strings.Contains(gotA2.body, `"v9"`) {
		t.Fatalf("A 的上报体不得含 B 的版本: %s", gotA2.body)
	}
	if !strings.Contains(gotB2.body, `"v9"`) || strings.Contains(gotB2.body, `"v7"`) {
		t.Fatalf("B 的上报体不得含 A 的版本: %s", gotB2.body)
	}
}

// TestIsolationRoutesPullNoCrossClusterContent **隔离面 3：插件拉取面隔离**。
//
// core 拉取面（/routes、/prescriptions）只暴露**本集群**内容：另一集群的处方/
// 路由不得出现在本实例的响应里。
//
// 负向：A 取 B 的处方 ⇒ 404；A 的 /routes 不得含 B 的租户；
// 正向：A 取本集群处方 ⇒ 200 且内容正确（本集群数据可见，防"全 nil"假阴性）。
func TestIsolationRoutesPullNoCrossClusterContent(t *testing.T) {
	// —— 集群 A 实例 ——
	memA := store.NewMemory()
	srvA := isolationServer(t, memA)
	_ = memA.Save(&route.RoutePrescription{PrescriptionID: "rx-a", Tenant: "tenant-a", Model: "qwen-plus"})
	rtA := route.NewRouteTable(7, 1234)
	rtA.Routes = []route.TableRoute{{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas"}}
	memA.SaveRouteTable(rtA)

	// —— 集群 B 实例（独立 store、独立路由表） ——
	memB := store.NewMemory()
	srvB := isolationServer(t, memB)
	_ = memB.Save(&route.RoutePrescription{PrescriptionID: "rx-b", Tenant: "tenant-b", Model: "deepseek-v3"})
	rtB := route.NewRouteTable(9, 1234)
	rtB.Routes = []route.TableRoute{{Tenant: "tenant-b", Model: "deepseek-v3", DefaultEngine: "cmaas"}}
	memB.SaveRouteTable(rtB)

	get := func(s *Server, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// 正向：A 取**本集群**处方 ⇒ 200 且内容正确（防假阴性）。
	rec := get(srvA, "/prescriptions/rx-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("A 取本集群处方应 200，got %d", rec.Code)
	}
	var got route.RoutePrescription
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析处方失败: %v", err)
	}
	if got.PrescriptionID != "rx-a" || got.Tenant != "tenant-a" {
		t.Fatalf("A 取到的应是本集群处方，got %+v", got)
	}

	// 负向：A 取 B 的处方 ⇒ 404（不得返回他集群内容）。
	if rec := get(srvA, "/prescriptions/rx-b"); rec.Code != http.StatusNotFound {
		t.Fatalf("A 取 B 的处方应 404（不得暴露他集群内容），got %d", rec.Code)
	}
	// 反向同理：B 取 A 的处方 ⇒ 404。
	if rec := get(srvB, "/prescriptions/rx-a"); rec.Code != http.StatusNotFound {
		t.Fatalf("B 取 A 的处方应 404（不得暴露他集群内容），got %d", rec.Code)
	}

	// 负向：A 的 /routes 不得含 B 的租户；正向：必须含本集群租户（防假阴性）。
	rec = get(srvA, "/routes")
	if rec.Code != http.StatusOK {
		t.Fatalf("A 拉取路由应 200，got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "tenant-a") {
		t.Fatalf("A 拉取的路由表应含本集群租户 tenant-a: %s", body)
	}
	if strings.Contains(body, "tenant-b") {
		t.Fatalf("A 拉取的路由表不得含他集群租户 tenant-b（串扰）: %s", body)
	}
	// 反向同理。
	rec = get(srvB, "/routes")
	if rec.Code != http.StatusOK {
		t.Fatalf("B 拉取路由应 200，got %d", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, "tenant-b") {
		t.Fatalf("B 拉取的路由表应含本集群租户 tenant-b: %s", body)
	}
	if strings.Contains(body, "tenant-a") {
		t.Fatalf("B 拉取的路由表不得含他集群租户 tenant-a（串扰）: %s", body)
	}
}
