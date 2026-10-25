// P2-4 T-1.7 快照持久化单测：原子性、恢复一致性、损坏拒载、开关关闭零行为、防回退。
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/gateway-core/internal/mcpsrv"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/mcpsec"
)

// fillSampleState 向 store 写入覆盖全部状态域的样例数据。
func fillSampleState(s Store) {
	_ = s.Save(&route.RoutePrescription{
		PrescriptionID: "rx-1", Tenant: "tenant-a", Model: "qwen-plus",
		CreatedAt: 1000, ExpiresAt: 2000, JTI: "jti-1",
	})
	_ = s.Save(&route.RoutePrescription{
		PrescriptionID: "rx-2", Tenant: "tenant-b", Model: "deepseek-v3",
		CreatedAt: 1100, ExpiresAt: 2100, JTI: "jti-2",
	})
	rt := route.NewRouteTable(7, 1234)
	rt.Routes = []route.TableRoute{{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas"}}
	s.SaveRouteTable(rt)

	rlt := ratelimit.NewTable(5, time.Unix(1234, 0))
	rlt.Rules = []ratelimit.Rule{{ID: "r1", Kind: ratelimit.KindRate, Target: "tenant-a", RPM: 60, Enabled: true}}
	s.SaveRateLimitTable(rlt)

	acl := a2aproxy.NewACLTable(3, time.Unix(1234, 0))
	s.SaveACLTable(acl)

	a2arl := a2aproxy.NewRateLimitTable(4, time.Unix(1234, 0))
	s.SaveA2ARateLimitTable(a2arl)

	s.SaveToolCatalog(&mcpsec.ToolCatalog{Version: 9, UpdatedAt: 1234, Tools: []mcpsec.TableTool{}})
	s.SaveRBACPolicy(&mcpsec.RBACPolicy{
		Version: 6, UpdatedAt: 1234,
		TenantRules: map[string]map[string]*mcpsec.PolicyBinding{
			"tenant-a": {"search": {}},
		},
	})
	s.SaveMCPServer(&mcpsrv.Server{ID: "sv-1", BaseURL: "https://mcp.example.com", Prefix: "a_", Track: "public"})
	s.SaveMCPServer(&mcpsrv.Server{ID: "sv-2", BaseURL: "https://mcp2.example.com", Prefix: "b_"})
}

// readPayload 读盘并解码快照载荷（测试辅助）。
func readPayload(t *testing.T, path string) *snapshotPayload {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}
	p, err := decodeSnapshot(b)
	if err != nil {
		t.Fatalf("解码快照失败: %v", err)
	}
	return p
}

// assertSameState 断言两个 store 的全部状态域一致（恢复一致性）。
func assertSameState(t *testing.T, want, got *Memory) {
	t.Helper()
	if len(want.ListMCPServers()) != len(got.ListMCPServers()) {
		t.Fatalf("MCP 后端数量不一致: want %d got %d", len(want.ListMCPServers()), len(got.ListMCPServers()))
	}
	for _, sv := range want.ListMCPServers() {
		g := got.GetMCPServer(sv.ID)
		if g == nil || *g != *sv {
			t.Fatalf("MCP 后端 %s 恢复不一致", sv.ID)
		}
	}
	for _, id := range []string{"rx-1", "rx-2"} {
		wp, ok1 := want.Get(id)
		gp, ok2 := got.Get(id)
		if ok1 != ok2 || wp == nil || gp == nil {
			t.Fatalf("处方 %s 恢复存在性不一致", id)
		}
		if *wp != *gp {
			t.Fatalf("处方 %s 恢复不一致", id)
		}
	}
	if len(want.ListByTenant("tenant-a")) != len(got.ListByTenant("tenant-a")) {
		t.Fatalf("tenant 索引恢复不一致")
	}
	wrt, grt := want.GetRouteTable(), got.GetRouteTable()
	if wrt == nil || grt == nil || wrt.Version != grt.Version || len(wrt.Routes) != len(grt.Routes) {
		t.Fatalf("路由表恢复不一致")
	}
	if wrt.Version != grt.Version || wrt.UpdatedAt != grt.UpdatedAt {
		t.Fatalf("路由表元数据恢复不一致")
	}
	wrl, grl := want.GetRateLimitTable(), got.GetRateLimitTable()
	if wrl == nil || grl == nil || wrl.Version != grl.Version || len(wrl.Rules) != len(grl.Rules) {
		t.Fatalf("限流表恢复不一致")
	}
	wacl, gacl := want.GetACLTable(), got.GetACLTable()
	if wacl == nil || gacl == nil || wacl.Version != gacl.Version {
		t.Fatalf("ACL 表恢复不一致")
	}
	wa2a, ga2a := want.GetA2ARateLimitTable(), got.GetA2ARateLimitTable()
	if wa2a == nil || ga2a == nil || wa2a.Version != ga2a.Version {
		t.Fatalf("A2A 限流表恢复不一致")
	}
	wc, gc := want.GetToolCatalog(), got.GetToolCatalog()
	if wc == nil || gc == nil || wc.Version != gc.Version {
		t.Fatalf("工具目录恢复不一致")
	}
	wp, gp := want.GetRBACPolicy(), got.GetRBACPolicy()
	if wp == nil || gp == nil || wp.Version != gp.Version || len(wp.TenantRules) != len(gp.TenantRules) {
		t.Fatalf("RBAC 策略恢复不一致")
	}
}

// TestSnapshotAtomicWriteSemantics 验证原子写语义：rename 后不留临时文件残留。
func TestSnapshotAtomicWriteSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	fillSampleState(ss) // 每次变更都会触发一次原子写

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("快照文件应存在: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("目录应仅剩快照文件（无临时文件残留）: got %d 项", len(entries))
	}
	// 再来一轮写盘，仍无残留。
	if err := ss.Persist(); err != nil {
		t.Fatalf("二次落盘失败: %v", err)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("二次落盘后目录仍应仅剩快照文件: got %d 项", len(entries))
	}
}

// TestSnapshotRoundTripRecovery 写 → 重建 → 读，全部状态域一致。
func TestSnapshotRoundTripRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	m1 := NewMemory()
	fillSampleState(m1)
	ss1 := NewSnapshotStore(m1, path, nil)
	if err := ss1.Persist(); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}

	// 全新进程语义：空内存 + LoadSnapshot 恢复。
	m2 := NewMemory()
	ss2 := NewSnapshotStore(m2, path, nil)
	if err := ss2.LoadSnapshot(); err != nil {
		t.Fatalf("快照恢复失败: %v", err)
	}
	assertSameState(t, m1, m2)
}

// TestSnapshotCorruptRejected 损坏快照（截断/篡改/空文件）拒绝加载且内存保持空。
func TestSnapshotCorruptRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	m1 := NewMemory()
	fillSampleState(m1)
	if err := NewSnapshotStore(m1, path, nil).Persist(); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"截断", raw[:len(raw)/2]},
		{"空文件", []byte{}},
		{"非法JSON", []byte("not-json{{{")},
		{"篡改载荷", tamperPayload(t, raw)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cpath := filepath.Join(t.TempDir(), "snap.json")
			if err := os.WriteFile(cpath, tc.data, 0o600); err != nil {
				t.Fatalf("写损坏快照失败: %v", err)
			}
			m := NewMemory()
			ss := NewSnapshotStore(m, cpath, nil)
			if err := ss.LoadSnapshot(); err == nil {
				t.Fatalf("损坏快照应拒绝加载")
			}
			// 内存保持空：fail-open 但不半恢复。
			if _, ok := m.Get("rx-1"); ok {
				t.Fatalf("拒载后内存不应含处方")
			}
			if m.GetRouteTable() != nil || m.GetACLTable() != nil || m.GetToolCatalog() != nil {
				t.Fatalf("拒载后内存不应含任何表")
			}
			if len(m.ListMCPServers()) != 0 {
				t.Fatalf("拒载后内存不应含 MCP 后端")
			}
		})
	}
}

// tamperPayload 保持 JSON 合法但改动载荷一个字节 → 校验和不匹配。
func tamperPayload(t *testing.T, raw []byte) []byte {
	t.Helper()
	var env snapshotEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("解析信封失败: %v", err)
	}
	// 把 checksum 替换成空载荷的正确校验和：内容变了、校验和与真实内容不符。
	sum := sha256.Sum256([]byte(`{}`))
	env.Checksum = checksumPrefix + hex.EncodeToString(sum[:])
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("重编码信封失败: %v", err)
	}
	return out
}

// TestSnapshotSchemaVersionReject 不识别的 schema 版本拒绝加载（防误读/防回退）。
func TestSnapshotSchemaVersionReject(t *testing.T) {
	payload, err := json.Marshal(snapshotPayload{SchemaVersion: 99, SavedAt: 100})
	if err != nil {
		t.Fatalf("编码载荷失败: %v", err)
	}
	sum := sha256.Sum256(payload)
	env, err := json.Marshal(snapshotEnvelope{Payload: payload, Checksum: checksumPrefix + hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("编码信封失败: %v", err)
	}
	cpath := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(cpath, env, 0o600); err != nil {
		t.Fatalf("写快照失败: %v", err)
	}
	ss := NewSnapshotStore(NewMemory(), cpath, nil)
	if err := ss.LoadSnapshot(); err == nil {
		t.Fatalf("未知 schema 版本应拒绝加载")
	}
}

// TestSnapshotAntiRollback 磁盘快照比待写快照新 → 拒绝覆盖（陈旧进程回写保护）。
func TestSnapshotAntiRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)

	if err := ss.persistAt(200); err != nil {
		t.Fatalf("写入 saved_at=200 失败: %v", err)
	}
	if got := readPayload(t, path).SavedAt; got != 200 {
		t.Fatalf("saved_at 应为 200: got %d", got)
	}
	stale, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}

	// 陈旧进程尝试回写更旧的状态 → 跳过写入、文件不变。
	if err := ss.persistAt(100); err != nil {
		t.Fatalf("防回退跳过应返回 nil: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}
	if string(after) != string(stale) {
		t.Fatalf("防回退应保持磁盘快照不变（saved_at=200）")
	}
	if !strings.Contains(string(after), `"saved_at":200`) {
		t.Fatalf("磁盘快照应仍为 saved_at=200")
	}

	// 更新的快照正常覆盖。
	if err := ss.persistAt(300); err != nil {
		t.Fatalf("写入 saved_at=300 失败: %v", err)
	}
	if got := readPayload(t, path).SavedAt; got != 300 {
		t.Fatalf("saved_at 应为 300: got %d", got)
	}
}

// TestSnapshotDisabledZeroBehavior 开关关闭（path=""）：零行为变化、零文件 I/O。
func TestSnapshotDisabledZeroBehavior(t *testing.T) {
	ss := NewSnapshotStore(NewMemory(), "", nil) // disabled
	fillSampleState(ss)

	// 内存行为与纯 Memory 完全一致。
	if _, ok := ss.Get("rx-1"); !ok {
		t.Fatalf("禁用持久化后 Get 应与 Memory 一致")
	}
	if err := ss.Persist(); err != nil {
		t.Fatalf("禁用态 Persist 应为 no-op nil: %v", err)
	}
	if err := ss.LoadSnapshot(); err != nil {
		t.Fatalf("禁用态 LoadSnapshot 应为 no-op nil: %v", err)
	}
	ss.Delete("rx-1")
	if _, ok := ss.Get("rx-1"); ok {
		t.Fatalf("禁用态 Delete 行为应与 Memory 一致")
	}
	if !ss.DeleteMCPServer("sv-1") {
		t.Fatalf("禁用态 DeleteMCPServer 行为应与 Memory 一致")
	}
}

// TestSnapshotMissingFileOK 首次启动无快照文件：正常空内存启动，不报错。
func TestSnapshotMissingFileOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-exist.json")
	m := NewMemory()
	ss := NewSnapshotStore(m, path, nil)
	if err := ss.LoadSnapshot(); err != nil {
		t.Fatalf("无快照文件应正常启动: %v", err)
	}
	if _, ok := m.Get("rx-1"); ok {
		t.Fatalf("空内存启动不应含任何状态")
	}
}

// TestSnapshotDuplicateIDRejected 快照内处方 ID 重复 → 拒绝加载（完整性防御）。
func TestSnapshotDuplicateIDRejected(t *testing.T) {
	payload, err := json.Marshal(snapshotPayload{
		SchemaVersion: snapshotSchemaVersion,
		SavedAt:       100,
		Prescriptions: []*route.RoutePrescription{
			{PrescriptionID: "rx-1", Tenant: "t1"},
			{PrescriptionID: "rx-1", Tenant: "t2"},
		},
	})
	if err != nil {
		t.Fatalf("编码载荷失败: %v", err)
	}
	sum := sha256.Sum256(payload)
	env, err := json.Marshal(snapshotEnvelope{Payload: payload, Checksum: checksumPrefix + hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("编码信封失败: %v", err)
	}
	cpath := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(cpath, env, 0o600); err != nil {
		t.Fatalf("写快照失败: %v", err)
	}
	m := NewMemory()
	ss := NewSnapshotStore(m, cpath, nil)
	if err := ss.LoadSnapshot(); err == nil {
		t.Fatalf("处方 ID 重复应拒绝加载")
	}
	if _, ok := m.Get("rx-1"); ok {
		t.Fatalf("拒载后内存应保持空")
	}
}
