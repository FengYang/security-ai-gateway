// P2-4 T-1.7 快照持久化单测：原子性、恢复一致性、损坏拒载、开关关闭零行为、
// 回退防护（内容级 revision 判据）、启动准备（父目录/可写/符号链接）、
// 写失败计数与告警升级（QA P3-6）、合并写节流（QA P3-5）。
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
	if wrt.UpdatedAt != grt.UpdatedAt {
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
	ss.SetFlushInterval(0) // 同步写：便于断言写盘结果
	fillSampleState(ss)    // 每次变更都会触发一次原子写

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
	sum := sha256Sum([]byte(`{}`))
	env.Checksum = checksumPrefix + hexEncode(sum)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("重编码信封失败: %v", err)
	}
	return out
}

// TestSnapshotAntiRollbackByRevision **防回退主判据 = 内容级 revision**：
// 磁盘 revision ≥ 待写 revision ⇒ 拒绝覆盖（陈旧进程不得回写旧状态）。
func TestSnapshotAntiRollbackByRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)

	if err := ss.writeSnapshotAt(5, 1000); err != nil {
		t.Fatalf("写入 revision=5 失败: %v", err)
	}
	if got := readPayload(t, path).Revision; got != 5 {
		t.Fatalf("revision 应为 5: got %d", got)
	}
	stale, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}

	// 陈旧进程（revision=3 < 磁盘 5）→ 拒绝覆盖，文件字节不变。
	if err := ss.writeSnapshotAt(3, 2000); err == nil {
		t.Fatalf("陈旧 revision 应被拒绝覆盖")
	} else if !strings.Contains(err.Error(), "防回退") {
		t.Fatalf("错误信息应说明防回退: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}
	if !bytes.Equal(after, stale) {
		t.Fatalf("防回退应保持磁盘快照不变")
	}

	// revision 推进（6 > 5）→ 正常覆盖。
	if err := ss.writeSnapshotAt(6, 3000); err != nil {
		t.Fatalf("revision=6 应允许写入: %v", err)
	}
	if got := readPayload(t, path).Revision; got != 6 {
		t.Fatalf("revision 应为 6: got %d", got)
	}
}

// TestSnapshotRollbackRejectAdvancesBaseline **QA P2-新：防回退拒绝不得造成
// 永久停滞**：拒绝后本地基线推进到磁盘 revision ⇒ 下一次写入以 diskRev+1 成功；
// 且拒绝必须计入失败指标（PersistFailures>0 / LastPersistError 非 nil /
// RollbackRejects>0），杜绝"静默失去持久化"。
func TestSnapshotRollbackRejectAdvancesBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(0) // 同步写：立即暴露拒绝

	// 本进程先落一版，建立基线 revision=5。
	if err := ss.writeSnapshotAt(5, 1000); err != nil {
		t.Fatalf("写入 revision=5 失败: %v", err)
	}

	// 模拟"另一写者"（多写者窗口）：把磁盘推进到 revision=9。
	other := NewSnapshotStore(NewMemory(), path, nil)
	if err := other.writeSnapshotAt(9, 2000); err != nil {
		t.Fatalf("外部写者写入 revision=9 失败: %v", err)
	}

	// 本进程（陈旧，基线仍为 5）写入 ⇒ 被拒。
	err := ss.Persist()
	if err == nil {
		t.Fatalf("陈旧进程写入应被防回退拒绝")
	}
	if !strings.Contains(err.Error(), "防回退") {
		t.Fatalf("错误信息应说明防回退: %v", err)
	}
	// 拒绝必须计入失败指标（否则"失去持久化"不可观测）。
	if ss.PersistFailures() == 0 {
		t.Fatalf("防回退拒绝应计入失败指标")
	}
	if ss.LastPersistError() == nil {
		t.Fatalf("应记录最近一次写失败原因")
	}
	if ss.RollbackRejects() == 0 {
		t.Fatalf("防回退拒绝次数应可观测")
	}
	// 拒绝期间磁盘快照不被陈旧进程改写。
	if got := readPayload(t, path).Revision; got != 9 {
		t.Fatalf("拒绝期间磁盘快照应保持 revision=9: got %d", got)
	}

	// 基线已推进 ⇒ 下一次写入以 diskRev+1(=10) 成功（不再永久停滞）。
	if err := ss.Persist(); err != nil {
		t.Fatalf("基线推进后下一次写入应成功: %v", err)
	}
	if got := readPayload(t, path).Revision; got != 10 {
		t.Fatalf("下一次写入应使用 diskRev+1=10: got %d", got)
	}
}

// TestSnapshotRollbackRejectAutoRetry **自动路径**：变更触发落盘被拒后，
// 基线推进 + 有界自动重试 ⇒ 待写状态最终落盘（不必等到下一次变更）。
func TestSnapshotRollbackRejectAutoRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(10 * time.Millisecond)

	// 先落一版，建立基线。
	if err := ss.Persist(); err != nil {
		t.Fatalf("首次落盘失败: %v", err)
	}
	// 外部写者把磁盘推进到 revision=9。
	other := NewSnapshotStore(NewMemory(), path, nil)
	if err := other.writeSnapshotAt(9, 2000); err != nil {
		t.Fatalf("外部写者写入失败: %v", err)
	}

	// 本进程变更 → 落盘被拒 → 自动重试 → 以 diskRev+1 落盘成功。
	_ = ss.Save(&route.RoutePrescription{PrescriptionID: "rx-1", Tenant: "t"})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p, err := readPayloadSoft(path)
		if err == nil && p.Revision == 10 && len(p.Prescriptions) == 1 {
			if ss.PersistFailures() == 0 {
				t.Fatalf("拒绝应计入失败指标")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("防回退拒绝后应自动重试并以 diskRev+1 落盘")
}

// readPayloadSoft 读盘并解码快照载荷；失败返回错误（轮询场景容忍瞬时失败）。
func readPayloadSoft(path string) (*snapshotPayload, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeSnapshot(b)
}

// TestSnapshotCoversAllMemoryFields **防回归断言（QA P3 口径项）**：
// 快照覆盖边界 = **store.Memory 的状态域全集**。
//
//  1. Memory 的每个字段都必须在 snapshotCoverage 清单中登记（新增字段未登记 ⇒ 失败）；
//  2. 登记为「持久化」的字段，其载荷字段名必须真实存在于 snapshotPayload；
//  3. 登记为「持久化」的字段，其值必须真的出现在 buildPayload 的产物里
//     （填满全部状态域后逐字段断言载荷非零）⇒ 防"登记了却没写进快照"。
//
// 失败含义：**漏域 ⇒ 重启后静默丢配置**（不报错、不可观测）。
func TestSnapshotCoversAllMemoryFields(t *testing.T) {
	// —— 1) Memory 字段全集 ↔ 覆盖清单 双向比对 ——
	memType := reflect.TypeOf(Memory{})
	registered := make(map[string]bool, len(snapshotCoverage))
	for _, e := range snapshotCoverage {
		if registered[e.Field] {
			t.Fatalf("覆盖清单重复登记字段: %s", e.Field)
		}
		registered[e.Field] = true
	}
	for i := 0; i < memType.NumField(); i++ {
		name := memType.Field(i).Name
		if !registered[name] {
			t.Fatalf("Memory 字段 %s 未登记快照覆盖清单（新增状态域必须登记 + 纳入 buildPayload/restore，"+
				"否则重启后静默丢配置）", name)
		}
		delete(registered, name)
	}
	if len(registered) > 0 {
		t.Fatalf("覆盖清单登记了 Memory 中不存在的字段: %v", registered)
	}

	// —— 2) 载荷字段名真实性 ——
	payloadType := reflect.TypeOf(snapshotPayload{})
	for _, e := range snapshotCoverage {
		if e.Kind != coveragePersisted {
			if e.Payload != "" {
				t.Fatalf("字段 %s 归类为非持久化，不应声明载荷字段 %s", e.Field, e.Payload)
			}
			continue
		}
		if e.Payload == "" {
			t.Fatalf("字段 %s 归类为持久化，必须声明载荷字段名", e.Field)
		}
		if _, ok := payloadType.FieldByName(e.Payload); !ok {
			t.Fatalf("字段 %s 声明的载荷字段 %s 在 snapshotPayload 中不存在", e.Field, e.Payload)
		}
	}

	// —— 3) 填满全部状态域，逐字段断言真的写进了载荷 ——
	m := NewMemory()
	m.byID = map[string]*route.RoutePrescription{
		"rx-1": {PrescriptionID: "rx-1", Tenant: "tenant-a"},
	}
	m.byT = map[string][]string{"tenant-a": {"rx-1"}}
	m.routeTable = route.NewRouteTable(7, 1234)
	m.rateLimitTable = ratelimit.NewTable(5, time.Unix(1234, 0))
	m.aclTable = a2aproxy.NewACLTable(3, time.Unix(1234, 0))
	m.a2aRLTable = a2aproxy.NewRateLimitTable(4, time.Unix(1234, 0))
	m.toolCatalog = &mcpsec.ToolCatalog{Version: 9, UpdatedAt: 1234, Tools: []mcpsec.TableTool{}}
	m.rbacPolicy = &mcpsec.RBACPolicy{Version: 6, UpdatedAt: 1234}
	m.mcpServers = map[string]*mcpsrv.Server{
		"sv-1": {ID: "sv-1", BaseURL: "https://mcp.example.com"},
	}

	ss := NewSnapshotStore(m, filepath.Join(t.TempDir(), "snap.json"), nil)
	raw, err := ss.buildPayload(1, 100)
	if err != nil {
		t.Fatalf("构造载荷失败: %v", err)
	}
	var got snapshotPayload
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("解码载荷失败: %v", err)
	}
	gv := reflect.ValueOf(got)
	for _, e := range snapshotCoverage {
		if e.Kind != coveragePersisted {
			continue
		}
		fv := gv.FieldByName(e.Payload)
		if !fv.IsValid() {
			t.Fatalf("载荷字段不存在: %s", e.Payload)
		}
		if fv.IsZero() {
			t.Fatalf("状态域 %s 未写入快照载荷字段 %s（漏域 ⇒ 重启后静默丢配置）", e.Field, e.Payload)
		}
	}
}

// TestSnapshotClockIsAuxiliaryOnly **时钟仅辅助**：磁盘 saved_at 更新但 revision
// 更旧 ⇒ 告警但仍以 revision 为准（允许写入），不因时钟回拨误拒。
func TestSnapshotClockIsAuxiliaryOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)

	if err := ss.writeSnapshotAt(5, 5000); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// revision 更高但 saved_at 更早（时钟回拨）→ 允许写入（内容判据为主）。
	if err := ss.writeSnapshotAt(6, 1000); err != nil {
		t.Fatalf("时钟回拨不应导致误拒: %v", err)
	}
	p := readPayload(t, path)
	if p.Revision != 6 || p.SavedAt != 1000 {
		t.Fatalf("写入结果不符: revision=%d saved_at=%d", p.Revision, p.SavedAt)
	}
}

// TestSnapshotRevisionMonotonic 连续写盘 revision 单调递增（内容级判据成立的基础）。
func TestSnapshotRevisionMonotonic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(0)
	for i := 0; i < 5; i++ {
		_ = ss.Save(&route.RoutePrescription{PrescriptionID: "rx-" + string(rune('a'+i)), Tenant: "t"})
	}
	p := readPayload(t, path)
	if p.Revision < 5 {
		t.Fatalf("revision 应单调递增至 ≥5: got %d", p.Revision)
	}
}

// TestSnapshotPrepareCreatesParentDir 启动准备：父目录不存在 → 自动创建（QA P3-9）。
func TestSnapshotPrepareCreatesParentDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", "deeper", "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	if err := ss.Prepare(); err != nil {
		t.Fatalf("Prepare 应创建父目录: %v", err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || !fi.IsDir() {
		t.Fatalf("父目录应已创建: %v", err)
	}
	// 准备通过后可正常写盘。
	if err := ss.Persist(); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("快照文件应存在: %v", err)
	}
}

// TestSnapshotPrepareRejectsSymlink 快照路径为符号链接 → 拒绝（rename 只替换链接
// 本身，其目标挂载点将停止更新且无报错——静默失效比报错更危险）。
func TestSnapshotPrepareRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("写目标文件失败: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不支持符号链接: %v", err)
	}
	ss := NewSnapshotStore(NewMemory(), link, nil)
	if err := ss.Prepare(); err == nil {
		t.Fatalf("符号链接路径应被拒绝")
	} else if !strings.Contains(err.Error(), "符号链接") {
		t.Fatalf("错误信息应说明符号链接: %v", err)
	}
	// 写盘路径同样拒绝（不静默替换链接）。
	if err := ss.Persist(); err == nil {
		t.Fatalf("符号链接路径写盘应被拒绝")
	}
}

// TestSnapshotPrepareRejectsDirectory 快照路径是目录 → 拒绝（rename 必失败）。
func TestSnapshotPrepareRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapdir")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	ss := NewSnapshotStore(NewMemory(), path, nil)
	if err := ss.Prepare(); err == nil {
		t.Fatalf("目录路径应被拒绝")
	}
}

// TestSnapshotWriteFailureCounted **写失败必须可见**（QA P3-6：path 为目录时
// rename 被拒且此前静默失效）→ 失败计数 + 最近错误可查。
func TestSnapshotWriteFailureCounted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapdir")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(0) // 同步写：立即暴露失败
	if err := ss.Save(&route.RoutePrescription{PrescriptionID: "rx-1", Tenant: "t"}); err != nil {
		t.Fatalf("变更本身不应报错（内存为准）: %v", err)
	}
	if ss.PersistFailures() == 0 {
		t.Fatalf("写失败应被计数")
	}
	if ss.LastPersistError() == nil {
		t.Fatalf("应记录最近一次写失败原因")
	}
}

// TestSnapshotMergedWriteFlush 合并写（QA P3-5）：窗口内多次变更合并为一次写盘；
// Flush 后落盘内容完整；优雅退出 Close 补写最后状态。
func TestSnapshotMergedWriteFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(50 * time.Millisecond)

	// 窗口内多次变更。
	for i := 0; i < 5; i++ {
		_ = ss.Save(&route.RoutePrescription{PrescriptionID: "rx-" + string(rune('a'+i)), Tenant: "t"})
	}
	// 显式刷盘后内容完整（5 条处方）。
	if err := ss.Flush(); err != nil {
		t.Fatalf("Flush 失败: %v", err)
	}
	p := readPayload(t, path)
	if len(p.Prescriptions) != 5 {
		t.Fatalf("刷盘后应有 5 条处方: got %d", len(p.Prescriptions))
	}
	// 合并写窗口到期后也应自动落盘（无需显式 Flush）。
	_ = ss.Save(&route.RoutePrescription{PrescriptionID: "rx-z", Tenant: "t"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// 轮询期间可能正好撞上原子替换（Windows 上读会瞬时失败）⇒ 容忍瞬时错误。
		p2, err := readPayloadSoft(path)
		if err == nil && len(p2.Prescriptions) == 6 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("合并写窗口到期后应自动落盘")
}

// TestSnapshotCloseFlushesPending Close 补写窗口内变更（优雅退出不丢数据）。
func TestSnapshotCloseFlushesPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(time.Hour) // 窗口极大：只有 Close 能触发写盘
	_ = ss.Save(&route.RoutePrescription{PrescriptionID: "rx-1", Tenant: "t"})
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("窗口内不应立即落盘")
	}
	if err := ss.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	p := readPayload(t, path)
	if len(p.Prescriptions) != 1 {
		t.Fatalf("Close 后应有 1 条处方: got %d", len(p.Prescriptions))
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
	if err := ss.Flush(); err != nil {
		t.Fatalf("禁用态 Flush 应为 no-op nil: %v", err)
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
	if ss.PersistFailures() != 0 {
		t.Fatalf("禁用态不应有写失败")
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
		Revision:      1,
		SavedAt:       100,
		Prescriptions: []*route.RoutePrescription{
			{PrescriptionID: "rx-1", Tenant: "t1"},
			{PrescriptionID: "rx-1", Tenant: "t2"},
		},
	})
	if err != nil {
		t.Fatalf("编码载荷失败: %v", err)
	}
	sum := sha256Sum(payload)
	env, err := json.Marshal(snapshotEnvelope{Payload: payload, Checksum: checksumPrefix + hexEncode(sum)})
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

// TestSnapshotSchemaVersionReject 不识别的 schema 版本拒绝加载（防误读/防回退）。
func TestSnapshotSchemaVersionReject(t *testing.T) {
	payload, err := json.Marshal(snapshotPayload{SchemaVersion: 99, Revision: 1, SavedAt: 100})
	if err != nil {
		t.Fatalf("编码载荷失败: %v", err)
	}
	sum := sha256Sum(payload)
	env, err := json.Marshal(snapshotEnvelope{Payload: payload, Checksum: checksumPrefix + hexEncode(sum)})
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

// TestSnapshotReadOnly 导出/读路径不改变链状态（只读语义）。
func TestSnapshotReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	m := NewMemory()
	fillSampleState(m)
	ss := NewSnapshotStore(m, path, nil)
	ss.SetFlushInterval(0)
	if err := ss.Persist(); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	beforeLen := len(m.ListByTenant("tenant-a")) + len(m.ListByTenant("tenant-b"))
	beforeTables := m.GetRouteTable().Version + m.GetRateLimitTable().Version
	for i := 0; i < 3; i++ {
		if _, ok := m.Get("rx-1"); !ok {
			t.Fatalf("读路径异常")
		}
		_ = m.ListByTenant("tenant-a")
	}
	if got := len(m.ListByTenant("tenant-a")) + len(m.ListByTenant("tenant-b")); got != beforeLen {
		t.Fatalf("读路径改变了链长度")
	}
	if got := m.GetRouteTable().Version + m.GetRateLimitTable().Version; got != beforeTables {
		t.Fatalf("读路径改变了策略表")
	}
}

// sha256Sum / hexEncode 小工具（测试内联实现，避免引入额外依赖）。
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}
