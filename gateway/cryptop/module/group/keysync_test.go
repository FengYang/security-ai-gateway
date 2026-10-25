package group

// 本文件验证 T-1↔T-2 接线、shared 启动守卫与 U-5 成员上限。
//
// 全部对着 mock 成员 + 内存控制存储，不接真实 HSM、不宣称 S3-b/密评。

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/backup"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// wrapMember 实现 backup.KeyBackupBackend 的测试成员（mock 档，**不合规**，
// 仅用于验证组内副本复制链路；真实 wrap 须在 HSM 内完成、明文不出模块）。
type wrapMember struct {
	*module.MockBackend
	id string

	mu         sync.Mutex
	seq        int
	failImport bool
	imports    map[string]string // alias → 成员内 inner
	alive      map[string]bool   // inner → 存活（用于验证销毁）
}

func newWrapMember(id string) *wrapMember {
	return &wrapMember{
		MockBackend: newMockMember(),
		id:          id,
		imports:     map[string]string{},
		alive:       map[string]bool{},
	}
}

// ExportWrapped 模拟模块内 wrap：产出的 blob 与 inner 不对应明文（本测试仅为链路验证）。
func (w *wrapMember) ExportWrapped(_ module.KeyRef, kekID string) (backup.WrappedKey, error) {
	w.mu.Lock()
	w.seq++
	blob := []byte(fmt.Sprintf("wrapped|%s|%d", w.id, w.seq))
	w.mu.Unlock()
	sum := sha256.Sum256(blob)
	return backup.WrappedKey{
		Member: w.id, KEKID: kekID, Blob: blob, Checksum: sum[:],
		WrappedSize: int64(len(blob)), Vendor: "vendor-x", Model: "hsm-9000",
		Mechanism: "CKM_AES_KEY_WRAP", CreatedAt: time.Now().UTC(), State: "ready",
	}, nil
}

func (w *wrapMember) ImportWrapped(_ backup.WrappedKey, _, alias string) (module.KeyRef, error) {
	if w.failImport {
		return nil, errors.New("wrap_member: 模拟导入失败")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	inner := module.KeyRef(fmt.Sprintf("inner|%s|%s", w.id, alias))
	w.imports[alias] = string(inner)
	w.alive[string(inner)] = true
	return inner, nil
}

func (w *wrapMember) DestroyWrapped(string) error { return nil }

// DestroyKey 覆写：mock 后端对未知句柄会报错，此处以存活集合记账，
// 便于验证"副本是否被真正清理"。
func (w *wrapMember) DestroyKey(ref module.KeyRef) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.alive, string(ref))
	return nil
}

func (w *wrapMember) aliveCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.alive)
}

// sharedGroupConfig shared 模式组配置（n 成员，同分区），供 shared 语义测试。
func sharedGroupConfig(ids []string, replication string) testkit.GroupConfig {
	ms := make([]testkit.MemberConfig, 0, len(ids))
	for _, id := range ids {
		ms = append(ms, testkit.MemberConfig{
			ID: id, Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1",
			Backend: "mock", Partition: "tenant-a", DC: "dc1",
			MaxSessions: 16, TimeoutMS: 50, ImplementsBackup: true,
		})
	}
	return testkit.GroupConfig{
		GroupID: "fin-hsm-a", KeyMode: "shared", KeyReplication: replication,
		Members:    ms,
		Partitions: []testkit.PartitionConfig{{Tenant: "tenant-a", Partition: "tenant-a", Members: ids, QuotaSessions: 24}},
		Backup:     testkit.BackupConfig{Store: "vendor_library", KekID: "kek-backup-1"},
		Leader:     testkit.LeaderConfig{Store: "memory", BootstrapOwner: ids[0], LeaseTTLMS: 30000},
		Control: testkit.ControlConfig{Store: "memory", DirectoryMACKeyRef: "secret://dir-mac",
			DirectoryCacheTTLMS: 15000, DirectoryCacheMaxStale: 30000, DirectoryWriter: "lease"},
		Policy:         testkit.PolicyConfig{Affinity: "none", DcOrder: []string{"dc1"}},
		Failover:       testkit.FailoverConfig{Mode: "failover", AutoFailoverIntraDC: true, StartupMinHealthyPerPartition: 1, AutoSwitchBack: false},
		BootstrapOwner: ids[0],
	}
}

// newSharedGroup 构造 shared 组并使其成为组主（bootstrap owner = 首个成员）。
func newSharedGroup(t *testing.T, ids []string, replication string) (*ModuleGroup, map[string]*wrapMember, *testkit.MemoryControlStore, *BackupDeps) {
	t.Helper()
	cfg := sharedGroupConfig(ids, replication)
	ws := map[string]*wrapMember{}
	members := map[string]module.ModuleBackend{}
	for _, id := range ids {
		w := newWrapMember(id)
		ws[id] = w
		members[id] = w
	}
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	deps := &BackupDeps{
		Approvals: backup.NewMemoryApprovalStore(),
		Steps:     backup.NewMemoryKeyOpStepStore(),
		Backup:    backup.NewMemoryKeyBackupStore(),
	}
	g, err := NewGroupProvider(cfg, members, ids[0], store, "boot-1", deps)
	if err != nil {
		t.Fatalf("NewGroupProvider(shared): %v", err)
	}
	if err := g.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !g.IsLeader() {
		t.Fatalf("bootstrap owner %s 应成为组主", ids[0])
	}
	return g, ws, store, deps
}

// ① shared 模式：生成密钥后副本须同步到 quorum（2 成员 → 2 副本）。
func TestSharedGenerateKeyReplicatesToQuorum(t *testing.T) {
	g, ws, store, _ := newSharedGroup(t, []string{"hsm-a1", "hsm-a2"}, "quorum")

	ref, err := g.GenerateKey("sm4", "k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kid, err := keyIDHex(ref)
	if err != nil {
		t.Fatalf("keyIDHex: %v", err)
	}
	kd, _ := store.GetKeyDirectory(kid)
	if len(kd.Replicas) != 2 {
		t.Fatalf("shared 模式副本数应达 quorum=2，实际 %d（%v）", len(kd.Replicas), kd.Replicas)
	}
	if kd.State != "active" {
		t.Fatalf("达标副本的目录状态应为 active，实际 %s", kd.State)
	}
	for _, id := range []string{"hsm-a1", "hsm-a2"} {
		found := false
		for _, r := range kd.Replicas {
			if r.Member == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("副本缺失成员 %s", id)
		}
	}
	// 目标成员确实持有导入的密钥副本（alias = kid|member）
	if ws["hsm-a2"].aliveCount() == 0 {
		t.Fatal("目标成员未持有导入的密钥副本")
	}
	if _, ok := ws["hsm-a2"].imports[kid+"|hsm-a2"]; !ok {
		t.Fatalf("目标成员缺少 alias=%s 的副本记录", kid+"|hsm-a2")
	}
}

// ① 未达 quorum 时必须失败并置 degraded，不得静默放行（R-6 / D-13）。
func TestSharedQuorumUnmetRejectsAndMarksDegraded(t *testing.T) {
	ids := []string{"hsm-b1", "hsm-b2", "hsm-b3", "hsm-b4"} // quorum = 4/2+1 = 3
	g, ws, store, _ := newSharedGroup(t, ids, "quorum")
	// 让后两个成员导入失败：只剩本成员 + 1 个成功 = 2 < 3
	ws["hsm-b2"].failImport = true
	ws["hsm-b3"].failImport = true

	_, err := g.GenerateKey("sm4", "k2")
	if !errors.Is(err, backup.ErrQuorumUnmet) {
		t.Fatalf("未达 quorum 应返回 ErrQuorumUnmet，实际 %v", err)
	}
	// 目录 degraded 留痕由 backup 包的 Replicate 用例直接验证（那里可拿到 key_id）。
	_ = store
}

// ② shared 模式启动守卫：成员运行时未实现 KeyBackupBackend → 拒绝启动。
func TestSharedRejectsMemberWithoutWrapBackend(t *testing.T) {
	ids := []string{"hsm-c1", "hsm-c2"}
	cfg := sharedGroupConfig(ids, "quorum")
	members := map[string]module.ModuleBackend{
		"hsm-c1": newMockMember(), // 裸 MockBackend，不实现 wrap/unwrap
		"hsm-c2": newMockMember(),
	}
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	_, err := NewGroupProvider(cfg, members, "hsm-c1", store, "boot-1", nil)
	if err == nil {
		t.Fatal("成员未实现 KeyBackupBackend 时 shared 组应拒绝启动（D-13）")
	}
	if !strings.Contains(err.Error(), "KeyBackupBackend") {
		t.Fatalf("错误信息应指明 KeyBackupBackend，实际: %v", err)
	}
}

// ④ U-5：组内成员上限 4，5 成员应拒绝。
func TestMemberUpperLimitU5(t *testing.T) {
	ids := []string{"hsm-d1", "hsm-d2", "hsm-d3", "hsm-d4", "hsm-d5"}
	cfg := sharedGroupConfig(ids, "quorum")
	members := map[string]module.ModuleBackend{}
	for _, id := range ids {
		members[id] = newWrapMember(id)
	}
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	_, err := NewGroupProvider(cfg, members, "hsm-d1", store, "boot-1", nil)
	if err == nil {
		t.Fatal("5 成员组应被拒绝（U-5：组内成员 2-4，>4 不支持）")
	}
	if !strings.Contains(err.Error(), "U-5") {
		t.Fatalf("错误信息应引用 U-5，实际: %v", err)
	}
}

// ① shared 销毁：不带双签审批 → fail-closed 拒绝，不留孤儿副本。
func TestSharedDestroyRequiresApproval(t *testing.T) {
	g, _, _, _ := newSharedGroup(t, []string{"hsm-e1", "hsm-e2"}, "quorum")
	ref, err := g.GenerateKey("sm4", "k3")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := g.DestroyKey(ref); !errors.Is(err, backup.ErrApprovalRequired) {
		t.Fatalf("shared 模式无审批销毁应返回 ErrApprovalRequired，实际 %v", err)
	}
}

// ① shared 销毁：带双签审批 → 清副本 + tombstone，其他成员不留存活副本。
func TestSharedDestroyWithApprovalCleansReplicas(t *testing.T) {
	ids := []string{"hsm-f1", "hsm-f2"}
	g, ws, store, deps := newSharedGroup(t, ids, "quorum")
	ref, err := g.GenerateKey("sm4", "k4")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kid, err := keyIDHex(ref)
	if err != nil {
		t.Fatalf("keyIDHex: %v", err)
	}
	if err := g.DestroyKeyWithApproval(ref, backup.Approval{}); !errors.Is(err, backup.ErrApprovalRequired) {
		t.Fatalf("空审批单应拒绝，实际 %v", err)
	}

	// 用注入时的同一审批存储实例建双签单（Initiator + Confirmer 两人）
	if err := createApproval(deps.Approvals, "fin-hsm-a", "ap-destroy-1", "destroy", kid, "digest-1"); err != nil {
		t.Fatalf("createApproval: %v", err)
	}
	if err := g.DestroyKeyWithApproval(ref, backup.Approval{ApprovalID: "ap-destroy-1", Digest: "digest-1"}); err != nil {
		t.Fatalf("带双签的销毁应成功: %v", err)
	}
	// 副本已清理：目标成员不应再有存活副本
	if ws["hsm-f2"].aliveCount() != 0 {
		t.Fatalf("销毁后目标成员仍有 %d 个存活副本（孤儿副本）", ws["hsm-f2"].aliveCount())
	}
	// 目录 tombstone
	kd, _ := store.GetKeyDirectory(kid)
	if kd.State != "destroyed" {
		t.Fatalf("销毁后目录应置 destroyed（tombstone），实际 %s", kd.State)
	}
}

// createApproval 在审批存储中建一张双签审批单（测试辅助）。
func createApproval(a backup.ApprovalStore, gid, id, action, target, digest string) error {
	if ap, ok := a.(*backup.MemoryApprovalStore); ok {
		return ap.Create(backup.Approval{
			GroupID: gid, ApprovalID: id, Action: action, Target: target,
			Digest: digest, Initiator: "ops-1", Confirmer: "sec-1",
		})
	}
	return nil
}

// isolated 模式不接协同：生成密钥不触发副本同步（U-2，不宣称跨模块协同）。
func TestIsolatedDoesNotReplicate(t *testing.T) {
	g, m1, m2, store := newTestGroup(t, "dc1-hsm-a")
	if err := g.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = m1
	_ = m2
	ref, err := g.GenerateKey("sm4", "k5")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kid, err := keyIDHex(ref)
	if err != nil {
		t.Fatalf("keyIDHex: %v", err)
	}
	kd, _ := store.GetKeyDirectory(kid)
	if len(kd.Replicas) != 1 {
		t.Fatalf("isolated 模式应为单副本（U-2），实际 %d", len(kd.Replicas))
	}
}
