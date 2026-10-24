package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ---------------------------------------------------------------------------
// mock wrap 后端：模拟成员侧 C_WrapKey/C_UnwrapKey 与备份对象删除。
// **非密码学实现**（blob 为可识别前缀 + 句柄），仅用于验证编排逻辑：
// 组主校验 / 双签 / quorum / tombstone / KeyOp 状态机。真实 wrap 走 PKCS#11，
// 其能力核验（§15.3 MUST-4）与真机验收仍挂起，本测试不代表真机通过。
// ---------------------------------------------------------------------------

type mockWrapBackend struct {
	member      string
	imported    map[string]module.KeyRef
	destroyed   map[string]bool
	failExport  bool
	failImport  bool
	failDestroy bool
}

func newMockWrapBackend(member string) *mockWrapBackend {
	return &mockWrapBackend{
		member:    member,
		imported:  map[string]module.KeyRef{},
		destroyed: map[string]bool{},
	}
}

func (m *mockWrapBackend) ExportWrapped(keyRef module.KeyRef, kekID string) (WrappedKey, error) {
	if m.failExport {
		return WrappedKey{}, ErrBackupUnsupported
	}
	if len(keyRef) == 0 {
		return WrappedKey{}, ErrBackupNotFound
	}
	blob := append([]byte("WRAP:"+kekID+":"), []byte(keyRef)...)
	sum := sha256.Sum256(blob)
	return WrappedKey{
		Member: m.member, KEKID: kekID, Blob: blob, Checksum: sum[:],
		WrappedSize: int64(len(blob)),
		Vendor:      "mock", Model: "mock-1", Mechanism: "CKM_MOCK_WRAP",
		CreatedAt: time.Now().UTC(), State: "ready",
	}, nil
}

func (m *mockWrapBackend) ImportWrapped(w WrappedKey, kekID string, alias string) (module.KeyRef, error) {
	if m.failImport {
		return nil, ErrBackupUnsupported
	}
	// 交叉校验：KEKID 必须一致，且 blob 必须是本 mock 体系产出的 wrap（不得软件解包）。
	if w.KEKID != kekID || !bytes.HasPrefix(w.Blob, []byte("WRAP:"+kekID+":")) {
		return nil, ErrBackupUnsupported
	}
	ref := module.KeyRef("imp-" + alias)
	m.imported[alias] = ref
	return ref, nil
}

func (m *mockWrapBackend) DestroyWrapped(backupID string) error {
	if m.failDestroy {
		return ErrBackupUnsupported
	}
	m.destroyed[backupID] = true
	return nil
}

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

type testEnv struct {
	ctrl  *testkit.MemoryControlStore
	appr  *MemoryApprovalStore
	steps *MemoryKeyOpStepStore
	store *MemoryKeyBackupStore
	be    map[string]*mockWrapBackend
	orch  *Orchestrator
}

// newTestEnv 构造编排环境：self=m1 作为 bootstrap 组主；目录预置一个 ready 副本。
func newTestEnv(t *testing.T, keyMode, replication string, members []string) *testEnv {
	t.Helper()

	ctrl := testkit.NewMemoryControlStore("g1")
	// m1 bootstrap 成为组主（生命周期写的前置条件）。
	if _, err := ctrl.AcquireOwner(testkit.OwnerAcquireRequest{
		Member: "m1", BootID: "boot1", DC: "dc1",
		AllowBootstrap: true, BootstrapOwner: "m1", TTL: time.Minute,
	}); err != nil {
		t.Fatalf("bootstrap 组主失败: %v", err)
	}

	be := map[string]*mockWrapBackend{}
	backends := map[string]KeyBackupBackend{}
	for _, m := range members {
		mb := newMockWrapBackend(m)
		be[m] = mb
		backends[m] = mb
	}

	appr := NewMemoryApprovalStore()
	steps := NewMemoryKeyOpStepStore()
	store := NewMemoryKeyBackupStore()

	orch := NewOrchestrator("g1", "m1", "kek-backup-1", keyMode, replication,
		ctrl, appr, steps, store, backends)

	return &testEnv{ctrl: ctrl, appr: appr, steps: steps, store: store, be: be, orch: orch}
}

// seedDirectory 预置目录项：keyID 在 member 上有一个 ready 副本。
func (e *testEnv) seedDirectory(t *testing.T, keyID, member string) {
	t.Helper()
	st := e.ctrl.GetOwnerState()
	kd := testkit.KeyDirectory{
		KeyID: keyID, KeyMode: "shared",
		Replicas: []testkit.KeyReplica{{
			Member: member, InnerB64: base64.StdEncoding.EncodeToString([]byte("ref-" + keyID)),
			State: "ready", UpdatedAt: time.Now().UTC(),
		}},
		State: "ready", CreatedBy: "m1",
		WriterEpoch: st.Epoch, WriterBootID: st.LastOwnerBootID,
		LeaseEpoch: st.Epoch, UpdatedAt: time.Now().UTC(),
	}
	if _, err := e.ctrl.CASKeyDirectory(keyID, 0, st.Epoch, st.LastOwnerBootID, kd); err != nil {
		t.Fatalf("预置目录失败: %v", err)
	}
}

// approve 登记双签审批单（initiator/confirmer 分离，满足 R-S3-10 分权）。
func (e *testEnv) approve(t *testing.T, id, action, target string) Approval {
	t.Helper()
	a := Approval{
		ApprovalID: id, GroupID: "g1", Action: action, Target: target,
		Digest: "digest-" + id, Initiator: "so", Confirmer: "auditor",
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	if err := e.appr.Create(a); err != nil {
		t.Fatalf("登记审批单失败: %v", err)
	}
	return a
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

func TestBackupSucceedsAndRecordsBackupID(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-backup", "m1")
	a := e.approve(t, "ap-bk", "backup", "k-backup")

	meta, err := e.orch.Backup("k-backup", a)
	if err != nil {
		t.Fatalf("Backup 失败: %v", err)
	}
	if meta.BackupID == "" || meta.WrappedSize == 0 {
		t.Fatalf("BackupMeta 异常: %+v", meta)
	}

	// 目录副本应回填 backup_id。
	kd, _ := e.ctrl.GetKeyDirectory("k-backup")
	if kd.Replicas[0].BackupID != meta.BackupID {
		t.Fatalf("目录未回填 backup_id: 期望 %s 实际 %s", meta.BackupID, kd.Replicas[0].BackupID)
	}

	// 步骤应记录 BackupMeta，且**不含 blob**（backup_store 步骤；与 backup 步骤以 action 区分）。
	st, _, err := e.steps.Get("op-k-backup-backup", "m1", "backup_store")
	if err != nil {
		t.Fatalf("读取 backup_store 步骤失败: %v", err)
	}
	if st.Status != "succeeded" || st.Result.BackupID != meta.BackupID {
		t.Fatalf("步骤状态/回执异常: %+v", st)
	}

	// KeyOp 应 succeeded。
	op, _, _ := e.ctrl.GetKeyOp("op-k-backup-backup")
	if op.Status != "succeeded" {
		t.Fatalf("KeyOp 状态应为 succeeded，实际 %s", op.Status)
	}
}

func TestBackupRequiresLeaderAndApproval(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-lead", "m1")

	// ① 无审批单 → ErrApprovalRequired
	if _, err := e.orch.Backup("k-lead", Approval{}); err != ErrApprovalRequired {
		t.Fatalf("缺审批单应返回 ErrApprovalRequired，实际 %v", err)
	}

	// ② digest 不匹配 → ErrApprovalDigest
	a := e.approve(t, "ap-bad", "backup", "k-lead")
	a.Digest = "wrong-digest"
	if _, err := e.orch.Backup("k-lead", a); err != ErrApprovalDigest {
		t.Fatalf("digest 不匹配应返回 ErrApprovalDigest，实际 %v", err)
	}

	// ③ 审批单 action 与操作不符 → ErrApprovalDigest（防审批单挪用）
	e.approve(t, "ap-wrong-action", "destroy", "k-lead")
	if _, err := e.orch.Backup("k-lead", Approval{ApprovalID: "ap-wrong-action", Digest: "digest-ap-wrong-action"}); err != ErrApprovalDigest {
		t.Fatalf("审批单 action 不符应返回 ErrApprovalDigest，实际 %v", err)
	}

	// ④ 非组主 → ErrNotLeader
	nonLeader := NewOrchestrator("g1", "m2", "kek-backup-1", "shared", "quorum",
		e.ctrl, e.appr, e.steps, e.store, map[string]KeyBackupBackend{})
	e.seedDirectory(t, "k-lead2", "m1")
	a2 := e.approve(t, "ap-nl", "backup", "k-lead2")
	if _, err := nonLeader.Backup("k-lead2", a2); err != ErrNotLeader {
		t.Fatalf("非组主应返回 ErrNotLeader，实际 %v", err)
	}
}

func TestBackupIsolatedRejected(t *testing.T) {
	// isolated：各成员独立密钥 + 路由，不宣称跨模块协同（D-20③/U-2）。
	e := newTestEnv(t, "isolated", "single", []string{"m1", "m2"})
	e.seedDirectory(t, "k-iso", "m1")
	a := e.approve(t, "ap-iso", "backup", "k-iso")

	if _, err := e.orch.Backup("k-iso", a); err != ErrBackupUnsupported {
		t.Fatalf("isolated 模式备份应返回 ErrBackupUnsupported，实际 %v", err)
	}
}

func TestRestoreSucceedsPreservingKeyID(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-rs", "m1")

	// 先备份
	a1 := e.approve(t, "ap-rs-bk", "backup", "k-rs")
	meta, err := e.orch.Backup("k-rs", a1)
	if err != nil {
		t.Fatalf("Backup 失败: %v", err)
	}

	// 恢复到 m2：应保留原 key_id（§6.2.3），不得重新分配。
	a2 := e.approve(t, "ap-rs-rs", "restore", "k-rs")
	ref, err := e.orch.Restore("k-rs", meta.BackupID, "m2", "k-rs|m2", a2)
	if err != nil {
		t.Fatalf("Restore 失败: %v", err)
	}
	if !bytes.HasPrefix([]byte(ref), []byte("imp-")) {
		t.Fatalf("Restore 返回的 KeyRef 异常: %q", string(ref))
	}

	kd, _ := e.ctrl.GetKeyDirectory("k-rs")
	if kd.KeyID != "k-rs" {
		t.Fatalf("恢复后 key_id 应保留为 k-rs，实际 %s", kd.KeyID)
	}
	if len(kd.Replicas) != 2 {
		t.Fatalf("恢复后应有 2 个副本，实际 %d", len(kd.Replicas))
	}
}

func TestRestoreAfterTombstoneFails(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-tomb", "m1")

	a1 := e.approve(t, "ap-tm-bk", "backup", "k-tomb")
	meta, err := e.orch.Backup("k-tomb", a1)
	if err != nil {
		t.Fatalf("Backup 失败: %v", err)
	}

	// 销毁 → tombstone
	a2 := e.approve(t, "ap-tm-ds", "destroy", "k-tomb")
	if err := e.orch.Destroy("k-tomb", a2); err != nil {
		t.Fatalf("Destroy 失败: %v", err)
	}

	// tombstone 后 restore **必须失败**（§6.2.5 销毁语义）。
	a3 := e.approve(t, "ap-tm-rs", "restore", "k-tomb")
	if _, err := e.orch.Restore("k-tomb", meta.BackupID, "m2", "k-tomb|m2", a3); err != ErrBackupTombstoned {
		t.Fatalf("tombstone 后 restore 应返回 ErrBackupTombstoned，实际 %v", err)
	}
}

func TestDestroyClearsBlobAndWritesTombstone(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-ds", "m1")

	a1 := e.approve(t, "ap-ds-bk", "backup", "k-ds")
	meta, err := e.orch.Backup("k-ds", a1)
	if err != nil {
		t.Fatalf("Backup 失败: %v", err)
	}

	a2 := e.approve(t, "ap-ds-ds", "destroy", "k-ds")
	if err := e.orch.Destroy("k-ds", a2); err != nil {
		t.Fatalf("Destroy 失败: %v", err)
	}

	// ① 目录 state=destroyed（tombstone）
	kd, _ := e.ctrl.GetKeyDirectory("k-ds")
	if kd.State != "destroyed" {
		t.Fatalf("目录应为 destroyed，实际 %s", kd.State)
	}
	// ② 副本全部 destroyed
	for _, r := range kd.Replicas {
		if r.State != "destroyed" {
			t.Fatalf("副本 %s 状态应为 destroyed，实际 %s", r.Member, r.State)
		}
	}
	// ③ 成员本地备份对象已删
	if !e.be["m1"].destroyed[meta.BackupID] {
		t.Fatalf("成员本地备份对象未删除（DestroyWrapped 未生效）")
	}
	// ④ 备份库 blob 已 tombstone（只删 HSM 对象不删备份不算销毁）
	if !e.store.TombstonedForTest("g1", "k-ds", meta.BackupID) {
		t.Fatalf("备份库 blob 未 tombstone")
	}
}

func TestDestroyPendingWhenReplicaUnreachable(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-dp", "m1")

	a1 := e.approve(t, "ap-dp-bk", "backup", "k-dp")
	if _, err := e.orch.Backup("k-dp", a1); err != nil {
		t.Fatalf("Backup 失败: %v", err)
	}

	// 让 m1 的 DestroyWrapped 失败（模拟副本不可达）
	e.be["m1"].failDestroy = true

	a2 := e.approve(t, "ap-dp-ds", "destroy", "k-dp")
	err := e.orch.Destroy("k-dp", a2)
	if err != ErrDestroyPending {
		t.Fatalf("副本不可达应返回 ErrDestroyPending，实际 %v", err)
	}

	// 目录应置 destroy_pending，**不得宣称已销毁**（L610）。
	kd, _ := e.ctrl.GetKeyDirectory("k-dp")
	if kd.State != "destroy_pending" {
		t.Fatalf("目录应为 destroy_pending，实际 %s", kd.State)
	}
}

func TestRotateSucceedsAndArchivesOldKey(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-rot", "m1")

	a := e.approve(t, "ap-rot", "rotate", "k-rot")
	if err := e.orch.Rotate("k-rot", "k-rot-v2", a); err != nil {
		t.Fatalf("Rotate 失败: %v", err)
	}

	// 新 key_id 目录项应就绪，含 quorum 副本（2 成员 → quorum=2）。
	nd, _ := e.ctrl.GetKeyDirectory("k-rot-v2")
	if nd.KeyID == "" || len(nd.Replicas) != 2 {
		t.Fatalf("新 key 目录异常: %+v", nd)
	}
	// 旧 key 归档（保留旧 KEK 以解旧备份）
	od, _ := e.ctrl.GetKeyDirectory("k-rot")
	if od.State != "archived" {
		t.Fatalf("旧 key 应 archived，实际 %s", od.State)
	}
}

func TestRotateQuorumUnmet(t *testing.T) {
	e := newTestEnv(t, "shared", "quorum", []string{"m1", "m2"})
	e.seedDirectory(t, "k-rq", "m1")

	// m2 导入失败 → 只同步到 1 个副本，未达 quorum(2)
	e.be["m2"].failImport = true

	a := e.approve(t, "ap-rq", "rotate", "k-rq")
	err := e.orch.Rotate("k-rq", "k-rq-v2", a)
	if err != ErrQuorumUnmet {
		t.Fatalf("未达 quorum 应返回 ErrQuorumUnmet，实际 %v", err)
	}
}

func TestQuorumForMatchesD13(t *testing.T) {
	// D-13：shared 默认 quorum，2→2、3→2、4→3
	cases := map[int]int{2: 2, 3: 2, 4: 3, 5: 3}
	for n, want := range cases {
		if got := quorumFor(n); got != want {
			t.Fatalf("quorumFor(%d) = %d，期望 %d", n, got, want)
		}
	}
}

func TestApprovalDualControlRejectsSamePerson(t *testing.T) {
	appr := NewMemoryApprovalStore()
	a := Approval{
		ApprovalID: "ap1", GroupID: "g1", Action: "destroy", Target: "k1",
		Digest: "d1", Initiator: "alice", Confirmer: "alice", // 同一人 → 双签分权违规
	}
	if err := appr.Create(a); err == nil {
		t.Fatalf("initiator 与 confirmer 同一人应被拒（双签分权）")
	}
}

func TestApprovalExpiredRejected(t *testing.T) {
	appr := NewMemoryApprovalStore()
	a := Approval{
		ApprovalID: "ap-exp", GroupID: "g1", Action: "destroy", Target: "k1",
		Digest: "d1", Initiator: "so", Confirmer: "auditor",
		ExpiresAt: time.Now().UTC().Add(-time.Minute), // 已过期
	}
	if err := appr.Create(a); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	if err := appr.Consume("g1", "ap-exp", "d1"); err != ErrApprovalExpired {
		t.Fatalf("过期审批应返回 ErrApprovalExpired，实际 %v", err)
	}
}

func TestBackupStoreRejectsBackupIDReuse(t *testing.T) {
	store := NewMemoryKeyBackupStore()
	w := WrappedKey{BackupID: "bk-fixed", Blob: []byte("WRAP:kek:x")}
	if _, err := store.Put("g1", "k1", "m1", "kek", w); err != nil {
		t.Fatalf("首次 Put 失败: %v", err)
	}
	// 同一 backup_id 复用（跨密钥/跨成员）必须拒绝
	if _, err := store.Put("g1", "k2", "m2", "kek", w); err == nil {
		t.Fatalf("backup_id 跨密钥复用应被拒")
	}
}

func TestBackupStoreGetAfterDeleteIsTombstoned(t *testing.T) {
	store := NewMemoryKeyBackupStore()
	w := WrappedKey{BackupID: "bk1", Blob: []byte("WRAP:kek:x")}
	meta, err := store.Put("g1", "k1", "m1", "kek", w)
	if err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if err := store.Delete("g1", "k1", meta.BackupID); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	if _, _, err := store.Get("g1", "k1", meta.BackupID); err != ErrBackupTombstoned {
		t.Fatalf("已删除备份 Get 应返回 ErrBackupTombstoned，实际 %v", err)
	}
}
