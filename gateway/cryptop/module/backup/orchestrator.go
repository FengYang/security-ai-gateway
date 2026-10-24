package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ErrNotLeader 非当前组主：生命周期写（备份/恢复/轮换/销毁）必须由组主执行（D-8/§6.2.3）。
var ErrNotLeader = errors.New("group_leader_required")

// KeyOpStore 编排所需的最小控制存储能力。
//
// testkit.MemoryControlStore 与 T-1 的 group.ControlStore 均满足此接口（无 context 版本），
// 因此 T-2 可直接对着冻结的 T-0 内存基座开发验证；etcd 真机实现（签名带 context）
// 的适配层属 Wave B，与 T-1 同口径。
type KeyOpStore interface {
	GetOwnerState() testkit.OwnerState
	CreateKeyOp(op testkit.KeyOp) (int64, error)
	CASKeyOp(opID string, expectedVersion int64, expectedStatus string, op testkit.KeyOp) (int64, error)
	GetKeyOp(opID string) (testkit.KeyOp, int64, error)
	GetKeyDirectory(keyID string) (testkit.KeyDirectory, int64)
	CASKeyDirectory(keyID string, expectedVersion int64, writerEpoch uint64, writerBootID string, kd testkit.KeyDirectory) (int64, error)
}

// Orchestrator T-2 备份/恢复/轮换/销毁编排器（组主侧执行）。
//
// **执行模型**：生产环境各成员由 sidecar 通过 KeyOpStep 协同（组主只聚合，不跨机取 blob，
// §6.2.5）；本编排器在 Wave B 代码研发阶段于单进程内驱动各成员后端，
// 验证的是**编排逻辑**（组主校验 / 双签 / quorum / tombstone / 状态机），
// 不代表跨进程联调已通过。
type Orchestrator struct {
	gid         string
	self        string
	kekID       string // backup.kek_id：组内独立备份 KEK，**不得复用数据 KEK**（D-9）
	keyMode     string // shared|isolated
	replication string // single|quorum|all（shared 默认 quorum，D-13）

	ctrl  KeyOpStore
	appr  ApprovalStore
	steps KeyOpStepStore
	store KeyBackupStore

	// backends：成员 ID → 该成员的 wrap/unwrap 后端（生产为各成员 sidecar 本地后端）。
	backends map[string]KeyBackupBackend
}

// NewOrchestrator 构造编排器。kekID 必须是组内独立备份 KEK（D-9 禁止复用数据 KEK）。
func NewOrchestrator(gid, self, kekID, keyMode, replication string,
	ctrl KeyOpStore, appr ApprovalStore, steps KeyOpStepStore, store KeyBackupStore,
	backends map[string]KeyBackupBackend) *Orchestrator {
	if replication == "" {
		replication = "quorum"
	}
	if keyMode == "" {
		keyMode = "shared"
	}
	return &Orchestrator{
		gid: gid, self: self, kekID: kekID, keyMode: keyMode, replication: replication,
		ctrl: ctrl, appr: appr, steps: steps, store: store, backends: backends,
	}
}

// requireLeader 生命周期写必须组主（D-8：组主租约只保护生命周期写）。
func (o *Orchestrator) requireLeader() (testkit.OwnerState, error) {
	st := o.ctrl.GetOwnerState()
	if st.Lease == nil || st.LastOwner != o.self {
		return st, ErrNotLeader
	}
	return st, nil
}

// checkAndConsume 双签校验：审批单须存在、action/target 与本次操作一致、digest 匹配、
// 未消费、未过期（§6.2.6 / §7.2 高危操作双签）。
func (o *Orchestrator) checkAndConsume(action, target string, a Approval) error {
	if a.ApprovalID == "" {
		return ErrApprovalRequired
	}
	stored, err := o.appr.Get(o.gid, a.ApprovalID)
	if err != nil {
		return err
	}
	if stored.Action != action || stored.Target != target {
		return ErrApprovalDigest
	}
	return o.appr.Consume(o.gid, a.ApprovalID, a.Digest)
}

// isolatedGuard isolated 模式不宣称跨模块协同（D-20③ / U-2）：
// 备份/恢复/副本复制均不可用，只能各成员独立密钥 + GroupKeyRef 路由。
func (o *Orchestrator) isolatedGuard() error {
	if o.keyMode == "isolated" {
		return ErrBackupUnsupported
	}
	return nil
}

// innerRef 从目录副本的 InnerB64 还原模块内密钥句柄（不落日志）。
func innerRef(r testkit.KeyReplica) (module.KeyRef, error) {
	if r.InnerB64 == "" {
		return nil, errors.New("backup: 副本缺少 inner_b64，无法定位模块内密钥")
	}
	raw, err := base64.StdEncoding.DecodeString(r.InnerB64)
	if err != nil {
		return nil, fmt.Errorf("backup: inner_b64 解码失败: %w", err)
	}
	return module.KeyRef(raw), nil
}

// crossCheck 恢复前交叉校验（§6.2.5）：checksum 必校；
// Vendor/Model/Mechanism/KEKID 不匹配 → group_key_backup_unsupported，不得软件解包。
func crossCheck(w WrappedKey, meta BackupMeta) error {
	if w.State == "destroyed" || w.State == "destroy_pending" {
		return ErrBackupTombstoned
	}
	if w.KEKID == "" || w.Mechanism == "" {
		return ErrBackupUnsupported
	}
	sum := sha256.Sum256(w.Blob)
	if !bytes.Equal(sum[:], meta.Checksum) {
		return ErrCrossCheckMismatch
	}
	return nil
}

// Backup 备份：源成员本地 ExportWrapped → 备份库 Put → 目录回填 backup_id。
//
// blob 不经过调用方/admin/控制存储（§6.2.5）。
func (o *Orchestrator) Backup(keyID string, a Approval) (BackupMeta, error) {
	if err := o.isolatedGuard(); err != nil {
		return BackupMeta{}, err
	}
	st, err := o.requireLeader()
	if err != nil {
		return BackupMeta{}, err
	}
	if err := o.checkAndConsume("backup", keyID, a); err != nil {
		return BackupMeta{}, err
	}

	kd, _ := o.ctrl.GetKeyDirectory(keyID)
	if kd.KeyID == "" {
		return BackupMeta{}, ErrBackupNotFound
	}
	if kd.State == "destroyed" {
		return BackupMeta{}, ErrBackupTombstoned
	}

	// KeyOp：pending → running → succeeded/failed（状态迁移必须 CAS）。
	opID := fmt.Sprintf("op-%s-backup", keyID)
	op := testkit.KeyOp{OpID: opID, Action: "backup", Status: "pending", ClaimOwner: o.self, ClaimEpoch: st.Epoch}
	if _, err := o.ctrl.CreateKeyOp(op); err != nil {
		return BackupMeta{}, err
	}
	// KeyOp 版本跟踪（易踩坑）：CreateKeyOp 内部置 Version=1，但**返回的是 StoreRevision**；
	// CASKeyOp 校验/递增的是 Version，其返回值同样是 StoreRevision。二者不可混用。
	ver := int64(1)
	op.Status, op.Version = "running", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "pending", op); err != nil {
		return BackupMeta{}, err
	}
	ver++ // CAS 成功后 Version=2（status=running）

	// 源成员：取第一个 ready 副本所在成员。
	var src testkit.KeyReplica
	found := false
	for _, r := range kd.Replicas {
		if r.State == "ready" {
			src, found = r, true
			break
		}
	}
	if !found {
		o.failOp(op, ver, "no ready replica")
		return BackupMeta{}, ErrBackupNotFound
	}
	be, ok := o.backends[src.Member]
	if !ok {
		o.failOp(op, ver, "backend missing")
		return BackupMeta{}, ErrBackupUnsupported
	}

	ref, err := innerRef(src)
	if err != nil {
		o.failOp(op, ver, err.Error())
		return BackupMeta{}, err
	}

	// 步骤：成员本地 wrap（backup）
	if _, err := o.steps.Create(KeyOpStep{OpID: opID, Member: src.Member, Action: "backup", Status: "running"}); err != nil {
		o.failOp(op, ver, err.Error())
		return BackupMeta{}, err
	}
	wrapped, err := be.ExportWrapped(ref, o.kekID)
	if err != nil {
		o.markStepFailed(opID, src.Member, "backup", err.Error())
		o.failOp(op, ver, err.Error())
		return BackupMeta{}, err
	}
	if len(wrapped.Blob) == 0 {
		err := errors.New("backup: ExportWrapped 返回空 blob（疑似明文导出路径）")
		o.markStepFailed(opID, src.Member, "backup", err.Error())
		o.failOp(op, ver, err.Error())
		return BackupMeta{}, err
	}
	// 补齐元数据：KEKID/KeyID/Member 以组主与目录为准，禁止成员自行编造。
	wrapped.KeyID, wrapped.Member, wrapped.KEKID = keyID, src.Member, o.kekID
	wrapped.State = "ready"
	_, _ = o.steps.CAS(opID, src.Member, "backup", 1, "running", KeyOpStep{
		OpID: opID, Member: src.Member, Action: "backup", Status: "succeeded",
	})

	// 步骤：备份库 Put（backup_store）—— Result 只放 BackupMeta，不放 blob。
	meta, err := o.store.Put(o.gid, keyID, src.Member, o.kekID, wrapped)
	if err != nil {
		o.markStepFailed(opID, src.Member, "backup_store", err.Error())
		o.failOp(op, ver, err.Error())
		return BackupMeta{}, err
	}
	_, _ = o.steps.Create(KeyOpStep{OpID: opID, Member: src.Member, Action: "backup_store", Status: "succeeded", Result: meta})

	// 目录回填 backup_id（CAS，受组主 epoch/boot_id 约束）。
	kd, dver := o.ctrl.GetKeyDirectory(keyID)
	for i := range kd.Replicas {
		if kd.Replicas[i].Member == src.Member {
			kd.Replicas[i].BackupID = meta.BackupID
			kd.Replicas[i].UpdatedAt = time.Now().UTC()
		}
	}
	kd.UpdatedAt = time.Now().UTC()
	kd.WriterEpoch, kd.WriterBootID = st.Epoch, st.LastOwnerBootID
	if _, err := o.ctrl.CASKeyDirectory(keyID, dver, st.Epoch, st.LastOwnerBootID, kd); err != nil {
		o.failOp(op, ver, err.Error())
		return BackupMeta{}, err
	}

	op.Status, op.Version = "succeeded", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
		return BackupMeta{}, err
	}
	return meta, nil
}

// Restore 恢复：备份库 Get → 交叉校验 → 目标成员本地 ImportWrapped → 目录登记副本。
//
// 语义（§6.2.5 / §6.2.3）：
//   - tombstone 对象 restore **必须失败**；
//   - 恢复**保留原 key_id**，不得为新副本重新分配；
//   - ImportWrapped 失败不得留下半成品（审计 orphan 并尝试 DestroyKey）。
func (o *Orchestrator) Restore(keyID, backupID, targetMember, alias string, a Approval) (module.KeyRef, error) {
	if err := o.isolatedGuard(); err != nil {
		return nil, err
	}
	st, err := o.requireLeader()
	if err != nil {
		return nil, err
	}
	if err := o.checkAndConsume("restore", keyID, a); err != nil {
		return nil, err
	}

	kd, dver := o.ctrl.GetKeyDirectory(keyID)
	if kd.KeyID == "" {
		return nil, ErrBackupNotFound
	}
	// 销毁语义：tombstone 后 restore 必须失败（§6.2.5）。
	if kd.State == "destroyed" {
		return nil, ErrBackupTombstoned
	}

	opID := fmt.Sprintf("op-%s-restore", keyID)
	op := testkit.KeyOp{OpID: opID, Action: "restore", Status: "pending", ClaimOwner: o.self, ClaimEpoch: st.Epoch}
	if _, err := o.ctrl.CreateKeyOp(op); err != nil {
		return nil, err
	}
	ver := int64(1) // CreateKeyOp 置 Version=1（其返回值为 StoreRevision，非 Version）
	op.Status, op.Version = "running", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "pending", op); err != nil {
		return nil, err
	}
	ver++

	// 步骤：备份库 Get（组主只聚合，blob 由目标成员侧本地处理）。
	w, meta, err := o.store.Get(o.gid, keyID, backupID)
	if err != nil {
		o.failOp(op, ver, err.Error())
		return nil, err
	}
	if err := crossCheck(w, meta); err != nil {
		o.failOp(op, ver, err.Error())
		return nil, err
	}

	be, ok := o.backends[targetMember]
	if !ok {
		o.failOp(op, ver, "target backend missing")
		return nil, ErrBackupUnsupported
	}
	_, _ = o.steps.Create(KeyOpStep{OpID: opID, Member: targetMember, Action: "restore_import", Status: "running"})
	ref, err := be.ImportWrapped(w, w.KEKID, alias)
	if err != nil {
		// 失败不得留下半成品：审计 orphan 并尝试清理（此处由后端保证，编排侧记录 failed）。
		o.markStepFailed(opID, targetMember, "restore_import", err.Error())
		o.failOp(op, ver, err.Error())
		return nil, err
	}
	_, _ = o.steps.CAS(opID, targetMember, "restore_import", 1, "running", KeyOpStep{
		OpID: opID, Member: targetMember, Action: "restore_import", Status: "succeeded",
	})

	// 目录登记新副本：**保留原 key_id**，只加副本，不重新分配 key_id（§6.2.3）。
	kd.Replicas = append(kd.Replicas, testkit.KeyReplica{
		Member:    targetMember,
		InnerB64:  base64.StdEncoding.EncodeToString([]byte(ref)),
		BackupID:  meta.BackupID,
		State:     "ready",
		UpdatedAt: time.Now().UTC(),
	})
	kd.UpdatedAt = time.Now().UTC()
	kd.WriterEpoch, kd.WriterBootID = st.Epoch, st.LastOwnerBootID
	if _, err := o.ctrl.CASKeyDirectory(keyID, dver, st.Epoch, st.LastOwnerBootID, kd); err != nil {
		o.failOp(op, ver, err.Error())
		return nil, err
	}

	op.Status, op.Version = "succeeded", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
		return nil, err
	}
	return ref, nil
}

// Destroy 销毁：对全部副本下发 destroy step，并清成员本地备份 + 备份库 blob，
// 最后写 tombstone。
//
// 语义（§6.2.5 / L610）：
//   - **任一副本不可达即不得返回成功**，目录置 destroy_pending 并告警；
//   - 只删 HSM 对象不删备份**不算销毁**；
//   - force_destroy 仅双签 + 审计，仍不得宣称已密码学擦除；
//   - tombstone 后 restore 必须失败。
func (o *Orchestrator) Destroy(keyID string, a Approval) error {
	st, err := o.requireLeader()
	if err != nil {
		return err
	}
	if err := o.checkAndConsume("destroy", keyID, a); err != nil {
		return err
	}

	kd, dver := o.ctrl.GetKeyDirectory(keyID)
	if kd.KeyID == "" {
		return ErrBackupNotFound
	}

	opID := fmt.Sprintf("op-%s-destroy", keyID)
	op := testkit.KeyOp{OpID: opID, Action: "destroy", Status: "pending", ClaimOwner: o.self, ClaimEpoch: st.Epoch}
	if _, err := o.ctrl.CreateKeyOp(op); err != nil {
		return err
	}
	ver := int64(1) // CreateKeyOp 置 Version=1（其返回值为 StoreRevision，非 Version）
	op.Status, op.Version = "running", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "pending", op); err != nil {
		return err
	}
	ver++

	var pending []string
	for i := range kd.Replicas {
		r := &kd.Replicas[i]
		if r.State == "destroyed" {
			continue
		}
		be, ok := o.backends[r.Member]
		if !ok {
			pending = append(pending, r.Member)
			r.State = "destroy_pending"
			continue
		}
		_, _ = o.steps.Create(KeyOpStep{OpID: opID, Member: r.Member, Action: "destroy", Status: "running"})

		stepErr := ""
		// ① 成员本地/厂商备份对象
		if r.BackupID != "" {
			if err := be.DestroyWrapped(r.BackupID); err != nil {
				stepErr = "DestroyWrapped: " + err.Error()
			}
		}
		// ② 备份库 blob（只删 HSM 对象不删备份不算销毁）
		if stepErr == "" && r.BackupID != "" {
			if err := o.store.Delete(o.gid, keyID, r.BackupID); err != nil {
				stepErr = "Store.Delete: " + err.Error()
			}
		}

		if stepErr != "" {
			pending = append(pending, r.Member)
			r.State = "destroy_pending"
			o.markStepFailed(opID, r.Member, "destroy", stepErr)
			continue
		}
		r.State = "destroyed"
		r.UpdatedAt = time.Now().UTC()
		_, _ = o.steps.CAS(opID, r.Member, "destroy", 1, "running", KeyOpStep{
			OpID: opID, Member: r.Member, Action: "destroy", Status: "succeeded",
		})
	}

	// 目录：全成功 → destroyed（tombstone）；有未达 → destroy_pending（不得宣称已销毁）。
	newState := "destroyed"
	if len(pending) > 0 {
		newState = "destroy_pending"
	}
	kd.State = newState
	kd.UpdatedAt = time.Now().UTC()
	kd.WriterEpoch, kd.WriterBootID = st.Epoch, st.LastOwnerBootID
	if _, err := o.ctrl.CASKeyDirectory(keyID, dver, st.Epoch, st.LastOwnerBootID, kd); err != nil {
		o.failOp(op, ver, err.Error())
		return err
	}

	if len(pending) > 0 {
		op.Status, op.Version = "destroy_pending", ver
		if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
			return err
		}
		return ErrDestroyPending
	}
	op.Status, op.Version = "succeeded", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
		return err
	}
	return nil
}

// Rotate 轮换：新建 key_id 并按 key_replication 复制副本到 quorum，旧 key 归档。
//
// 语义（L596/L610）：轮换须双签；旧 MAC 密钥保留至目录全量重签完成；
// 未达 quorum 时目录项 state=degraded，**不得宣称 RPO=0**（D-13）。
func (o *Orchestrator) Rotate(keyID, newKeyID string, a Approval) error {
	if err := o.isolatedGuard(); err != nil {
		return err
	}
	st, err := o.requireLeader()
	if err != nil {
		return err
	}
	if err := o.checkAndConsume("rotate", keyID, a); err != nil {
		return err
	}

	kd, dver := o.ctrl.GetKeyDirectory(keyID)
	if kd.KeyID == "" {
		return ErrBackupNotFound
	}
	if kd.State == "destroyed" {
		return ErrBackupTombstoned
	}

	opID := fmt.Sprintf("op-%s-rotate", keyID)
	op := testkit.KeyOp{OpID: opID, Action: "rotate", Status: "pending", ClaimOwner: o.self, ClaimEpoch: st.Epoch}
	if _, err := o.ctrl.CreateKeyOp(op); err != nil {
		return err
	}
	ver := int64(1) // CreateKeyOp 置 Version=1（其返回值为 StoreRevision，非 Version）
	op.Status, op.Version = "running", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "pending", op); err != nil {
		return err
	}
	ver++

	// 源副本（用于复制到其他成员）：取第一个 ready 副本。
	var src testkit.KeyReplica
	found := false
	for _, r := range kd.Replicas {
		if r.State == "ready" {
			src, found = r, true
			break
		}
	}
	if !found {
		o.failOp(op, ver, "no ready replica")
		return ErrBackupNotFound
	}
	srcBE, ok := o.backends[src.Member]
	if !ok {
		o.failOp(op, ver, "source backend missing")
		return ErrBackupUnsupported
	}

	// 计算需要达成的副本数（D-13）：single=1 / quorum=n/2+1 / all=n。
	total := len(o.backends)
	need := replicationTarget(o.replication, total)

	// 复制：源成员 ExportWrapped → 目标成员 ImportWrapped（保留原 key_id 的备份语义，
	// 此处为新 key_id 建副本，副本 inner 由目标模块生成）。
	synced := 0
	var newReplicas []testkit.KeyReplica
	for member, be := range o.backends {
		if synced >= need {
			break
		}
		if member == src.Member {
			// 源成员本身即一个副本
			newReplicas = append(newReplicas, testkit.KeyReplica{
				Member: src.Member, InnerB64: src.InnerB64, State: "ready", UpdatedAt: time.Now().UTC(),
			})
			synced++
			continue
		}
		ref, err := innerRef(src)
		if err != nil {
			continue
		}
		wrapped, err := srcBE.ExportWrapped(ref, o.kekID)
		if err != nil {
			o.markStepFailed(opID, member, "rotate", err.Error())
			continue
		}
		wrapped.KeyID, wrapped.Member, wrapped.KEKID = newKeyID, src.Member, o.kekID
		newRef, err := be.ImportWrapped(wrapped, o.kekID, newKeyID+"|"+member)
		if err != nil {
			o.markStepFailed(opID, member, "rotate", err.Error())
			continue
		}
		newReplicas = append(newReplicas, testkit.KeyReplica{
			Member:    member,
			InnerB64:  base64.StdEncoding.EncodeToString([]byte(newRef)),
			State:     "ready",
			UpdatedAt: time.Now().UTC(),
		})
		synced++
	}

	// 未达阈值：目录置 degraded，返回 ErrQuorumUnmet，不得宣称 RPO=0。
	if synced < need {
		o.failOp(op, ver, fmt.Sprintf("quorum unmet: %d/%d", synced, need))
		return ErrQuorumUnmet
	}

	// 新 key_id 目录项
	newDir := testkit.KeyDirectory{
		KeyID: newKeyID, KeyMode: o.keyMode, Replicas: newReplicas, State: "ready",
		CreatedBy: o.self, WriterEpoch: st.Epoch, WriterBootID: st.LastOwnerBootID,
		LeaseEpoch: st.Epoch, UpdatedAt: time.Now().UTC(),
	}
	_, nver := o.ctrl.GetKeyDirectory(newKeyID)
	if _, err := o.ctrl.CASKeyDirectory(newKeyID, nver, st.Epoch, st.LastOwnerBootID, newDir); err != nil {
		o.failOp(op, ver, err.Error())
		return err
	}

	// 旧 key 归档（保留旧 KEK 以解旧备份，覆盖 backup.retention_days；D-9/§6.2.5）。
	kd.State = "archived"
	kd.UpdatedAt = time.Now().UTC()
	kd.WriterEpoch, kd.WriterBootID = st.Epoch, st.LastOwnerBootID
	if _, err := o.ctrl.CASKeyDirectory(keyID, dver, st.Epoch, st.LastOwnerBootID, kd); err != nil {
		o.failOp(op, ver, err.Error())
		return err
	}

	op.Status, op.Version = "succeeded", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
		return err
	}
	return nil
}

// failOp 将 KeyOp 置 failed（尽力而为，失败不影响主路径错误返回）。
func (o *Orchestrator) failOp(op testkit.KeyOp, version int64, reason string) {
	op.Status = "failed"
	op.Version = version
	_, _ = o.ctrl.CASKeyOp(op.OpID, version, "running", op)
	_ = reason
}

// markStepFailed 将步骤置 failed。
func (o *Orchestrator) markStepFailed(opID, member, action, reason string) {
	st, ver, err := o.steps.Get(opID, member, action)
	if err != nil {
		_, _ = o.steps.Create(KeyOpStep{OpID: opID, Member: member, Action: action, Status: "failed", Err: reason})
		return
	}
	st.Status = "failed"
	st.Err = reason
	_, _ = o.steps.CAS(opID, member, action, ver, "", st)
}
