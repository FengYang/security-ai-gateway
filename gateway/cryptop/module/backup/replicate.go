package backup

// 本文件实现组内密钥副本复制（D-13 key_replication）。
//
// 语义定位（与 Backup 严格区分，勿混用）：
//   - Replicate＝组内成员间副本复制（shared 同密钥域：多成员同时持有同一密钥对象），
//     blob **不落备份库**，属常规生命周期写，双签**可选**；
//   - Backup＝灾难恢复路径，blob 落备份库并分配 backup_id（§6.2.5），
//     属 §7.2 高危操作，双签**必需**。
//
// 副本与备份的销毁路径也因此不同：
//   - Replicate 副本无 backup_id → 销毁时清成员本地密钥对象；
//   - Backup 副本有 backup_id → 销毁时 DestroyWrapped + 备份库 Delete + tombstone。

import (
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ReplicaTarget 副本目标：成员 ID + 该成员所属分区（便于目录登记）。
type ReplicaTarget struct {
	Member    string
	Partition string
}

// ReplicateResult 副本同步结果（D-13）。
//
// Replicas 为同步后的副本总数（含源成员与既有副本）；Needed 为 key_replication 阈值。
// 未达阈值时目录置 degraded 并返回 ErrQuorumUnmet，**不得宣称 RPO=0**（D-13）。
type ReplicateResult struct {
	KeyID     string
	Source    string
	Succeeded []string
	Failed    []string
	Replicas  int
	Needed    int
}

// Replicate 将组内密钥副本同步到 key_replication 阈值要求的成员数（D-13）。
//
// 流程：源成员 ExportWrapped（KEK 为组内独立备份 KEK，D-9 禁用数据 KEK）
// → 各目标成员 ImportWrapped（目标模块内直接建对象，明文不出模块）
// → 目录回填副本；副本数未达阈值 → 目录 degraded + ErrQuorumUnmet。
//
// 目标顺序确定（显式传入或按成员 ID 排序），**不依赖 map 遍历顺序**，
// 避免副本分布随机导致 quorum 成员集不可预期。
//
// Approval 可选：Replicate 属常规生命周期写，不强制双签；
// 若传入审批单则按 action=replicate 校验并消费（便于运维侧强制审批）。
func (o *Orchestrator) Replicate(keyID string, targets []ReplicaTarget, a Approval) (ReplicateResult, error) {
	res := ReplicateResult{KeyID: keyID}

	if err := o.isolatedGuard(); err != nil {
		return res, err
	}
	st, err := o.requireLeader()
	if err != nil {
		return res, err
	}
	if a.ApprovalID != "" {
		if err := o.checkAndConsume("replicate", keyID, a); err != nil {
			return res, err
		}
	}

	kd, dver := o.ctrl.GetKeyDirectory(keyID)
	if kd.KeyID == "" {
		return res, ErrBackupNotFound
	}
	if kd.State == "destroyed" {
		return res, ErrBackupTombstoned
	}

	opID := fmt.Sprintf("op-%s-replicate", keyID)
	op := testkit.KeyOp{OpID: opID, Action: "replicate", Status: "pending", ClaimOwner: o.self, ClaimEpoch: st.Epoch}
	if _, err := o.ctrl.CreateKeyOp(op); err != nil {
		return res, err
	}
	// KeyOp 版本跟踪：CreateKeyOp 置 Version=1（其返回值为 StoreRevision，非 Version）。
	ver := int64(1)
	op.Status, op.Version = "running", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "pending", op); err != nil {
		return res, err
	}
	ver++

	src, ok := pickUsableReplica(kd.Replicas, o.self)
	if !ok {
		o.failOp(op, ver, "no usable replica")
		return res, ErrBackupNotFound
	}
	srcBE, ok := o.backends[src.Member]
	if !ok {
		o.failOp(op, ver, "source backend missing")
		return res, ErrBackupUnsupported
	}
	inner, err := innerRef(src)
	if err != nil {
		o.failOp(op, ver, err.Error())
		return res, err
	}
	res.Source = src.Member

	// 既有可用副本计入（本成员刚生成的副本已由 group 写入目录）。
	replicas := usableReplicas(kd.Replicas)
	synced := len(replicas)
	need := replicationTarget(o.replication, len(o.backends))
	res.Needed = need

	for _, t := range o.orderedTargets(targets, src.Member, replicas) {
		if synced >= need {
			break
		}
		be, ok := o.backends[t.Member]
		if !ok {
			res.Failed = append(res.Failed, t.Member)
			continue
		}
		_, _ = o.steps.Create(KeyOpStep{OpID: opID, Member: t.Member, Action: "replicate", Status: "running"})

		wrapped, err := srcBE.ExportWrapped(inner, o.kekID)
		if err != nil {
			o.markStepFailed(opID, t.Member, "replicate", "ExportWrapped: "+err.Error())
			res.Failed = append(res.Failed, t.Member)
			continue
		}
		wrapped.KeyID, wrapped.Member, wrapped.KEKID = keyID, src.Member, o.kekID

		newRef, err := be.ImportWrapped(wrapped, o.kekID, keyID+"|"+t.Member)
		if err != nil {
			o.markStepFailed(opID, t.Member, "replicate", "ImportWrapped: "+err.Error())
			res.Failed = append(res.Failed, t.Member)
			continue
		}
		replicas = append(replicas, testkit.KeyReplica{
			Member:    t.Member,
			Partition: t.Partition,
			InnerB64:  base64.StdEncoding.EncodeToString([]byte(newRef)),
			State:     "ready",
			UpdatedAt: time.Now().UTC(),
		})
		res.Succeeded = append(res.Succeeded, t.Member)
		synced++
		_, _ = o.steps.CAS(opID, t.Member, "replicate", 1, "running", KeyOpStep{
			OpID: opID, Member: t.Member, Action: "replicate", Status: "succeeded",
		})
	}
	res.Replicas = synced

	kd.Replicas = replicas
	kd.UpdatedAt = time.Now().UTC()
	kd.WriterEpoch, kd.WriterBootID = st.Epoch, st.LastOwnerBootID
	if synced < need {
		// 未达阈值：目录置 degraded，不得宣称 RPO=0（D-13）。
		kd.State = "degraded"
	}
	if _, err := o.ctrl.CASKeyDirectory(keyID, dver, st.Epoch, st.LastOwnerBootID, kd); err != nil {
		o.failOp(op, ver, err.Error())
		return res, err
	}

	if synced < need {
		op.Status, op.Version = "failed", ver
		if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
			return res, err
		}
		return res, ErrQuorumUnmet
	}
	op.Status, op.Version = "succeeded", ver
	if _, err := o.ctrl.CASKeyOp(opID, ver, "running", op); err != nil {
		return res, err
	}
	return res, nil
}

// pickUsableReplica 选源副本：优先本成员，否则第一个可用副本。
//
// 可用态含 "active"（group 侧新建副本的初态）与 "ready"（备份/复制后常态）。
func pickUsableReplica(rs []testkit.KeyReplica, self string) (testkit.KeyReplica, bool) {
	for _, r := range rs {
		if r.Member == self && isUsableState(r.State) {
			return r, true
		}
	}
	for _, r := range rs {
		if isUsableState(r.State) {
			return r, true
		}
	}
	return testkit.KeyReplica{}, false
}

func isUsableState(s string) bool { return s == "ready" || s == "active" }

func usableReplicas(rs []testkit.KeyReplica) []testkit.KeyReplica {
	out := make([]testkit.KeyReplica, 0, len(rs))
	for _, r := range rs {
		if isUsableState(r.State) {
			out = append(out, r)
		}
	}
	return out
}

// orderedTargets 生成确定顺序的目标列表：跳过源成员与已有副本的成员。
func (o *Orchestrator) orderedTargets(targets []ReplicaTarget, src string, have []testkit.KeyReplica) []ReplicaTarget {
	var cand []ReplicaTarget
	if len(targets) > 0 {
		cand = targets
	} else {
		ids := make([]string, 0, len(o.backends))
		for id := range o.backends {
			ids = append(ids, id)
		}
		sort.Strings(ids) // 确定性：map 遍历顺序随机，会导致副本分布不可预期
		for _, id := range ids {
			cand = append(cand, ReplicaTarget{Member: id})
		}
	}
	out := make([]ReplicaTarget, 0, len(cand))
	for _, t := range cand {
		if t.Member == src || hasMember(have, t.Member) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func hasMember(rs []testkit.KeyReplica, member string) bool {
	for _, r := range rs {
		if r.Member == member {
			return true
		}
	}
	return false
}
