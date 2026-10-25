package group

// 本文件实现 T-1（组抽象）与 T-2（密钥跨模块协同）的接线。
//
// 背景：T-1 的生命周期写此前只在 self 成员本地执行，目录副本恒为单副本，
// 导致 key_mode=shared 的 quorum 副本同步（D-13）在产品链路上不存在——
// G-4「跨模块密钥协同」实际空转。本文件把 T-2 编排器接进组生命周期写。
//
// 语义边界（U-2 / D-13 / D-20③）：
//   - shared：生成/导入/轮换后把密钥副本同步到 key_replication 阈值成员数，
//     销毁连带清副本与备份；
//   - isolated：不接协同，各成员独立密钥 + GroupKeyRef 路由，**不宣称跨模块协同**。

import (
	"encoding/base64"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/backup"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// maxMembersPerGroup U-5 组内成员上限（2-4，默认 4；>4 不支持）。
//
// U-5 原文：「2-4，默认 4；>4 不支持（性能报告可下调，不可上调）」。
const maxMembersPerGroup = 4

// BackupDeps 组模式密钥协同的外部依赖（key_mode=shared 必需）。
//
// 生产须注入外部实现（控制存储承载审批/步骤 + 厂商备份库）；传 nil 时使用进程内
// 内存实现，**仅适用于测试/开发**——内存实现随进程消亡，且不满足 U-6
// 「生产 etcd v3 全量（单 txn）」。
type BackupDeps struct {
	Approvals backup.ApprovalStore
	Steps     backup.KeyOpStepStore
	Backup    backup.KeyBackupStore
}

// newKeySync 构造密钥协同编排器（仅 shared 模式调用）。
//
// backends 取自组成员后端中那些**运行时**实现了 wrap/unwrap 的成员；
// 调用方（NewGroupProvider）已先行断言全部成员满足，此处仅取可用者。
func newKeySync(cfg testkit.GroupConfig, self string, store ControlStore,
	members map[string]module.ModuleBackend, deps *BackupDeps) *backup.Orchestrator {
	be := make(map[string]backup.KeyBackupBackend, len(members))
	for id, b := range members {
		if kb, ok := b.(backup.KeyBackupBackend); ok {
			be[id] = kb
		}
	}
	// 直接按接口接收，**不对具体类型做断言**——否则外部注入的 etcd/厂商实现
	// 会被静默丢弃并回退到内存实现（生产事故级缺陷）。
	var appr backup.ApprovalStore
	var steps backup.KeyOpStepStore
	var bst backup.KeyBackupStore
	if deps != nil {
		appr, steps, bst = deps.Approvals, deps.Steps, deps.Backup
	}
	// 缺省回退到内存实现（测试/开发）；生产须显式注入外部持久实现。
	if appr == nil {
		appr = backup.NewMemoryApprovalStore()
	}
	if steps == nil {
		steps = backup.NewMemoryKeyOpStepStore()
	}
	if bst == nil {
		bst = backup.NewMemoryKeyBackupStore()
	}
	return backup.NewOrchestrator(cfg.GroupID, self, cfg.Backup.KekID, cfg.KeyMode,
		cfg.KeyReplication, store, appr, steps, bst, be)
}

// replicaTargets 按稳定顺序给出副本目标（成员 + 其分区）。
//
// 顺序取自组内成员稳定序（非 map 遍历序），保证副本分布可预期。
func (g *ModuleGroup) replicaTargets() []backup.ReplicaTarget {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]backup.ReplicaTarget, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, backup.ReplicaTarget{Member: id, Partition: g.partOf[id]})
	}
	return out
}

// isShared 是否 shared 模式（isolated 不接密钥协同，U-2）。
func (g *ModuleGroup) isShared() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.shared && g.orch != nil
}

// keyIDHex 从 GroupKeyRef 信封取出目录 key_id（hex 形式）。
func keyIDHex(ref module.KeyRef) (string, error) {
	gk, err := testkit.DecodeGroupKeyRef(ref)
	if err != nil {
		return "", err
	}
	return hexKeyID(gk.KeyID), nil
}

// archiveKey 把旧 key 目录项置 archived（轮换后旧密钥须保留以解旧密文，D-9/§6.2.5）。
//
// 尽力而为：归档失败不阻断轮换主路径，但会留待后续一致性巡检发现。
func (g *ModuleGroup) archiveKey(kid string) {
	g.mu.RLock()
	store, coord := g.store, g.coord
	g.mu.RUnlock()
	ls, ok := coord.LeaderLease()
	if !ok {
		return
	}
	kd, ver := store.GetKeyDirectory(kid)
	if kd.KeyID == "" {
		return
	}
	kd.State = "archived"
	kd.UpdatedAt = time.Now().UTC()
	kd.WriterEpoch, kd.WriterBootID = ls.Epoch, ls.HolderBootID
	_, _ = store.CASKeyDirectory(kid, ver, ls.Epoch, ls.HolderBootID, kd)
}

// destroyReplicas shared 模式下销毁各成员内的密钥副本对象（skip 成员由调用方单独处理）。
//
// 必要性：编排器的 Destroy 只清有 backup_id 的备份对象与备份库 blob；
// Replicate 产生的组内副本**没有 backup_id**，若不逐个成员销毁就会留下孤儿密钥对象。
//
// 返回未成功销毁的成员列表（尽力而为，调用方据此决定是否上报 ErrDestroyPending）。
func (g *ModuleGroup) destroyReplicas(kid, skipMember string) []string {
	g.mu.RLock()
	store, members := g.store, g.members
	g.mu.RUnlock()
	kd, _ := store.GetKeyDirectory(kid)
	var pending []string
	for _, r := range kd.Replicas {
		if r.Member == skipMember {
			continue
		}
		inner, err := base64.StdEncoding.DecodeString(r.InnerB64)
		if err != nil {
			pending = append(pending, r.Member)
			continue
		}
		m, ok := members[r.Member]
		if !ok {
			pending = append(pending, r.Member)
			continue
		}
		if err := m.Backend.DestroyKey(module.KeyRef(inner)); err != nil {
			pending = append(pending, r.Member)
			continue
		}
		g.metrics.recordOp("destroy_replica", "ok")
	}
	return pending
}

// syncKeyReplicas shared 模式下把密钥副本同步到 key_replication 阈值（D-13）。
//
// 未达阈值时返回 backup.ErrQuorumUnmet 且目录已置 degraded：
// 按 R-6「绝不静默降级」向上报错，不伪装成成功，也不宣称 RPO=0（D-13）。
// isolated 模式（orch=nil）直接返回 nil，保持各成员独立密钥语义（U-2）。
func (g *ModuleGroup) syncKeyReplicas(keyID string) error {
	g.mu.RLock()
	orch, shared := g.orch, g.shared
	g.mu.RUnlock()
	if !shared || orch == nil {
		return nil
	}
	targets := g.replicaTargets()
	_, err := orch.Replicate(keyID, targets, backup.Approval{})
	if err != nil {
		g.metrics.recordOp("replicate", "err")
		return err
	}
	g.metrics.recordOp("replicate", "ok")
	return nil
}
