// Package main — 集群注册/摘除的双签受理（P2-4 T-2.4 / T-2.5）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.1「双人确认 / 双签落点」。
//
// 契约（fail-closed）：
//  1. 摘除等受控操作须**两名不同授权人**各自独立产生一条审批审计事件
//     （action=cluster_registry_approval，落 admin 链 G1）；
//  2. 变更事件（action=cluster_registry_changed）引用两条审批事件 ID
//     （证据字段 `dual_approval_ids`，不进 11 字段 hash 域 ⇒ 旧链逐字节不变）；
//  3. 受理校验：**actor_a ≠ actor_b**（同一人自批双签无效）、两条审批的 target
//     **均须等于**变更 target（禁止 X 集群审批挪用于 Y 变更）、审批自产生起
//     **≤15min** 有效、审批**一次性消费**（被引用后作废，禁止复用）；
//  4. 缺 actor/会话标识、校验任一条不过 ⇒ 拒绝受理。
//
// 落链语义：先落链（审计先行）再执行状态变更——落链失败即拒绝变更（fail-closed）。
package main

import (
	"fmt"
	"sync"
	"time"
)

// 集群注册相关审计动作常量定义于 audit_events.go（白名单扩展段）：
//   auditActionClusterRegistryApproval = "cluster_registry_approval"（单次审批）
//   auditActionClusterRegistryChanged  = "cluster_registry_changed"（变更事件，引用双签）

// clusterApprovalTTL 审批有效期（§6.1 S2(6)：≤15min，过期须重新提交）。
const clusterApprovalTTL = 15 * time.Minute

// clusterApprovalRegistry 双签审批登记（基于 admin 审计链）。
//
// 审批事件本体落 admin 链（可核验、可导出、可被 audit-verify 复算）；
// 本结构只维护**消费状态**（哪条审批已被哪个变更引用），用于一次性消费判定。
type clusterApprovalRegistry struct {
	chain *adminAuditChain

	mu       sync.Mutex
	consumed map[string]time.Time // 审批事件 ID → 被消费时刻
}

// newClusterApprovalRegistry 构造审批登记器。
func newClusterApprovalRegistry(chain *adminAuditChain) *clusterApprovalRegistry {
	return &clusterApprovalRegistry{chain: chain, consumed: make(map[string]time.Time)}
}

// RegisterApproval 产生一条审批审计事件，返回其事件 ID（供变更事件引用）。
// actor 为审批人主体身份（来自认证会话 sub），target 为集群 ID。
func (r *clusterApprovalRegistry) RegisterApproval(actor, target string) (string, error) {
	if r == nil || r.chain == nil {
		return "", fmt.Errorf("cluster_approval: 审计链未启用（fail-closed）")
	}
	if actor == "" || target == "" {
		return "", fmt.Errorf("cluster_approval: 审批人或目标缺失（fail-closed）")
	}
	ev := adminAuditEvent{
		Actor:  actor,
		Action: auditActionClusterRegistryApproval,
		Target: target,
		Result: "ok",
	}
	// 单锁内"生成 ID + 写入"，返回确切 ID（不靠事后回读最新事件——并发下会取错审批）。
	id, err := r.chain.appendWithID(ev)
	if err != nil {
		return "", fmt.Errorf("cluster_approval: 审批事件落链失败: %w", err)
	}
	if id == "" {
		return "", fmt.Errorf("cluster_approval: 审批事件未返回 ID（fail-closed）")
	}
	return id, nil
}

// ValidateDualApproval 校验双签是否成立（不消费）。
//
// 校验项：两条 ID 存在且互异、均为审批事件、actor 不同、target 均等于变更 target、
// 均未超过有效期、均未被消费。
func (r *clusterApprovalRegistry) ValidateDualApproval(actor, target string, ids [2]string, now time.Time) error {
	if r == nil || r.chain == nil {
		return fmt.Errorf("cluster_approval: 审计链未启用（fail-closed）")
	}
	if actor == "" || target == "" {
		return fmt.Errorf("cluster_approval: 变更人或目标缺失（fail-closed）")
	}
	if ids[0] == "" || ids[1] == "" {
		return fmt.Errorf("cluster_approval: 缺少双签审批 ID（fail-closed）")
	}
	if ids[0] == ids[1] {
		return fmt.Errorf("cluster_approval: 双签审批 ID 不得相同（fail-closed）")
	}
	if now.IsZero() {
		now = time.Now()
	}

	var (
		actors  [2]string
		targets [2]string
		stamps  [2]time.Time
	)
	for i, id := range ids {
		ev, ok := r.chain.eventByID(id)
		if !ok {
			return fmt.Errorf("cluster_approval: 审批事件 %s 不存在（fail-closed）", id)
		}
		if ev.Action != auditActionClusterRegistryApproval {
			return fmt.Errorf("cluster_approval: 事件 %s 不是审批事件（fail-closed）", id)
		}
		actors[i] = ev.Actor
		targets[i] = ev.Target
		stamps[i] = time.Unix(0, ev.Timestamp)
	}
	// 两名不同授权人（禁止同一人开两会话自批）。
	if actors[0] == actors[1] {
		return fmt.Errorf("cluster_approval: 双签审批人必须不同（fail-closed）")
	}
	// 目标绑定（禁止 X 集群的审批挪用于 Y 集群的变更）。
	for i := range ids {
		if targets[i] != target {
			return fmt.Errorf("cluster_approval: 审批 %s 的目标 %q 与变更目标 %q 不一致（fail-closed）", ids[i], targets[i], target)
		}
	}
	// 有效期（≤15min）。
	for i := range ids {
		if now.Sub(stamps[i]) > clusterApprovalTTL {
			return fmt.Errorf("cluster_approval: 审批 %s 已超过 %v 有效期（fail-closed）", ids[i], clusterApprovalTTL)
		}
	}
	// 一次性消费。
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range ids {
		if _, used := r.consumed[ids[i]]; used {
			return fmt.Errorf("cluster_approval: 审批 %s 已被消费，不可复用（fail-closed）", ids[i])
		}
	}
	return nil
}

// ConsumeDualApproval 标记两条审批已被本次变更消费（一次性消费）。
func (r *clusterApprovalRegistry) ConsumeDualApproval(ids [2]string, now time.Time) {
	if r == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, used := r.consumed[id]; !used {
			r.consumed[id] = now
		}
	}
}

// AppendRegistryChange 落集群注册/摘除变更审计事件（引用双签）。
//
// 落链失败即返回错误——调用方据此**不执行**状态变更（fail-closed）。
func (r *clusterApprovalRegistry) AppendRegistryChange(actor, target string, ids [2]string, detail string) error {
	if r == nil || r.chain == nil {
		return fmt.Errorf("cluster_approval: 审计链未启用（fail-closed）")
	}
	ev := adminAuditEvent{
		Actor:           actor,
		Action:          auditActionClusterRegistryChanged,
		Target:          target,
		Result:          "ok",
		Detail:          detail,
		DualApprovalIDs: ids,
	}
	if err := r.chain.append(ev); err != nil {
		return fmt.Errorf("cluster_approval: 变更事件落链失败: %w", err)
	}
	return nil
}
