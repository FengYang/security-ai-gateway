package main

// T-4 生产协作者：etcd 版成员注册表 + KeyRefProbe 契约。
//
// 设计口径（评审结论）：
//   - **MemberRegistry 落 etcd**：T-4 的语义是**运行时**开通/更新/回收，不是部署时配置。
//     若成员表只来自 GroupConfig 文件，分区回收后成员仍显示存在，D-11「一成员一登录域」
//     隔离校验会继续批准往已回收分区开密钥。故成员注册表是由 desired 驱动的控制面状态，
//     GroupConfig 仅作初始基线。
//   - **KeyRefStore 不落 etcd**：它是 sidecar 运行时计数器。落 etcd 有写放大、计数延迟、
//     etcd 不可用时计数中断三个问题；而分区回收需要的是**跨 sidecar 全局视图**
//     （一个分区的成员可能分布在多个 sidecar 进程）。故改为 KeyRefProbe：由 admin-service
//     向各 sidecar 查询端点汇聚，**任一不可达即拒绝回收（fail-closed）**。
//
// 键布局与 cryptop 控制存储对齐（复用 ctrlstore.KeyPrefix）：
//
//	/cryptop/groups/<gid>/members/<memberID> = JSON(MemberInfo)
//
// 由 EtcdDesiredPublisher 的 apply 动作写入、remove 时清理（清理前先过 KeyRefProbe 守卫）。

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"security-ai-gateway/gateway/cryptop/module/ctrlstore"
)

// 编译期契约：etcd 成员注册表满足 T-4 协作者接口。
var _ MemberRegistry = (*EtcdMemberRegistry)(nil)

// EtcdMemberRegistry 从 etcd 读成员注册表（生产实现）。
type EtcdMemberRegistry struct {
	cli    *clientv3.Client
	gid    string
	prefix string
}

// NewEtcdMemberRegistry 构造 etcd 成员注册表。
//
// 未做缓存：管理面校验是低频操作（分区开通/回收时才触发），每次直读 etcd 更简单且
// 不会读到过期成员；若后续成为热点可加短 TTL 缓存。
func NewEtcdMemberRegistry(cli *clientv3.Client, gid, prefix string) (*EtcdMemberRegistry, error) {
	if cli == nil {
		return nil, fmt.Errorf("etcd members: client 为 nil")
	}
	if gid == "" {
		return nil, fmt.Errorf("etcd members: 组 ID 不能为空")
	}
	if prefix == "" {
		prefix = ctrlstore.KeyPrefix
	}
	return &EtcdMemberRegistry{cli: cli, gid: gid, prefix: prefix}, nil
}

// Member 查询成员信息；不存在返回 (零值, false)。
func (r *EtcdMemberRegistry) Member(id string) (MemberInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := r.cli.Get(ctx, r.key(id))
	if err != nil || len(resp.Kvs) == 0 {
		// 读失败按"不存在"处理：隔离校验会因此拒绝（fail-closed），
		// 而不是放行一个无法确认的成员。
		return MemberInfo{}, false
	}
	var mi MemberInfo
	if err := json.Unmarshal(resp.Kvs[0].Value, &mi); err != nil {
		return MemberInfo{}, false // 格式非法同样按不存在处理（fail-closed）
	}
	return mi, true
}

// Upsert 写入/更新成员注册项（由 desired apply 驱动；分区回收时不调用本方法）。
func (r *EtcdMemberRegistry) Upsert(ctx context.Context, id string, mi MemberInfo) error {
	if id == "" {
		return fmt.Errorf("etcd members: 成员 ID 不能为空")
	}
	blob, err := json.Marshal(mi)
	if err != nil {
		return fmt.Errorf("etcd members: 序列化 %s 失败: %w", id, err)
	}
	if _, err := r.cli.Put(ctx, r.key(id), string(blob)); err != nil {
		return fmt.Errorf("etcd members: 写入 %s 失败: %w", id, err)
	}
	return nil
}

// Remove 删除成员注册项（分区回收时调用；调用方须先过 KeyRefProbe 守卫）。
func (r *EtcdMemberRegistry) Remove(ctx context.Context, id string) error {
	if _, err := r.cli.Delete(ctx, r.key(id)); err != nil {
		return fmt.Errorf("etcd members: 删除 %s 失败: %w", id, err)
	}
	return nil
}

func (r *EtcdMemberRegistry) key(id string) string {
	return fmt.Sprintf("%s/groups/%s/members/%s", r.prefix, r.gid, id)
}

// ---- KeyRefProbe：活动 KeyRef 计数探测（不落 etcd）----

// KeyRefProbe 跨 sidecar 汇聚活动 KeyRef 计数。
//
// 与 KeyRefStore 的区别：KeyRefStore 是单进程内存计数（Wave A 单测用），
// 而分区回收需要的是**全局视图**——同一分区的成员可能分布在多个 sidecar 进程，
// 任一 sidecar 的本地计数都给不出"该分区是否仍有活动 KeyRef"的答案。
//
// fail-closed 语义：探测失败/不可达时返回 error，由调用方**拒绝回收**，
// 而不是按"计数为 0"放行（那会导致带着活动密钥回收分区）。
type KeyRefProbe interface {
	// ProbePartition 返回该分区在当前 sidecar 上的活动 KeyRef 数。
	ProbePartition(ctx context.Context, partition string) (int, error)
}

// AggregateKeyRefs 汇聚多个 sidecar 的探测结果。
//
// 任一侧返回 error → 整体返回 error（调用方据此拒绝回收，fail-closed）。
// 全部成功 → 返回总数；总数为 0 才允许回收（§6.3 无活动 KeyRef 校验）。
func AggregateKeyRefs(ctx context.Context, probes []KeyRefProbe, partition string) (int, error) {
	total := 0
	for i, p := range probes {
		if p == nil {
			return 0, fmt.Errorf("keyref probe[%d] 为 nil（无法确认活动 KeyRef，拒绝回收）", i)
		}
		n, err := p.ProbePartition(ctx, partition)
		if err != nil {
			return 0, fmt.Errorf("keyref probe[%d] 探测分区 %s 失败: %w", i, partition, err)
		}
		total += n
	}
	return total, nil
}
