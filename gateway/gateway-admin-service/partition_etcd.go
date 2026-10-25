package main

// T-4 的 etcd 版 DesiredPublisher（本体 §7.2 T-4「k8s_crd / etcd desired」）。
//
// 键布局与 cryptop 控制存储对齐（复用 ctrlstore.KeyPrefix，避免两处硬编码漂移）：
//
//	/cryptop/groups/<gid>/desired/partitions/<tenant>|<partition> = JSON(PartitionDesiredOut)
//
// version 取 etcd 返回的 Revision（单调递增，天然适合作 desired 版本号，
// 与内存实现的"进程内计数"语义不同——后者重启即归零，生产不可用）。
//
// 范围说明（如实）：仅实现文档明确的 desired 下发。MemberRegistry / KeyRefStore 的
// etcd 化**未实现**——成员信息的权威源是 GroupConfig（配置面，非控制面），
// 活动 KeyRef 计数是 sidecar 运行时状态，二者是否落 etcd 需产品决策，
// 不擅自设计。

import (
	"context"
	"encoding/json"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"
	"security-ai-gateway/gateway/cryptop/module/ctrlstore"
)

// 编译期契约：etcd 发布者必须满足 T-4 协作者接口（装配层可直接注入）。
var _ DesiredPublisher = (*EtcdDesiredPublisher)(nil)

// EtcdDesiredPublisher 把分区期望态写入 etcd。
type EtcdDesiredPublisher struct {
	cli    *clientv3.Client
	gid    string
	prefix string
}

// NewEtcdDesiredPublisher 构造 etcd desired 发布者。
//
// gid 为组 ID（不可为空）；prefix 为空时用 ctrlstore.KeyPrefix（/cryptop）。
func NewEtcdDesiredPublisher(cli *clientv3.Client, gid, prefix string) (*EtcdDesiredPublisher, error) {
	if cli == nil {
		return nil, fmt.Errorf("etcd desired: client 为 nil")
	}
	if gid == "" {
		return nil, fmt.Errorf("etcd desired: 组 ID 不能为空")
	}
	if prefix == "" {
		prefix = ctrlstore.KeyPrefix
	}
	return &EtcdDesiredPublisher{cli: cli, gid: gid, prefix: prefix}, nil
}

// PublishDesired 下发分区期望态；返回 etcd Revision 作为版本号。
//
// action=remove 走 Delete（删除即表达"该分区不再期望存在"）；
// action=apply 走 Put。两者都返回操作后的 etcd Revision（单调递增）。
func (p *EtcdDesiredPublisher) PublishDesired(ctx context.Context, pd PartitionDesiredOut) (uint64, error) {
	if pd.Tenant == "" || pd.Partition == "" {
		return 0, fmt.Errorf("etcd desired: tenant/partition 不能为空")
	}
	switch pd.Action {
	case "apply", "remove":
	default:
		return 0, fmt.Errorf("etcd desired: action 非法 %q（仅 apply|remove）", pd.Action)
	}

	key := p.key(pd.Tenant, pd.Partition)
	if pd.Action == "remove" {
		resp, err := p.cli.Delete(ctx, key)
		if err != nil {
			return 0, fmt.Errorf("etcd desired: 删除 %s 失败: %w", key, err)
		}
		return uint64(resp.Header.Revision), nil
	}

	blob, err := json.Marshal(pd)
	if err != nil {
		return 0, fmt.Errorf("etcd desired: 序列化失败: %w", err)
	}
	resp, err := p.cli.Put(ctx, key, string(blob))
	if err != nil {
		return 0, fmt.Errorf("etcd desired: 写入 %s 失败: %w", key, err)
	}
	return uint64(resp.Header.Revision), nil
}

// key 生成 desired 键路径（tenant 与 partition 用 | 分隔，避免 / 冲突）。
func (p *EtcdDesiredPublisher) key(tenant, partition string) string {
	return fmt.Sprintf("%s/groups/%s/desired/partitions/%s|%s", p.prefix, p.gid, tenant, partition)
}
