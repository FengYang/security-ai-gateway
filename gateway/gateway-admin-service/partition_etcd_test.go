package main

// etcd 版 DesiredPublisher 测试：只覆盖**不依赖 etcd 可达**的部分
// （构造校验、入参校验、键布局）；真实读写由真机用例覆盖。

import (
	"context"
	"strings"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestEtcdDesiredPublisherRejectsBadInput(t *testing.T) {
	if _, err := NewEtcdDesiredPublisher(nil, "g1", ""); err == nil {
		t.Fatal("nil client 应被拒绝")
	}
	p, err := NewEtcdDesiredPublisher(&clientv3.Client{}, "g1", "")
	if err != nil {
		t.Fatalf("合法参数应构造成功: %v", err)
	}

	// 空 tenant / partition
	if _, err := p.PublishDesired(context.Background(), PartitionDesiredOut{Action: "apply"}); err == nil {
		t.Fatal("空 tenant/partition 应被拒绝")
	}
	// 非法 action
	if _, err := p.PublishDesired(context.Background(), PartitionDesiredOut{
		Tenant: "tenant-a", Partition: "tenant-a", Action: "delete",
	}); err == nil {
		t.Fatal("非法 action 应被拒绝（仅 apply|remove）")
	}
}

// 键布局必须与 cryptop 控制存储同前缀，否则 desired 与组控制面分处两套键空间。
func TestEtcdDesiredPublisherKeyLayout(t *testing.T) {
	p, err := NewEtcdDesiredPublisher(&clientv3.Client{}, "fin-hsm-a", "")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	got := p.key("tenant-a", "tenant-a")
	want := "/cryptop/groups/fin-hsm-a/desired/partitions/tenant-a|tenant-a"
	if got != want {
		t.Fatalf("键路径不一致：\n got  %q\n want %q", got, want)
	}
	if !strings.HasPrefix(got, "/cryptop/groups/") {
		t.Fatalf("键前缀未与 cryptop 控制存储对齐: %q", got)
	}
}
