package main

// etcd 成员注册表与 KeyRefProbe 测试：只覆盖不依赖 etcd 可达的部分
// （构造校验、键布局对齐、汇聚 fail-closed 语义）。

import (
	"context"
	"strings"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestEtcdMemberRegistryRejectsBadInput(t *testing.T) {
	if _, err := NewEtcdMemberRegistry(nil, "g1", ""); err == nil {
		t.Fatal("nil client 应被拒绝")
	}
	if _, err := NewEtcdMemberRegistry(&clientv3.Client{}, "", ""); err == nil {
		t.Fatal("空组 ID 应被拒绝")
	}
	r, err := NewEtcdMemberRegistry(&clientv3.Client{}, "fin-hsm-a", "")
	if err != nil {
		t.Fatalf("合法参数应构造成功: %v", err)
	}
	// 键布局必须与 cryptop 控制存储同前缀，否则成员表与 desired 分处两套键空间。
	got := r.key("dc1-hsm-a")
	want := "/cryptop/groups/fin-hsm-a/members/dc1-hsm-a"
	if got != want {
		t.Fatalf("成员键路径不一致：\n got  %q\n want %q", got, want)
	}
	if !strings.HasPrefix(got, "/cryptop/groups/") {
		t.Fatalf("成员键前缀未与 cryptop 控制存储对齐: %q", got)
	}
}

// stubProbe 测试替身：按预设返回计数或错误。
type stubProbe struct {
	n   int
	err error
}

func (s stubProbe) ProbePartition(context.Context, string) (int, error) {
	return s.n, s.err
}

// 全部可达 → 求和；这才能作为"允许回收"的依据。
func TestAggregateKeyRefsSumsWhenAllReachable(t *testing.T) {
	got, err := AggregateKeyRefs(context.Background(), []KeyRefProbe{
		stubProbe{n: 2}, stubProbe{n: 0}, stubProbe{n: 3},
	}, "tenant-a")
	if err != nil {
		t.Fatalf("全部可达时应成功: %v", err)
	}
	if got != 5 {
		t.Fatalf("汇聚计数应为 5，实际 %d", got)
	}
}

// 任一侧不可达 → 整体失败（fail-closed）：绝不可按"计数为 0"放行回收。
func TestAggregateKeyRefsFailClosedOnUnreachable(t *testing.T) {
	_, err := AggregateKeyRefs(context.Background(), []KeyRefProbe{
		stubProbe{n: 0}, stubProbe{err: context.DeadlineExceeded},
	}, "tenant-a")
	if err == nil {
		t.Fatal("任一 sidecar 不可达时必须返回错误（拒绝回收），不得放行")
	}

	// nil probe 同样按不可达处理
	if _, err := AggregateKeyRefs(context.Background(), []KeyRefProbe{nil}, "tenant-a"); err == nil {
		t.Fatal("nil probe 应导致失败（无法确认活动 KeyRef）")
	}
}
