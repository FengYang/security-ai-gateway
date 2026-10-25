package ctrlstore

// ctrlstore 测试：契约断言 + 键布局一致性 + 启动 fail-closed。
//
// 真机行为（租约抢占 / CAS / fencing / 目录 MAC）的验证依赖 etcd 实例，
// 由后续真机用例覆盖（POC 侧已有 v2_control_test.go / v5_directory_test.go 可迁移为
// 产品实现的真机测试）；本文件只覆盖**不依赖 etcd 可达**的部分。

import (
	"context"
	"testing"

	"security-ai-gateway/gateway/cryptop/module/group"
)

// 编译期契约：**适配器**必须满足组控制存储接口（U-6 接入点）。
//
// EtcdControlStore 本身带 context 签名，不直接满足；装配层经 ControlStoreAdapter 接入。
// group 包不反向依赖本包，故此处由测试建立断言；若 group.ControlStore 变更
// （如补 error 通道），这里会第一时间编译失败。
var _ group.ControlStore = (*ControlStoreAdapter)(nil)

// 注意：EtcdControlStore 的方法带 context.Context，**不**直接满足无 context 契约，
// 装配层必须经 ControlStoreAdapter 接入（见 adapter.go 文件头的装配说明）。

// 键前缀必须与 POC 侧 TestPrefix 同值，否则两份实现的键布局分叉，
// "同一组真机测试同时约束产品实现与 POC"的前提即不成立。
func TestKeyPrefixMatchesPOC(t *testing.T) {
	if KeyPrefix != "/cryptop" {
		t.Fatalf("KeyPrefix 应为 /cryptop（与 POC TestPrefix 一致），实际 %q", KeyPrefix)
	}
}

// 键路径公式与 POC 一致：<prefix>/groups/<gid>/<part>。
func TestKeyLayoutFormula(t *testing.T) {
	s := &EtcdControlStore{gid: "fin-hsm-a", dirMACKey: []byte("k")}
	cases := map[string]string{
		s.k(kEpoch):      KeyPrefix + "/groups/fin-hsm-a/" + kEpoch,
		s.k(kLease):      KeyPrefix + "/groups/fin-hsm-a/" + kLease,
		s.k(kOps):        KeyPrefix + "/groups/fin-hsm-a/" + kOps,
		s.k(kKeys, "k1"): KeyPrefix + "/groups/fin-hsm-a/" + kKeys + "/k1",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("键路径不一致：got %q want %q", got, want)
		}
	}
}

// 空目录 MAC 密钥必须拒收（§6.2.2：无 MAC 密钥时目录写入一律失败，不得退化为无保护目录）。
//
// 校验置于连接 etcd 之前，故无需 etcd 可达即可验证 fail-closed。
func TestNewRejectsEmptyMACKey(t *testing.T) {
	if _, err := NewEtcdControlStore(context.Background(), []string{"127.0.0.1:2379"}, "g1", nil); err == nil {
		t.Fatal("空目录 MAC 密钥应被拒绝（无 MAC 目录不得退化）")
	}
	if _, err := NewEtcdControlStoreAuth(context.Background(), []string{"127.0.0.1:2379"}, "g1", "u", "p", nil); err == nil {
		t.Fatal("Auth 版空目录 MAC 密钥应被拒绝")
	}
}
