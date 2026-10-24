package poc

// V-5：目录 MAC 与越权写 POC（本体 §7.3.1 测试矩阵·安全层 / §6.2.2 / R3-P1-05）。
//
// 验收判据（对齐证据包 README）：
//   - etcd_role 档：被撤销 keys/* 写角色的成员直写 keys/{key_id} 被 etcd 拒绝；
//   - 读者侧：任一字段被篡改（MAC 不匹配）→ 拒绝且不回退旧值；
//   - lease 档：持静态写权限的成员可造成 DoS，但**无法伪造**（读者 MAC 拒绝）。
//
// 说明：本用例会开启 etcd auth 并在结束时关闭，避免影响同集群其它用例。

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	v5RootPass = "p23-root-pass"
	v5PassA    = "p23-mbr-a-pass"
	v5PassB    = "p23-mbr-b-pass"
	v5KeyID    = "fedcba9876543210fedcba9876543210"
)

// v5AdminClient 以 root 身份连接（管理 auth/RBAC）。
func v5AdminClient(t *testing.T, ctx context.Context) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   etcdEndpoints(t),
		DialTimeout: 5 * time.Second,
		Username:    "root",
		Password:    v5RootPass,
	})
	if err != nil {
		t.Fatalf("root 连接 etcd 失败: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

// v5SetupAuth 装配 etcd auth/RBAC：
//   - role-leader：对整个组前缀 readwrite；
//   - role-member：对组前缀 read + 对各非 keys 子前缀 readwrite（keys/ 只读）。
func v5SetupAuth(t *testing.T, ctx context.Context, admin *clientv3.Client) {
	t.Helper()
	// 先关 auth 再配置（支持重复执行）。
	_, _ = admin.AuthDisable(ctx)

	if _, err := admin.UserAdd(ctx, "root", v5RootPass); err != nil && !isUserExists(err) {
		t.Fatalf("UserAdd(root): %v", err)
	}
	// root 用户必须持 root 角色，否则无法 AuthEnable。
	if _, err := admin.UserGrantRole(ctx, "root", "root"); err != nil {
		t.Fatalf("UserGrantRole(root): %v", err)
	}
	if _, err := admin.RoleAdd(ctx, "role-leader"); err != nil && !isRoleExists(err) {
		t.Fatalf("RoleAdd(role-leader): %v", err)
	}
	if _, err := admin.RoleAdd(ctx, "role-member"); err != nil && !isRoleExists(err) {
		t.Fatalf("RoleAdd(role-member): %v", err)
	}
	groupPrefix := TestPrefix + "/groups/" + TestGID + "/"
	groupEnd := clientv3.GetPrefixRangeEnd(groupPrefix)

	// role-leader：全组 readwrite。
	if _, err := admin.RoleGrantPermission(ctx, "role-leader", groupPrefix, groupEnd,
		clientv3.PermissionType(clientv3.PermReadWrite)); err != nil {
		t.Fatalf("RoleGrantPermission(role-leader): %v", err)
	}
	// role-member：全组 read（含 keys/）+ 非 keys 子前缀 readwrite。
	if _, err := admin.RoleGrantPermission(ctx, "role-member", groupPrefix, groupEnd,
		clientv3.PermissionType(clientv3.PermRead)); err != nil {
		t.Fatalf("RoleGrantPermission(role-member read): %v", err)
	}
	for _, sub := range []string{"epoch", "epochmeta", "claim", "writer", "lease",
		"leaseexp", "desired", "approvals", "ops", "opvs", "dirvs"} {
		p := groupPrefix + sub + "/"
		if _, err := admin.RoleGrantPermission(ctx, "role-member", p,
			clientv3.GetPrefixRangeEnd(p), clientv3.PermissionType(clientv3.PermReadWrite)); err != nil {
			t.Fatalf("RoleGrantPermission(role-member %s): %v", sub, err)
		}
	}
	if _, err := admin.UserAdd(ctx, "mbr-a", v5PassA); err != nil && !isUserExists(err) {
		t.Fatalf("UserAdd(mbr-a): %v", err)
	}
	if _, err := admin.UserAdd(ctx, "mbr-b", v5PassB); err != nil && !isUserExists(err) {
		t.Fatalf("UserAdd(mbr-b): %v", err)
	}
	if _, err := admin.UserGrantRole(ctx, "mbr-a", "role-leader"); err != nil {
		t.Fatalf("UserGrantRole(mbr-a): %v", err)
	}
	if _, err := admin.UserGrantRole(ctx, "mbr-b", "role-member"); err != nil {
		t.Fatalf("UserGrantRole(mbr-b): %v", err)
	}
	if _, err := admin.AuthEnable(ctx); err != nil {
		t.Fatalf("AuthEnable: %v", err)
	}
}

// etcd 的"已存在"错误文案：user name already exists / role name already exists。
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}

func isUserExists(err error) bool { return isAlreadyExists(err) }

func isRoleExists(err error) bool { return isAlreadyExists(err) }

// TestV5UnauthorizedDirectoryWriteRejected etcd_role 档：撤销写角色后直写 keys/* 被拒。
func TestV5UnauthorizedDirectoryWriteRejected(t *testing.T) {
	if !rbacEnabled() {
		t.Skip("P23_POC_RBAC=0，跳过 etcd auth/RBAC 用例")
	}
	eps := etcdEndpoints(t)
	ctx := context.Background()

	admin, err := clientv3.New(clientv3.Config{Endpoints: eps, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("连接 etcd 失败: %v", err)
	}
	defer admin.Close()
	v5SetupAuth(t, ctx, admin)
	t.Cleanup(func() {
		root, err := clientv3.New(clientv3.Config{
			Endpoints: eps, DialTimeout: 5 * time.Second,
			Username: "root", Password: v5RootPass,
		})
		if err == nil {
			_, _ = root.AuthDisable(ctx)
			root.Close()
		}
	})

	// 以 mbr-b（无 keys/* 写权）建客户端。
	mbrB, err := clientv3.New(clientv3.Config{
		Endpoints: eps, DialTimeout: 5 * time.Second,
		Username: "mbr-b", Password: v5PassB,
	})
	if err != nil {
		t.Fatalf("mbr-b 连接失败: %v", err)
	}
	defer mbrB.Close()

	// mbr-b 直写 keys/{key_id}（伪造目录项）→ 必须被 etcd 拒绝。
	keysKey := TestPrefix + "/groups/" + TestGID + "/keys/" + v5KeyID
	forged := `{"version":1,"key_id":"` + v5KeyID + `","key_mode":"shared","state":"ready","mac":"deadbeef"}`
	if _, err := mbrB.Put(ctx, keysKey, forged); err == nil {
		t.Fatalf("无 keys/* 写权的成员直写目录项必须被 etcd 拒绝")
	} else {
		t.Logf("etcd_role 档：mbr-b 直写 keys/%s 被拒：%v", v5KeyID[:8], err)
	}

	// mbr-b 读 keys/* 仍应允许（读者需要验 MAC）。
	if _, err := mbrB.Get(ctx, keysKey); err != nil {
		t.Fatalf("mbr-b 读取 keys/* 应被允许（读者侧 MAC 校验）: %v", err)
	}
}

// TestV5DirectoryMACTamperRejected 读者侧：篡改任一字段 → MAC 校验失败，不回退旧值。
func TestV5DirectoryMACTamperRejected(t *testing.T) {
	eps := etcdEndpoints(t)
	ctx := context.Background()

	// 未开 auth 的普通客户端（V-2 语义已覆盖 auth 场景；本例聚焦 MAC）。
	store, err := NewEtcdControlStore(ctx, eps, TestGID)
	if err != nil {
		t.Fatalf("连接 etcd 失败: %v", err)
	}
	defer store.Close()

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}

	// 组主写入合法目录项（含正确 MAC）。
	dir := KeyDirectory{
		KeyID: v5KeyID, KeyMode: "shared", State: "creating", CreatedBy: TestMemberA,
		Replicas: []KeyReplica{{Member: TestMemberA, Partition: TestPartition, State: "ready"}},
	}
	if _, err := store.CASKeyDirectory(ctx, v5KeyID, 0, 1, "boot-a1", dir); err != nil {
		t.Fatalf("组主写目录失败: %v", err)
	}
	// 读者读取成功（MAC 通过）。
	kd, ver, err := store.GetKeyDirectory(ctx, v5KeyID)
	if err != nil {
		t.Fatalf("合法目录项读取失败: %v", err)
	}
	if ver != 1 || kd.State != "creating" {
		t.Fatalf("目录项异常: ver=%d state=%s", ver, kd.State)
	}

	// 篡改：改 state 但不更新 MAC（保持 JSON 合法，绕过"未知字段"检查）。
	raw, err := store.GetKeyDirectoryRaw(ctx, v5KeyID)
	if err != nil {
		t.Fatalf("读取原始目录项失败: %v", err)
	}
	raw.State = "ready" // 篡改点
	tampered, err := CanonicalJSON(raw)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := store.PutKeyDirectoryRaw(ctx, v5KeyID, tampered); err != nil {
		t.Fatalf("写入篡改值失败: %v", err)
	}

	// 读者必须拒绝，且不得回退到旧值/静默通过。
	if _, _, err := store.GetKeyDirectory(ctx, v5KeyID); !errors.Is(err, ErrDirectoryMACInvalid) {
		t.Fatalf("篡改后读取应返回 ErrDirectoryMACInvalid，实际: %v", err)
	}
	t.Logf("读者侧 MAC 校验拒绝篡改值（state creating→ready），未回退旧值")

	// 追加副本（数组内容篡改）同样必须被拒。
	raw2, _ := store.GetKeyDirectoryRaw(ctx, v5KeyID)
	raw2.Replicas = append(raw2.Replicas, KeyReplica{
		Member: TestMemberB, Partition: TestPartition, State: "ready",
	})
	tampered2, err := CanonicalJSON(raw2)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := store.PutKeyDirectoryRaw(ctx, v5KeyID, tampered2); err != nil {
		t.Fatalf("写入篡改值失败: %v", err)
	}
	if _, _, err := store.GetKeyDirectory(ctx, v5KeyID); !errors.Is(err, ErrDirectoryMACInvalid) {
		t.Fatalf("副本篡改后读取应被拒，实际: %v", err)
	}

	// 恢复：组主走 CAS 正规路径重写（自动重算 MAC），读取应重新通过
	// —— 证明拒绝源于 MAC 校验而非状态机。
	restored := KeyDirectory{
		KeyID: v5KeyID, KeyMode: "shared", State: "ready", CreatedBy: TestMemberA,
		Replicas: []KeyReplica{{Member: TestMemberA, Partition: TestPartition, State: "ready"}},
	}
	if _, err := store.CASKeyDirectory(ctx, v5KeyID, 1, 1, "boot-a1", restored); err != nil {
		t.Fatalf("组主 CAS 重写失败: %v", err)
	}
	kd2, ver2, err := store.GetKeyDirectory(ctx, v5KeyID)
	if err != nil {
		t.Fatalf("修复后读取应通过: %v", err)
	}
	if ver2 != 2 || kd2.State != "ready" {
		t.Fatalf("修复后目录异常: ver=%d state=%s", ver2, kd2.State)
	}
}

// TestV5LeaseTierForgeryImpossible lease 档：持静态写权限的成员可写但无法伪造。
func TestV5LeaseTierForgeryImpossible(t *testing.T) {
	eps := etcdEndpoints(t)
	ctx := context.Background()
	store, err := NewEtcdControlStore(ctx, eps, TestGID)
	if err != nil {
		t.Fatalf("连接 etcd 失败: %v", err)
	}
	defer store.Close()

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	dir := KeyDirectory{
		KeyID: v5KeyID, KeyMode: "shared", State: "creating", CreatedBy: TestMemberA,
		Replicas: []KeyReplica{{Member: TestMemberA, Partition: TestPartition, State: "ready"}},
	}
	if _, err := store.CASKeyDirectory(ctx, v5KeyID, 0, 1, "boot-a1", dir); err != nil {
		t.Fatalf("组主写目录失败: %v", err)
	}

	// lease 档：假设被入侵成员持静态写权限（可直接写 keys/*）。
	// 它没有目录 MAC 密钥（HSM 内不可导出），只能写"格式合法但 MAC 错误"的伪造项。
	forged := dir
	forged.State = "ready"
	forged.Version = 1
	forgedBlob, err := CanonicalJSON(forged) // 无 mac 字段
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := store.PutKeyDirectoryRaw(ctx, v5KeyID, forgedBlob); err != nil {
		t.Fatalf("写入伪造值失败: %v", err)
	}
	// 读者拒绝 → 伪造不可能（只能造成 DoS：读者读不到目录）。
	if _, _, err := store.GetKeyDirectory(ctx, v5KeyID); !errors.Is(err, ErrDirectoryMACInvalid) {
		t.Fatalf("伪造目录项必须被读者 MAC 拒绝，实际: %v", err)
	}
	t.Logf("lease 档：持写权限的成员写入的伪造项被读者 MAC 拒绝（DoS 可能，伪造不可能）")
}
