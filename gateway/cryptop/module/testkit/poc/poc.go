// Package poc 是 P2-3「模块组」的**真机 POC 验证骨架**（独立嵌套 module）。
//
// 定位（本体 §7.3.1 测试矩阵 / 评审报告 §13.3 V-*）：
//
//	V-2  etcd 单主与 fencing：GroupControlStore 语义在真实 etcd v3.5 上的复现；
//	V-3  SoftHSM/厂商 wrap：KeyBackupBackend 的 wrap/unwrap 与 KeyBackupStore 读写契约；
//	V-4  GroupKeyRef 重启解析：持久 CKA_ID 寻址，不依赖 CK_OBJECT_HANDLE；
//	V-5  目录 MAC 与越权写：etcd RBAC 撤销写角色 + 读者侧 MAC 校验。
//
// 与 testkit（内存参考实现）的关系：testkit 锁定语义，poc 证明同一份契约在**真实后端**
// 上成立。两者独立实现，避免"自证自明"。
//
// 边界（重要）：
//   - 未设置对应环境变量时用例自动 Skip——**不得以 mock/内存结果冒充真机证据**
//     （本体 §7.3.1 明令）；
//   - 本包不接入产品链路，不被 cryptopsvc / gateway-core 引用；
//   - 用例通过不等于 S3-b 通过，也不构成生产合规/密评结论；
//   - SoftHSM 无 SM2/SM3/SM4 机制，V-3/V-4 以 AES 验证**机制级**契约，
//     国密机制须在厂商 HSM 上复跑（已在证据包中如实登记）。
package poc

import (
	"os"
	"strings"
	"testing"
)

// 环境变量约定（在具备 etcd + SoftHSM 的主机上设置，见 README.md）：
//
//	P23_POC_ETCD       etcd 客户端端点，逗号分隔（V-2/V-5）
//	P23_POC_P11_MODULE PKCS#11 模块 .so 路径（V-3/V-4）
//	P23_POC_P11_PIN    token PIN
//	P23_POC_P11_LABEL  token label
//	P23_POC_RBAC       设为 1 时执行 etcd auth/RBAC 装配（V-5；会改动集群认证状态）
const (
	EnvEtcd      = "P23_POC_ETCD"
	EnvP11Module = "P23_POC_P11_MODULE"
	EnvP11Pin    = "P23_POC_P11_PIN"
	EnvP11Label  = "P23_POC_P11_LABEL"
	EnvRBAC      = "P23_POC_RBAC"
)

// 测试用组/分区/成员标识（与本体 §6.1 示例一致）。
const (
	TestGID       = "fin-hsm-a"
	TestPartition = "tenant-a"
	TestMemberA   = "dc1-hsm-a"
	TestMemberB   = "dc2-hsm-b"
	TestDCA       = "dc1"
	TestDCB       = "dc2"
	TestPrefix    = "/cryptop"
)

// etcdEndpoints 返回真机 etcd 端点；未配置则 Skip（不产生虚假结论）。
func etcdEndpoints(t *testing.T) []string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(EnvEtcd))
	if v == "" {
		t.Skipf("%s 未设置：跳过真机 etcd POC（§7.3.1 不得以 mock 冒充真机）", EnvEtcd)
	}
	eps := make([]string, 0, 3)
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			eps = append(eps, p)
		}
	}
	if len(eps) == 0 {
		t.Fatalf("%s 为空", EnvEtcd)
	}
	return eps
}

// p11Config 返回 SoftHSM/厂商模块配置；未配置则 Skip。
func p11Config(t *testing.T) (module, pin, label string) {
	t.Helper()
	module = strings.TrimSpace(os.Getenv(EnvP11Module))
	pin = os.Getenv(EnvP11Pin)
	label = strings.TrimSpace(os.Getenv(EnvP11Label))
	if module == "" || label == "" {
		t.Skipf("%s/%s 未设置：跳过真机 PKCS#11 POC（§7.3.1 不得以 mock 冒充真机）", EnvP11Module, EnvP11Label)
	}
	return module, pin, label
}

// rbacEnabled 是否执行 etcd auth/RBAC 装配（默认开启：V-5 需要）。
func rbacEnabled() bool {
	return os.Getenv(EnvRBAC) != "0"
}
