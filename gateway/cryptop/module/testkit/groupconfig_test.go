package testkit

import (
	"strings"
	"testing"
)

// baseConfig 一个合法的生产 shared 配置（对齐 §6.1 示例）。
func baseConfig() GroupConfig {
	return GroupConfig{
		GroupID: "fin-hsm-a", KeyMode: "shared", KeyReplication: "quorum",
		Members: []MemberConfig{
			{ID: "dc1-hsm-a", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1",
				Backend: "sdf", LibPath: "/opt/vendor/lib/libsdf.so", Slot: 0,
				PinRef: "secret://cryptop/dc1-hsm-a/pin", Partition: "tenant-a",
				PartitionPinRef: "secret://cryptop/dc1-hsm-a/partition-pin", DC: "dc1",
				MaxSessions: 16, TimeoutMS: 50, ImplementsBackup: true},
			{ID: "dc2-hsm-a", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1",
				Backend: "sdf", LibPath: "/opt/vendor/lib/libsdf.so", Slot: 0,
				PinRef: "secret://cryptop/dc2-hsm-a/pin", Partition: "tenant-a",
				PartitionPinRef: "secret://cryptop/dc2-hsm-a/partition-pin",
				Endpoint:        "https://hsm-dc2:9000", DC: "dc2",
				MaxSessions: 16, TimeoutMS: 120, ImplementsBackup: true},
		},
		Partitions: []PartitionConfig{
			{Tenant: "tenant-a", Partition: "tenant-a", Members: []string{"dc1-hsm-a", "dc2-hsm-a"}, QuotaSessions: 24},
		},
		Leader: LeaderConfig{Store: "etcd", Endpoints: []string{"https://e1:2379", "https://e2:2379", "https://e3:2379"},
			TLSCARef: "secret://ca", TLSCertRef: "secret://cert", TLSKeyRef: "secret://key",
			BootstrapOwner: "dc1-hsm-a", LeaseTTLMS: 30000},
		Control: ControlConfig{Store: "etcd", DirectoryMACKeyRef: "secret://cryptop/dir-mac",
			DirectoryCacheTTLMS: 15000, DirectoryCacheMaxStale: 30000, DirectoryWriter: "lease"},
		Backup: BackupConfig{Store: "vendor_library", KekID: "backup-kek-v1", Endpoint: "https://backup:8443"},
		Policy: PolicyConfig{Affinity: "partition", DcOrder: []string{"dc1", "dc2"}},
		Failover: FailoverConfig{Mode: "failover", AutoFailoverIntraDC: true,
			StartupMinHealthyPerPartition: 1, AutoSwitchBack: false},
		BootstrapOwner: "dc1-hsm-a",
	}
}

func baseCaps() map[string]Capabilities {
	return map[string]Capabilities{
		"dc1-hsm-a": {Backend: "sdf", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1"},
		"dc2-hsm-a": {Backend: "sdf", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1"},
	}
}

func assertViolation(t *testing.T, c GroupConfig, caps map[string]Capabilities, p Profile, want string) []string {
	t.Helper()
	v := c.Validate(p, caps)
	if len(v) == 0 {
		t.Fatalf("应检出违规（期望包含 %q），实际通过", want)
	}
	found := false
	for _, s := range v {
		if strings.Contains(s, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("违规项未包含 %q，实测: %v", want, v)
	}
	return v
}

func TestValidConfigPasses(t *testing.T) {
	if v := baseConfig().Validate(ProfileProduction, baseCaps()); len(v) != 0 {
		t.Fatalf("合法配置应通过，实际违规: %v", v)
	}
}

func TestRule1GroupAndMembers(t *testing.T) {
	c := baseConfig()
	c.GroupID = "Bad_ID"
	assertViolation(t, c, baseCaps(), ProfileProduction, "规则1")

	c = baseConfig()
	c.Members = c.Members[:1]
	assertViolation(t, c, baseCaps(), ProfileProduction, "规则1")

	c = baseConfig()
	c.Members[1].ImplementsBackup = false
	assertViolation(t, c, baseCaps(), ProfileProduction, "KeyBackupBackend")
}

// TestRule1IsolatedValid isolated + single + backup 空 为合法组合（不得误判）。
func TestRule1IsolatedValid(t *testing.T) {
	c := baseConfig()
	c.KeyMode = "isolated"
	c.KeyReplication = "single"
	c.Backup = BackupConfig{}
	if v := c.Validate(ProfileProduction, baseCaps()); len(v) != 0 {
		t.Fatalf("isolated+single+空 backup 应合法，实际违规: %v", v)
	}
}

func TestRule1IsolatedRejectsBackupAndQuorum(t *testing.T) {
	c := baseConfig()
	c.KeyMode = "isolated"
	c.KeyReplication = "quorum"
	assertViolation(t, c, baseCaps(), ProfileProduction, "key_replication 只能 single")

	c = baseConfig()
	c.KeyMode = "isolated"
	c.KeyReplication = "single"
	assertViolation(t, c, baseCaps(), ProfileProduction, "backup 必须为空")
}

func TestRule2PartitionMappingAndQuota(t *testing.T) {
	// 分区引用的成员分区不一致
	c := baseConfig()
	c.Members[1].Partition = "tenant-b"
	assertViolation(t, c, baseCaps(), ProfileProduction, "规则2")

	// 配额超卖
	c = baseConfig()
	c.Partitions[0].QuotaSessions = 999
	assertViolation(t, c, baseCaps(), ProfileProduction, "配额超卖")

	// 分区为空
	c = baseConfig()
	c.Partitions = nil
	assertViolation(t, c, baseCaps(), ProfileProduction, "partitions 不能为空")

	// 同一成员分配到两个分区
	c = baseConfig()
	c.Partitions = []PartitionConfig{
		{Tenant: "t1", Partition: "tenant-a", Members: []string{"dc1-hsm-a"}},
		{Tenant: "t2", Partition: "tenant-b", Members: []string{"dc1-hsm-a"}},
	}
	assertViolation(t, c, baseCaps(), ProfileProduction, "一成员一分区")
}

func TestRule3ControlStoreMatrix(t *testing.T) {
	c := baseConfig()
	c.Leader.Endpoints = []string{"https://e1:2379", "https://e2:2379"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "≥3 个奇数端点")

	c = baseConfig()
	c.Leader.Store = "k8s_lease"
	c.Control.Store = "etcd"
	assertViolation(t, c, baseCaps(), ProfileProduction, "control.store 必须为 k8s_crd")

	c = baseConfig()
	c.Leader.Store = "memory"
	assertViolation(t, c, baseCaps(), ProfileProduction, "backend=mock")
}

func TestRule4PolicyAndFailover(t *testing.T) {
	c := baseConfig()
	c.Policy.DcOrder = []string{"dc1"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "未覆盖 DC")

	c = baseConfig()
	c.Failover.Mode = "degrade"
	c.Failover.DegradeAck = false
	assertViolation(t, c, baseCaps(), ProfileProduction, "degrade_ack")
}

func TestRule5TimeoutAndAffinity(t *testing.T) {
	c := baseConfig()
	c.Members[1].Endpoint = "https://hsm-dc2:9000"
	c.Members[1].TimeoutMS = 0
	assertViolation(t, c, baseCaps(), ProfileProduction, "timeout_ms 必填")

	c = baseConfig()
	c.Policy.Affinity = "none"
	assertViolation(t, c, baseCaps(), ProfileProduction, "affinity=none")
}

func TestRule6VendorModelFirmware(t *testing.T) {
	c := baseConfig()
	c.Members[1].Model = "hsm-8000"
	assertViolation(t, c, baseCaps(), ProfileProduction, "厂商/型号不一致")

	c = baseConfig()
	c.Members[1].Firmware = "3.1.0"
	assertViolation(t, c, baseCaps(), ProfileProduction, "固件不一致")

	// 能力快照不可探测 -> 生产启动拒
	c = baseConfig()
	caps := baseCaps()
	caps["dc1-hsm-a"] = Capabilities{Backend: "sdf", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "unknown"}
	assertViolation(t, c, caps, ProfileProduction, "firmware 不可探测")

	// 配置与实测不一致
	c = baseConfig()
	caps = baseCaps()
	caps["dc2-hsm-a"] = Capabilities{Backend: "sdf", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "9.9.9"}
	assertViolation(t, c, caps, ProfileProduction, "与实测")

	// 生产禁止 mock
	c = baseConfig()
	c.Members[0].Backend = "mock"
	assertViolation(t, c, baseCaps(), ProfileProduction, "禁止 backend=mock")

	// sm2_uid 覆盖不一致
	c = baseConfig()
	c.SM2UID = "1234567812345678"
	c.MemberSM2UID = map[string]string{"dc2-hsm-a": "8765432187654321"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "sm2_uid")
}

func TestRule6MockAllowedInTest(t *testing.T) {
	c := baseConfig()
	c.Members[0].Backend = "mock"
	c.Members[1].Backend = "mock"
	c.Policy.Affinity = "none"
	if v := c.Validate(ProfileTest, baseCaps()); len(v) != 0 {
		t.Fatalf("测试 profile 下 mock 应允许，实际违规: %v", v)
	}
}

func TestRule7SensitiveAndKEK(t *testing.T) {
	c := baseConfig()
	c.SensitiveLiterals = []string{"pin=123456"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "字面值")

	c = baseConfig()
	c.DataKEKNames = []string{"backup-kek-v1"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "与数据 KEK 同名")

	c = baseConfig()
	c.Members[0].PinRef = "plaintext-pin"
	assertViolation(t, c, baseCaps(), ProfileProduction, "非引用形态")
}

func TestRule8And9And11And12(t *testing.T) {
	c := baseConfig()
	c.LegacyStaticKeys = true
	assertViolation(t, c, baseCaps(), ProfileProduction, "LegacyStaticKeys")

	c = baseConfig()
	c.BootstrapOwner = "not-a-member"
	assertViolation(t, c, baseCaps(), ProfileProduction, "必须是组内成员")

	c = baseConfig()
	c.VendorAdmin = VendorAdmin{Endpoint: "https://hsm-mgmt:8443"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "TLS 三件套")

	c = baseConfig()
	c.VendorAdmin = VendorAdmin{Endpoint: "https://hsm-mgmt:8443", TLSCARef: "secret://ca",
		TLSCertRef: "secret://cert", TLSKeyRef: "secret://key",
		CredentialRef: "secret://cryptop/dc1-hsm-a/pin", Executor: "admin_service"}
	assertViolation(t, c, baseCaps(), ProfileProduction, "不得与成员")

	c = baseConfig()
	c.Control.DirectoryMACKeyRef = ""
	assertViolation(t, c, baseCaps(), ProfileProduction, "directory_mac_key_ref")

	c = baseConfig()
	c.Control.DirectoryCacheTTLMS = 20000 // > 30000/2
	assertViolation(t, c, baseCaps(), ProfileProduction, "directory_cache_ttl_ms")

	c = baseConfig()
	c.Control.DirectoryCacheMaxStale = 5000 // < ttl 15000
	assertViolation(t, c, baseCaps(), ProfileProduction, "directory_cache_max_stale_ms")

	c = baseConfig()
	c.Control.DirectoryWriter = "etcd_role"
	assertViolation(t, c, baseCaps(), ProfileProduction, "etcd auth 管理凭据")
}

// TestValidateReportsAllViolations 一次校验应能同时报出多条违规（便于启动期一次性修复）。
func TestValidateReportsAllViolations(t *testing.T) {
	c := baseConfig()
	c.GroupID = "Bad"
	c.Members = c.Members[:1]
	c.Partitions = nil
	v := c.Validate(ProfileProduction, baseCaps())
	if len(v) < 3 {
		t.Fatalf("应同时报出多条违规，实际仅 %d 条: %v", len(v), v)
	}
}
