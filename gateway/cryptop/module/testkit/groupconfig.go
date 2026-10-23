package testkit

import (
	"fmt"
	"regexp"
	"strings"
)

// 本文件固化《P2--HSM集成》§6.1 的启动校验规则（1-12）为可执行断言（测试基座）。
// 目的：P1-10 / R3-P1-02 —— 让"异构混池、分区错位、配额超卖、timeout 缺省、
// 敏感字面值、配置混配"等在编码期即可被单测拦截，而不是等到备份交叉导入才暴露。

var (
	reGroupID  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	reMemberID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Profile 运行档：production 启用固件/厂商一致性等硬校验。
type Profile string

const (
	ProfileProduction Profile = "production"
	ProfileTest       Profile = "test"
)

// Capabilities 成员能力快照（对齐 §6.2.1，含新增 Firmware 字段）。
type Capabilities struct {
	Backend    string
	Vendor     string
	Model      string
	Firmware   string // 无法探测时为 "unknown"
	Mechanisms []string
}

// MemberConfig / PartitionConfig / GroupConfig 为 §6.1 字段子集（覆盖校验所需字段）。
type MemberConfig struct {
	ID               string
	Vendor           string
	Model            string
	Firmware         string
	Backend          string // sdf|pkcs11|mock
	LibPath          string
	Slot             int
	PinRef           string
	Partition        string
	PartitionPinRef  string
	Endpoint         string
	DC               string
	Weight           int
	MaxSessions      int
	TimeoutMS        int
	ImplementsBackup bool // 是否实现 KeyBackupBackend
}

type PartitionConfig struct {
	Tenant        string
	Partition     string
	Members       []string
	QuotaSessions int
	QuotaQPS      int
}

type VendorAdmin struct {
	Endpoint      string
	CredentialRef string
	TLSCARef      string
	TLSCertRef    string
	TLSKeyRef     string
	Executor      string // admin_service|new_leader|auto
}

type GroupConfig struct {
	GroupID           string
	KeyMode           string // shared|isolated
	KeyReplication    string // single|quorum|all
	Members           []MemberConfig
	Partitions        []PartitionConfig
	Leader            LeaderConfig
	Control           ControlConfig
	Backup            BackupConfig
	VendorAdmin       VendorAdmin
	Policy            PolicyConfig
	Failover          FailoverConfig
	BootstrapOwner    string
	SM2UID            string
	MemberSM2UID      map[string]string // 成员覆盖值
	SensitiveLiterals []string          // 用于模拟"字面值"注入（正常应为空）
	LegacyStaticKeys  bool              // 组模式下设置 LegacyStaticKeys
	DataKEKNames      []string          // 数据 KEK 名，用于 kek_id 冲突校验
}

type LeaderConfig struct {
	Store          string // etcd|k8s_lease|memory
	Endpoints      []string
	TLSCARef       string
	TLSCertRef     string
	TLSKeyRef      string
	BootstrapOwner string
	LeaseTTLMS     int
}

type ControlConfig struct {
	Store                  string // etcd|k8s_crd|memory
	DirectoryMACKeyRef     string
	DirectoryCacheTTLMS    int
	DirectoryCacheMaxStale int
	DirectoryWriter        string // lease|etcd_role
	EtcdAuthCredRef        string
}

type BackupConfig struct {
	Store    string // vendor_library|vendor_clone|mofn
	KekID    string
	Endpoint string
}

type PolicyConfig struct {
	Affinity          string // partition|none
	DcOrder           []string
	AllowLegacyKeyRef bool
	LegacyMember      string
}

type FailoverConfig struct {
	Mode                          string // fail_closed|failover|degrade
	DegradeAck                    bool
	AutoFailoverIntraDC           bool
	StartupMinHealthyPerPartition int
	AutoSwitchBack                bool
}

// Validate 返回全部违规项（空表示通过）。任一违规在启动期都应导致启动拒。
func (c GroupConfig) Validate(p Profile, caps map[string]Capabilities) []string {
	var v []string
	add := func(format string, a ...any) { v = append(v, fmt.Sprintf(format, a...)) }

	// 规则 1：组与成员基本形态
	if !reGroupID.MatchString(c.GroupID) {
		add("规则1: group_id %q 不符合 ^[a-z0-9][a-z0-9-]{2,62}$", c.GroupID)
	}
	if len(c.Members) < 2 {
		add("规则1: 组模式成员数 %d < 2", len(c.Members))
	}
	seen := map[string]bool{}
	for _, m := range c.Members {
		if !reMemberID.MatchString(m.ID) {
			add("规则1: 成员 id %q 不符合命名规则", m.ID)
		}
		if seen[m.ID] {
			add("规则1: 成员 id %q 重复", m.ID)
		}
		seen[m.ID] = true
	}
	switch c.KeyMode {
	case "shared":
		for _, m := range c.Members {
			if !m.ImplementsBackup {
				add("规则1: key_mode=shared 要求所有成员实现 KeyBackupBackend，%s 未实现", m.ID)
			}
		}
		if c.Backup.Store == "" || c.Backup.KekID == "" {
			add("规则1: key_mode=shared 要求 backup 完整（store/kek_id）")
		}
	case "isolated":
		if c.KeyReplication != "" && c.KeyReplication != "single" {
			add("规则1: isolated 模式下 key_replication 只能 single，实测 %s", c.KeyReplication)
		}
		if c.Backup.Store != "" || c.Backup.KekID != "" {
			add("规则1: isolated 模式下 backup 必须为空（避免把备份能力误标为 shared）")
		}
	default:
		add("规则1: key_mode 非法 %q", c.KeyMode)
	}

	// 规则 2：分区映射与配额
	if len(c.Partitions) == 0 {
		add("规则2: partitions 不能为空")
	}
	partSeen := map[string]string{}
	tenantSeen := map[string]bool{}
	memberPart := map[string]string{}
	for _, m := range c.Members {
		memberPart[m.ID] = m.Partition
	}
	for _, pt := range c.Partitions {
		if partSeen[pt.Partition] != "" {
			add("规则2: 分区 %q 重复（一个分区只属一个 tenant）", pt.Partition)
		}
		partSeen[pt.Partition] = pt.Tenant
		if tenantSeen[pt.Tenant] {
			add("规则2: tenant %q 重复", pt.Tenant)
		}
		tenantSeen[pt.Tenant] = true
		total := 0
		for _, mid := range pt.Members {
			mp, ok := memberPart[mid]
			if !ok {
				add("规则2: 分区 %q 引用了不存在的成员 %q", pt.Partition, mid)
				continue
			}
			if mp != pt.Partition {
				add("规则2: 成员 %s 的分区 %q 与本行分区 %q 不一致", mid, mp, pt.Partition)
			}
			for _, m := range c.Members {
				if m.ID == mid {
					total += m.MaxSessions
				}
			}
		}
		if pt.QuotaSessions > total {
			add("规则2: 分区 %q 配额 %d 超过成员 max_sessions 之和 %d（配额超卖）", pt.Partition, pt.QuotaSessions, total)
		}
	}
	// 同一成员不得对应多个 partition
	memberPartCount := map[string]int{}
	for _, pt := range c.Partitions {
		for _, mid := range pt.Members {
			memberPartCount[mid]++
		}
	}
	for mid, n := range memberPartCount {
		if n > 1 {
			add("规则2: 成员 %s 被分配到 %d 个分区（一成员一分区/登录域）", mid, n)
		}
	}

	// 规则 3：控制存储后端矩阵
	switch c.Leader.Store {
	case "etcd":
		if len(c.Leader.Endpoints) < 3 || len(c.Leader.Endpoints)%2 == 0 {
			add("规则3: leader.store=etcd 需 ≥3 个奇数端点，实测 %d", len(c.Leader.Endpoints))
		}
		if c.Leader.TLSCARef == "" || c.Leader.TLSCertRef == "" || c.Leader.TLSKeyRef == "" {
			add("规则3: leader.store=etcd 需 TLS 三件套")
		}
	case "k8s_lease":
		if c.Control.Store != "k8s_crd" {
			add("规则3: k8s_lease 时 control.store 必须为 k8s_crd，实测 %q", c.Control.Store)
		}
	case "memory":
		for _, m := range c.Members {
			if m.Backend != "mock" {
				add("规则3: memory 存储仅允许 backend=mock，%s 为 %s", m.ID, m.Backend)
			}
		}
	default:
		add("规则3: leader.store 非法 %q", c.Leader.Store)
	}

	// 规则 4：策略
	dcSet := map[string]bool{}
	for _, m := range c.Members {
		dcSet[m.DC] = true
	}
	for _, dc := range c.Policy.DcOrder {
		delete(dcSet, dc)
	}
	for dc := range dcSet {
		add("规则4: policy.dc_order 未覆盖 DC %q", dc)
	}
	if c.Failover.Mode == "degrade" && !c.Failover.DegradeAck {
		add("规则4: degrade 模式须 degrade_ack=true")
	}

	// 规则 5：timeout 与 affinity
	for _, m := range c.Members {
		if m.Endpoint != "" && m.TimeoutMS <= 0 {
			add("规则5: 成员 %s 为网络形态（endpoint 非空）时 timeout_ms 必填，不得套用本机 50ms", m.ID)
		}
	}
	if c.Policy.Affinity == "none" {
		for _, m := range c.Members {
			if m.Backend != "mock" {
				add("规则5: affinity=none 仅允许 backend=mock，%s 为 %s", m.ID, m.Backend)
			}
		}
	}

	// 规则 6：厂商/型号/固件一致 + sm2_uid 一致
	if len(c.Members) > 0 {
		base := c.Members[0]
		for _, m := range c.Members[1:] {
			if m.Vendor != base.Vendor || m.Model != base.Model {
				add("规则6: 组内厂商/型号不一致（%s: %s/%s vs %s: %s/%s）",
					base.ID, base.Vendor, base.Model, m.ID, m.Vendor, m.Model)
			}
			if m.Firmware != base.Firmware {
				add("规则6: 组内固件不一致（%s=%s vs %s=%s）", base.ID, base.Firmware, m.ID, m.Firmware)
			}
		}
		for _, m := range c.Members {
			if m.Vendor == "" || m.Model == "" {
				add("规则6: 成员 %s 的 vendor/model 必填", m.ID)
			}
			if p == ProfileProduction {
				if m.Firmware == "" {
					add("规则6: 生产 profile 下成员 %s 的 firmware 必填", m.ID)
					continue
				}
				cap, ok := caps[m.ID]
				if !ok {
					add("规则6: 成员 %s 缺能力快照，无法校验 firmware", m.ID)
					continue
				}
				if cap.Firmware == "" || cap.Firmware == "unknown" {
					add("规则6: 成员 %s 的 firmware 不可探测（unknown），生产启动拒", m.ID)
				} else if cap.Firmware != m.Firmware {
					add("规则6: 成员 %s 的 firmware 配置 %q 与实测 %q 不一致", m.ID, m.Firmware, cap.Firmware)
				}
			}
			if p == ProfileProduction && m.Backend == "mock" {
				add("规则6: 生产 profile 禁止 backend=mock（%s）", m.ID)
			}
		}
	}
	if c.SM2UID != "" {
		for mid, uid := range c.MemberSM2UID {
			if uid != c.SM2UID {
				add("规则6: 成员 %s 的 sm2_uid 覆盖值 %q 与组级 %q 不一致（跨成员验签须禁用）", mid, uid, c.SM2UID)
			}
		}
	}

	// 规则 7：敏感项引用 + KEK 不复用
	badLiterals := []string{"pin=", "password=", "token="}
	for _, s := range c.SensitiveLiterals {
		for _, b := range badLiterals {
			if strings.Contains(strings.ToLower(s), b) {
				add("规则7: 敏感项出现字面值 %q（必须使用 secret:// 或文件引用）", s)
			}
		}
	}
	for _, m := range c.Members {
		if m.PinRef != "" && !strings.HasPrefix(m.PinRef, "secret://") && !strings.HasPrefix(m.PinRef, "file://") {
			add("规则7: 成员 %s 的 pin_ref 非引用形态", m.ID)
		}
	}
	for _, n := range c.DataKEKNames {
		if c.Backup.KekID != "" && n == c.Backup.KekID {
			add("规则7: backup.kek_id %q 与数据 KEK 同名，禁止复用", n)
		}
	}

	// 规则 8：组模式不得与单模块 LegacyStaticKeys 并存
	if c.LegacyStaticKeys {
		add("规则8: 组模式禁止设置 LegacyStaticKeys（与单模块 MODULE_* 互斥）")
	}

	// 规则 9：bootstrap_owner
	if c.BootstrapOwner != "" {
		ok := false
		for _, m := range c.Members {
			if m.ID == c.BootstrapOwner {
				ok = true
			}
		}
		if !ok {
			add("规则9: bootstrap_owner %q 必须是组内成员", c.BootstrapOwner)
		}
	}

	// 规则 11：厂商管理面
	if c.VendorAdmin.Endpoint != "" {
		if c.VendorAdmin.TLSCARef == "" || c.VendorAdmin.TLSCertRef == "" || c.VendorAdmin.TLSKeyRef == "" {
			add("规则11: vendor_admin.endpoint 非空时 TLS 三件套必填")
		}
		if c.VendorAdmin.CredentialRef == "" {
			add("规则11: vendor_admin.credential_ref 必填")
		}
		for _, m := range c.Members {
			if c.VendorAdmin.CredentialRef != "" && c.VendorAdmin.CredentialRef == m.PinRef {
				add("规则11: vendor_admin 凭据不得与成员 %s 的 pin_ref 复用", m.ID)
			}
		}
		if c.VendorAdmin.Executor == "" {
			add("规则11: vendor_admin.executor 不应为空")
		}
	}

	// 规则 12：目录 MAC 密钥与缓存窗口
	if c.Control.DirectoryMACKeyRef == "" {
		add("规则12: control.directory_mac_key_ref 必填（无 MAC 密钥不得成为组主）")
	}
	if c.Leader.LeaseTTLMS > 0 {
		if c.Control.DirectoryCacheTTLMS > c.Leader.LeaseTTLMS/2 {
			add("规则12: directory_cache_ttl_ms %d 超过 lease_ttl_ms/2 = %d",
				c.Control.DirectoryCacheTTLMS, c.Leader.LeaseTTLMS/2)
		}
	}
	if c.Control.DirectoryCacheMaxStale < c.Control.DirectoryCacheTTLMS {
		add("规则12: directory_cache_max_stale_ms %d 小于 ttl %d",
			c.Control.DirectoryCacheMaxStale, c.Control.DirectoryCacheTTLMS)
	}
	if c.Control.DirectoryWriter == "etcd_role" && c.Control.EtcdAuthCredRef == "" {
		add("规则12: directory_writer=etcd_role 时必须配置 etcd auth 管理凭据")
	}
	return v
}
