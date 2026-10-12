package cryptopmodule

// config.go —— §6.4 配置项与校验规则（R-S3-1/2/7/11 等）的落地。
//
// 载体为环境变量（键名与文档键名一一对应，大写）；生产经 Secret/Vault/挂载文件
// 注入引用（R-S3-2：口令只存引用名，绝不落配置字面值/命令行/日志）。

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 环境变量键名（§6.4 配置项的大写形态）。
const (
	EnvBackend               = "MODULE_BACKEND"
	EnvLibPath               = "MODULE_LIB_PATH"
	EnvSlot                  = "MODULE_SLOT"
	EnvBackupLibPath         = "MODULE_BACKUP_LIB_PATH"
	EnvBackupSlot            = "MODULE_BACKUP_SLOT"
	EnvBackupPinRef          = "MODULE_BACKUP_PIN_REF"
	EnvBackupEndpoint        = "MODULE_BACKUP_ENDPOINT"
	EnvBackupTLSCARef        = "MODULE_BACKUP_TLS_CA_REF"
	EnvBackupTLSCertRef      = "MODULE_BACKUP_TLS_CERT_REF"
	EnvPinRef                = "MODULE_PIN_REF"
	EnvKeyPrefix             = "MODULE_KEY_PREFIX"
	EnvPartition             = "MODULE_PARTITION"
	EnvPartitionPinRef       = "MODULE_PARTITION_PIN_REF"
	EnvSM2UID                = "MODULE_SM2_UID"
	EnvMaxSessions           = "MODULE_MAX_SESSIONS"
	EnvSessionQueueSize      = "MODULE_SESSION_QUEUE_SIZE"
	EnvHealthInterval        = "MODULE_HEALTH_INTERVAL"
	EnvHealthFailCount       = "MODULE_HEALTH_FAIL_COUNT"
	EnvFailoverMode          = "MODULE_FAILOVER_MODE"
	EnvFailoverAutoSwitchBack = "MODULE_FAILOVER_AUTO_SWITCH_BACK"
	EnvSwitchBackCooldown    = "MODULE_SWITCH_BACK_COOLDOWN"
	EnvTimeoutMS             = "MODULE_TIMEOUT_MS"
	EnvRequiredMechanisms    = "MODULE_REQUIRED_MECHANISMS"
	EnvDegradeAck            = "MODULE_DEGRADE_ACK"
)

// 缺省值（§6.4 配置表）。
const (
	defaultSM2UID           = "1234567812345678" // 与 sm-software 档 sm.go:45 一致（保跨档交叉验签）
	defaultKeyPrefix        = "otpmask/"
	defaultMaxSessions      = 16
	defaultSessionQueueSize = 64
	defaultHealthInterval   = 10 * time.Second
	defaultHealthFailCount  = 3
	defaultFailoverMode     = "fail_closed"
	defaultTimeoutMS        = 50
)

// 故障切换模式（module_failover_mode 取值）。
const (
	FailoverFailClosed = "fail_closed" // 默认：不可用即拒，绝不静默降级（C-3/D-6）
	FailoverFailover   = "failover"    // 主备模块切换
	FailoverDegrade    = "degrade"     // 显式降级到 sm-software（须 module_degrade_ack=true）
)

// Config §6.4 配置项全集（env 载体）。
type Config struct {
	Backend string // module_backend：sdf|pkcs11|mock（mock 仅功能验证）
	LibPath string // module_lib_path：厂商 .so 绝对路径
	Slot    int    // module_slot：PKCS#11 槽位

	BackupLibPath  string // module_backup_lib_path（failover 本机形态必填）
	BackupSlot     int    // module_backup_slot
	BackupPinRef   string // module_backup_pin_ref
	BackupEndpoint string // module_backup_endpoint（failover 网络形态必填）
	BackupTLSCARef   string // module_backup_tls_ca_ref
	BackupTLSCertRef string // module_backup_tls_cert_ref

	PinRef string // module_pin_ref：登录口令引用名（非字面值；R-S3-2）

	KeyPrefix       string // module_key_prefix：模块内对象名前缀（仅命名，非访问控制）
	Partition       string // module_partition：多租户强制隔离分区（R-S3-8）
	PartitionPinRef string // module_partition_pin_ref

	SM2UID string // module_sm2_uid

	MaxSessions      int // module_max_sessions
	SessionQueueSize int // module_session_queue_size

	HealthInterval  time.Duration // module_health_interval
	HealthFailCount int           // module_health_fail_count

	FailoverMode          string // module_failover_mode
	FailoverAutoSwitchBack bool   // module_failover_auto_switch_back
	SwitchBackCooldown    time.Duration

	TimeoutMS int // module_timeout_ms（按访问形态分别配置，R2-07）

	RequiredMechanisms []string // module_required_mechanisms（R-S3-11）
	DegradeAck         bool     // module_degrade_ack（degrade 模式显式确认，R-S3-3）
}

// DefaultConfig 返回缺省配置（未含厂商特定项；LibPath/PinRef 等由环境注入）。
func DefaultConfig() *Config {
	return &Config{
		Backend:            BackendSDF,
		Slot:               0,
		KeyPrefix:          defaultKeyPrefix,
		SM2UID:             defaultSM2UID,
		MaxSessions:        defaultMaxSessions,
		SessionQueueSize:   defaultSessionQueueSize,
		HealthInterval:     defaultHealthInterval,
		HealthFailCount:    defaultHealthFailCount,
		FailoverMode:       defaultFailoverMode,
		TimeoutMS:          defaultTimeoutMS,
		RequiredMechanisms: DefaultRequiredMechanisms(),
	}
}

// LoadConfig 从环境变量加载配置（未设置的键取缺省值）。
func LoadConfig() *Config {
	cfg := DefaultConfig()
	if v := os.Getenv(EnvBackend); v != "" {
		cfg.Backend = v
	}
	cfg.LibPath = os.Getenv(EnvLibPath)
	if v := os.Getenv(EnvSlot); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Slot = n
		}
	}
	cfg.BackupLibPath = os.Getenv(EnvBackupLibPath)
	if v := os.Getenv(EnvBackupSlot); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.BackupSlot = n
		}
	}
	cfg.BackupPinRef = os.Getenv(EnvBackupPinRef)
	cfg.BackupEndpoint = os.Getenv(EnvBackupEndpoint)
	cfg.BackupTLSCARef = os.Getenv(EnvBackupTLSCARef)
	cfg.BackupTLSCertRef = os.Getenv(EnvBackupTLSCertRef)
	cfg.PinRef = os.Getenv(EnvPinRef)
	if v := os.Getenv(EnvKeyPrefix); v != "" {
		cfg.KeyPrefix = v
	}
	cfg.Partition = os.Getenv(EnvPartition)
	cfg.PartitionPinRef = os.Getenv(EnvPartitionPinRef)
	if v := os.Getenv(EnvSM2UID); v != "" {
		cfg.SM2UID = v
	}
	if v := os.Getenv(EnvMaxSessions); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxSessions = n
		}
	}
	if v := os.Getenv(EnvSessionQueueSize); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.SessionQueueSize = n
		}
	}
	if v := os.Getenv(EnvHealthInterval); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.HealthInterval = d
		}
	}
	if v := os.Getenv(EnvHealthFailCount); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			cfg.HealthFailCount = n
		}
	}
	if v := os.Getenv(EnvFailoverMode); v != "" {
		cfg.FailoverMode = v
	}
	cfg.FailoverAutoSwitchBack = os.Getenv(EnvFailoverAutoSwitchBack) == "true"
	if v := os.Getenv(EnvSwitchBackCooldown); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			cfg.SwitchBackCooldown = d
		}
	}
	if v := os.Getenv(EnvTimeoutMS); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TimeoutMS = n
		}
	}
	if v := os.Getenv(EnvRequiredMechanisms); v != "" {
		parts := strings.Split(v, ",")
		mechs := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				mechs = append(mechs, p)
			}
		}
		if len(mechs) > 0 {
			cfg.RequiredMechanisms = mechs
		}
	}
	cfg.DegradeAck = os.Getenv(EnvDegradeAck) == "true"
	return cfg
}

// Validate 配置校验（§6.4 校验规则；返回首个违规的明确错误）。
//
// 覆盖：R-S3-1（sdf/pkcs11 库路径必填且存在）、R-S3-2（口令引用名必填）、
// R-S3-7（failover 备模块配置）、R-S3-11（机制名合法）、R-S3-3（degrade 显式确认）、
// 以及数值域校验。mock 后端跳过厂商项校验（功能验证档）。
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config: nil")
	}
	if !IsKnownBackend(c.Backend) {
		return fmt.Errorf("module_backend=%q 非法（sdf|pkcs11|mock）", c.Backend)
	}
	// 机制名合法性（R-S3-11 的静态部分）。
	for _, m := range c.RequiredMechanisms {
		if !IsKnownMechanism(m) {
			return fmt.Errorf("module_required_mechanisms 含未知机制 %q", m)
		}
	}
	// 数值域。
	if c.MaxSessions <= 0 {
		return fmt.Errorf("module_max_sessions=%d 须 > 0", c.MaxSessions)
	}
	if c.SessionQueueSize < 0 {
		return fmt.Errorf("module_session_queue_size=%d 须 ≥ 0", c.SessionQueueSize)
	}
	if c.HealthInterval <= 0 {
		return fmt.Errorf("module_health_interval=%v 须 > 0", c.HealthInterval)
	}
	if c.HealthFailCount < 1 {
		return fmt.Errorf("module_health_fail_count=%d 须 ≥ 1", c.HealthFailCount)
	}
	if c.TimeoutMS <= 0 {
		return fmt.Errorf("module_timeout_ms=%d 须 > 0", c.TimeoutMS)
	}
	if c.SM2UID == "" {
		return fmt.Errorf("module_sm2_uid 不能为空（GM2-06）")
	}
	// 故障切换模式（R-S3-3：degrade 须显式确认）。
	switch c.FailoverMode {
	case FailoverFailClosed, FailoverFailover, FailoverDegrade:
	default:
		return fmt.Errorf("module_failover_mode=%q 非法（fail_closed|failover|degrade）", c.FailoverMode)
	}
	if c.FailoverMode == FailoverDegrade && !c.DegradeAck {
		return fmt.Errorf("module_failover_mode=degrade 须同时置 module_degrade_ack=true（R-S3-3 显式确认）")
	}
	// mock 后端到此为止（功能验证档，无厂商项）。
	if c.Backend == BackendMock {
		return nil
	}
	// ---- 以下仅生产后端（sdf/pkcs11）----
	// R-S3-1：库路径必填且可加载。
	if c.LibPath == "" {
		return fmt.Errorf("module_lib_path 必填（backend=%s，R-S3-1）", c.Backend)
	}
	if _, err := os.Stat(c.LibPath); err != nil {
		return fmt.Errorf("module_lib_path=%q 不可访问（R-S3-1）: %w", c.LibPath, err)
	}
	// R-S3-2：口令仅存引用名。
	if strings.TrimSpace(c.PinRef) == "" {
		return fmt.Errorf("module_pin_ref 必填（登录口令引用名，R-S3-2；禁止口令字面值）")
	}
	// R-S3-7：failover 档备模块配置（本机形态 = 库/槽位/口令；网络形态 = 端点 + mTLS）。
	if c.FailoverMode == FailoverFailover {
		localOK := c.BackupLibPath != "" && c.BackupPinRef != ""
		networkOK := c.BackupEndpoint != "" && c.BackupTLSCARef != "" && c.BackupTLSCertRef != ""
		if !localOK && !networkOK {
			return fmt.Errorf("module_failover_mode=failover 须配置备模块（本机：backup_lib_path+backup_pin_ref；网络：backup_endpoint+TLS CA/Cert，R-S3-7）")
		}
	}
	// 多租户共享模块：分区口令引用（R-S3-8 相关；分区标识非空时口令引用必填）。
	if c.Partition != "" && strings.TrimSpace(c.PartitionPinRef) == "" {
		return fmt.Errorf("module_partition 非空时 module_partition_pin_ref 必填（R-S3-8）")
	}
	return nil
}

// CheckCapabilities R-S3-11：模块实际能力须覆盖 RequiredMechanisms 全部项。
func CheckCapabilities(caps Capabilities, required []string) error {
	if miss := MissingMechanisms(caps, required); len(miss) > 0 {
		return fmt.Errorf("%w: 缺失 %v（R-S3-11）", ErrMechanismMissing, miss)
	}
	return nil
}
