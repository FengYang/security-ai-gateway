package cryptopmodule

// config_test.go —— §6.4 配置校验规则测试（R-S3-1/2/3/7/8/11 + 数值域）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 造一个真实存在的文件充当厂商 .so（R-S3-1 的存在性校验）。
func fakeLib(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "libmock.so")
	if err := os.WriteFile(p, []byte("not-a-real-so"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Backend != BackendSDF || cfg.MaxSessions != 16 || cfg.SessionQueueSize != 64 {
		t.Fatalf("缺省值与 §6.4 不符: %+v", cfg)
	}
	if cfg.HealthInterval != 10*time.Second || cfg.HealthFailCount != 3 || cfg.TimeoutMS != 50 {
		t.Fatalf("缺省值（健康/超时）与 §6.4 不符: %+v", cfg)
	}
	if len(cfg.RequiredMechanisms) != 6 || cfg.SM2UID != "1234567812345678" {
		t.Fatalf("缺省机制/UID 与 §6.4 不符: %+v", cfg)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("sdf 后端缺 LibPath/PinRef 应校验失败（R-S3-1/2）")
	}
}

func TestConfigValidateRules(t *testing.T) {
	lib := fakeLib(t)
	base := func() *Config {
		return &Config{
			Backend: BackendSDF, LibPath: lib, PinRef: "hsm-pin",
			SM2UID: "1234567812345678", MaxSessions: 16, SessionQueueSize: 64,
			HealthInterval: 10 * time.Second, HealthFailCount: 3, FailoverMode: FailoverFailClosed,
			TimeoutMS: 50, RequiredMechanisms: DefaultRequiredMechanisms(),
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("合法配置应通过: %v", err)
	}

	cases := []struct {
		name  string
		mut   func(*Config)
		want  string // 错误信息须包含的子串
	}{
		{"backend 非法", func(c *Config) { c.Backend = "xxx" }, "module_backend"},
		{"R-S3-1 库缺失", func(c *Config) { c.LibPath = "" }, "module_lib_path"},
		{"R-S3-1 库不可访问", func(c *Config) { c.LibPath = filepath.Join(t.TempDir(), "nope.so") }, "不可访问"},
		{"R-S3-2 口令引用缺失", func(c *Config) { c.PinRef = "  " }, "module_pin_ref"},
		{"R-S3-7 failover 无备模块", func(c *Config) { c.FailoverMode = FailoverFailover }, "备模块"},
		{"R-S3-3 degrade 未确认", func(c *Config) { c.FailoverMode = FailoverDegrade }, "module_degrade_ack"},
		{"R-S3-11 未知机制", func(c *Config) { c.RequiredMechanisms = []string{"sm9"} }, "未知机制"},
		{"max_sessions=0", func(c *Config) { c.MaxSessions = 0 }, "module_max_sessions"},
		{"queue 负", func(c *Config) { c.SessionQueueSize = -1 }, "module_session_queue_size"},
		{"health_interval=0", func(c *Config) { c.HealthInterval = 0 }, "module_health_interval"},
		{"fail_count=0", func(c *Config) { c.HealthFailCount = 0 }, "module_health_fail_count"},
		{"timeout=0", func(c *Config) { c.TimeoutMS = 0 }, "module_timeout_ms"},
		{"UID 空", func(c *Config) { c.SM2UID = "" }, "module_sm2_uid"},
		{"failover_mode 非法", func(c *Config) { c.FailoverMode = "magic" }, "module_failover_mode"},
		{"R-S3-8 分区无口令", func(c *Config) { c.Partition = "t1" }, "module_partition_pin_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mut(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("应校验失败")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息 %q 应包含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestConfigValidateFailoverNetworkForm(t *testing.T) {
	lib := fakeLib(t)
	c := &Config{
		Backend: BackendSDF, LibPath: lib, PinRef: "pin",
		SM2UID: "1234567812345678", MaxSessions: 4, SessionQueueSize: 8,
		HealthInterval: time.Second, HealthFailCount: 2,
		FailoverMode:  FailoverFailover,
		BackupEndpoint: "10.0.0.9:8443", BackupTLSCARef: "ca", BackupTLSCertRef: "cert",
		TimeoutMS: 200, RequiredMechanisms: DefaultRequiredMechanisms(),
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("网络形态备模块（端点+mTLS）应通过 R-S3-7: %v", err)
	}
}

func TestConfigMockSkipsVendorChecks(t *testing.T) {
	c := DefaultConfig()
	c.Backend = BackendMock
	c.LibPath = "" // mock 无厂商库
	c.PinRef = ""  // mock 无口令
	if err := c.Validate(); err != nil {
		t.Fatalf("mock 后端应跳过厂商项校验: %v", err)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv(EnvBackend, BackendMock)
	t.Setenv(EnvMaxSessions, "8")
	t.Setenv(EnvSessionQueueSize, "0")
	t.Setenv(EnvHealthInterval, "5s")
	t.Setenv(EnvHealthFailCount, "5")
	t.Setenv(EnvTimeoutMS, "200")
	t.Setenv(EnvFailoverMode, FailoverFailover)
	t.Setenv(EnvFailoverAutoSwitchBack, "true")
	t.Setenv(EnvDegradeAck, "false")
	t.Setenv(EnvRequiredMechanisms, "sm3, rand ,")
	t.Setenv(EnvSM2UID, "1122334455667788")
	cfg := LoadConfig()
	if cfg.Backend != BackendMock || cfg.MaxSessions != 8 || cfg.SessionQueueSize != 0 {
		t.Fatalf("env 加载失败: %+v", cfg)
	}
	if cfg.HealthInterval.Seconds() != 5 || cfg.HealthFailCount != 5 || cfg.TimeoutMS != 200 {
		t.Fatalf("env 数值加载失败: %+v", cfg)
	}
	if !cfg.FailoverAutoSwitchBack || cfg.FailoverMode != FailoverFailover {
		t.Fatalf("env 开关/模式加载失败: %+v", cfg)
	}
	if len(cfg.RequiredMechanisms) != 2 || cfg.RequiredMechanisms[0] != "sm3" || cfg.RequiredMechanisms[1] != "rand" {
		t.Fatalf("机制列表解析（去空/去空白）失败: %v", cfg.RequiredMechanisms)
	}
	if cfg.SM2UID != "1122334455667788" {
		t.Fatalf("UID 加载失败: %q", cfg.SM2UID)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("mock 配置应通过: %v", err)
	}
}

func TestCheckCapabilities(t *testing.T) {
	caps := Capabilities{Mechanisms: []string{MechSM3, MechRand}}
	if err := CheckCapabilities(caps, []string{MechSM3}); err != nil {
		t.Fatalf("全覆盖应通过: %v", err)
	}
	err := CheckCapabilities(caps, []string{MechSM3, MechSM4GCM})
	if err == nil {
		t.Fatal("缺失机制应失败（R-S3-11）")
	}
	if !strings.Contains(err.Error(), "sm4-gcm") {
		t.Fatalf("错误应列出缺失机制: %v", err)
	}
}
