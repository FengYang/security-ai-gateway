package billing

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ---------- 配置校验单元测试（R-1 ~ R-34） ----------

func TestConfig_DefaultDisabled(t *testing.T) {
	// R-1: BILLING_ENABLED 未设置时配置无效
	os.Unsetenv(envPrefix + "ENABLED")
	cfg, err := LoadBillingConfig()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg.Enabled {
		t.Error("expected enabled=false by default")
	}
}

func TestConfig_ValidMinimal(t *testing.T) {
	// 最小合法配置
	setEnvs(t, map[string]string{
		"ENABLED":                    "true",
		"STORE_DRIVER":               "sqlite",
		"STORE_DSN":                  ":memory:",
		"SOURCE_TEE_URL":             "http://127.0.0.1:19090",
		"SOURCE_ADMIN_TOKEN_REF":     "env:TEE_TOKEN",
		"SOURCE_SYNC_MODE":           "pull",
		"SOURCE_PUSH_ENABLED":        "false",
		"SECRETS_EVENTS_SECRET_REF":  "env:EVENTS_SECRET",
		"SOURCE_PUSH_SECRET_REF":     "env:UNUSED",
	})
	cfg, err := LoadBillingConfig()
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true")
	}
	if cfg.Store.DSN != ":memory:" {
		t.Errorf("DSN = %q, want :memory:", cfg.Store.DSN)
	}
}

func TestConfig_R2_InvalidDriver(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"STORE_DRIVER", "mysql")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-2: expected error for invalid driver")
	}
}

func TestConfig_R4_InvalidTeeURL(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"SOURCE_TEE_URL", "ftp://bad")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-4: expected error for non-http URL")
	}
}

func TestConfig_R5_InvalidTokenRef(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"SOURCE_ADMIN_TOKEN_REF", "plaintext-token")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-5: expected error for invalid token ref")
	}
}

func TestConfig_R7_LookbackSmallerThanInterval(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"SOURCE_PULL_INTERVAL", "5m")
	os.Setenv(envPrefix+"SOURCE_PULL_LOOKBACK", "1m")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-7: expected error for lookback < interval")
	}
}

func TestConfig_R9_PushEnabledNoSecret(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"SOURCE_PUSH_ENABLED", "true")
	os.Setenv(envPrefix+"SOURCE_PUSH_SECRET_REF", "")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-9: expected error for push enabled without secret ref")
	}
}

func TestConfig_R16_AccumulateThenRoundFalse(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"RATING_ACCUMULATE_THEN_ROUND", "false")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-16: expected error for accumulate_then_round=false")
	}
}

func TestConfig_R30_InvalidSyncMode(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"SOURCE_SYNC_MODE", "both")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-30: expected error for invalid sync_mode")
	}
}

func TestConfig_R33_SpikeCriticalBelowWarning(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"ANOMALY_DAILY_SPIKE_RATIO", "5")
	os.Setenv(envPrefix+"ANOMALY_SPIKE_CRITICAL_RATIO", "2")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-33: expected error for spike_critical < daily_spike")
	}
}

func TestConfig_R27_EventsSecretSameAsPush(t *testing.T) {
	setEnvs(t, baseEnvs())
	os.Setenv(envPrefix+"SOURCE_PUSH_ENABLED", "true")
	os.Setenv(envPrefix+"SOURCE_PUSH_SECRET_REF", "env:SHARED_SECRET")
	os.Setenv(envPrefix+"SECRETS_EVENTS_SECRET_REF", "env:SHARED_SECRET")
	_, err := LoadBillingConfig()
	if err == nil {
		t.Error("R-27: expected error for events secret same as push secret")
	}
}

// TestConfig_AllRulesReject 逐条非法拒绝（§10.1：R-1..R-34）。
//
// 覆盖：对每条**可拒绝**规则构造一处非法输入，断言 (a) 拒加载、(b) 错误信息含规则号。
// 说明：R-1（enabled=false 隔离）由 TestBillingIsolationDisabledWhenFeatureOff /
// TestRenderMetrics_EmptyWhenDisabled 覆盖；R-8 与 R-9 同条件（push_enabled 无密钥）；
// R-14 由 TestLoadPriceTable_MissingVersion 覆盖；R-23/R-31 为 bool（无非法面，仅记录）；
// R-29 由 TestValidatePlanPricing_R29 覆盖（属套餐 upsert 交叉约束，非本表 config 段）；
// R-3 与 R-4（空值）经 env 不可达（空 = 回退默认），由 TestValidateConfig_DirectStruct 覆盖。
func TestConfig_AllRulesReject(t *testing.T) {
	cases := []struct {
		name string
		rule string
		set  map[string]string
	}{
		{"R2 非法 driver", "R-2", map[string]string{"STORE_DRIVER": "mysql"}},
		{"R4 非 http(s) URL", "R-4", map[string]string{"SOURCE_TEE_URL": "ftp://bad"}},
		{"R5 内联明文 token", "R-5", map[string]string{"SOURCE_ADMIN_TOKEN_REF": "plaintext"}},
		{"R6 pull_interval 过小", "R-6", map[string]string{"SOURCE_PULL_INTERVAL": "5s"}},
		{"R7 lookback < interval", "R-7", map[string]string{"SOURCE_PULL_INTERVAL": "5m", "SOURCE_PULL_LOOKBACK": "1m"}},
		{"R7 lookback > 7d", "R-7", map[string]string{"SOURCE_PULL_LOOKBACK": "192h"}},
		{"R9 push 无密钥", "R-9", map[string]string{"SOURCE_PUSH_ENABLED": "true", "SOURCE_PUSH_SECRET_REF": ""}},
		{"R10 非 UTC+8 时区", "R-10", map[string]string{"PERIOD_TIMEZONE": "UTC"}},
		{"R11 daily_close_at 早于 00:05", "R-11", map[string]string{"PERIOD_DAILY_CLOSE_AT": "00:00"}},
		{"R11 daily_close_at 非法格式", "R-11", map[string]string{"PERIOD_DAILY_CLOSE_AT": "25:99"}},
		{"R12 monthly_close_day 越界", "R-12", map[string]string{"PERIOD_MONTHLY_CLOSE_DAY": "4"}},
		{"R13 monthly_close_at 非法格式", "R-13", map[string]string{"PERIOD_MONTHLY_CLOSE_AT": "24:00"}},
		{"R15 非法 rounding", "R-15", map[string]string{"RATING_ROUNDING": "banker"}},
		{"R16 accumulate_then_round=false", "R-16", map[string]string{"RATING_ACCUMULATE_THEN_ROUND": "false"}},
		{"R17 tier_mode 非 progressive", "R-17", map[string]string{"RATING_TIER_MODE": "flat"}},
		{"R18 retry_attribution 非 platform", "R-18", map[string]string{"RATING_RETRY_ATTRIBUTION": "user"}},
		{"R19 daily_spike_ratio 过小", "R-19", map[string]string{"ANOMALY_DAILY_SPIKE_RATIO": "1.0"}},
		{"R20 reconcile_alert_ratio 越界", "R-20", map[string]string{"ANOMALY_RECONCILE_ALERT_RATIO": "1.5"}},
		{"R21 quota_warn_ratio 过小", "R-21", map[string]string{"ANOMALY_QUOTA_WARN_RATIO": "0.01"}},
		{"R22 listener 非 admin", "R-22", map[string]string{"API_LISTENER": "public"}},
		{"R24 anomaly_scan_interval 过小", "R-24", map[string]string{"SCHEDULE_ANOMALY_SCAN_INTERVAL": "30s"}},
		{"R25 verify_interval 过小", "R-25", map[string]string{"SCHEDULE_VERIFY_INTERVAL": "5m"}},
		{"R26 quota_scan_interval 过大", "R-26", map[string]string{"SCHEDULE_QUOTA_SCAN_INTERVAL": "2h"}},
		{"R27 events 密钥同 push", "R-27", map[string]string{"SOURCE_PUSH_ENABLED": "true", "SOURCE_PUSH_SECRET_REF": "env:X", "SECRETS_EVENTS_SECRET_REF": "env:X"}},
		{"R28 price_public_url 非 https", "R-28", map[string]string{"API_PRICE_PUBLIC_URL": "http://x/y"}},
		{"R30 非法 sync_mode", "R-30", map[string]string{"SOURCE_SYNC_MODE": "both"}},
		{"R32 expiry_scan_interval 过小", "R-32", map[string]string{"SCHEDULE_EXPIRY_SCAN_INTERVAL": "30s"}},
		{"R33 spike_critical < daily_spike", "R-33", map[string]string{"ANOMALY_DAILY_SPIKE_RATIO": "5", "ANOMALY_SPIKE_CRITICAL_RATIO": "2"}},
		{"R34 verify_assoc_interval 过小", "R-34", map[string]string{"SCHEDULE_VERIFY_ASSOC_INTERVAL": "5m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := baseEnvs()
			for k, v := range tc.set {
				env[k] = v
			}
			setEnvs(t, env)
			_, err := LoadBillingConfig()
			if err == nil {
				t.Fatalf("%s: 期望拒绝，实际通过加载", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.rule) {
				t.Errorf("%s: 错误信息未含规则号（可能是其它规则先触发）: %v", tc.rule, err)
			}
		})
	}
}

// TestValidateConfig_DirectStruct 覆盖经 env 不可达的规则（空值 = 回退默认）：
// R-3（sqlite 空 dsn）与 R-4（空 tee_url / 非 http(s)）。直接构造 BillingConfig 调 validateConfig。
func TestValidateConfig_DirectStruct(t *testing.T) {
	valid := func() *BillingConfig {
		return &BillingConfig{
			Enabled: true,
			Store:   StoreConfig{Driver: "sqlite", DSN: ":memory:"},
			Source: SourceConfig{
				TEEURL: "http://127.0.0.1:19090", AdminTokenRef: "env:T", SyncMode: SyncModePull,
				PullInterval: time.Minute, PullLookback: time.Hour, PushSecretRef: "env:P",
			},
			Period: PeriodConfig{Timezone: "UTC+8", DailyCloseAt: "02:10", MonthlyCloseDay: 1, MonthlyCloseAt: "03:10"},
			Rating: RatingConfig{
				Rounding: "half_up", AccumulateThenRound: true,
				TierMode: "progressive", RetryAttribution: "platform",
			},
			Anomaly: AnomalyConfig{
				DailySpikeRatio: 3, ReconcileAlertRatio: 0.001, QuotaWarnRatio: 0.2, SpikeCriticalRatio: 10,
			},
			API: APIConfig{Listener: "admin"},
			Schedule: ScheduleConfig{
				AnomalyScanInterval: 5 * time.Minute, VerifyInterval: time.Hour,
				QuotaScanInterval: 5 * time.Minute, ExpiryScanInterval: 6 * time.Hour,
				VerifyAssocInterval: 24 * time.Hour,
			},
			Secrets: SecretsConfig{EventsSecretRef: "env:E"},
		}
	}
	if err := validateConfig(valid()); err != nil {
		t.Fatalf("基线配置应合法，实际被拒：%v", err)
	}
	cases := []struct {
		name string
		rule string
		mut  func(*BillingConfig)
	}{
		{"R3 sqlite 空 dsn", "R-3", func(c *BillingConfig) { c.Store.Driver = "sqlite"; c.Store.DSN = "" }},
		{"R4 空 tee_url", "R-4", func(c *BillingConfig) { c.Source.TEEURL = "" }},
		{"R4 非 http(s)", "R-4", func(c *BillingConfig) { c.Source.TEEURL = "ftp://bad" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mut(c)
			err := validateConfig(c)
			if err == nil {
				t.Fatalf("%s: 期望拒绝，实际通过", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.rule) {
				t.Errorf("%s: 错误信息未含规则号: %v", tc.rule, err)
			}
		})
	}
}

// ---------- helpers ----------

func baseEnvs() map[string]string {
	return map[string]string{
		"ENABLED":                    "true",
		"STORE_DRIVER":               "sqlite",
		"STORE_DSN":                  ":memory:",
		"SOURCE_TEE_URL":             "http://127.0.0.1:19090",
		"SOURCE_ADMIN_TOKEN_REF":     "env:TEE_TOKEN",
		"SOURCE_SYNC_MODE":           "pull",
		"SOURCE_PUSH_ENABLED":        "false",
		"SOURCE_PUSH_SECRET_REF":     "env:PUSH_SECRET",
		"SECRETS_EVENTS_SECRET_REF":  "env:EVENTS_SECRET",
	}
}

func setEnvs(t *testing.T, m map[string]string) {
	t.Helper()
	// 先清掉所有 BILLING_ 前缀环境变量
	for _, e := range os.Environ() {
		if len(e) >= len(envPrefix) && e[:len(envPrefix)] == envPrefix {
			idx := len(envPrefix)
			for idx < len(e) && e[idx] != '=' {
				idx++
			}
			if idx < len(e) {
				os.Unsetenv(envPrefix + e[len(envPrefix):idx])
			}
		}
	}
	for k, v := range m {
		os.Setenv(envPrefix+k, v)
	}
	t.Cleanup(func() {
		for k := range m {
			os.Unsetenv(envPrefix + k)
		}
	})
}

// 确保 getDurationEnv 正确解析
func TestGetDurationEnv(t *testing.T) {
	os.Setenv("TEST_DUR", "5m")
	defer os.Unsetenv("TEST_DUR")
	d := getDurationEnv("TEST_DUR", time.Minute)
	if d != 5*time.Minute {
		t.Errorf("duration = %v, want 5m", d)
	}
}
