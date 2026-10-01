package billing

import (
	"os"
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
