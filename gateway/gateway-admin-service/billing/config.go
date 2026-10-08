package billing

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------- 配置结构（§4.2） ----------

// BillingConfig 计费子系统配置（从环境变量加载，对齐 admin-service 现有风格）。
type BillingConfig struct {
	Enabled  bool
	Store    StoreConfig
	Source   SourceConfig
	Period   PeriodConfig
	Rating   RatingConfig
	Anomaly  AnomalyConfig
	Display  DisplayConfig
	Schedule ScheduleConfig
	Secrets  SecretsConfig
	API      APIConfig
}

type StoreConfig struct {
	Driver string // sqlite | postgres
	DSN    string
	WAL    bool
}

type SourceConfig struct {
	TEEURL        string
	AdminTokenRef string // env:NAME | file:PATH
	SyncMode      string // pull | push（单写者，R-30）
	PullInterval  time.Duration
	PullLookback  time.Duration
	PushEnabled   bool
	PushSecretRef string
}

type PeriodConfig struct {
	Timezone        string
	DailyCloseAt    string // "HH:MM"
	MonthlyCloseDay int
	MonthlyCloseAt  string // "HH:MM"
}

type RatingConfig struct {
	PriceTable          string // 配置文件路径
	Rounding            string // half_up | floor
	AccumulateThenRound bool
	TierMode            string // progressive
	RetryAttribution    string // platform
}

type AnomalyConfig struct {
	DailySpikeRatio     float64
	ReconcileAlertRatio float64
	QuotaWarnRatio      float64
	AutoThrottle        bool
	SpikeCriticalRatio  float64
}

type DisplayConfig struct {
	AmountDisplay bool
}

type ScheduleConfig struct {
	// Enabled 是否启动后台调度器（S-8 缺口扫描等；默认 true）。
	// false = 仅提供 HTTP 手动端点（close-daily 等），不跑后台任务。
	Enabled bool
	// BackfillLookbackDays S-8 缺口扫描回看窗口（天；默认 7，<=0 = 不限）。
	BackfillLookbackDays int

	AnomalyScanInterval time.Duration
	VerifyInterval      time.Duration
	QuotaScanInterval   time.Duration
	ExpiryScanInterval  time.Duration
	VerifyAssocInterval time.Duration

	// MonthlyCloseDay / MonthlyCloseAt 月结触发（日 1..3 ｜ HH:MM，UTC+8；§6.16 S-3）。
	// 与 period 段同源（LoadBillingConfig 同步），供调度器按"每月某日某刻"触发 CloseMonthly。
	MonthlyCloseDay int
	MonthlyCloseAt  string

	// PullInterval 增量拉取周期（S-1，§6.16）。与 source.pull_interval 同源（避免重复定义）。
	PullInterval time.Duration
}

type SecretsConfig struct {
	EventsSecretRef string
	SigningKeyRef   string // 账单签名密钥（引用式；空 = 不签名）
	// AlertWebhookURL 告警外部交付 Webhook（§6.11；空 = 仅本地日志 + Prometheus 规则）。
	// 建议以 env 注入（URL 可能含 token）。非密钥引用形式，直接使用。
	AlertWebhookURL string
}

type APIConfig struct {
	Listener       string
	PricePublicURL string
}

// ---------- 环境变量前缀 ----------

const envPrefix = "BILLING_"

// LoadBillingConfig 从环境变量加载计费配置（与 admin-service 风格一致：env 注入）。
// 未启用（BILLING_ENABLED=false 或空）返回零值配置，调用方不初始化子系统。
func LoadBillingConfig() (*BillingConfig, error) {
	enabled := os.Getenv(envPrefix+"ENABLED") == "true"
	if !enabled {
		return &BillingConfig{Enabled: false}, nil
	}

	cfg := &BillingConfig{Enabled: true}

	// Store
	cfg.Store.Driver = getEnv(envPrefix+"STORE_DRIVER", "sqlite")
	cfg.Store.DSN = getEnv(envPrefix+"STORE_DSN", "/var/lib/gateway/billing.db")
	cfg.Store.WAL = getEnv(envPrefix+"STORE_WAL", "true") == "true"

	// Source
	cfg.Source.TEEURL = strings.TrimRight(getEnv(envPrefix+"SOURCE_TEE_URL", "http://127.0.0.1:19090"), "/")
	cfg.Source.AdminTokenRef = os.Getenv(envPrefix + "SOURCE_ADMIN_TOKEN_REF")
	cfg.Source.SyncMode = getEnv(envPrefix+"SOURCE_SYNC_MODE", SyncModePull)
	cfg.Source.PullInterval = getDurationEnv(envPrefix+"SOURCE_PULL_INTERVAL", 60*time.Second)
	cfg.Source.PullLookback = getDurationEnv(envPrefix+"SOURCE_PULL_LOOKBACK", 24*time.Hour)
	cfg.Source.PushEnabled = getEnv(envPrefix+"SOURCE_PUSH_ENABLED", "true") == "true"
	cfg.Source.PushSecretRef = os.Getenv(envPrefix + "SOURCE_PUSH_SECRET_REF")

	// Period
	cfg.Period.Timezone = getEnv(envPrefix+"PERIOD_TIMEZONE", "UTC+8")
	cfg.Period.DailyCloseAt = getEnv(envPrefix+"PERIOD_DAILY_CLOSE_AT", "02:10")
	cfg.Period.MonthlyCloseDay = getIntEnv(envPrefix+"PERIOD_MONTHLY_CLOSE_DAY", 1)
	cfg.Period.MonthlyCloseAt = getEnv(envPrefix+"PERIOD_MONTHLY_CLOSE_AT", "03:10")

	// Rating
	// 默认路径与加载器（JSON）及样例文件（pricing.sample.json）一致（★ DOC-003：此前默认 .yaml 属陷阱）
	cfg.Rating.PriceTable = getEnv(envPrefix+"RATING_PRICE_TABLE", "/etc/gateway/pricing.json")
	cfg.Rating.Rounding = getEnv(envPrefix+"RATING_ROUNDING", "half_up")
	cfg.Rating.AccumulateThenRound = getEnv(envPrefix+"RATING_ACCUMULATE_THEN_ROUND", "true") == "true"
	cfg.Rating.TierMode = getEnv(envPrefix+"RATING_TIER_MODE", "progressive")
	cfg.Rating.RetryAttribution = getEnv(envPrefix+"RATING_RETRY_ATTRIBUTION", "platform")

	// Anomaly
	cfg.Anomaly.DailySpikeRatio = getFloatEnv(envPrefix+"ANOMALY_DAILY_SPIKE_RATIO", 3.0)
	cfg.Anomaly.ReconcileAlertRatio = getFloatEnv(envPrefix+"ANOMALY_RECONCILE_ALERT_RATIO", 0.001)
	cfg.Anomaly.QuotaWarnRatio = getFloatEnv(envPrefix+"ANOMALY_QUOTA_WARN_RATIO", 0.2)
	cfg.Anomaly.AutoThrottle = getEnv(envPrefix+"ANOMALY_AUTO_THROTTLE", "false") == "true"
	cfg.Anomaly.SpikeCriticalRatio = getFloatEnv(envPrefix+"ANOMALY_SPIKE_CRITICAL_RATIO", 10.0)

	// Display
	cfg.Display.AmountDisplay = getEnv(envPrefix+"DISPLAY_AMOUNT_DISPLAY", "false") == "true"

	// Schedule
	cfg.Schedule.Enabled = getEnv(envPrefix+"SCHEDULE_ENABLED", "true") == "true"
	cfg.Schedule.BackfillLookbackDays = getIntEnv(envPrefix+"SCHEDULE_BACKFILL_LOOKBACK_DAYS", 7)
	cfg.Schedule.AnomalyScanInterval = getDurationEnv(envPrefix+"SCHEDULE_ANOMALY_SCAN_INTERVAL", 5*time.Minute)
	cfg.Schedule.VerifyInterval = getDurationEnv(envPrefix+"SCHEDULE_VERIFY_INTERVAL", 1*time.Hour)
	cfg.Schedule.QuotaScanInterval = getDurationEnv(envPrefix+"SCHEDULE_QUOTA_SCAN_INTERVAL", 5*time.Minute)
	cfg.Schedule.ExpiryScanInterval = getDurationEnv(envPrefix+"SCHEDULE_EXPIRY_SCAN_INTERVAL", 6*time.Hour)
	cfg.Schedule.VerifyAssocInterval = getDurationEnv(envPrefix+"SCHEDULE_VERIFY_ASSOC_INTERVAL", 24*time.Hour)
	// 月结触发（同步自 period 段；§6.16 S-3）
	cfg.Schedule.MonthlyCloseDay = cfg.Period.MonthlyCloseDay
	cfg.Schedule.MonthlyCloseAt = cfg.Period.MonthlyCloseAt
	// 增量拉取周期（同步自 source 段；§6.16 S-1）
	cfg.Schedule.PullInterval = cfg.Source.PullInterval

	// Secrets
	cfg.Secrets.EventsSecretRef = os.Getenv(envPrefix + "SECRETS_EVENTS_SECRET_REF")
	cfg.Secrets.SigningKeyRef = os.Getenv(envPrefix + "SECRETS_SIGNING_KEY_REF")
	cfg.Secrets.AlertWebhookURL = os.Getenv(envPrefix + "SECRETS_ALERT_WEBHOOK_URL")

	// API
	cfg.API.Listener = getEnv(envPrefix+"API_LISTENER", "admin")
	cfg.API.PricePublicURL = os.Getenv(envPrefix + "API_PRICE_PUBLIC_URL")

	// 执行 R-1 ~ R-34 校验
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("billing config: %w", err)
	}

	return cfg, nil
}

// ---------- 配置校验（R-1 ~ R-34） ----------

var secretRefPattern = regexp.MustCompile(`^(env|file):.+$`)

// validateConfig 执行所有 R-n 校验规则。非法配置拒绝加载（fail-closed）。
func validateConfig(c *BillingConfig) error {
	// R-1: enabled=false 时无校验必要（默认即"逐字节一致"）
	if !c.Enabled {
		return nil
	}

	// R-2: driver ∈ {sqlite, postgres}（P0 仅二值）
	if c.Store.Driver != "sqlite" && c.Store.Driver != "postgres" {
		return fmt.Errorf("R-2: store.driver must be 'sqlite' or 'postgres', got %q", c.Store.Driver)
	}

	// R-3: sqlite 时 dsn 非空
	if c.Store.Driver == "sqlite" && c.Store.DSN == "" {
		return fmt.Errorf("R-3: store.dsn must not be empty for sqlite")
	}

	// R-4: tee_url 非空且合法 URL（仅 http(s)）
	if c.Source.TEEURL == "" {
		return fmt.Errorf("R-4: source.tee_url must not be empty")
	}
	u, err := url.Parse(c.Source.TEEURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("R-4: source.tee_url must be a valid http(s) URL, got %q", c.Source.TEEURL)
	}

	// R-5: admin_token_ref 必须为引用形式
	if !secretRefPattern.MatchString(c.Source.AdminTokenRef) {
		return fmt.Errorf("R-5: source.admin_token_ref must be 'env:NAME' or 'file:PATH', got %q", c.Source.AdminTokenRef)
	}

	// R-6: pull_interval ∈ [10s, 1h]
	if c.Source.PullInterval < 10*time.Second || c.Source.PullInterval > time.Hour {
		return fmt.Errorf("R-6: source.pull_interval must be in [10s, 1h], got %v", c.Source.PullInterval)
	}

	// R-7: pull_lookback ≥ pull_interval（否则无法覆盖重叠）
	if c.Source.PullLookback < c.Source.PullInterval {
		return fmt.Errorf("R-7: source.pull_lookback (%v) must be >= pull_interval (%v)",
			c.Source.PullLookback, c.Source.PullInterval)
	}
	if c.Source.PullLookback > 7*24*time.Hour {
		return fmt.Errorf("R-7: source.pull_lookback must be <= 7d, got %v", c.Source.PullLookback)
	}

	// R-8: push_enabled=true 时 R-9 必须提供密钥
	if c.Source.PushEnabled {
		// R-9: push_secret_ref 必须为引用形式
		if !secretRefPattern.MatchString(c.Source.PushSecretRef) {
			return fmt.Errorf("R-9: source.push_secret_ref must be 'env:NAME' or 'file:PATH' when push_enabled=true, got %q",
				c.Source.PushSecretRef)
		}
	}

	// R-10: timezone 只允许 UTC+8（P0）
	if c.Period.Timezone != "UTC+8" {
		return fmt.Errorf("R-10: period.timezone must be 'UTC+8' (P0), got %q", c.Period.Timezone)
	}

	// R-11: daily_close_at 格式 HH:MM 且 ≥ 00:05
	if !isValidHHMM(c.Period.DailyCloseAt) {
		return fmt.Errorf("R-11: period.daily_close_at must be HH:MM, got %q", c.Period.DailyCloseAt)
	}
	if c.Period.DailyCloseAt < "00:05" {
		return fmt.Errorf("R-11: period.daily_close_at must be >= 00:05 (avoid day boundary jitter)")
	}

	// R-12: monthly_close_day ∈ [1, 3]
	if c.Period.MonthlyCloseDay < 1 || c.Period.MonthlyCloseDay > 3 {
		return fmt.Errorf("R-12: period.monthly_close_day must be in [1,3], got %d", c.Period.MonthlyCloseDay)
	}

	// R-13: monthly_close_at 格式 HH:MM
	if !isValidHHMM(c.Period.MonthlyCloseAt) {
		return fmt.Errorf("R-13: period.monthly_close_at must be HH:MM, got %q", c.Period.MonthlyCloseAt)
	}

	// R-14: 价格表路径（不校验文件存在性，运行时校验；仅校验版本号非空在加载时）

	// R-15: rounding ∈ {half_up, floor}
	if c.Rating.Rounding != "half_up" && c.Rating.Rounding != "floor" {
		return fmt.Errorf("R-15: rating.rounding must be 'half_up' or 'floor', got %q", c.Rating.Rounding)
	}

	// R-16: accumulate_then_round 必须为 true（P0 强制）
	if !c.Rating.AccumulateThenRound {
		return fmt.Errorf("R-16: rating.accumulate_then_round must be true (P0 mandatory)")
	}

	// R-17: tier_mode 必须为 progressive（P0 强制）
	if c.Rating.TierMode != "progressive" {
		return fmt.Errorf("R-17: rating.tier_mode must be 'progressive' (P0 mandatory), got %q", c.Rating.TierMode)
	}

	// R-18: retry_attribution 必须为 platform（P0 强制；M9 不变量）
	if c.Rating.RetryAttribution != "platform" {
		return fmt.Errorf("R-18: rating.retry_attribution must be 'platform' (P0 mandatory; M9 invariant), got %q",
			c.Rating.RetryAttribution)
	}

	// R-19: daily_spike_ratio ∈ [1.5, 100]
	if c.Anomaly.DailySpikeRatio < 1.5 || c.Anomaly.DailySpikeRatio > 100 {
		return fmt.Errorf("R-19: anomaly.daily_spike_ratio must be in [1.5, 100], got %v", c.Anomaly.DailySpikeRatio)
	}

	// R-20: reconcile_alert_ratio ∈ [0, 1]
	if c.Anomaly.ReconcileAlertRatio < 0 || c.Anomaly.ReconcileAlertRatio > 1 {
		return fmt.Errorf("R-20: anomaly.reconcile_alert_ratio must be in [0, 1], got %v", c.Anomaly.ReconcileAlertRatio)
	}

	// R-21: quota_warn_ratio ∈ [0.05, 0.9]
	if c.Anomaly.QuotaWarnRatio < 0.05 || c.Anomaly.QuotaWarnRatio > 0.9 {
		return fmt.Errorf("R-21: anomaly.quota_warn_ratio must be in [0.05, 0.9], got %v", c.Anomaly.QuotaWarnRatio)
	}

	// R-22: api.listener 只允许 admin（P0）
	if c.API.Listener != "admin" {
		return fmt.Errorf("R-22: api.listener must be 'admin' (P0), got %q", c.API.Listener)
	}

	// R-23: amount_display ∈ {true,false}（bool 天然满足，仅记录）

	// R-24: anomaly_scan_interval ∈ [1m, 1h]
	if c.Schedule.AnomalyScanInterval < time.Minute || c.Schedule.AnomalyScanInterval > time.Hour {
		return fmt.Errorf("R-24: schedule.anomaly_scan_interval must be in [1m, 1h], got %v", c.Schedule.AnomalyScanInterval)
	}

	// R-25: verify_interval ∈ [10m, 24h]
	if c.Schedule.VerifyInterval < 10*time.Minute || c.Schedule.VerifyInterval > 24*time.Hour {
		return fmt.Errorf("R-25: schedule.verify_interval must be in [10m, 24h], got %v", c.Schedule.VerifyInterval)
	}

	// R-26: quota_scan_interval ∈ [1m, 1h]
	if c.Schedule.QuotaScanInterval < time.Minute || c.Schedule.QuotaScanInterval > time.Hour {
		return fmt.Errorf("R-26: schedule.quota_scan_interval must be in [1m, 1h], got %v", c.Schedule.QuotaScanInterval)
	}

	// R-27: events_secret_ref **可选**（未配置 → 回退 source.push_secret_ref，向后兼容）；
	// 配置时须为引用形式，且与推送密钥不同源（S-2：独立子密钥）。
	if c.Secrets.EventsSecretRef != "" {
		if !secretRefPattern.MatchString(c.Secrets.EventsSecretRef) {
			return fmt.Errorf("R-27: secrets.events_secret_ref must be 'env:NAME' or 'file:PATH' when set, got %q",
				c.Secrets.EventsSecretRef)
		}
		if c.Source.PushSecretRef != "" && c.Secrets.EventsSecretRef == c.Source.PushSecretRef {
			return fmt.Errorf("R-27: secrets.events_secret_ref must differ from source.push_secret_ref (S-2: separate auth domains)")
		}
	}

	// R-28: price_public_url 空 = 单价表不对外公开；非空须为 https
	if c.API.PricePublicURL != "" {
		u2, err := url.Parse(c.API.PricePublicURL)
		if err != nil || u2.Scheme != "https" {
			return fmt.Errorf("R-28: api.price_public_url must be an https URL when set, got %q", c.API.PricePublicURL)
		}
	}

	// R-30: sync_mode ∈ {pull, push}
	if c.Source.SyncMode != SyncModePull && c.Source.SyncMode != SyncModePush {
		return fmt.Errorf("R-30: source.sync_mode must be 'pull' or 'push', got %q", c.Source.SyncMode)
	}

	// R-31: auto_throttle ∈ {true,false}（bool 天然满足，仅记录；P0 默认 false）

	// R-32: expiry_scan_interval ∈ [1m, 24h]
	if c.Schedule.ExpiryScanInterval < time.Minute || c.Schedule.ExpiryScanInterval > 24*time.Hour {
		return fmt.Errorf("R-32: schedule.expiry_scan_interval must be in [1m, 24h], got %v", c.Schedule.ExpiryScanInterval)
	}

	// R-33: spike_critical_ratio ≥ daily_spike_ratio 且 ∈ [1.5, 1000]
	if c.Anomaly.SpikeCriticalRatio < c.Anomaly.DailySpikeRatio {
		return fmt.Errorf("R-33: anomaly.spike_critical_ratio (%v) must be >= anomaly.daily_spike_ratio (%v)",
			c.Anomaly.SpikeCriticalRatio, c.Anomaly.DailySpikeRatio)
	}
	if c.Anomaly.SpikeCriticalRatio < 1.5 || c.Anomaly.SpikeCriticalRatio > 1000 {
		return fmt.Errorf("R-33: anomaly.spike_critical_ratio must be in [1.5, 1000], got %v", c.Anomaly.SpikeCriticalRatio)
	}

	// R-34: verify_assoc_interval ∈ [10m, 24h]
	if c.Schedule.VerifyAssocInterval < 10*time.Minute || c.Schedule.VerifyAssocInterval > 24*time.Hour {
		return fmt.Errorf("R-34: schedule.verify_assoc_interval must be in [10m, 24h], got %v", c.Schedule.VerifyAssocInterval)
	}

	return nil
}

// ---------- 工具函数 ----------

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getIntEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func getFloatEnv(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func getDurationEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

var hhmmPattern = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9]$`)

func isValidHHMM(s string) bool {
	return hhmmPattern.MatchString(s)
}
