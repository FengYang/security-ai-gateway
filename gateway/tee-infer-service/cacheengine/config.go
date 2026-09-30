package cacheengine

import (
	"fmt"
	"time"
)

// CacheConfig 缓存完整配置。
// 对应设计文档 §4.2 的 YAML schema。
type CacheConfig struct {
	Mode                       CacheMode         `yaml:"mode"`
	Scope                      string            `yaml:"scope"`
	PolicyVersion              string            `yaml:"policy_version"`
	InvalidatePropagateInterval time.Duration   `yaml:"invalidate_propagate_interval"`
	CacheMemoryBudget          int64             `yaml:"cache_memory_budget"` // bytes
	KeyFormat                  string            `yaml:"key_format"`

	Memory   MemoryConfig   `yaml:"memory"`
	Exact    ExactConfig    `yaml:"exact"`
	Negative NegativeConfig `yaml:"negative"`
	Semantic SemanticConfig `yaml:"semantic"`
	Redis    RedisConfig    `yaml:"redis"`
	Warmup   WarmupConfig   `yaml:"warmup"`
	Guard    GuardConfig    `yaml:"guard"`
	Gray     GrayConfig     `yaml:"gray"`

	SingleFlight SingleFlightConfig `yaml:"singleflight"`
	Stream       StreamConfig       `yaml:"stream"`
	Cacheability CacheabilityConfig `yaml:"cacheability"`
	TTLPolicy    TTLPolicyConfig    `yaml:"ttl_policy"`
}

// MemoryConfig 内存水位与清理配置。
type MemoryConfig struct {
	WatermarkHigh   float64       `yaml:"watermark_high"`
	WatermarkLow    float64       `yaml:"watermark_low"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
	CleanupBatch    int           `yaml:"cleanup_batch"`
}

// ExactConfig 精确缓存配置。
type ExactConfig struct {
	Enabled        bool          `yaml:"enabled"`
	TTL            time.Duration `yaml:"ttl"`
	MaxEntries     int           `yaml:"max_entries"`
	MaxEntryBytes  int           `yaml:"max_entry_bytes"`
	MinTokens      int           `yaml:"min_tokens"`
	MinPromptTokens int          `yaml:"min_prompt_tokens"`
}

// NegativeConfig 负向缓存配置。
type NegativeConfig struct {
	Enabled    bool          `yaml:"enabled"`
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
	OnlyFor    []string      `yaml:"only_for"`
}

// SemanticConfig 语义缓存配置。
type SemanticConfig struct {
	Enabled  bool             `yaml:"enabled"`
	Embedder EmbedderConfig   `yaml:"embedder"`
	Vector   VectorConfig     `yaml:"vector"`
	Threshold ThresholdConfig  `yaml:"threshold"`
	SceneHint SceneHintConfig  `yaml:"scene_hint"`
	Jitter    JitterConfig    `yaml:"jitter"`
}

// EmbedderConfig embedding 配置。
type EmbedderConfig struct {
	Kind      string        `yaml:"kind"` // sidecar | stub
	Endpoint  string        `yaml:"endpoint"`
	ModelID   string        `yaml:"model_id"`
	Dim       int           `yaml:"dim"`
	Timeout   time.Duration `yaml:"timeout"`
	BatchMax  int           `yaml:"batch_max"`
	FailOpen  bool          `yaml:"fail_open"`
}

// VectorConfig 向量索引配置。
type VectorConfig struct {
	Backend        string            `yaml:"backend"` // flat | hnsw | redis-vss
	FlatMaxEntries int              `yaml:"flat_max_entries"`
	TopK           int               `yaml:"top_k"`
	TenantPolicy   map[string]string `yaml:"tenant_policy"` // off | exact_only
}

// ThresholdConfig 相似度阈值配置（场景化）。
type ThresholdConfig struct {
	Factual          float64    `yaml:"factual"`
	General          float64    `yaml:"general"`
	Code             float64    `yaml:"math"`
	Math             float64    `yaml:"code"`
	StrictFingerprint []string   `yaml:"strict_fingerprint"`
}

// SceneHintConfig 场景提示配置。
type SceneHintConfig struct {
	Enabled bool `yaml:"enabled"`
}

// JitterConfig 侧信道抖动配置。
type JitterConfig struct {
	Enabled             bool `yaml:"enabled"`
	MaxMs               int  `yaml:"max_ms"`
	HitOnlyCompensation bool `yaml:"hit_only_compensation"`
}

// RedisConfig Redis 配置（形态 B/C）。
type RedisConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Addr         string        `yaml:"addr"`
	DB           int           `yaml:"db"`
	PasswordRef  string        `yaml:"password_ref"`
	TrustedCIDR  []string      `yaml:"trusted_cidr"`
	KeyPrefix    string        `yaml:"key_prefix"`
	TTLSlack     time.Duration `yaml:"ttl_slack"`
	PoolSize     int           `yaml:"pool_size"`
	PoolTimeout  time.Duration `yaml:"pool_timeout"`
	DialTimeout  time.Duration `yaml:"dial_timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	MaxRetries   int           `yaml:"max_retries"`
}

// WarmupConfig 预热配置。
type WarmupConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Source       string `yaml:"source"`
	File         string `yaml:"file"`
	Trigger      string `yaml:"trigger"`
	DailyAt      string `yaml:"daily_at"`
	MaxItems     int    `yaml:"max_items"`
	BudgetExempt bool   `yaml:"budget_exempt"`
}

// GuardConfig 缓存安全配置。
type GuardConfig struct {
	ReadFastCheck       bool   `yaml:"read_fast_check"`
	ReadFastCheckAction string `yaml:"read_fast_check_action"` // treat_as_miss | block
	WriteRequiresOutGuard bool `yaml:"write_requires_out_guard"`
}

// GrayConfig 灰度配置。
type GrayConfig struct {
	Enabled        bool     `yaml:"enabled"`
	CanaryTenants  []string `yaml:"canary_tenants"`
	CanaryScenes   []string `yaml:"canary_scenes"`
	CanaryModels   []string `yaml:"canary_models"`
	TrafficPercent int      `yaml:"traffic_percent"`
	WriteOnly      bool     `yaml:"write_only"`
}

// SingleFlightConfig 请求合并配置。
type SingleFlightConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxWait       time.Duration `yaml:"max_wait"`
	FailurePolicy string        `yaml:"failure_policy"` // independent | propagate
}

// StreamConfig 流式分段缓存配置。
type StreamConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxSegments int           `yaml:"max_segments"`
	MinGap      time.Duration `yaml:"min_gap"`
	MaxGap      time.Duration `yaml:"max_gap"`
}

// CacheabilityConfig 可缓存性配置。
type CacheabilityConfig struct {
	MultiTurn            bool     `yaml:"multi_turn"`
	BypassHeader         string   `yaml:"bypass_header"`
	TimeSensitiveScenes  []string `yaml:"time_sensitive_scenes"`
	DisabledScenes       []string `yaml:"disabled_scenes"`
}

// TTLPolicyConfig TTL 维度覆盖配置。
type TTLPolicyConfig struct {
	Resolution string            `yaml:"resolution"` // specific_first | min
	ByTenant   map[string]string `yaml:"by_tenant"`  // duration string
	ByModel    map[string]string `yaml:"by_model"`
	ByScene    map[string]string `yaml:"by_scene"`
}

// DefaultConfig 返回默认配置（mode=off，与现网逐字节一致）。
func DefaultConfig() CacheConfig {
	return CacheConfig{
		Mode:                       ModeOff,
		Scope:                      "per_tenant",
		PolicyVersion:              "1",
		InvalidatePropagateInterval: 5 * time.Second,
		CacheMemoryBudget:          512 * 1024 * 1024, // 512MB（§5.6 推荐：缓存结构 + 预留，一期精确+二期向量）
		KeyFormat:                  "v2",
		Memory: MemoryConfig{
			WatermarkHigh:   0.9,
			WatermarkLow:    0.8,
			CleanupInterval: 60 * time.Second,
			CleanupBatch:    1000,
		},
		Exact: ExactConfig{
			Enabled:        true,
			TTL:            3600 * time.Second,
			MaxEntries:     8192,
			MaxEntryBytes:  65536,
			MinTokens:      4,
			MinPromptTokens: 8,
		},
		Negative: NegativeConfig{
			Enabled:    true,
			TTL:        60 * time.Second,
			MaxEntries: 4096,
			OnlyFor:    []string{"guardrail", "output_guard"},
		},
		Semantic: SemanticConfig{
			Enabled: false,
			Embedder: EmbedderConfig{
				Kind:      "sidecar",
				Endpoint:  "http://127.0.0.1:18081",
				ModelID:   "bge-small-zh-v1.5",
				Dim:       512,
				Timeout:   200 * time.Millisecond,
				BatchMax:  8,
				FailOpen:  true,
			},
			Vector: VectorConfig{
				Backend:        "flat",
				FlatMaxEntries: 50000,
				TopK:           5,
				TenantPolicy:   map[string]string{},
			},
			Threshold: ThresholdConfig{
				Factual:          0.93,
				General:          0.87,
				Code:             0.96,
				Math:             0.96,
				StrictFingerprint: []string{"code", "math"},
			},
			SceneHint: SceneHintConfig{Enabled: true},
			Jitter: JitterConfig{
				Enabled:             true,
				MaxMs:               20,
				HitOnlyCompensation: false,
			},
		},
		Redis: RedisConfig{
			Enabled:      false,
			Addr:         "redis-address:6379",
			DB:           3,
			KeyPrefix:    "og:c:1:",
			TTLSlack:     300 * time.Second,
			PoolSize:     32,
			PoolTimeout:  100 * time.Millisecond,
			DialTimeout:  200 * time.Millisecond,
			ReadTimeout:  150 * time.Millisecond,
			WriteTimeout: 500 * time.Millisecond,
			MaxRetries:   2,
		},
		Warmup: WarmupConfig{
			Enabled:  false,
			Source:   "file",
			Trigger:  "manual",
			MaxItems: 1000,
		},
		Guard: GuardConfig{
			ReadFastCheck:       true,
			ReadFastCheckAction: "treat_as_miss",
			WriteRequiresOutGuard: true,
		},
		Gray: GrayConfig{
			Enabled:        false,
			TrafficPercent: 0,
		},
		SingleFlight: SingleFlightConfig{
			Enabled:       true,
			MaxWait:       3 * time.Second,
			FailurePolicy: "independent",
		},
		Stream: StreamConfig{
			Enabled:     true,
			MaxSegments: 512,
			MinGap:      8 * time.Millisecond,
			MaxGap:      400 * time.Millisecond,
		},
		Cacheability: CacheabilityConfig{
			MultiTurn:    false,
			BypassHeader: "x-no-cache",
		},
		TTLPolicy: TTLPolicyConfig{
			Resolution: "specific_first",
			ByTenant:   map[string]string{},
			ByModel:    map[string]string{},
			ByScene:    map[string]string{},
		},
	}
}

// Validate 启动期校验（§4.2.1 校验规则）。
// 返回所有违反项的错误列表。
func (c CacheConfig) Validate() []error {
	var errs []error

	// 规则 2：mode=semantic/full 时 semantic.enabled 必须为 true
	if (c.Mode == ModeSemantic || c.Mode == ModeFull) && !c.Semantic.Enabled {
		errs = append(errs, fmt.Errorf("rule 2: mode=%s requires semantic.enabled=true", c.Mode))
	}

	// 规则 4：阈值在 (0.5, 1.0] 区间，且 code/math ≥ factual ≥ general
	if c.Semantic.Enabled {
		th := c.Semantic.Threshold
		if th.Factual <= 0.5 || th.Factual > 1.0 {
			errs = append(errs, fmt.Errorf("rule 4: threshold.factual must be in (0.5, 1.0]"))
		}
		if th.General <= 0.5 || th.General > 1.0 {
			errs = append(errs, fmt.Errorf("rule 4: threshold.general must be in (0.5, 1.0]"))
		}
		if th.Code <= 0.5 || th.Code > 1.0 {
			errs = append(errs, fmt.Errorf("rule 4: threshold.code must be in (0.5, 1.0]"))
		}
		if th.Math <= 0.5 || th.Math > 1.0 {
			errs = append(errs, fmt.Errorf("rule 4: threshold.math must be in (0.5, 1.0]"))
		}
		if !(th.Code >= th.Factual && th.Factual >= th.General) {
			errs = append(errs, fmt.Errorf("rule 4: threshold order must be code/math >= factual >= general"))
		}
	}

	// 规则 5：ttl >= 1s；negative.ttl <= exact.ttl
	if c.Exact.TTL < time.Second {
		errs = append(errs, fmt.Errorf("rule 5: exact.ttl must be >= 1s"))
	}
	if c.Negative.TTL < time.Second {
		errs = append(errs, fmt.Errorf("rule 5: negative.ttl must be >= 1s"))
	}
	if c.Negative.TTL > c.Exact.TTL {
		errs = append(errs, fmt.Errorf("rule 5: negative.ttl must be <= exact.ttl"))
	}

	// 规则 6：max_entries × max_entry_bytes <= cache_memory_budget
	memBudget := int64(c.Exact.MaxEntries) * int64(c.Exact.MaxEntryBytes)
	if memBudget > c.CacheMemoryBudget {
		errs = append(errs, fmt.Errorf("rule 6: exact.max_entries × max_entry_bytes (%d) > cache_memory_budget (%d)",
			memBudget, c.CacheMemoryBudget))
	}

	// 规则 13：semantic.enabled 时 scope 必须为 per_tenant
	if c.Semantic.Enabled && c.Scope != "per_tenant" {
		errs = append(errs, fmt.Errorf("rule 13: semantic.enabled requires scope=per_tenant"))
	}

	// 规则 15：cacheability.multi_turn=true 时 mode 必须为 exact
	if c.Cacheability.MultiTurn && (c.Mode == ModeSemantic || c.Mode == ModeFull) {
		errs = append(errs, fmt.Errorf("rule 15: multi_turn=true requires mode=exact"))
	}

	// 规则 23：内存水位
	if c.Memory.WatermarkHigh <= 0 || c.Memory.WatermarkHigh > 1 {
		errs = append(errs, fmt.Errorf("rule 23: memory.watermark_high must be in (0, 1]"))
	}
	if c.Memory.WatermarkLow < 0 || c.Memory.WatermarkLow >= c.Memory.WatermarkHigh {
		errs = append(errs, fmt.Errorf("rule 23: memory.watermark_low must be in [0, watermark_high)"))
	}

	// 规则 24：key_format=v1 仅允许与 scope=per_engine_model 共用
	if c.KeyFormat == "v1" && c.Scope != "per_engine_model" {
		errs = append(errs, fmt.Errorf("rule 24: key_format=v1 requires scope=per_engine_model"))
	}
	if c.KeyFormat == "v1" && c.Semantic.Enabled {
		errs = append(errs, fmt.Errorf("rule 24: key_format=v1 cannot be used with semantic.enabled=true"))
	}

	return errs
}
