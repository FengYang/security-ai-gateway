package cacheengine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration 是支持 JSON 字符串表示的时间长度（如 "5s"、"200ms"，对齐详设 §4.2）
// 或整数（纳秒）的类型。用于配置文件中的人类可读写法。
type Duration time.Duration

// D 返回标准库 time.Duration。
func (d Duration) D() time.Duration { return time.Duration(d) }

// String 返回 Go 时长字符串（如 "5s"）。
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalJSON 接受字符串（Go 时长语法，如 "5s"）或整数（纳秒）。
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		*d = 0
		return nil
	}
	if len(s) >= 2 && s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return fmt.Errorf("duration: %w", err)
		}
		v, err := time.ParseDuration(str)
		if err != nil {
			return fmt.Errorf("duration %q: %w", str, err)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	*d = Duration(n)
	return nil
}

// MarshalJSON 以 Go 时长字符串输出（如 "5s"）。
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// ByteSize 是支持 JSON 字符串（"256MB"、"64KB"）或整数（字节）的容量类型。
type ByteSize int64

// Bytes 返回字节数。
func (b ByteSize) Bytes() int64 { return int64(b) }

// UnmarshalJSON 接受容量字符串（"256MB"/"64KB"/"1GB"/"512B"）或整数（字节）。
func (b *ByteSize) UnmarshalJSON(raw []byte) error {
	s := strings.TrimSpace(string(raw))
	if s == "null" || s == `""` {
		*b = 0
		return nil
	}
	if len(s) >= 2 && s[0] == '"' {
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return fmt.Errorf("bytesize: %w", err)
		}
		v, err := parseByteSize(str)
		if err != nil {
			return err
		}
		*b = ByteSize(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return fmt.Errorf("bytesize: %w", err)
	}
	*b = ByteSize(n)
	return nil
}

// MarshalJSON 以整数字节输出。
func (b ByteSize) MarshalJSON() ([]byte, error) {
	return json.Marshal(int64(b))
}

// parseByteSize 解析 "256MB"/"64KB"/"1GB"/"512B"/"1024" 等容量字符串。
func parseByteSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "" {
		return 0, fmt.Errorf("bytesize: empty")
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(t, "KB"):
		mult, t = 1024, strings.TrimSuffix(t, "KB")
	case strings.HasSuffix(t, "MB"):
		mult, t = 1024*1024, strings.TrimSuffix(t, "MB")
	case strings.HasSuffix(t, "GB"):
		mult, t = 1024*1024*1024, strings.TrimSuffix(t, "GB")
	case strings.HasSuffix(t, "B"):
		mult, t = 1, strings.TrimSuffix(t, "B")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bytesize %q: %w", s, err)
	}
	return n * mult, nil
}

// CacheConfig 缓存完整配置。
// 字段语义对齐设计文档 §4.2 的配置 schema；实现采用 JSON 加载（见 loader.go），
// 时间/容量字段支持 "5s"/"200ms"、"256MB" 等人类可读写法（等价于 §4.2 的 YAML 表示）。
type CacheConfig struct {
	Mode                       CacheMode         `json:"mode"`
	Scope                      string            `json:"scope"`
	PolicyVersion              string            `json:"policy_version"`
	InvalidatePropagateInterval Duration              `json:"invalidate_propagate_interval"`
	CacheMemoryBudget          ByteSize              `json:"cache_memory_budget"` // 支持 "256MB" 或整数（字节）
	KeyFormat                  string                `json:"key_format"`

	Memory   MemoryConfig   `json:"memory"`
	Exact    ExactConfig    `json:"exact"`
	Negative NegativeConfig `json:"negative"`
	Semantic SemanticConfig `json:"semantic"`
	Redis    RedisConfig    `json:"redis"`
	Warmup   WarmupConfig   `json:"warmup"`
	Guard    GuardConfig    `json:"guard"`
	Gray     GrayConfig     `json:"gray"`

	WriteLimit WriteLimitConfig `json:"write_limit"`

	SingleFlight SingleFlightConfig `json:"singleflight"`
	Stream       StreamConfig       `json:"stream"`
	Cacheability CacheabilityConfig `json:"cacheability"`
	TTLPolicy    TTLPolicyConfig    `json:"ttl_policy"`
}

// MemoryConfig 内存水位与清理配置。
type MemoryConfig struct {
	WatermarkHigh   float64  `json:"watermark_high"`
	WatermarkLow    float64  `json:"watermark_low"`
	CleanupInterval Duration `json:"cleanup_interval"`
	CleanupBatch    int      `json:"cleanup_batch"`
}

// ExactConfig 精确缓存配置。
type ExactConfig struct {
	Enabled         bool     `json:"enabled"`
	TTL             Duration `json:"ttl"`
	MaxEntries      int      `json:"max_entries"`
	MaxEntryBytes   ByteSize `json:"max_entry_bytes"`
	MinTokens       int      `json:"min_tokens"`
	MinPromptTokens int      `json:"min_prompt_tokens"`
}

// NegativeConfig 负向缓存配置。
type NegativeConfig struct {
	Enabled    bool     `json:"enabled"`
	TTL        Duration `json:"ttl"`
	MaxEntries int      `json:"max_entries"`
	OnlyFor    []string `json:"only_for"`
}

// SemanticConfig 语义缓存配置。
type SemanticConfig struct {
	Enabled  bool             `json:"enabled"`
	Embedder EmbedderConfig   `json:"embedder"`
	Vector   VectorConfig     `json:"vector"`
	Threshold ThresholdConfig  `json:"threshold"`
	SceneHint SceneHintConfig  `json:"scene_hint"`
	Jitter    JitterConfig    `json:"jitter"`
}

// EmbedderConfig embedding 配置。
type EmbedderConfig struct {
	Kind           string   `json:"kind"` // sidecar | stub
	Endpoint       string   `json:"endpoint"`
	HealthEndpoint string   `json:"health_endpoint"` // 探活端点（留空则由 Endpoint 推导 host/health）
	ModelID        string   `json:"model_id"`
	Dim            int      `json:"dim"`
	Timeout        Duration `json:"timeout"`
	BatchMax       int      `json:"batch_max"`
	FailOpen       bool     `json:"fail_open"`
}

// VectorConfig 向量索引配置。
type VectorConfig struct {
	Backend        string            `json:"backend"` // flat | hnsw | redis-vss（默认 hnsw）
	FlatMaxEntries int               `json:"flat_max_entries"`
	TopK           int               `json:"top_k"`
	TenantPolicy   map[string]string `json:"tenant_policy"` // off | exact_only
	HNSW           HNSWConfig        `json:"hnsw"`
}

// HNSWConfig HNSW 图索引参数（§4.2；backend=hnsw 时生效）。
type HNSWConfig struct {
	M              int `json:"m"`               // 邻居数
	EfConstruction int `json:"ef_construction"` // 建图候选宽度
	EfSearch       int `json:"ef_search"`       // 检索候选宽度
	MaxEntries     int `json:"max_entries"`     // 容量
}

// ThresholdConfig 相似度阈值配置（场景化）。
type ThresholdConfig struct {
	Factual          float64    `json:"factual"`
	General          float64    `json:"general"`
	Code             float64    `json:"code"`
	Math             float64    `json:"math"`
	StrictFingerprint []string   `json:"strict_fingerprint"`
}

// SceneHintConfig 场景提示配置。
type SceneHintConfig struct {
	Enabled bool `json:"enabled"`
}

// JitterConfig 侧信道抖动配置。
type JitterConfig struct {
	Enabled             bool `json:"enabled"`
	MaxMs               int  `json:"max_ms"`
	HitOnlyCompensation bool `json:"hit_only_compensation"`
}

// RedisConfig Redis 配置（形态 B/C）。
type RedisConfig struct {
	Enabled      bool          `json:"enabled"`
	Addr         string        `json:"addr"`
	DB           int           `json:"db"`
	PasswordRef  string        `json:"password_ref"`
	TrustedCIDR  []string      `json:"trusted_cidr"`
	KeyPrefix    string        `json:"key_prefix"`
	TTLSlack     Duration   `json:"ttl_slack"`
	PoolSize     int        `json:"pool_size"`
	PoolTimeout  Duration   `json:"pool_timeout"`
	DialTimeout  Duration   `json:"dial_timeout"`
	ReadTimeout  Duration   `json:"read_timeout"`
	WriteTimeout Duration   `json:"write_timeout"`
	MaxRetries   int           `json:"max_retries"`
}

// WarmupConfig 预热配置。
type WarmupConfig struct {
	Enabled      bool   `json:"enabled"`
	Source       string `json:"source"`
	File         string `json:"file"`
	Trigger      string `json:"trigger"`
	DailyAt      string `json:"daily_at"`
	MaxItems     int    `json:"max_items"`
	BudgetExempt bool   `json:"budget_exempt"`
	QPS          int    `json:"qps"` // 预热节流上限（次/秒；0 = 不限）
}

// GuardConfig 缓存安全配置。
type GuardConfig struct {
	ReadFastCheck       bool   `json:"read_fast_check"`
	ReadFastCheckAction string `json:"read_fast_check_action"` // treat_as_miss | block
	WriteRequiresOutGuard bool `json:"write_requires_out_guard"`
}

// WriteLimitConfig 写入限流配置（§7.4.2 写入滥用约束）。
// 单租户写入速率上限 = min(入向QPS × InboundHeadroom, MaxQPS)；超限写入丢弃。
type WriteLimitConfig struct {
	Enabled         bool     `json:"enabled"`
	MaxQPS          int      `json:"max_qps"`          // 单租户写入速率硬上限（次/秒）
	InboundHeadroom float64  `json:"inbound_headroom"` // 入向QPS 余量系数
	Window          Duration `json:"window"`           // 统计窗口
}

// GrayConfig 灰度配置。
type GrayConfig struct {
	Enabled        bool     `json:"enabled"`
	Stage          string   `json:"stage"` // 灰度阶段 G-0..G-5（§12.2；用于 #36 指标/审计）
	CanaryTenants  []string `json:"canary_tenants"`
	CanaryScenes   []string `json:"canary_scenes"`
	CanaryModels   []string `json:"canary_models"`
	TrafficPercent int      `json:"traffic_percent"`
	WriteOnly      bool     `json:"write_only"`
}

// SingleFlightConfig 请求合并配置。
type SingleFlightConfig struct {
	Enabled       bool     `json:"enabled"`
	MaxWait       Duration `json:"max_wait"`
	FailurePolicy string   `json:"failure_policy"` // independent | propagate
}

// StreamConfig 流式分段缓存配置。
type StreamConfig struct {
	Enabled     bool     `json:"enabled"`
	MaxSegments int      `json:"max_segments"`
	MinGap      Duration `json:"min_gap"`
	MaxGap      Duration `json:"max_gap"`
}

// CacheabilityConfig 可缓存性配置。
type CacheabilityConfig struct {
	MultiTurn            bool     `json:"multi_turn"`
	BypassHeader         string   `json:"bypass_header"`
	TimeSensitiveScenes  []string `json:"time_sensitive_scenes"`
	DisabledScenes       []string `json:"disabled_scenes"`
}

// TTLPolicyConfig TTL 维度覆盖配置。
type TTLPolicyConfig struct {
	Resolution string            `json:"resolution"` // specific_first | min
	ByTenant   map[string]string `json:"by_tenant"`  // duration string
	ByModel    map[string]string `json:"by_model"`
	ByScene    map[string]string `json:"by_scene"`
}

// DefaultConfig 返回默认配置（mode=off，与现网逐字节一致）。
func DefaultConfig() CacheConfig {
	return CacheConfig{
		Mode:                       ModeOff,
		Scope:                      "per_tenant",
		PolicyVersion:              "1",
		InvalidatePropagateInterval: Duration(5 * time.Second),
		CacheMemoryBudget:          ByteSize(512 * 1024 * 1024), // 512MB（§5.6 推荐：缓存结构 + 预留，一期精确+二期向量）
		KeyFormat:                  "v2",
		Memory: MemoryConfig{
			WatermarkHigh:   0.9,
			WatermarkLow:    0.8,
			CleanupInterval: Duration(60 * time.Second),
			CleanupBatch:    1000,
		},
		Exact: ExactConfig{
			Enabled:         true,
			TTL:             Duration(3600 * time.Second),
			MaxEntries:      8192,
			MaxEntryBytes:   ByteSize(65536),
			MinTokens:       4,
			MinPromptTokens: 8,
		},
		Negative: NegativeConfig{
			Enabled:    true,
			TTL:        Duration(60 * time.Second),
			MaxEntries: 4096,
			OnlyFor:    []string{"guardrail", "output_guard"},
		},
		Semantic: SemanticConfig{
			Enabled: false,
			Embedder: EmbedderConfig{
				Kind:           "sidecar",
				Endpoint:       "http://127.0.0.1:18081/embed",  // §4.2 端点(18081) + /embed 路径
				HealthEndpoint: "http://127.0.0.1:18081/health", // 探活端点（与 /embed 同源，不再拼接 /embed/health）
				ModelID:        "bge-small-zh-v1.5",
				Dim:            512,
				Timeout:        Duration(200 * time.Millisecond),
				BatchMax:       8,
				FailOpen:       true,
			},
			Vector: VectorConfig{
				Backend:        "hnsw", // 默认 HNSW（§4.2；flat 仅用于小规模/基准对照）
				FlatMaxEntries: 50000,
				TopK:           5,
				TenantPolicy:   map[string]string{},
				HNSW: HNSWConfig{
					M:              16,
					EfConstruction: 200,
					EfSearch:       64,
					MaxEntries:     50000,
				},
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
			TTLSlack:     Duration(300 * time.Second),
			PoolSize:     32,
			PoolTimeout:  Duration(100 * time.Millisecond),
			DialTimeout:  Duration(200 * time.Millisecond),
			ReadTimeout:  Duration(150 * time.Millisecond),
			WriteTimeout: Duration(500 * time.Millisecond),
			MaxRetries:   2,
		},
		Warmup: WarmupConfig{
			Enabled:  false,
			Source:   "file",
			Trigger:  "manual",
			MaxItems: 1000,
			QPS:      0, // 0 = 不限速
		},
		Guard: GuardConfig{
			ReadFastCheck:       true,
			ReadFastCheckAction: "treat_as_miss",
			WriteRequiresOutGuard: true,
		},
		Gray: GrayConfig{
			Enabled:        false,
			Stage:          "G-0",
			TrafficPercent: 0,
		},
		WriteLimit: WriteLimitConfig{
			Enabled:         true,
			MaxQPS:          200,
			InboundHeadroom: 1.2,
			Window:          Duration(1 * time.Second),
		},
		SingleFlight: SingleFlightConfig{
			Enabled:       true,
			MaxWait:       Duration(3 * time.Second),
			FailurePolicy: "independent",
		},
		Stream: StreamConfig{
			Enabled:     true,
			MaxSegments: 512,
			MinGap:      Duration(8 * time.Millisecond),
			MaxGap:      Duration(400 * time.Millisecond),
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
	if c.Exact.TTL.D() < time.Second {
		errs = append(errs, fmt.Errorf("rule 5: exact.ttl must be >= 1s"))
	}
	if c.Negative.TTL.D() < time.Second {
		errs = append(errs, fmt.Errorf("rule 5: negative.ttl must be >= 1s"))
	}
	if c.Negative.TTL.D() > c.Exact.TTL.D() {
		errs = append(errs, fmt.Errorf("rule 5: negative.ttl must be <= exact.ttl"))
	}

	// 规则 6：max_entries × max_entry_bytes <= cache_memory_budget
	memBudget := int64(c.Exact.MaxEntries) * c.Exact.MaxEntryBytes.Bytes()
	if memBudget > c.CacheMemoryBudget.Bytes() {
		errs = append(errs, fmt.Errorf("rule 6: exact.max_entries × max_entry_bytes (%d) > cache_memory_budget (%d)",
			memBudget, c.CacheMemoryBudget.Bytes()))
	}

	// 规则 11：预热配置（§6.7）。文件存在性/逐行 JSON 校验由 LoadWarmItems 承担（装配期调用，按行号报错）。
	if c.Warmup.Enabled {
		if c.Warmup.Source != "file" {
			errs = append(errs, fmt.Errorf("rule 11: warmup.source must be \"file\""))
		}
		if strings.TrimSpace(c.Warmup.File) == "" {
			errs = append(errs, fmt.Errorf("rule 11: warmup.file must be set when warmup.enabled=true"))
		}
		if c.Warmup.MaxItems <= 0 {
			errs = append(errs, fmt.Errorf("rule 11: warmup.max_items must be >= 1"))
		}
	}
	if c.Warmup.QPS < 0 || c.Warmup.QPS > 10000 {
		errs = append(errs, fmt.Errorf("rule 11: warmup.qps must be in [0, 10000]"))
	}

	// 规则 13：semantic.enabled 时 scope 必须为 per_tenant
	if c.Semantic.Enabled && c.Scope != "per_tenant" {
		errs = append(errs, fmt.Errorf("rule 13: semantic.enabled requires scope=per_tenant"))
	}

	// 规则 15：cacheability.multi_turn=true 时 mode 必须为 exact
	if c.Cacheability.MultiTurn && (c.Mode == ModeSemantic || c.Mode == ModeFull) {
		errs = append(errs, fmt.Errorf("rule 15: multi_turn=true requires mode=exact"))
	}

	// 规则 22：灰度（§12）。白名单元素须为已知租户/场景/模型（控制面校验，引擎侧无租户注册表）；
	// 此处校验阶段枚举与流量百分比。
	if !validGrayStage(c.Gray.Stage) {
		errs = append(errs, fmt.Errorf("rule 22: gray.stage must be one of G-0..G-5"))
	}
	if c.Gray.TrafficPercent < 0 || c.Gray.TrafficPercent > 100 {
		errs = append(errs, fmt.Errorf("rule 22: gray.traffic_percent must be in [0,100]"))
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

	// 规则 26：写入限流（§7.4.2）
	if c.WriteLimit.Enabled {
		if c.WriteLimit.MaxQPS < 1 || c.WriteLimit.MaxQPS > 100000 {
			errs = append(errs, fmt.Errorf("rule 26: write_limit.max_qps must be in [1, 100000]"))
		}
		if c.WriteLimit.InboundHeadroom < 1.0 || c.WriteLimit.InboundHeadroom > 10.0 {
			errs = append(errs, fmt.Errorf("rule 26: write_limit.inbound_headroom must be in [1.0, 10.0]"))
		}
		if c.WriteLimit.Window.D() < 100*time.Millisecond || c.WriteLimit.Window.D() > 60*time.Second {
			errs = append(errs, fmt.Errorf("rule 26: write_limit.window must be in [100ms, 60s]"))
		}
	}

	// 规则 27：向量后端与 HNSW 参数（§4.2）
	switch c.Semantic.Vector.Backend {
	case "", "flat", "hnsw", "redis-vss":
	default:
		errs = append(errs, fmt.Errorf("rule 27: semantic.vector.backend must be one of flat|hnsw|redis-vss, got %q", c.Semantic.Vector.Backend))
	}
	if bk := c.Semantic.Vector.Backend; bk == "hnsw" || bk == "" {
		h := c.Semantic.Vector.HNSW
		if h.M < 4 || h.M > 64 {
			errs = append(errs, fmt.Errorf("rule 27: semantic.vector.hnsw.m must be in [4, 64]"))
		}
		if h.EfConstruction < 16 || h.EfConstruction > 2000 {
			errs = append(errs, fmt.Errorf("rule 27: semantic.vector.hnsw.ef_construction must be in [16, 2000]"))
		}
		if h.EfSearch < 4 || h.EfSearch > 2000 {
			errs = append(errs, fmt.Errorf("rule 27: semantic.vector.hnsw.ef_search must be in [4, 2000]"))
		}
		if h.MaxEntries < 1 {
			errs = append(errs, fmt.Errorf("rule 27: semantic.vector.hnsw.max_entries must be >= 1"))
		}
		if h.EfSearch < c.Semantic.Vector.TopK {
			errs = append(errs, fmt.Errorf("rule 27: semantic.vector.hnsw.ef_search must be >= vector.top_k"))
		}
	}

	return errs
}

// validGrayStage 校验灰度阶段枚举（§12.2）。空值视为缺省 G-0。
func validGrayStage(s string) bool {
	if s == "" {
		return true
	}
	switch s {
	case "G-0", "G-1", "G-2", "G-3", "G-4", "G-5":
		return true
	}
	return false
}
