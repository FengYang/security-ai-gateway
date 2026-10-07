package cacheengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultConfigPath 缓存配置默认路径（可由环境变量 CACHE_CONFIG_PATH 覆盖）。
const DefaultConfigPath = "config/cache.json"

// LoadConfig 从 JSON 文件加载缓存配置。
//
// 语义：以 DefaultConfig() 为基线，仅覆盖文件中显式给出的字段，最后执行 Validate()。
// 兼容两种根形态：
//   - 平铺：{"mode":"exact", ...}
//   - 嵌套：{"cache":{"mode":"exact", ...}}（对齐详设 §4.2 的 cache: 根）
//
// 时间字段支持 "5s"/"200ms" 字符串或纳秒整数；容量字段支持 "256MB"/"64KB" 或字节整数。
func LoadConfig(path string) (CacheConfig, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultConfig(), fmt.Errorf("cache: read config %q: %w", path, err)
	}
	return LoadConfigBytes(data)
}

// LoadConfigBytes 从 JSON 字节加载配置（供已知内容或测试使用）。
func LoadConfigBytes(data []byte) (CacheConfig, error) {
	// 允许 {"cache": {...}} 包装（对齐详设 §4.2）。
	var wrapper struct {
		Cache json.RawMessage `json:"cache"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Cache) > 0 {
		data = wrapper.Cache
	}

	cfg := DefaultConfig()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("cache: parse config: %w", err)
	}

	if errs := cfg.Validate(); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return cfg, fmt.Errorf("cache: invalid config: %s", strings.Join(msgs, "; "))
	}
	return cfg, nil
}

// ApplyEnv 用环境变量覆盖关键开关（部署期切换，无需改配置文件）。
// 仅覆盖"总开关"与"连接参数"，不覆盖安全阈值（阈值须走配置文件评审）。
// 识别的前缀：CACHE_*。返回遇到非法取值时的错误（首个）。
func ApplyEnv(cfg *CacheConfig) error {
	if v, ok := os.LookupEnv("CACHE_MODE"); ok && v != "" {
		cfg.Mode = CacheMode(strings.TrimSpace(v))
	}
	if v, ok := os.LookupEnv("CACHE_REDIS_ENABLED"); ok && v != "" {
		b, err := parseBoolEnv("CACHE_REDIS_ENABLED", v)
		if err != nil {
			return err
		}
		cfg.Redis.Enabled = b
	}
	if v, ok := os.LookupEnv("CACHE_REDIS_ADDR"); ok && v != "" {
		cfg.Redis.Addr = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("CACHE_SEMANTIC_ENABLED"); ok && v != "" {
		b, err := parseBoolEnv("CACHE_SEMANTIC_ENABLED", v)
		if err != nil {
			return err
		}
		cfg.Semantic.Enabled = b
	}
	if v, ok := os.LookupEnv("CACHE_EMBEDDER_ENDPOINT"); ok && v != "" {
		cfg.Semantic.Embedder.Endpoint = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("CACHE_EMBEDDER_MODEL"); ok && v != "" {
		cfg.Semantic.Embedder.ModelID = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("CACHE_EMBEDDER_DIM"); ok && v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return fmt.Errorf("cache: CACHE_EMBEDDER_DIM must be a positive integer, got %q", v)
		}
		cfg.Semantic.Embedder.Dim = n
	}
	if v, ok := os.LookupEnv("CACHE_VECTOR_BACKEND"); ok && v != "" {
		cfg.Semantic.Vector.Backend = strings.TrimSpace(v)
	}

	// 覆盖后仍需通过同一套校验（防止环境变量组合出非法配置）。
	if errs := cfg.Validate(); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return fmt.Errorf("cache: invalid config after env override: %s", strings.Join(msgs, "; "))
	}
	return nil
}

// parseBoolEnv 解析布尔型环境变量（接受 1/0/true/false/yes/no，大小写不敏感）。
func parseBoolEnv(name, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("cache: %s must be boolean, got %q", name, v)
	}
}
