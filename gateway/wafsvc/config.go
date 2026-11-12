package wafsvc

// config.go — M3-1 安装期参数（技术方案 §2.6；四要素：参数名·默认值·覆写点·未填行为）。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WafMode 取值。
const (
	ModeOff       = "off"
	ModeDetection = "detection"
	ModeBlocking  = "blocking"
)

// Config 安装期参数集合（全部可经 env 覆写；未填一律走缺省，不等客户确认）。
type Config struct {
	Mode         string // WAF_MODE·detection·env·未填=检测模式（命中告警不阻断）
	CRSVersion   string // WAF_CRS_VERSION·4.25.0·env·未填=内置登记版本
	Paranoia     int    // WAF_PARANOIA_LEVEL·1·env·未填=PL1
	BodyMaxBytes int    // WAF_BODY_MAX_BYTES·262144·env·未填=默认值
	ExcludesPath string // WAF_EXCLUDES_PATH·空·env·未填=无排除项
	Excludes     []WafExclusion
	FailMode     string // WAF_FAIL_MODE·auto·env·未填=按 WAF_MODE 联动
}

// DefaultConfig 缺省配置（检测模式、PL1、256KB body 上限、无排除项）。
func DefaultConfig() Config {
	return Config{
		Mode: ModeDetection, CRSVersion: CRSVersion, Paranoia: 1,
		BodyMaxBytes: 262144, FailMode: "auto",
	}
}

// ConfigFromEnv 解析安装期参数并校验（非法值 fail-closed 返回 error，调用方拒绝启动）。
func ConfigFromEnv() (Config, error) {
	c := DefaultConfig()
	if v := strings.TrimSpace(os.Getenv("WAF_MODE")); v != "" {
		c.Mode = v
	}
	switch c.Mode {
	case ModeOff, ModeDetection, ModeBlocking:
	default:
		return c, fmt.Errorf("wafsvc: WAF_MODE %q 非法（off|detection|blocking）", c.Mode)
	}
	if v := strings.TrimSpace(os.Getenv("WAF_CRS_VERSION")); v != "" {
		c.CRSVersion = v
	}
	if c.CRSVersion != CRSVersion {
		return c, fmt.Errorf("wafsvc: WAF_CRS_VERSION %q 与内嵌定版 %q 不符（升级须走规则集变更评审并重登记校验和）", c.CRSVersion, CRSVersion)
	}
	if v := strings.TrimSpace(os.Getenv("WAF_PARANOIA_LEVEL")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 4 {
			return c, fmt.Errorf("wafsvc: WAF_PARANOIA_LEVEL %q 非法（1..4）", v)
		}
		c.Paranoia = n
	}
	if v := strings.TrimSpace(os.Getenv("WAF_BODY_MAX_BYTES")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return c, fmt.Errorf("wafsvc: WAF_BODY_MAX_BYTES %q 非法（正整数）", v)
		}
		c.BodyMaxBytes = n
	}
	if v := strings.TrimSpace(os.Getenv("WAF_FAIL_MODE")); v != "" {
		c.FailMode = v
	}
	switch c.FailMode {
	case "auto", "open", "block":
	default:
		return c, fmt.Errorf("wafsvc: WAF_FAIL_MODE %q 非法（auto|open|block）", c.FailMode)
	}
	c.ExcludesPath = strings.TrimSpace(os.Getenv("WAF_EXCLUDES_PATH"))
	if c.ExcludesPath != "" {
		xs, err := LoadExcludes(c.ExcludesPath)
		if err != nil {
			return c, err
		}
		c.Excludes = xs
	}
	return c, nil
}

// LoadExcludes 读取并校验排除表 JSON（安装期受配置文件；变更须落审计）。
// 形如：[{"tenant":"acme","location":"/provider/openai/.*","rule_id":"942190","reason":"LLM 提示词含 SQL 术语"}]
func LoadExcludes(path string) ([]WafExclusion, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("wafsvc: WAF_EXCLUDES_PATH 须为绝对路径（受信安装输入）: %q", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wafsvc: 排除表读取失败: %w", err)
	}
	var xs []WafExclusion
	if err := json.Unmarshal(b, &xs); err != nil {
		return nil, fmt.Errorf("wafsvc: 排除表 JSON 解析失败: %w", err)
	}
	for i, x := range xs {
		if err := validateExclude(x); err != nil {
			return nil, fmt.Errorf("wafsvc: 排除项[%d] 非法: %w", i, err)
		}
	}
	return xs, nil
}
