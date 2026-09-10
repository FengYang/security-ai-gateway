// Package main — 配置加载。
//
// 管理门户业务服务（gateway-admin-service）配置一律经环境变量注入
// （docs/管理门户-细化方案.md §3.2：ConfigMap/Secret + 环境变量），不读本地文件。
//
// M2 A-1 追加：broker 凭据目录（文件 Secret 源，见 broker_secret.go）与
// 最小角色控制白名单（ADMIN_SVC_ROLE_ADMINS，见 auth.go）。
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// config 运行配置（env 注入，带默认值；密钥类无默认，缺失即拒绝启动 = fail-closed）。
type config struct {
	listen      string              // 监听地址
	jwtSecret   []byte              // 内部服务令牌共享密钥（Java 控制台 ↔ Go 服务，来自 Secret）
	jwtIssuer   string              // 允许的签发方（缺省 higress-console）
	jwtAudience string              // 本服务 audience（缺省 gateway-admin-service）
	roleAdmins  map[string]struct{} // 最小角色控制（M2 §2.4）：写权限用户名白名单
}

// defaultIssuer / defaultAudience 内部令牌的签发方与本服务受众默认值。
const (
	defaultIssuer   = "higress-console"
	defaultAudience = "gateway-admin-service"
)

// loadConfig 从环境变量加载配置。
func loadConfig() (*config, error) {
	secret := os.Getenv("ADMIN_SVC_JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("配置缺失：ADMIN_SVC_JWT_SECRET 未设置（内部服务令牌共享密钥，禁止空密钥启动）")
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("配置错误：ADMIN_SVC_JWT_SECRET 过短（<16 字节）")
	}

	issuer := os.Getenv("ADMIN_SVC_JWT_ISSUER")
	if issuer == "" {
		issuer = defaultIssuer
	}
	audience := os.Getenv("ADMIN_SVC_JWT_AUD")
	if audience == "" {
		audience = defaultAudience
	}
	listen := os.Getenv("ADMIN_SVC_LISTEN")
	if listen == "" {
		listen = ":19095"
	}

	return &config{
		listen:      listen,
		jwtSecret:   []byte(secret),
		jwtIssuer:   issuer,
		jwtAudience: audience,
		roleAdmins:  parseRoleAdmins(os.Getenv("ADMIN_SVC_ROLE_ADMINS")),
	}, nil
}

// parseRoleAdmins 解析管理员用户名白名单（逗号分隔；空白项忽略）。
//
// 最小角色控制（M2 §2.4，S-1 定案）：命中 → role=admin（可写凭据），
// 否则 role=auditor（只读）。未配置 = 空集合 = **无人可写**（fail-closed）。
func parseRoleAdmins(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		if name := strings.TrimSpace(item); name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

// ---------- broker（apiTokens Secret 化，路线丙）----------
//
// 设计：docs/管理门户-apiTokens-Secret化方案设计.md §4.2（M1）；
// M2 A-1 追加文件凭据源与热加载：docs/管理门户-apiTokens-Secret化-M2细化方案.md §2.1.5。
// provider 的 openaiCustomUrl 指向 /llm-broker/{provider}/...，CR 不含任何 token；
// Key 经 env / 凭据目录进入本进程内存，绝不落日志。

// defaultBrokerPathPrefixes allowPathPrefixes 缺省最小集（S-1：fail-closed 收窄滥用面）。
var defaultBrokerPathPrefixes = []string{"/v1/chat/completions", "/v1/models", "/v1/embeddings"}

// brokerProvider 单个 broker 托管厂商。
type brokerProvider struct {
	upstream          *url.URL // 厂商上游（scheme://host[:port][/base]）
	key               []byte   // 厂商 API Key（env/Secret 注入；禁止进入日志/错误信息/序列化）
	allowPathPrefixes []string // 中转路径白名单（S-1 处置；缺省 = defaultBrokerPathPrefixes）
}

// brokerConfig broker 整体配置；未启用时为 nil（特性关闭，零影响既有行为）。
type brokerConfig struct {
	providers map[string]*brokerProvider
}

// brokerEntryJSON ADMIN_BROKER_PROVIDERS_JSON 的单 provider 条目。
type brokerEntryJSON struct {
	Upstream          string   `json:"upstream"`
	AllowPathPrefixes []string `json:"allowPathPrefixes"`
}

// loadBrokerConfig 解析 broker 配置（env 注入，fail-closed）。
//
// ADMIN_BROKER_PROVIDERS_JSON 形如：
//
//		{"phala":{"upstream":"https://inference.phala.com","allowPathPrefixes":["/v1/chat/completions"]}}
//
//	  - 未设置 = 特性关闭（返回 nil，不注册端点，既有行为零影响）；
//	  - JSON 非法 / 上游缺 scheme / provider 已声明但 ADMIN_BROKER_KEY_<NAME> 缺失
//	    = 拒绝启动（fail-closed，与 ADMIN_SVC_JWT_SECRET 同策略）。
func loadBrokerConfig() (*brokerConfig, error) {
	raw := os.Getenv("ADMIN_BROKER_PROVIDERS_JSON")
	if raw == "" {
		return nil, nil
	}

	var entries map[string]brokerEntryJSON
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("ADMIN_BROKER_PROVIDERS_JSON 解析失败: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("ADMIN_BROKER_PROVIDERS_JSON 已设置但不含任何 provider（fail-closed）")
	}

	providers := make(map[string]*brokerProvider, len(entries))
	for name, e := range entries {
		if err := validateProviderName(name); err != nil {
			return nil, err
		}
		u, prefixes, err := parseProviderEntry(name, e.Upstream, e.AllowPathPrefixes)
		if err != nil {
			return nil, err
		}
		envKey := "ADMIN_BROKER_KEY_" + strings.ToUpper(name)
		key := os.Getenv(envKey)
		if key == "" {
			return nil, fmt.Errorf("配置缺失：%s 未设置（provider %s 已声明，fail-closed 拒绝启动）", envKey, name)
		}
		if err := validateProviderKey(name, key); err != nil {
			return nil, err
		}
		providers[name] = &brokerProvider{upstream: u, key: []byte(key), allowPathPrefixes: prefixes}
	}
	return &brokerConfig{providers: providers}, nil
}

// ---------- broker 凭据目录（M2 A-1：文件 Secret 源 + 热加载）----------

// defaultBrokerSecretsDir 凭据文件目录缺省值（deploy/secrets/ 整目录已 gitignore）。
const defaultBrokerSecretsDir = "deploy/secrets/broker-providers"

// brokerSettings broker 文件源配置（M2 A-1）。
type brokerSettings struct {
	secretsDir string // 凭据目录（存在即接管；目录内每 provider 一个 .env）
	publicBase string // broker 对外基址（生成 customUrl；broker 启用时必填）
	crFile     string // ai-proxy CR 文件路径（可选；设置后启用漂移检测）
}

// loadBrokerSettings 解析 broker 文件源配置（env 注入，均带缺省）。
func loadBrokerSettings() *brokerSettings {
	s := &brokerSettings{
		secretsDir: os.Getenv("ADMIN_BROKER_SECRETS_DIR"),
		publicBase: strings.TrimRight(os.Getenv("ADMIN_BROKER_PUBLIC_BASE"), "/"),
		crFile:     os.Getenv("ADMIN_BROKER_CR_FILE"),
	}
	if s.secretsDir == "" {
		s.secretsDir = defaultBrokerSecretsDir
	}
	return s
}

// openBrokerConfig 装配 broker 配置：**凭据目录存在即接管**（含"目录为空 = 0 provider"，
// 不再合并环境变量，避免删除后被 env 复活），否则回落 M1 环境变量路径。
//
// fromDir 表示配置源，热加载仅在目录模式下启用。
func openBrokerConfig(s *brokerSettings) (cfg *brokerConfig, fromDir bool, err error) {
	if fi, statErr := os.Stat(s.secretsDir); statErr == nil && fi.IsDir() {
		cfg, err = loadBrokerConfigFromDir(s.secretsDir)
		return cfg, true, err
	}
	cfg, err = loadBrokerConfig()
	return cfg, false, err
}

// ---------- 校验（env 与目录两种来源共用，保证同规则）----------

// validateProviderName 校验 provider 名：小写字母/数字/连字符，首字符非连字符，长度 ≤32。
func validateProviderName(name string) error {
	if name == "" {
		return fmt.Errorf("broker provider 名称为空（fail-closed）")
	}
	if len(name) > maxProviderNameLen {
		return fmt.Errorf("broker provider 名称过长（>%d）: %q", maxProviderNameLen, name)
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return fmt.Errorf("broker provider 名称非法（仅小写字母/数字/连字符，且不以连字符开头）: %q", name)
		}
	}
	return nil
}

// validateProviderKey 校验 Key 长度（防 DoS 上限 / 防误填空值静默生效）。
func validateProviderKey(name, key string) error {
	if len(key) < minProviderKeyLen {
		return fmt.Errorf("broker provider %s key 过短（<%d 字节）", name, minProviderKeyLen)
	}
	if len(key) > maxProviderKeyLen {
		return fmt.Errorf("broker provider %s key 过长（>%d 字节）", name, maxProviderKeyLen)
	}
	return nil
}

// parseProviderEntry 解析并校验 upstream 与路径白名单（两种来源共用）。
func parseProviderEntry(name, upstream string, prefixes []string) (*url.URL, []string, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("broker provider %s upstream 解析失败: %w", name, err)
	}
	// 默认仅允许 https（http 留待显式放开；本地演示可经 ADMIN_BROKER_ALLOW_HTTP=true 开启）
	if u.Scheme != "https" && !(u.Scheme == "http" && allowBrokerHTTP) {
		return nil, nil, fmt.Errorf("broker provider %s upstream 必须为 https://host 形态: %q", name, upstream)
	}
	if u.Host == "" {
		return nil, nil, fmt.Errorf("broker provider %s upstream 缺少 host: %q", name, upstream)
	}

	if len(prefixes) == 0 {
		prefixes = defaultBrokerPathPrefixes
	}
	if len(prefixes) > maxPathPrefixes {
		return nil, nil, fmt.Errorf("broker provider %s allowPathPrefixes 项数过多（>%d）", name, maxPathPrefixes)
	}
	norm := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if !strings.HasPrefix(p, "/") {
			return nil, nil, fmt.Errorf("broker provider %s allowPathPrefixes 必须以 / 开头: %q", name, p)
		}
		if strings.Contains(p, "..") {
			return nil, nil, fmt.Errorf("broker provider %s allowPathPrefixes 不得含 .. : %q", name, p)
		}
		if len(p) > maxPathPrefixLen {
			return nil, nil, fmt.Errorf("broker provider %s allowPathPrefixes 过长（>%d）: %q", name, maxPathPrefixLen, p)
		}
		if p != "/" { // 去尾部 /，保证精确/子路径匹配语义一致
			p = strings.TrimRight(p, "/")
		}
		norm = append(norm, p)
	}
	return u, norm, nil
}
