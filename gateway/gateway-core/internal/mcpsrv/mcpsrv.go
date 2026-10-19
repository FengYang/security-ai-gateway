// Package mcpsrv：MCP 后端注册域模型与校验（P2-1 T-3 联邦目录治理，本体 §6.1/§7.2、D-4）。
//
// 定位：gateway-core 管理面内部模型——登记后端元数据（id/baseUrl/track/namespace/prefix/
// 健康状态），驱动目录重签与 `mcp_server_changed` 审计；**不代理流量**（D-2）。
// 目录内的对外摘要（mcpsec.CatalogServer）由本包映射生成（变更要求 §6.2）。
//
// 口径（U-5 默认，未决项不得静默变更，D-6）：
//   - 命名空间化：工具缺省 Namespace ＝ 该 server 的 Prefix（"工具默认以 server 前缀命名空间化"）；
//     对外命名空间名 = "<prefix>__<name>"（`__` 分隔，C-MCP-1 §6.3 D-3/A-1）；
//   - 冲突裁决：前缀/生效命名空间排他 + 目录内命名空间名去重，冲突即校验拒绝（fail-closed）。
package mcpsrv

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"security-ai-gateway/gateway/mcpsec"
)

// 取值域（fail-closed：未知取值即校验拒绝）。
const (
	// TrackPublic 非敏感轨；TrackSecure 敏感轨（空值视同 secure，与 mcpsec 同口径）。
	TrackPublic = mcpsec.TrackPublic
	TrackSecure = mcpsec.TrackSecure

	// Health 健康状态登记值（实际探活归运维，本域只如实记录；缺省 unknown）。
	HealthUnknown   = "unknown"
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
)

var (
	idRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{0,62}$`)
	prefixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{0,31}$`)
)

// ValidNamespace 命名空间/前缀格式判据（同注册域 prefix 规则：^[a-z0-9][a-z0-9-]{0,31}$）。
// 禁 `_` ⇒ "<namespace>__<name>" 首个 `__` 即分隔符，命名空间名可无损解析（C-MCP-1 D-3）。
func ValidNamespace(s string) bool { return prefixRe.MatchString(s) }

// Server 后端注册条目（gateway-core /tools/servers* 管理域，D-4）。
type Server struct {
	ID        string `json:"id"`
	BaseURL   string `json:"base_url"`            // 规范化：http(s)、无 userinfo/query/fragment、去尾斜杠
	Track     string `json:"track,omitempty"`     // "public"|"secure"；空值视同 secure（fail-closed）
	Namespace string `json:"namespace,omitempty"` // 命名空间标签（缺省 = Prefix）；排他
	Prefix    string `json:"prefix"`              // 工具名前缀（命名空间化来源；排他）
	Health    string `json:"health,omitempty"`    // unknown|healthy|unhealthy（缺省 unknown）
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// EffectiveTrack 有效分轨：空值 ⇒ secure（与 TableTool.ToolTrack 同口径，消费点统一经此读取）。
func (s *Server) EffectiveTrack() string {
	if s.Track == "" {
		return TrackSecure
	}
	return s.Track
}

// EffectiveNamespace 生效命名空间：显式 Namespace 优先，缺省 = Prefix。
// 工具缺省命名空间化直接取 Prefix（本体 §7.2 T-3 步骤③），本方法用于登记域排他与展示。
func (s *Server) EffectiveNamespace() string {
	if s.Namespace != "" {
		return s.Namespace
	}
	return s.Prefix
}

// NormalizeBaseURL 校验并规范化 base_url（**凭据零容忍**：userinfo/query 可能夹带凭据，
// 明文登记与入审计均不可接受 → 一律拒绝；尾斜杠归一，host 小写）。
func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("base_url 非法: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("base_url 仅支持 http/https（got %q）", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("base_url 缺少主机")
	}
	if u.User != nil {
		return "", fmt.Errorf("base_url 禁止携带 userinfo（凭据不得明文登记/入审计）")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("base_url 禁止携带 query（易夹带凭据；凭据请走独立通道）")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("base_url 禁止携带 fragment")
	}
	return scheme + "://" + strings.ToLower(u.Host) + strings.TrimRight(u.Path, "/"), nil
}

// Validate 校验登记条目（就地规范化 base_url、补健康状态缺省）。fail-closed：任一不合法即拒绝。
func Validate(s *Server) error {
	if !idRe.MatchString(s.ID) {
		return fmt.Errorf("id 非法（须 ^[a-z0-9][a-z0-9.-]{0,62}$）: %q", s.ID)
	}
	nu, err := NormalizeBaseURL(s.BaseURL)
	if err != nil {
		return err
	}
	s.BaseURL = nu
	switch s.Track {
	case "", TrackPublic, TrackSecure:
	default:
		return fmt.Errorf("track 仅支持 public|secure（空值视同 secure）: %q", s.Track)
	}
	if !prefixRe.MatchString(s.Prefix) {
		return fmt.Errorf("prefix 非法（须 ^[a-z0-9][a-z0-9-]{0,31}$）: %q", s.Prefix)
	}
	if s.Namespace != "" && !prefixRe.MatchString(s.Namespace) {
		return fmt.Errorf("namespace 非法（同 prefix 规则）: %q", s.Namespace)
	}
	switch s.Health {
	case "", HealthUnknown, HealthHealthy, HealthUnhealthy:
	default:
		return fmt.Errorf("health 仅支持 unknown|healthy|unhealthy（空值缺省 unknown）: %q", s.Health)
	}
	if s.Health == "" {
		s.Health = HealthUnknown
	}
	return nil
}

// CheckConflicts 注册域排他校验（U-5 默认：前缀命名空间 + 校验拒绝冲突）。
// 候选与**其它** id 的 prefix 或生效命名空间撞车即拒绝；自身 id 更新放行（迁移）。
func CheckConflicts(list []*Server, cand *Server) error {
	for _, e := range list {
		if e.ID == cand.ID {
			continue
		}
		if e.Prefix == cand.Prefix {
			return fmt.Errorf("prefix 冲突：后端 %q 已占用 %q（U-5 默认：前缀命名空间 + 校验拒绝冲突）", e.ID, cand.Prefix)
		}
		if e.EffectiveNamespace() == cand.EffectiveNamespace() {
			return fmt.Errorf("命名空间冲突：后端 %q 已占用 %q（U-5 默认：前缀命名空间 + 校验拒绝冲突）", e.ID, cand.EffectiveNamespace())
		}
	}
	return nil
}

// SummaryLine 审计摘要（不含凭据；base_url 已规范化）。供 mcp_server_changed 事件旧/新值。
func SummaryLine(s *Server) string {
	return fmt.Sprintf("track=%s prefix=%s namespace=%s base_url=%s",
		s.EffectiveTrack(), s.Prefix, s.EffectiveNamespace(), s.BaseURL)
}

// Summaries 注册域 → 目录摘要（id 字典序，确定性输出；供 ToolCatalog.Servers 重签）。
func Summaries(list []*Server) []mcpsec.CatalogServer {
	out := make([]mcpsec.CatalogServer, 0, len(list))
	for _, s := range list {
		out = append(out, mcpsec.CatalogServer{ID: s.ID, BaseURL: s.BaseURL, Track: s.Track, Prefix: s.Prefix})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
