// Package auditexport — 审计链导出端点的公共安全边界与 NDJSON 输出（P2-4 T-4.2 / T-4.1 聚合侧）。
//
// 定位：core（gateway-core 策略变更链）与 tee（tee-infer-service 审计链）两条链
// 的导出端点**同构**（同一路径口径、同一 NDJSON 输出、同一套安全边界），
// 便于 T-4.1 跨集群聚合侧统一处理。
//
// 安全边界（S1(6)）：
//  1. 默认关闭：端点仅在显式开关启用时注册/放行（未启用 = 404，零新增攻击面）；
//  2. 授权钩子：Authorizer 接口，**默认实现 deny-all**；真实实现由 T-2.3
//     （集群身份凭证：签发/校验/轮换/吊销）注入，本包不实现凭证本身；
//  3. 网络边界：来源 IP CIDR 白名单，**空 = 不允许任何来源**（fail-closed）；
//     来源 IP 只取 RemoteAddr，不信任 X-Forwarded-For 等可伪造头。
//
// 只读语义：本包只做输出与门控，不触碰任何链状态（导出不得污染 WORM 链）。
package auditexport

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// DefaultMaxLimit 单次导出行数默认上限（防超大响应拖垮控制面/推理面）。
const DefaultMaxLimit = 100000

// HeaderPrefix 导出元信息响应头前缀（body 保持纯 NDJSON，元信息一律走响应头）。
const HeaderPrefix = "X-Audit-Export-"

// ErrDisabled 端点未启用（调用方应返回 404：不注册/不放行）。
var ErrDisabled = errors.New("auditexport: 端点未启用")

// Authorizer 导出端点授权钩子（**T-2.3 集群身份凭证接线点**）。
//
// 语义：Authorize 返回 nil = 放行；返回 error = 拒绝（调用方一律 403，
// 且不向客户端回显具体原因，避免授权实现细节外泄）。
//
// 默认实现：DenyAllAuthorizer（deny-all，fail-closed）。
// 后续接线：由 T-2.3 集群身份凭证（签发/校验/轮换/吊销）提供实现，
// 经 Config.Authorizer 注入；**本任务不实现凭证本身**，故默认一律拒绝。
type Authorizer interface {
	Authorize(r *http.Request) error
}

// DenyAllAuthorizer 默认授权实现：一律拒绝。
type DenyAllAuthorizer struct{}

// Authorize 实现 Authorizer（deny-all）。
func (DenyAllAuthorizer) Authorize(_ *http.Request) error {
	return errors.New("授权未配置（默认 deny-all；T-2.3 集群身份凭证就绪后注入真实实现）")
}

// TokenAuthorizer 静态 Bearer 令牌授权（**临时联调口径，非 T-2.3 凭证实现**）。
//
// 用途：T-2.3 落地前供 T-4.1 聚合侧联调抓取；令牌为空即一律拒绝（fail-closed）。
// 令牌比较经 ConstantTimeCompare（防时序侧信道）。
type TokenAuthorizer struct {
	Token string
}

// Authorize 实现 Authorizer（Bearer 静态令牌；空令牌拒绝）。
func (a TokenAuthorizer) Authorize(r *http.Request) error {
	if a.Token == "" {
		return errors.New("静态令牌未配置（拒绝）")
	}
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, "Bearer ") {
		return errors.New("缺少 Bearer 令牌")
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(got, "Bearer ")), []byte(a.Token)) != 1 {
		return errors.New("令牌不匹配")
	}
	return nil
}

// FuncAuthorizer 函数式授权适配器（便于单测/后续接线注入）。
type FuncAuthorizer func(r *http.Request) error

// Authorize 实现 Authorizer。
func (f FuncAuthorizer) Authorize(r *http.Request) error { return f(r) }

// SourceWhitelist 来源 IP 白名单（CIDR 列表）。
//
// ⚠️ fail-closed 口径：**空白名单 = 不允许任何来源**（配置遗漏不得变成放开）。
type SourceWhitelist struct {
	nets []*net.IPNet
}

// NewSourceWhitelist 解析 CIDR 列表；任一非法即返回错误（调用方须 fail-closed，
// 不得静默忽略后放行）。
func NewSourceWhitelist(cidrs []string) (*SourceWhitelist, error) {
	w := &SourceWhitelist{}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("auditexport: 来源白名单 CIDR 非法 %q: %w", raw, err)
		}
		w.nets = append(w.nets, n)
	}
	return w, nil
}

// Allows 判定 IP 是否在白名单内（nil/空白名单恒 false）。
func (w *SourceWhitelist) Allows(ip net.IP) bool {
	if w == nil || len(w.nets) == 0 {
		return false
	}
	if ip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Empty 返回白名单是否为空（空 = 拒绝所有来源）。
func (w *SourceWhitelist) Empty() bool { return w == nil || len(w.nets) == 0 }

// ClientIP 取来源 IP：**仅**依据 RemoteAddr。
//
// 不信任 X-Forwarded-For / X-Real-IP 等可伪造头——网络边界由部署侧（Ingress/
// NetworkPolicy）保证，伪造头不得成为绕过白名单的入口。
func ClientIP(r *http.Request) (net.IP, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // 无端口形式（单测/Unix socket）
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, errors.New("auditexport: 来源地址为空")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("auditexport: 来源地址非法 %q", host)
	}
	return ip, nil
}

// Config 导出端点配置（三道门：开关 / 授权 / 来源白名单）。
type Config struct {
	// Enabled 显式开关：false（默认）= 端点未启用（404）。
	Enabled bool
	// Authorizer 授权钩子；nil = DenyAllAuthorizer（deny-all，fail-closed）。
	Authorizer Authorizer
	// Whitelist 来源 CIDR 白名单；nil 或空 = 拒绝所有来源（fail-closed）。
	Whitelist *SourceWhitelist
	// MaxLimit 单次导出行数上限；<= 0 = DefaultMaxLimit。
	MaxLimit int
}

// authorizer 归一授权器（nil → deny-all）。
func (c Config) authorizer() Authorizer {
	if c.Authorizer == nil {
		return DenyAllAuthorizer{}
	}
	return c.Authorizer
}

// maxLimit 归一上限。
func (c Config) maxLimit() int {
	if c.MaxLimit <= 0 {
		return DefaultMaxLimit
	}
	return c.MaxLimit
}

// Check 门控总入口：未启用 → ErrDisabled（404）；授权失败 / 来源不在白名单 → error（403）。
func (c Config) Check(r *http.Request) error {
	if !c.Enabled {
		return ErrDisabled
	}
	if err := c.authorizer().Authorize(r); err != nil {
		return err
	}
	ip, err := ClientIP(r)
	if err != nil {
		return err
	}
	if !c.Whitelist.Allows(ip) {
		return fmt.Errorf("auditexport: 来源 %s 不在白名单", ip)
	}
	return nil
}

// ParseLimit 解析 ?limit= 参数。
//
// 口径：空 / 0 = 全量（按 max 上限截断）；负数或非数字 = 错误（400）；
// 超过 max → 归一到 max 并返回 truncated=true。
func ParseLimit(raw string, max int) (limit int, truncated bool, err error) {
	if max <= 0 {
		max = DefaultMaxLimit
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return max, false, nil
	}
	n, perr := strconv.Atoi(raw)
	if perr != nil {
		return 0, false, fmt.Errorf("auditexport: limit 非法 %q", raw)
	}
	if n < 0 {
		return 0, false, fmt.Errorf("auditexport: limit 不得为负 %q", raw)
	}
	if n == 0 || n > max {
		return max, true, nil
	}
	return n, false, nil
}

// Meta 导出元信息（链尾/锚点），经响应头下发（body 保持纯 NDJSON）。
type Meta struct {
	Schema    string // core | tee（与 T-4.1 聚合侧 schema 口径一致）
	Events    int    // 本次导出事件数
	Total     int    // 链总长度
	PrevHash  string // 导出区间首条的前链哈希（全量导出 = ""）
	TailHash  string // 链尾哈希（本次导出末条事件哈希；空链 = ""）
	Truncated bool   // 是否因 limit 截断
	// 锚点信息（tee 侧来自锚定文件最后一条记录；core 侧无锚定文件时为零值）。
	AnchorHash     string
	AnchorAt       int64
	AnchorEvents   int
	AnchorVerified bool // 锚点链尾哈希与本次导出链尾一致
}

// WriteNDJSON 输出 NDJSON（每行一条事件，字段与 WORM 行序列化一致）+ 元信息响应头。
func WriteNDJSON(w http.ResponseWriter, lines []string, m Meta) {
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set(HeaderPrefix+"Schema", m.Schema)
	h.Set(HeaderPrefix+"Events", strconv.Itoa(m.Events))
	h.Set(HeaderPrefix+"Total", strconv.Itoa(m.Total))
	h.Set(HeaderPrefix+"Prev-Hash", m.PrevHash)
	h.Set(HeaderPrefix+"Tail-Hash", m.TailHash)
	h.Set(HeaderPrefix+"Truncated", strconv.FormatBool(m.Truncated))
	if m.AnchorHash != "" {
		h.Set(HeaderPrefix+"Anchor-Hash", m.AnchorHash)
		h.Set(HeaderPrefix+"Anchor-Timestamp", strconv.FormatInt(m.AnchorAt, 10))
		h.Set(HeaderPrefix+"Anchor-Events", strconv.Itoa(m.AnchorEvents))
		h.Set(HeaderPrefix+"Anchor-Verified", strconv.FormatBool(m.AnchorVerified))
	}
	w.WriteHeader(http.StatusOK)
	for _, l := range lines {
		_, _ = io.WriteString(w, l)
		_, _ = io.WriteString(w, "\n")
	}
}

// WriteError 输出标准错误 JSON。
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}
