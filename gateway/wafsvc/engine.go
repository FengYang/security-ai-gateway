// Package wafsvc — 明文 Provider 入口 WAF 过滤服务（M3-1，技术实现方案 §2）。
//
// 形态：独立 sidecar（in-process Coraza v3.8.1 + OWASP CRS 4.25.0），一期不碰
// Higress 插件链本体（P1-8 红线：deploy/higress/* 与 otpmask-plugin 只读不动）。
// 防护边界：仅明文 Provider 入口 `/provider/<name>/...`；密态路径仅元数据防护不变。
//
// 许可登记：Coraza Apache-2.0；OWASP CRS 4.25.0 **Apache-2.0**（CRS 4.x 起为 ASLv2，
// 非技术方案 §2.4 表格所写的 CC-BY-SA 3.0——那是 CRS 3.x 口径；规则集数据随 Go 模块
// github.com/corazawaf/coraza-coreruleset/v4 内嵌发布，署名与校验和见
// deploy/security/waf/crs-manifest.yaml）。禁止引入 AGPL/GPL/SSPL/BUSL 引擎。
//
// 安装期参数（参数名·默认值·覆写点·未填行为）：
//   - WAF_MODE·detection·env/租户策略·未填=检测模式（命中告警不阻断）；off 全局关闭
//   - WAF_CRS_VERSION·4.25.0·env·未填=内置登记版本；与内嵌版本不符 fail-closed 拒绝启动
//   - WAF_PARANOIA_LEVEL·1·env·未填=PL1；越界 fail-closed 拒绝启动
//   - WAF_BODY_MAX_BYTES·262144·env·未填=默认值；超限跳过 body 检查（不丢弃请求）
//   - WAF_EXCLUDES_PATH·空·env·未填=无排除项；文件非法 fail-closed 拒绝启动
//   - WAF_FAIL_MODE·auto·env·未填=按 WAF_MODE 联动（检测→放行+告警；阻断→403）
//
// 性能红线（§2.5 实测教训）：不在请求路径做规则解析/加载；引擎只读热路径，
// 规则集仅启动/Reload 时构建；body 检查有硬上限；无轮询空转。
package wafsvc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

// 版本定版（安装期 WAF_CRS_VERSION 必须与之匹配；升级走规则集变更评审 + 重登记校验和）。
const (
	CorazaVersion = "3.8.1"
	CRSVersion    = "4.25.0"
)

// WafAction 决策动作（WafDecision.Action）。
const (
	WafActionAllow  = "allow"
	WafActionDetect = "detect"
	WafActionBlock  = "block"
)

// WafRequest 已抽取的请求切片（引擎与 HTTP 层解耦）。
type WafRequest struct {
	Method  string
	URI     string // path + RawQuery
	Host    string
	Headers map[string][]string
	GetArgs map[string][]string
	Body    []byte
	Tenant  string
	Path    string // 纯路径，供排除表 location 正则匹配
}

// WafDecision 单请求决策。
type WafDecision struct {
	Action  string   // "allow" | "detect" | "block"
	RuleIDs []string // 命中（且未被排除）的 CRS 攻击规则 ID
	Score   int      // 可观测近似分：命中攻击规则数 × 5（CRS critical 分值）；
	// ⚠ 不参与阻断判定——阻断由 Coraza 中断/模式决定，避免自造异常评分语义。
	Version string // 引擎+规则集版本（进指标与审计）
}

// WafExclusion 租户排除项（误杀调优通道，§2.2）。
type WafExclusion struct {
	Tenant   string `json:"tenant"`   // 具体租户或 "*"（全体）
	Location string `json:"location"` // path 正则（空 = 全路径）
	RuleID   string `json:"rule_id"`  // 规则 ID 或 "all"（慎用，须留 reason）
	Reason   string `json:"reason"`   // "all" 时必填
}

// RuleSetBundle 规则集/排除表换入载荷（Reload 原子换入）。
type RuleSetBundle struct {
	Paranoia int
	Excludes []WafExclusion
}

// WafEngine 与具体引擎解耦的最小接口（§2.2 接口冻结基线）。
type WafEngine interface {
	Eval(r WafRequest) (WafDecision, error)
	Reload(bundle RuleSetBundle) error
	Version() string // 引擎+规则集版本（进指标与审计）
}

// wafState 一次规则集构建的不可变快照（atomic.Pointer 换入，评估无锁读）。
type wafState struct {
	waf      coraza.WAF
	version  string
	checksum string // 内嵌 CRS 规则集 sha256（hex）
	paranoia int
	excludes []WafExclusion
}

// corazaEngine Coraza 实现。
type corazaEngine struct {
	cur      atomic.Pointer[wafState]
	mode     string // detection | blocking
	bodyMax  int
	checksum string
}

// NewEngine 构建引擎并加载内嵌 CRS（fail-closed：任何加载错误返回 error，调用方拒绝启动）。
func NewEngine(cfg Config) (*corazaEngine, error) {
	sum, err := crsChecksum()
	if err != nil {
		return nil, fmt.Errorf("wafsvc: CRS 校验和计算失败: %w", err)
	}
	e := &corazaEngine{mode: cfg.Mode, bodyMax: cfg.BodyMaxBytes, checksum: sum}
	if err := e.Reload(RuleSetBundle{Paranoia: cfg.Paranoia, Excludes: cfg.Excludes}); err != nil {
		return nil, err
	}
	return e, nil
}

// crsChecksum 对 coreruleset.FS 内全部文件按路径排序做流式 sha256（版本固定 + 变更可检出）。
func crsChecksum() (string, error) {
	h := sha256.New()
	var paths []string
	err := fs.WalkDir(coreruleset.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
		b, err := fs.ReadFile(coreruleset.FS, p)
		if err != nil {
			return "", err
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// directives 构造 Coraza 指令串：CRS 全量规则 + 引擎模式 + paranoia level。
func directives(mode string, paranoia int) string {
	engine := "DetectionOnly"
	if mode == "blocking" {
		engine = "On"
	}
	return strings.Join([]string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"Include @owasp_crs/*.conf",
		"SecRuleEngine " + engine,
		"SecRequestBodyAccess On",
		fmt.Sprintf(`SecAction "id:900001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d"`, paranoia),
	}, "\n") + "\n"
}

// validateExclude 排除项合法性（location 正则须可编译；"all" 须留 reason）。
func validateExclude(x WafExclusion) error {
	if strings.TrimSpace(x.Tenant) == "" {
		return fmt.Errorf("tenant 为空")
	}
	if x.Location != "" {
		if _, err := regexp.Compile(x.Location); err != nil {
			return fmt.Errorf("location 正则 %q 非法: %w", x.Location, err)
		}
	}
	if x.RuleID == "" {
		return fmt.Errorf("rule_id 为空")
	}
	if x.RuleID != "all" {
		if _, err := strconv.Atoi(x.RuleID); err != nil {
			return fmt.Errorf("rule_id %q 非数字且非 all", x.RuleID)
		}
	} else if strings.TrimSpace(x.Reason) == "" {
		return fmt.Errorf("rule_id=all 必须填写 reason（调优良性须留痕）")
	}
	return nil
}

// Reload 原子换入新规则集/排除表（评估中请求继续用旧集；构建失败保持旧集）。
func (e *corazaEngine) Reload(bundle RuleSetBundle) error {
	if bundle.Paranoia < 1 || bundle.Paranoia > 4 {
		return fmt.Errorf("wafsvc: paranoia level %d 越界（允许 1..4）", bundle.Paranoia)
	}
	for _, x := range bundle.Excludes {
		if err := validateExclude(x); err != nil {
			return fmt.Errorf("wafsvc: 排除项非法: %w", err)
		}
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives(e.mode, bundle.Paranoia)))
	if err != nil {
		return fmt.Errorf("wafsvc: 规则集加载失败（保持旧集）: %w", err)
	}
	xsum := sha256.New()
	for _, x := range bundle.Excludes {
		fmt.Fprintf(xsum, "%s|%s|%s|%s\n", x.Tenant, x.Location, x.RuleID, x.Reason)
	}
	ver := fmt.Sprintf("coraza-%s/crs-%s/pl%d/rules-%s/excl-%s",
		CorazaVersion, CRSVersion, bundle.Paranoia, e.checksum[:12], hex.EncodeToString(xsum.Sum(nil))[:8])
	e.cur.Store(&wafState{
		waf: waf, version: ver, checksum: e.checksum,
		paranoia: bundle.Paranoia, excludes: append([]WafExclusion(nil), bundle.Excludes...),
	})
	return nil
}

// Version 当前引擎+规则集版本。
func (e *corazaEngine) Version() string {
	if s := e.cur.Load(); s != nil {
		return s.version
	}
	return ""
}

// Checksum 内嵌 CRS 规则集校验和（部署登记与对账用）。
func (e *corazaEngine) Checksum() string { return e.checksum }

// isAttackRule CRS 攻击规则识别：tags 带 "attack-" 前缀（排除 901xxx 初始化/PL 标记等恒命中期）。
func isAttackRule(tags []string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, "attack-") {
			return true
		}
	}
	return false
}

// excluded 判断某规则 ID 是否被租户/路径级排除项命中。
func excluded(st *wafState, tenant, path, ruleID string) bool {
	for _, x := range st.excludes {
		if x.Tenant != "*" && x.Tenant != tenant {
			continue
		}
		if x.Location != "" {
			re, err := regexp.Compile(x.Location)
			if err != nil || !re.MatchString(path) {
				continue
			}
		}
		if x.RuleID == "all" || x.RuleID == ruleID {
			return true
		}
	}
	return false
}

// Eval 评估单个请求：phase:1（headers/URI）+ phase:2（GET/POST 参数与 body，
// 无 body 也必须调用 ProcessRequestBody 才跑 CRS phase:2 规则）。
func (e *corazaEngine) Eval(r WafRequest) (WafDecision, error) {
	st := e.cur.Load()
	if st == nil {
		return WafDecision{}, fmt.Errorf("wafsvc: 引擎未加载")
	}
	dec := WafDecision{Action: WafActionAllow, Version: st.version}

	tx := st.waf.NewTransaction()
	defer tx.Close()

	u, err := url.ParseRequestURI(r.URI)
	if err != nil {
		return dec, fmt.Errorf("wafsvc: URI 解析失败: %w", err)
	}
	tx.ProcessURI(r.URI, nonempty(r.Method, "GET"), "HTTP/1.1")
	for k, vs := range r.GetArgs {
		for _, v := range vs {
			tx.AddGetRequestArgument(k, v)
		}
	}
	host := r.Host
	if host == "" {
		host = u.Host
	}
	if host == "" {
		host = "unknown"
	}
	tx.AddRequestHeader("Host", host)
	for k, vs := range r.Headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	body := r.Body
	inspectBody := len(body) <= e.bodyMax
	if !inspectBody {
		body = nil // §2.5：超限跳过 body 检查（不丢弃请求，filter 负责还原）
	}
	// CRS 920180 会因缺 Content-Length 误报协议攻击，统一显式给出长度。
	tx.AddRequestHeader("Content-Length", strconv.Itoa(len(body)))

	it := tx.ProcessRequestHeaders()
	if it == nil && inspectBody && len(body) > 0 {
		if _, _, err := tx.WriteRequestBody(body); err != nil {
			return dec, fmt.Errorf("wafsvc: 写请求体失败: %w", err)
		}
	}
	it2, err := tx.ProcessRequestBody()
	if err != nil {
		return dec, fmt.Errorf("wafsvc: 请求体处理失败: %w", err)
	}
	interrupted := it != nil || it2 != nil

	seen := map[string]bool{}
	for _, m := range tx.MatchedRules() {
		if !isAttackRule(m.Rule().Tags()) {
			continue
		}
		id := strconv.Itoa(m.Rule().ID())
		if seen[id] || excluded(st, r.Tenant, r.Path, id) {
			continue
		}
		seen[id] = true
		dec.RuleIDs = append(dec.RuleIDs, id)
	}
	sort.Strings(dec.RuleIDs)
	dec.Score = len(dec.RuleIDs) * 5 // 近似分，仅可观测

	switch {
	case len(dec.RuleIDs) == 0:
		dec.Action = WafActionAllow
	case e.mode == "blocking" && interrupted:
		dec.Action = WafActionBlock
	default:
		dec.Action = WafActionDetect
	}
	return dec, nil
}

func nonempty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
