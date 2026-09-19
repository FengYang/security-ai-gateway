// 输出侧内容审查配置（P-* 参数组，技术方案 §5；§3.2 文件清单 outputguard_config.go）。
//
// OG-4 先落 D 组「缓冲与资源」中与缓冲器直接相关的参数（P-UNIT、P-MAX-UNIT-RUNES、
// P-FIRST-UNIT-MAX-RUNES、P-MAX-BUFFER-BYTES、P-WINDOW-MARGIN 及派生的 P-WINDOW-CHARS）；
// OG-8 在此基础上扩展启动 flag、运行时覆盖、/config 快照与持久化，并接入 D8 变更流程。
// 全局在飞上限（P-MAX-INFLIGHT-BYTES）与句数上限（P-MAX-SLOTS）随 enforcing/级联（M4）落地。
//
// 两条纪律：
//   - 「未配置」用哨兵 paramUnset(-1) 表达——OG-8 的 flag 解析器把"未提供"映射为 -1，
//     "显式提供 0"保持 0。否则无法区分二者，而 §5.4 明确「显式 0」属非法（启动失败）。
//   - resolve 只派生（不报错）、validate 只校验（不派生），职责分离——
//     防止"非法值被兜底逻辑悄悄改成合法值"，使「非法＝启动失败」不被掩蔽（§5.4 兜底列）。
package main

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

// paramUnset 未配置哨兵（见文件头约定）。
const paramUnset = -1

// M1 缓冲默认值（T5 标定前的保守取值；取值回填不改类型/接口，§5 约定）。
const (
	defaultMaxUnitRunes   = 500     // P-MAX-UNIT-RUNES 保守默认
	defaultMaxBufferBytes = 1 << 20 // P-MAX-BUFFER-BYTES 每请求默认 1MiB
	firstUnitRatio        = 0.4     // P-FIRST-UNIT-MAX-RUNES 派生比例（§5.4）
	windowMarginRatio     = 1.5     // P-WINDOW-MARGIN 保守默认（≥ 词库最长词 × 1.5，§5.4）
)

// outputGuardParams D 组缓冲参数（原始值 + 派生值）。
type outputGuardParams struct {
	Unit              string // P-UNIT：sentence｜fixed-window
	MaxUnitRunes      int    // P-MAX-UNIT-RUNES（判定单元 rune 上限）
	FirstUnitMaxRunes int    // P-FIRST-UNIT-MAX-RUNES（首句强切阈值，≤ MaxUnitRunes）
	MaxBufferBytes    int    // P-MAX-BUFFER-BYTES（每请求缓冲字节上限）
	WindowMargin      int    // P-WINDOW-MARGIN（滑窗余量 rune 数；0 非法）
	MaxKeywordRunes   int    // 词库最长命中长度（P-WINDOW-CHARS 派生输入；OG-9 后取词库实测值）
	WindowRunes       int    // P-WINDOW-CHARS（派生只读：MaxKeywordRunes + WindowMargin）
}

// defaultOutputGuardParams 返回未配置态（全哨兵）的 D 组参数。
func defaultOutputGuardParams() outputGuardParams {
	return outputGuardParams{
		Unit:              unitSentence,
		MaxUnitRunes:      paramUnset,
		FirstUnitMaxRunes: paramUnset,
		MaxBufferBytes:    paramUnset,
		WindowMargin:      paramUnset,
	}
}

// resolveOutputGuardParams 填入缺省并派生 P-WINDOW-CHARS / P-FIRST-UNIT-MAX-RUNES（§5.4）。
// 只做派生，不做合法性判断：0/负值一律按"未配置"处理（保证零值结构体也能安全构造），
// "显式 0 非法"由 validateOutputGuardParams 对**原始值**拦截（启动期先 validate 再 resolve）。
func resolveOutputGuardParams(p outputGuardParams) outputGuardParams {
	if p.Unit == "" {
		p.Unit = unitSentence
	}
	if p.MaxUnitRunes <= 0 {
		p.MaxUnitRunes = defaultMaxUnitRunes
	}
	// §5.4：未配置＝0.4 派生；大于 P-MAX-UNIT-RUNES＝非法，按 0.4 比例自动取。
	if p.FirstUnitMaxRunes <= 0 || p.FirstUnitMaxRunes > p.MaxUnitRunes {
		p.FirstUnitMaxRunes = int(float64(p.MaxUnitRunes)*firstUnitRatio + 0.5)
		if p.FirstUnitMaxRunes < 1 {
			p.FirstUnitMaxRunes = 1
		}
	}
	if p.MaxBufferBytes <= 0 {
		p.MaxBufferBytes = defaultMaxBufferBytes
	}
	// §5.4：未配置＝保守默认（≥ 词库最长词 × 1.5），下限 1。
	if p.WindowMargin <= 0 {
		p.WindowMargin = int(float64(p.MaxKeywordRunes)*windowMarginRatio + 0.5)
		if p.WindowMargin < 1 {
			p.WindowMargin = 1
		}
	}
	p.WindowRunes = p.MaxKeywordRunes + p.WindowMargin
	return p
}

// validateOutputGuardParams 校验原始参数；非法即返回错误（调用方 fail-closed 拒绝启动）。
// 显式 0 一律非法（§5.4）；未配置须留 paramUnset，不得填 0。
func validateOutputGuardParams(p outputGuardParams) error {
	switch p.Unit {
	case "", unitSentence, unitFixedWindow:
	default:
		return fmt.Errorf("P-UNIT=%q 非法（取值：sentence|fixed-window）", p.Unit)
	}
	if err := validatePositiveRunes("P-MAX-UNIT-RUNES", p.MaxUnitRunes); err != nil {
		return err
	}
	if err := validatePositiveRunes("P-MAX-BUFFER-BYTES", p.MaxBufferBytes); err != nil {
		return err
	}
	if err := validatePositiveRunes("P-WINDOW-MARGIN", p.WindowMargin); err != nil {
		return err
	}
	if p.MaxKeywordRunes < 0 {
		return fmt.Errorf("P-WINDOW-CHARS 派生输入（词库最长命中长度）=%d 非法（不得为负）", p.MaxKeywordRunes)
	}
	return nil
}

// validatePositiveRunes 校验 int 参数：paramUnset＝未配置（放行）；0 或负＝非法。
func validatePositiveRunes(name string, v int) error {
	if v == paramUnset {
		return nil
	}
	if v <= 0 {
		return fmt.Errorf("%s=%d 非法（不得为 0/负数；未配置请留 %d）", name, v, paramUnset)
	}
	return nil
}

// ---- E 组：级联并发参数（§5.5；M3 OG-13）----
//
// 与 D 组同一纪律：未配置＝哨兵语义、显式 0/负非法、resolve 只派生、validate 只校验。
// 注意：本组由启动 flag 构造，flag 缺省值是 0（无法与"用户显式传 0"区分），故
// 0 一律按"未配置"处理、负值＝非法——与 D 组 paramUnset 语义等价（D 组由代码路径构造）。
// P-TIMEOUT 复用既有启动参数 -output-guard-l2-timeout（单一事实源，避免两处取值打架）。

const (
	defaultAvgSentenceRunes = 64               // P-MAX-SLOTS 派生的平均句长（rune，保守取值）
	minMaxSlots             = 8                // P-MAX-SLOTS 派生下限
	defaultCascadeTimeout   = 2 * time.Second   // P-TIMEOUT 兜底默认（与 outputL2HTTPClassifier 客户端默认同源）
)

// P-DEGRADE 取值（§5 E 组）。
const (
	degradeFailClosed = "fail-closed"      // 默认（当前唯一生效值）：触发级联的句子按 fail-closed 处置（shadow 只记不拦；enforcing 丢该句、不整流终止）
	degradeFallback   = "fallback-keyword" // **尚未实现**（§5 E 组取值之一）；配置即拒绝启动，不静默按 fail-closed 处置
)

// outputGuardCascadeParams E 组级联并发参数（原始值 + 派生值）。
type outputGuardCascadeParams struct {
	Timeout       time.Duration // P-TIMEOUT：L2 单次调用超时（必填；复用 -output-guard-l2-timeout）
	Concurrency   int           // P-CONCURRENCY：单请求在飞句数上限（未配置＝按 CPU 核数派生）
	MaxSlots      int           // P-MAX-SLOTS：单请求槽位上限（未配置＝按 P-MAX-BUFFER-BYTES/平均句长派生）
	BlockCancel   bool          // P-BLOCK-CANCEL：block 后是否中断引擎生成（M4 生效；M3 只落配置与快照）
	Degrade       string        // P-DEGRADE：fail-closed（默认，当前唯一生效值）｜fallback-keyword（尚未实现，配置即拒绝启动）
	BlockEmission bool          // 阻塞预演开关（非 §5 参数表参数，仅浸泡期用）：true＝按 enforcing 时序阻塞下发；false＝shadow 现状（超并发/超时才等待）
}

// defaultOutputGuardCascadeParams 返回未配置态的 E 组参数。
func defaultOutputGuardCascadeParams() outputGuardCascadeParams {
	return outputGuardCascadeParams{
		Concurrency: 0,
		MaxSlots:    0,
		Degrade:     degradeFailClosed,
	}
}

// resolveOutputGuardCascadeParams 填入缺省并派生 P-CONCURRENCY / P-MAX-SLOTS（§5.5 兜底列）。
// params 须为已 resolve 的 D 组参数（P-MAX-SLOTS 派生依赖 P-MAX-BUFFER-BYTES）。
func resolveOutputGuardCascadeParams(c outputGuardCascadeParams, params outputGuardParams) outputGuardCascadeParams {
	if c.Timeout <= 0 {
		// 防御：直接构造（测试/内嵌）可能未给超时；0 值会让 AfterFunc 立刻到期（槽位瞬超时）。
		// 启动路径已由 validateOutputGuardCascadeParams 保证 > 0，此处仅兜底派生。
		c.Timeout = defaultCascadeTimeout
	}
	if c.Degrade == "" {
		c.Degrade = degradeFailClosed
	}
	if c.Concurrency <= 0 {
		c.Concurrency = runtime.NumCPU()
		if c.Concurrency < 1 {
			c.Concurrency = 1
		}
	}
	if c.MaxSlots <= 0 {
		// 保守折算：缓冲字节上限 / 平均句长字节（按 UTF-8 单 rune 最多 4 字节计）。
		c.MaxSlots = params.MaxBufferBytes / (defaultAvgSentenceRunes * utf8.UTFMax)
		if c.MaxSlots < minMaxSlots {
			c.MaxSlots = minMaxSlots
		}
	}
	return c
}

// validateOutputGuardCascadeParams 校验 E 组参数（非法＝拒绝启动，§5.4 纪律）。
func validateOutputGuardCascadeParams(c outputGuardCascadeParams) error {
	if c.Timeout <= 0 {
		return fmt.Errorf("P-TIMEOUT=%s 非法（必须为正；L2 调用超时是首帧预算的直接决定项）", c.Timeout)
	}
	if c.Concurrency < 0 {
		return fmt.Errorf("P-CONCURRENCY=%d 非法（不得为负；未配置请留 0）", c.Concurrency)
	}
	if c.MaxSlots < 0 {
		return fmt.Errorf("P-MAX-SLOTS=%d 非法（不得为负；未配置请留 0）", c.MaxSlots)
	}
	switch c.Degrade {
	case "", degradeFailClosed:
	case degradeFallback:
		return fmt.Errorf("P-DEGRADE=%s 尚未实现；拒绝启动，不静默按 fail-closed 处置", degradeFallback)
	default:
		return fmt.Errorf("P-DEGRADE=%q 非法（取值：fail-closed|fallback-keyword）", c.Degrade)
	}
	return nil
}

// outputGuardConfig 审查管线构造配置（§2.3 I1 `outputguard.New(cfg)`）。
type outputGuardConfig struct {
	Mode          string                    // P-MODE：off｜shadow｜enforcing（M4 拦截仅启动参数可开；运行时/持久化通道限 off｜shadow）
	PolicyVersion string                    // 策略版本（manifest.policy_version；M1 未接词库，用 defaultPolicyVersion）
	Params        outputGuardParams         // D 组缓冲参数（允许传未 resolve 值，构造时会 resolve）
	Cascade       outputGuardCascadeParams  // E 组级联并发参数（允许传未 resolve 值，构造时会 resolve）
	MaskEnabled   bool                      // OG-18：PII mask 改写开关（默认 false = block-only 深度，mask 降为 flag；true = 启用实打马赛克）
	MaskRegexps   []*regexp.Regexp          // OG-18：PII 正则切片（与 pii_patterns.json 顺序一致；为空则不改写）
}

// ---- OG-8：运行时配置请求 / 持久化记录（与 guardrailConfigRequest 同构）----

// outputGuardConfigRequest POST /config/output-guard 请求体（OG-8 运行时覆盖）。
// 仅允许切换 mode（off｜shadow）；enforcing 拦截已实现（M4 OG-17）但运行时通道不开放
// （D4'：仅启动参数可开，待治理闸门批次放开）。
// 治理链在 gateway-admin-service（D8 高敏变更 submitter≠reviewer 复核通过后执行），
// 本端点只做"配置生效 + 持久化 + 落 tee-infer 审计链"。
type outputGuardConfigRequest struct {
	Mode string `json:"mode"`
}

// outputGuardConfigRecord 持久化记录（JSON 单行，写 0600；与 guardrailConfigRecord 同构）。
// 启动时读取恢复运行时覆盖（文件缺失/解析失败/取值非法 → 沿用启动参数，不阻断启动）。
type outputGuardConfigRecord struct {
	Mode      string `json:"mode"`
	Actor     string `json:"actor"`
	RequestID string `json:"request_id"`
	UpdatedAt int64  `json:"updated_at"` // UTC 纳秒
}

// ---- B 组「后端接线」参数：P-BACKEND-TARGET 可信域白名单（§5.3；2026-09-18 裁定 A2）----
//
// 安全语义：L2 侧车收到的 body 是**被审查的用户生成明文**。地址若落在可信域外
// （S3＝飞地外／S2＝客户可信域外），等于把生成明文外发。故：
//   - 默认仅 localhost（未配白名单时非 localhost 一律启动失败）；
//   - 跨主机必须用 -output-guard-l2-allowed-cidrs 显式声明可信域 CIDR；
//   - 双层校验：启动期（本文件）+ 连接期实际对端 IP（outputguard.go newL2HTTPTransport，
//     防 DNS 漂移/rebinding）；
//   - 域名按启动期解析结果校验，须**全部**落在可信域内（解析失败亦拒绝）。

// lookupIPFunc 域名解析入口（默认 net.LookupIP；单测可替换，避免依赖真实 DNS）。
var lookupIPFunc = net.LookupIP

// outputGuardBackendParams B 组参数（L2 侧车地址与可信域白名单）。
type outputGuardBackendParams struct {
	Target      string       // P-BACKEND-TARGET：L2 侧车 URL（空＝不启用 L2）
	AllowedNets []*net.IPNet // 可信域 CIDR 白名单（空＝仅 localhost）
}

// defaultOutputGuardBackendParams 返回未配置态的 B 组参数。
func defaultOutputGuardBackendParams() outputGuardBackendParams {
	return outputGuardBackendParams{}
}

// parseOutputGuardAllowedCIDRs 解析逗号分隔的 CIDR 白名单（空串＝空白名单）。
// 非法 CIDR 一律报错——不静默忽略，否则会以"以为配了白名单、其实没配"的方式放开边界。
func parseOutputGuardAllowedCIDRs(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("P-BACKEND-TARGET 白名单 CIDR %q 非法: %v", part, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// l2TargetIPAllowed 判定单个 IP 是否落在可信域内（回环 ∪ 白名单）。
// 启动期与连接期共用同一谓词，避免两处判定漂移。
func l2TargetIPAllowed(ip net.IP, allowedNets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// validateOutputGuardBackendParams 校验 L2 侧车地址落点（启动期，fail-closed，§5.3 裁定 A2）。
// Target 为空＝未启用 L2，直接放行（行为零变化）。
func validateOutputGuardBackendParams(b outputGuardBackendParams) error {
	if b.Target == "" {
		return nil
	}
	u, err := url.Parse(b.Target)
	if err != nil {
		return fmt.Errorf("P-BACKEND-TARGET %q 不是合法 URL: %v", b.Target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("P-BACKEND-TARGET %q scheme 非法（仅支持 http|https）", b.Target)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("P-BACKEND-TARGET %q 缺少主机名", b.Target)
	}
	if host == "localhost" {
		return nil // 实际对端由连接期校验（回环）
	}
	if ip := net.ParseIP(host); ip != nil {
		if l2TargetIPAllowed(ip, b.AllowedNets) {
			return nil
		}
		return fmt.Errorf("P-BACKEND-TARGET %s 不在可信域内：默认仅 localhost，跨主机请用 "+
			"-output-guard-l2-allowed-cidrs 显式声明可信域 CIDR（被审明文不得出可信域）", b.Target)
	}
	// 域名：启动期解析并校验全部结果；解析失败同样拒绝（无法证明其指向可信域）。
	ips, err := lookupIPFunc(host)
	if err != nil {
		return fmt.Errorf("P-BACKEND-TARGET 域名 %q 解析失败（无法证明其指向可信域，拒绝启动）: %v", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("P-BACKEND-TARGET 域名 %q 无解析结果（拒绝启动）", host)
	}
	for _, ip := range ips {
		if !l2TargetIPAllowed(ip, b.AllowedNets) {
			return fmt.Errorf("P-BACKEND-TARGET 域名 %q 解析出可信域外地址 %s（拒绝启动；连接期亦会再次校验）", host, ip)
		}
	}
	return nil
}
