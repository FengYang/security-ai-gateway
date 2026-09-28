// 输出侧内容审查管线（GA-输出侧内容审查-技术实现方案 §2.3 集成点 I1–I7）。
//
// 模式（研发计划 OG-3 骨架 + OG-4 缓冲）：
//   - off：New 返回 nil → streamTextInfer 走原路径，行为与现网**逐字节一致**（零开销）；
//   - shadow：跑 **OG-4 判定单元缓冲**（按句切分，§4.3.1）→ 每个完整单元跑 L1 规则
//     （复用既有 guardrail.check），命中记审计 `output_would_reject` + 指标
//     （l1_hit / would_reject），**输出原样逐 delta 放行**（只记不拦、不改变时延）；
//   - enforcing：M4 OG-17 已实现缓冲模式 A——未决句不下发，命中 block 的句子整流终止
//     （管线层发 finish=content_filter 终止帧），句级 P-DEGRADE 丢句续传。
//     **仅启动参数可开启**；运行时热切换与持久化恢复仍只接受 off|shadow（闸门见 main.go），
//     默认 off，不静默降级（非法值拒绝启动，对齐 §5.1 P-MODE）。
//
// 判定单元一致性（关键）：shadow 与 enforcing 使用**同一套缓冲/切分**（§4.3.1 P-UNIT），
// 否则 shadow 统计的命中率/误杀率不能代表 enforcing 的实况，影子失去意义。
//
// 硬边界（§2.3 复用清单 / §5.9 写死项）：
//   - 所有下发经唯一出口 emit（防绕过）；
//   - 不新增 wire 信封字段、不改信封协议版本（五元组不变）；
//   - 审计证据字段一律 omitempty、不进 hash()（旧链可复算，见 audit.go AuditEvent.hash）；
//   - 明文只在 tee-infer 内流转，审计不落原文/命中词（§4.11）。
//
// 与输入侧隔离：输出侧分类器为独立接口 OutputClassifier（§3.6.5），
// 输入侧 model.Classifier 不动，避免交叉回归。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// 输出侧审查模式（P-MODE，§5.1）。
const (
	outputGuardOff       = "off"       // 缺省：完全不介入，行为与现网一致
	outputGuardShadow    = "shadow"    // 跑完整判定但输出原样放行（只记不拦）
	outputGuardEnforcing = "enforcing" // 按动作表拦截下发/终止（M4 OG-17 缓冲模式 A；仅启动参数可开）
)

// defaultPolicyVersion M1 骨架策略版本（mode/policy_version gauge 与审计证据字段用）。
// OG-9 词库/策略供应链落地后改为 manifest.policy_version（§4.2.4）。
const defaultPolicyVersion = "v0"

// OutputClassifier 输出侧独立分类器接口（§3.6.5，M1 冻结项 #1）。
//
//	Classify(text) (category, confidence, match)
//	  category   内部类目 ID（经 P-CATEGORY-MAP 映射后）；未命中返回空串
//	  confidence 0.0–1.0 命中置信度；规则层命中默认 1.0，未命中 0.0
//	  match      命中片段/关键词（语义模型可返回空串）
//
// 注意：**不与输入侧 model.Classifier 共用**（输入侧二元返回保持原状）。
type OutputClassifier interface {
	Classify(text string) (category string, confidence float64, match string)
}

// EarlyOutputClassifier 支持两段式响应的输出侧 L2 分类器（D8 议题二 T6，S2 批次）。
//
// 冻结物 #1 主签名 Classify 不变；本接口是可选能力扩展，由适配层实现、
// 级联按 type-assert 消费（未实现时级联回退为完整段一处置，零行为变化）：
//
//	ClassifyWithEarly(text, onEarly)
//	  读到响应文档 1（轻段 {"blocked":bool}）时同步回调 onEarly 一次：
//	  - onEarly(false)：轻段判 safe → 级联可将槽位提前终态 pass（首帧放行，T2）；
//	  - onEarly(true) ：轻段判 unsafe → 槽位 held，等完整段类目定动作（策略 i）。
//	onEarly 可为 nil（等价 Classify）；回调至多一次，且发生在返回前。
type EarlyOutputClassifier interface {
	OutputClassifier
	ClassifyWithEarly(text string, onEarly func(blocked bool)) (category string, confidence float64, match string)
}

// l1Classifier 将既有 guardrail 规则包装为 OutputClassifier（L1 规则/词库层）。
// 规则命中 confidence=1.0、未命中 0.0（§3.6.5 置信度贯通）。
//
// 类目取值为 L1 原生标签（pii / sql_injection / prompt_injection）；
// 映射到内部 31 类 ID（A1-01…A5-02）由 OG-2 映射表承担（§2.4 / §5.8 #2）。
type l1Classifier struct{ g *guardrail }

func (c l1Classifier) Classify(text string) (string, float64, string) {
	h := c.g.check(text)
	if h == nil {
		return "", 0, ""
	}
	return h.Category, 1.0, h.Match
}

// outputEmitFunc 唯一出口（§2.3 I2）：所有写给客户端的内容都必须经此函数。
type outputEmitFunc func(delta, finish string) error

// outputGuard 输出侧审查管线（请求级）。
type outputGuard struct {
	mode          string
	policyVersion string
	strategy      string // S3-2 P-STRATEGY：A/B/C
	field         string // X-2：审查内容来源字段（text / tool_input；用于指标归因，低基数）
	l1            OutputClassifier
	l2            OutputClassifier // nil = 未启用 L2（纯 L1 = 当前行为）
	metrics       *otpmaskMetrics
	audit         *auditChain
	tenant        string
	requestID     string
	// buf：OG-4 判定单元缓冲（按句/固定窗聚合，§4.3.1）。
	buf *unitBuffer
	// casc：OG-13 级联并发控制器（槽位状态机 + 有序下发 + 容量阀 + 指标/留痕）。
	// 判定与留痕状态（命中去重、首次命中、L2 判定）一律由 cascade 持有——它在锁内并发访问。
	casc *cascade
	// closed：已 Close（断连/收尾）；置位后不再缓冲与判定。
	closed bool
}

// validateOutputGuardMode 校验审查模式（启动期调用；空串按缺省 off）。
// enforcing 经启动参数显式开启即合法；运行时热切换/持久化恢复另有 off|shadow 白名单
// （main.go，D4' 闸门批次前不放开）。
func validateOutputGuardMode(mode string) error {
	switch mode {
	case "", outputGuardOff, outputGuardShadow, outputGuardEnforcing:
		return nil
	default:
		return fmt.Errorf("output-guard=%q 非法（取值：off|shadow|enforcing）", mode)
	}
}

// newOutputGuard 构造请求级审查管线（§2.3 I1 `outputguard.New(cfg)`）。
// cfg.Mode=off/空 → 返回 nil（调用侧走原路径，零行为变化）；非法模式返回错误（启动期已校验，此处兜底）。
func newOutputGuard(cfg outputGuardConfig, l1 OutputClassifier, l2 OutputClassifier, m *otpmaskMetrics, a *auditChain,
	tenant, requestID string) (*outputGuard, error) {
	if err := validateOutputGuardMode(cfg.Mode); err != nil {
		return nil, err
	}
	if cfg.Mode == "" || cfg.Mode == outputGuardOff {
		return nil, nil
	}
	pv := cfg.PolicyVersion
	if pv == "" {
		pv = defaultPolicyVersion
	}
	strat := cfg.Strategy
	if strat == "" {
		strat = outputStrategyA
	}
	og := &outputGuard{
		mode:          cfg.Mode,
		policyVersion: pv,
		strategy:      strat,
		field:         "text", // X-2：默认审查 text 字段；可通过 withField 切换为 tool_input 等
		l1:            l1,
		l2:            l2,
		metrics:       m,
		audit:         a,
		tenant:        tenant,
		requestID:     requestID,
	}
	// 缓冲参数允许传入未 resolve 的原始值（构造处兜底 resolve，非法值已在启动期拦截）。
	params := resolveOutputGuardParams(cfg.Params)
	og.buf = newUnitBuffer(params, func(reason string) {
		if og.metrics != nil {
			og.metrics.incOGForcedSplit(reason)
		}
	})
	// 级联参数：P-MAX-SLOTS 派生依赖已 resolve 的 P-MAX-BUFFER-BYTES，故传入 params。
	firstChunkSkipL2Enabled := (strat == outputStrategyC)
	og.casc = newCascade(resolveOutputGuardCascadeParams(cfg.Cascade, params), cfg.Mode, cfg.MaskEnabled, cfg.MaskRegexps, l1, l2, m, a, tenant, requestID, pv, og.field, firstChunkSkipL2Enabled)
	if og.metrics != nil {
		og.metrics.incOGRequest(cfg.Mode, og.field) // X-2：审查过的请求数（按模式 + field）
	}
	return og, nil
}

// Process 处理引擎下发的一个 delta（§2.3 I2 集成点）。
//
// OG-4/OG-13：delta 先进判定单元缓冲（按句切分），完整单元逐个提交给级联控制器判定；
// 下发一律经 cascade 的唯一下发游标（按序、不跳发、不合并帧）。
// 生产 shadow（`BlockEmission=false`）下行为与 M2 逐字节一致：逐 delta 立即原样放行；
// 阻塞形态（浸泡预演）下遇未决句即停，产出真实首帧延迟增量。
// 下发失败（慢客户端）→ 立即 Close（停止缓冲）并把错误上抛以终止引擎（§4.3 慢客户端行）。
func (og *outputGuard) Process(delta string, emit outputEmitFunc) error {
	if og.closed {
		return nil // 已断连/关闭：不再缓冲，也不再下发
	}
	if err := og.casc.pushDelta(delta, og.buf.Push(delta), emit); err != nil {
		og.Close() // 慢客户端：立即释放，不继续缓冲
		return err
	}
	return nil
}

// Finish 收尾（§2.3 I3）：把缓冲尾部作为最后一个判定单元送判（否则末句逃逸审查）；
// 随后等所有在飞 L2 收敛（上限＝P-TIMEOUT，与客户端超时同源）并排空下发（§3.6.3 收尾语义）。
func (og *outputGuard) Finish(emit outputEmitFunc) error {
	if og.closed {
		return nil
	}
	return og.casc.finish(og.buf.Flush(), emit)
}

// Close 幂等释放（§2.3 I1 / C4）：释放级联（停表、未决槽位置 closed、唤醒等待者）+ 丢弃缓冲；
// 重复调用无副作用。
func (og *outputGuard) Close() {
	og.closed = true
	og.casc.close()
	og.buf.Reset()
}

// BlockInfo 返回 enforcing 整流终止状态与触发 block 的类目。
// cat 为空表示未终止，或 D5 无槽位可审的降级终止（终止帧不带 category，§4.10）。
func (og *outputGuard) BlockInfo() (bool, string) {
	return og.casc.blockInfo()
}

// MaskedCategories 返回本请求中命中 mask 动作的所有类目（去重）。
// 用于上层在请求结束时发射 output_masked 审计事件（OG-18）。
func (og *outputGuard) MaskedCategories() []string {
	return og.casc.maskedCategories()
}

// ogMaskDowngradeWarn 保证 PII mask→flag 降级告警每进程只打一行（D1'，P-PII-ACTION）。
var ogMaskDowngradeWarn sync.Once

// catActionForMode 返回指定类目在指定模式下的**实际生效动作**（用于槽位处置与 chunk-meta）。
// shadow 下恒为 flag（只标记不拦截）；enforcing 下按类目默认动作（M4）。
// maskEnabled = true（OG-18）时，mask 类目（A4-06 PII）返回 catActionMask（实打马赛克后下发）；
// maskEnabled = false（默认，block-only 深度）时，mask 类目降为 flag（D1'，P-PII-ACTION）。
func catActionForMode(cat, mode string, maskEnabled bool) string {
	if mode == outputGuardShadow {
		return catActionFlag
	}
	c, ok := getCategory(cat)
	if !ok {
		return catActionBlock // 兜底：未知类目按 block 处理（fail-closed）
	}
	if mode == outputGuardEnforcing && c.DefaultAction == catActionMask {
		if maskEnabled {
			return catActionMask // OG-18：改写启用，实打马赛克后下发
		}
		// D1'：当前输出深度为 block-only（改写未启用），PII 类目的 mask 动作无法执行——
		// 按参数表 P-PII-ACTION 降为 flag（原样下发+留痕）并每进程告警一行。
		ogMaskDowngradeWarn.Do(func() {
			log.Printf("[output-guard] PII 类目 %s 默认 mask，但当前为 block-only 输出深度（改写未启用）：按 P-PII-ACTION 降为 flag 放行并留痕（输出改写归 OG-18）", cat)
		})
		return catActionFlag
	}
	return c.DefaultAction
}

// BuildGuardMeta 构造 chunk-meta 的 guard 字段（用于终止帧；og=nil 时由调用方不带该字段）。
//
// 语义：
//   - 未命中 → detected=false, filtered=false, 无 category；
//   - enforcing 整流终止（blocked，含 D5 降级终止）→ detected=true, filtered=true,
//     action=block；category 与 output_blocked 审计同源同值（D5 时缺省，§4.10 L1293）；
//   - 其余命中（shadow 命中、enforcing 下仅 flag/pass）→ detected=true, filtered=false。
func (og *outputGuard) BuildGuardMeta() *chunkGuardMeta {
	gm := &chunkGuardMeta{
		PolicyVersion: og.policyVersion,
		Mode:          og.mode,
	}
	if blocked, blockCat := og.casc.blockInfo(); blocked {
		gm.Detected = true
		gm.Filtered = true
		gm.Action = catActionBlock
		gm.Category = blockCat // D5 降级终止时为空 → omitempty 不输出（不得伪造类目，§4.10）
		return gm
	}
	firstHitCat, firstHitAction := og.casc.firstHit() // 命中状态由 cascade 在锁内维护（L2 异步写入）
	if firstHitCat == "" {
		return gm // 未命中：detected=false（零值），不带 category/rule_version
	}
	gm.Detected = true
	gm.Action = firstHitAction
	gm.Category = firstHitCat
	return gm
}

// ---- outputL2HTTPClassifier：输出侧 L2 语义分类器 HTTP 侧车实现 ----
//
// 契约（v2，D8 两段式 T1=a；v1 单段向后兼容）：
//
//	POST <url>
//	Content-Type: application/json
//	{"text": "<待分类文本>"}
//	→ 200，响应体为换行分隔的 1 或 2 个 JSON 文档：
//
//	单段（v1 旧契约，stub/浸泡口径保持不改）：一个文档，命中时
//	  {"blocked": bool, "category": "...", "confidence": 0.95, "match": "..."}
//	  （未命中时仅 {"blocked": false}——与两段轻段字节同形，由"其后是否还有
//	  文档"区分，见 ClassifyWithEarly 解析顺序）
//	两段（v2，D8 议题一 T1=a）：
//	  文档 1（轻段）：Safety 行即出即 flush，{"blocked": bool}；
//	  文档 2（完整段）：完整输出后，{"blocked": bool, "category": "<Qwen 原生类目>",
//	                   "confidence": 1.0, "match": ""}（命中置信度固定 1.0：
//	                   贪心解码＝模型硬决策，无数值置信度输出）
//
// 降级语义（M2 OG-12；2026-09-19 与实现对齐）：
//   - 非 200 / 超时 / 网络错误 / JSON 非法 → 视为不可用；
//   - 调用方按 P-DEGRADE 处置：fail-closed（当前唯一生效值）下 enforcing **丢该句**
//     （不整流终止、后续干净句继续，§3.6.3 细节 1 / §4.5 变更记录 #54）、shadow 只记不拦；
//     **不回退 L1 关键词重判**（P-DEGRADE=fallback-keyword 尚未实现，配置即拒绝启动）；
//   - 失败同时记 degraded_total{backend="l2", reason=...}；
//   - Classify 返回 ("", -1, "") 作为失败哨兵（confidence=-1 表示调用失败，
//     区别于正常未命中的 confidence=0）。
//   - 两段式特例（S2 批次，D8 T5）：轻段 false 后文档 2 断流 → **正常 miss**
//     （判定已由轻段给出且首帧已放行，第二段仅补审计，不记 degraded）；
//     轻段 true 后断流 → 失败哨兵（类目未定，held 槽位超时降级）。
//
// 置信度语义（M3，§5.2 P-CONF-BAND 写死）：命中时置信度是**必带字段**——
// 侧车只返 category 不返 confidence → 返回 (cat, 0, "")，由调用方按"格式错误＝P-DEGRADE"处置；
// 本层**不做 1.0 兜底**（M2 曾兜底，M3 修正）。
//
// 与输入侧隔离：不复用 model.HTTPClassifier（接口签名不同），本文件独立实现。
type outputL2HTTPClassifier struct {
	url      string
	key      string
	client   *http.Client
	metrics  *otpmaskMetrics
	onResult func(reason string) // 失败回调，记 degraded；reason=unreachable/timeout/bad_response
}

// newOutputL2HTTPClassifier 构造输出侧 L2 HTTP 分类器。
// timeout <= 0 时取 2s（在请求路径上，必须有限且小）。
// allowedNets ＝ P-BACKEND-TARGET 可信域白名单（空＝仅 localhost）；连接期按实际对端 IP
// 校验（§5.3 裁定 A2 双层校验的第二层）。
// metrics / onResult 均可为 nil。
func newOutputL2HTTPClassifier(url, key string, timeout time.Duration, allowedNets []*net.IPNet, m *otpmaskMetrics, onResult func(reason string)) *outputL2HTTPClassifier {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &outputL2HTTPClassifier{
		url:      url,
		key:      key,
		metrics:  m,
		onResult: onResult,
		client: &http.Client{
			Timeout:   timeout,
			Transport: newL2HTTPTransport(allowedNets),
			// 不跟随重定向：307/308 会把 body 重发到 Location，等于把被审明文外发到
			// 可信域外（白名单只约束首次连接，管不住重定向目标）。
			// 返回 3xx 原响应 → 由调用方按"非 200"处置（bad_status → P-DEGRADE，fail-safe）。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// newL2HTTPTransport 构造 L2 侧车专用 transport（§5.3 裁定 A2 连接期校验）。
//   - Proxy 置 nil：不经 HTTP_PROXY/HTTPS_PROXY——代理出口不受白名单约束，等于绕过边界；
//   - DialContext 先解析、再按**已校验的 IP** 直连，避免"用于校验的解析结果"与
//     "实际连接的解析结果"不一致（TOCTOU / DNS rebinding）。
func newL2HTTPTransport(allowedNets []*net.IPNet) *http.Transport {
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("L2 侧车地址解析失败: %w", err)
			}
			var ips []net.IP
			if ip := net.ParseIP(host); ip != nil {
				ips = []net.IP{ip}
			} else {
				ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("L2 侧车地址 %s 无解析结果", host)
			}
			var lastErr error
			for _, ip := range ips {
				if !l2TargetIPAllowed(ip, allowedNets) {
					return nil, fmt.Errorf("L2 侧车对端 %s 不在可信域内，拒绝连接（被审明文不得出可信域）", ip)
				}
				conn, derr := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			return nil, lastErr
		},
	}
}

type l2ClassifyResponse struct {
	Blocked    bool    `json:"blocked"`
	Category   string  `json:"category,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Match      string  `json:"match,omitempty"`
}

// Classify 实现 OutputClassifier（无早出回调；解析逻辑与 ClassifyWithEarly 一致）。
// 调用失败时返回 ("", -1, "")——confidence=-1 是失败哨兵，
// 调用方据此判断走 degraded 路径。
func (c *outputL2HTTPClassifier) Classify(text string) (string, float64, string) {
	return c.ClassifyWithEarly(text, nil)
}

// ClassifyWithEarly 实现 EarlyOutputClassifier（两段式解析，D8 T1=a/T6）。
//
// 解析顺序：按 JSON 文档边界顺序解码——文档 1 解码成功即回调 onEarly（轻段已到）；
// 再尝试解码文档 2，以其结果区分契约形态：
//   - 文档 2 存在（两段式）：两段 blocked 必须一致，矛盾 = bad_response（fail-closed）；
//     一致则以文档 2（完整段）为准返回；
//   - 文档 2 为 EOF（单段 v1 旧契约）：文档 1 即完整结果，按 v1 语义返回（零行为变化）；
//   - 文档 2 解码失败（断流/超时/非法 JSON）：轻段 false → 正常 miss（D8 T5，
//     判定已由轻段给出、首帧已放行，第二段仅补审计）；轻段 true → 失败哨兵
//     （类目未定，fail-closed，held 槽位超时降级）。
//
// 调用失败时同样返回 ("", -1, "") 失败哨兵。
func (c *outputL2HTTPClassifier) ClassifyWithEarly(text string, onEarly func(blocked bool)) (string, float64, string) {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		c.report("bad_request")
		return "", -1, ""
	}
	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		c.report("unreachable")
		return "", -1, ""
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		// 超时 / 连接拒绝 / DNS 失败 都归到 unreachable
		c.report("unreachable")
		return "", -1, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		c.report("bad_status")
		return "", -1, ""
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	var light l2ClassifyResponse
	if err := dec.Decode(&light); err != nil {
		c.report("bad_response")
		return "", -1, ""
	}
	if onEarly != nil {
		onEarly(light.Blocked)
	}
	var full l2ClassifyResponse
	switch err := dec.Decode(&full); {
	case err == nil:
		// 两段式（v2）：文档 2 为完整段——两段 blocked 矛盾 = 响应不自洽，fail-closed。
		if full.Blocked != light.Blocked {
			c.report("bad_response")
			return "", -1, ""
		}
		if !full.Blocked {
			return "", 0, ""
		}
		// P-CONF-BAND（§5.2 写死）：置信度是命中的必带字段，缺失＝格式错误＝P-DEGRADE。
		// 故此处**不做兜底猜测**——原样返回，conf<=0 由调用方（cascade）判降级。
		return full.Category, full.Confidence, full.Match
	case errors.Is(err, io.EOF):
		// 单段（v1 旧契约）：文档 1 即完整结果，与既有行为逐字节一致。
		if !light.Blocked {
			return "", 0, ""
		}
		return light.Category, light.Confidence, light.Match
	default:
		// 文档 2 断流/超时/非法：轻段 false → 判定已给出（且首帧已放行），按 miss；
		// 轻段 true → 类目未定，失败哨兵（held 槽位超时降级）。
		if !light.Blocked {
			return "", 0, ""
		}
		c.report("bad_response")
		return "", -1, ""
	}
}

func (c *outputL2HTTPClassifier) report(reason string) {
	if c.metrics != nil {
		c.metrics.incOGDegraded("l2", reason)
	}
	if c.onResult != nil {
		c.onResult(reason)
	}
}
