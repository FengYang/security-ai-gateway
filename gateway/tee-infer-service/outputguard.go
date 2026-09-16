// 输出侧内容审查管线（GA-输出侧内容审查-技术实现方案 §2.3 集成点 I1–I7）。
//
// 模式（研发计划 OG-3 骨架 + OG-4 缓冲）：
//   - off：New 返回 nil → streamTextInfer 走原路径，行为与现网**逐字节一致**（零开销）；
//   - shadow：跑 **OG-4 判定单元缓冲**（按句切分，§4.3.1）→ 每个完整单元跑 L1 规则
//     （复用既有 guardrail.check），命中记审计 `output_would_reject` + 指标
//     （l1_hit / would_reject），**输出原样逐 delta 放行**（只记不拦、不改变时延）；
//   - enforcing：属 M4，M1 未实现——配置为 enforcing 即**拒绝启动**（不静默降级，
//     避免"以为开了其实没开"，对齐 §5.1 P-MODE 非法值语义）。
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

import "fmt"

// 输出侧审查模式（P-MODE，§5.1）。
const (
	outputGuardOff       = "off"       // 缺省：完全不介入，行为与现网一致
	outputGuardShadow    = "shadow"    // 跑完整判定但输出原样放行（只记不拦）
	outputGuardEnforcing = "enforcing" // 按动作表改写下发/终止（M4，M1 未实现）
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
	l1            OutputClassifier
	metrics       *otpmaskMetrics
	audit         *auditChain
	tenant        string
	requestID     string
	// seenCategory：同一请求内同一类目只落一次审计/would_reject，避免重复计数；
	// 不同类目各自计数，避免丢失 PII/SQL 等并存命中的观测。
	seenCategory map[string]bool
	// buf：OG-4 判定单元缓冲（按句/固定窗聚合，§4.3.1）。
	buf *unitBuffer
	// closed：已 Close（断连/收尾）；置位后不再缓冲与判定。
	closed bool
	// firstHitCat：首次命中的内部类目 ID（供 chunk-meta / 终止帧使用；空=未命中）。
	firstHitCat string
	// firstHitAction：首次命中对应的动作（shadow=flag；enforcing=block/mask；M1 shadow 下恒为 flag）。
	firstHitAction string
}

// validateOutputGuardMode 校验审查模式（启动期调用；非法/enforcing 未实现即拒绝启动）。
// 空串按缺省 off 处理（P-MODE：未配置＝off）。
func validateOutputGuardMode(mode string) error {
	switch mode {
	case "", outputGuardOff, outputGuardShadow:
		return nil
	case outputGuardEnforcing:
		return fmt.Errorf("output-guard=enforcing 在 M1 骨架未实现（enforcing 属 M4）；拒绝启动，拒绝静默降级为 shadow")
	default:
		return fmt.Errorf("output-guard=%q 非法（取值：off|shadow；enforcing 未实现）", mode)
	}
}

// newOutputGuard 构造请求级审查管线（§2.3 I1 `outputguard.New(cfg)`）。
// cfg.Mode=off/空 → 返回 nil（调用侧走原路径，零行为变化）。
// 非法或在 M1 未实现的 enforcing → 返回错误（fail-closed；启动期已校验，此处为兜底）。
func newOutputGuard(cfg outputGuardConfig, l1 OutputClassifier, m *otpmaskMetrics, a *auditChain,
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
	og := &outputGuard{
		mode:          cfg.Mode,
		policyVersion: pv,
		l1:            l1,
		metrics:       m,
		audit:         a,
		tenant:        tenant,
		requestID:     requestID,
		seenCategory:  make(map[string]bool, 4),
	}
	// 缓冲参数允许传入未 resolve 的原始值（构造处兜底 resolve，非法值已在启动期拦截）。
	og.buf = newUnitBuffer(resolveOutputGuardParams(cfg.Params), func(reason string) {
		if og.metrics != nil {
			og.metrics.incOGForcedSplit(reason)
		}
	})
	if og.metrics != nil {
		og.metrics.incOGRequest(cfg.Mode) // 审查过的请求数（按模式）
	}
	return og, nil
}

// Process 处理引擎下发的一个 delta（§2.3 I2 集成点）。
//
// OG-4：delta 先进入判定单元缓冲，完整的句子单元逐个送 L1（命中记指标与审计）；
// 输出仍**逐 delta 原样放行**（shadow 只记不拦，不改变输出字节与时延）。
// 下发失败（慢客户端）→ 立即 Close（停止缓冲）并把错误上抛以终止引擎（§4.3 慢客户端行）。
func (og *outputGuard) Process(delta string, emit outputEmitFunc) error {
	if og.closed {
		return nil // 已断连/关闭：不再缓冲，也不再下发
	}
	for _, unit := range og.buf.Push(delta) {
		og.classifyUnit(unit)
	}
	if err := emit(delta, ""); err != nil {
		og.Close() // 慢客户端：立即释放，不继续缓冲
		return err
	}
	return nil
}

// Finish 收尾（§2.3 I3）：把缓冲尾部作为最后一个判定单元送判（否则末句逃逸审查）；
// shadow 无内容需补下发（delta 已逐条放行）。enforcing 在此下发已判定剩余内容。
func (og *outputGuard) Finish(emit outputEmitFunc) error {
	if og.closed {
		return nil
	}
	for _, unit := range og.buf.Flush() {
		og.classifyUnit(unit)
	}
	return nil
}

// Close 幂等释放（§2.3 I1 / C4）：丢弃缓冲与状态；重复调用无副作用。
func (og *outputGuard) Close() {
	og.closed = true
	og.buf.Reset()
}

// classifyUnit 对一个判定单元跑 L1 并落观测（命中→l1_hit；首见类目→would_reject+审计）。
// 类目一律收敛到内部 ID（附录 A）：词库路径（lexiconRegistry）**已返回内部 ID**，直接采用；
// guardrail 路径返回 L1 原生标签，经 P-CATEGORY-MAP 映射。未映射 = P-DEGRADE（fail-closed），
// 记 unmapped 计数但不记 would_reject（因无法归到任何已知类目）。
func (og *outputGuard) classifyUnit(unit string) {
	if unit == "" {
		return
	}
	l1Cat, _, _ := og.l1.Classify(unit)
	if l1Cat == "" {
		return
	}
	cat := l1Cat
	if !isValidCategory(cat) {
		// L1 原生类目（pii / sql_injection / prompt_injection）→ 内部 ID（OG-2 映射表）。
		mapped, ok := mapL1Category(cat)
		if !ok {
			if og.metrics != nil {
				og.metrics.incOGUnmapped("l1", cat)
			}
			return // 未映射 = P-DEGRADE：不记 would_reject（无类目可归），只记 unmapped 诊断
		}
		cat = mapped
	}
	if og.metrics != nil {
		og.metrics.incOGL1Hit(cat)
	}
	if og.seenCategory[cat] {
		return
	}
	og.seenCategory[cat] = true
	// 记录首次命中（供 chunk-meta 终止帧注入使用；M1 shadow 下动作恒为 flag）。
	if og.firstHitCat == "" {
		og.firstHitCat = cat
		og.firstHitAction = catActionForMode(cat, og.mode)
	}
	if og.metrics != nil {
		og.metrics.incOGWouldReject(cat)
	}
	og.auditWouldReject(cat)
}

// auditWouldReject 落 `output_would_reject` 审计事件（§4.10）。
// Result 取值：`would_reject_<内部类目 ID>`（如 would_reject_A1-07）；
// OGCategory = 内部类目 ID（如 A1-07，与 chunk-meta guard.category 同源）。
// 证据字段一律 omitempty、不进 hash()，旧链可复算。
func (og *outputGuard) auditWouldReject(cat string) {
	if og.audit == nil {
		return
	}
	og.audit.append(AuditEvent{
		TenantID:  og.tenant,
		RequestID: og.requestID,
		Action:    "output_would_reject",
		Result:          "would_reject_" + cat,
		OGCategory:      cat,
		OGMode:          og.mode,
		OGPolicyVersion: og.policyVersion,
	})
}

// catActionForMode 返回指定类目在指定模式下的动作（用于 chunk-meta action 字段）。
// shadow 下恒为 flag（只标记不拦截）；enforcing 下按类目默认动作（M4 实现）。
func catActionForMode(cat, mode string) string {
	if mode == outputGuardShadow {
		return catActionFlag
	}
	// enforcing 模式下：查类目默认动作（M1 骨架期 enforcing 未启用，此处为前瞻性实现）。
	c, ok := getCategory(cat)
	if !ok {
		return catActionBlock // 兜底：未知类目按 block 处理（fail-closed）
	}
	return c.DefaultAction
}

// BuildGuardMeta 构造 chunk-meta 的 guard 字段（用于首帧/终止帧/周期重复注入）。
// nil 表示「不带 guard 字段」（omitempty 不输出）。
//
// M1 行为：
//   - 未命中 → detected=false, filtered=false, 无 category/rule_version
//   - shadow 命中 → detected=true, filtered=false, action=flag
//   - enforcing 未实现（启动期已拦截）
func (og *outputGuard) BuildGuardMeta() *chunkGuardMeta {
	gm := &chunkGuardMeta{
		PolicyVersion: og.policyVersion,
		Mode:          og.mode,
	}
	if og.firstHitCat == "" {
		return gm // 未命中：detected=false（零值），不带 category/rule_version
	}
	gm.Detected = true
	gm.Action = og.firstHitAction
	gm.Category = og.firstHitCat
	// filtered：shadow 下为 false（只标记不拦截）；enforcing 下为 true
	// （M1 enforcing 未启用，故 filtered 恒为 false；M4 实现 enforcing 后改为按动作判断）
	gm.Filtered = (og.mode == outputGuardEnforcing) &&
		(og.firstHitAction == catActionBlock || og.firstHitAction == catActionMask)
	return gm
}
