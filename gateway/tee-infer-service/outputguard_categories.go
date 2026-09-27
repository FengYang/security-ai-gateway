// 输出侧内容审查 — 31 类安全风险类目定义（OG-2：类目体系与映射）。
//
// 唯一出处：技术方案附录 A（GB/T 45654—2025 附录 A 工程化转写）。
// 本文件为代码内的单一事实源（single source of truth）：
//   - 词库加载器用本列表校验 category 合法性（不存在 = 拒加载，§4.2.4）
//   - 映射表用本列表校验映射落点（不得落到不存在的类目）
//   - 审计 / 指标 / chunk-meta 的 category 取值均来自本列表
//
// 命名纪律（§4.2.4 / §5.8 #2）：
//   - ID 作为「值」使用时大写（A1-06）
//   - 文件路径 / map key 小写（a1-06）— 与 JSON 文件名一致
//   - 对外材料 / 备案一律引用标准原文编号（"附录 A.1 第 6 项"），不引用内部 ID
//
// 注意：本文件的「默认级别 / 默认动作」是策略默认值（可配），来源 = 附录 A 策略列；
// 「ID / 名称 / 族」是标准原文的工程化转写，须经 §9.4 S0-A3 官方文本逐条核对。
// 核对差异只改 name 字符串，不改内部 ID（词库文件名 / 代码引用因此不受影响）。
package main

// 风险级别（附录 A 默认级别；可按策略表覆盖）。
const (
	catLevelHigh   = "high"   // 高：默认 block
	catLevelMedium = "medium" // 中：默认 flag（可升档 block）
	catLevelLow    = "low"    // 低：默认 flag / pass
)

// 默认动作（§4.4 动作表；与级别绑定，可按策略表覆盖）。
const (
	catActionBlock = "block" // 拒发 / 终止（enforcing 模式）
	catActionMask  = "mask"  // 改写 / 脱敏（PII 专用）
	catActionFlag  = "flag"  // 标记（只落审计与指标，不拦截）
	catActionPass  = "pass"  // 不干预（A.5 族默认）
)

// outputCategory 单个安全风险类目定义。
type outputCategory struct {
	ID          string // 内部 ID（大写：A1-06）
	Name        string // 类目名称（标准原文转写）
	Family      string // 族：A1 / A2 / A3 / A4 / A5
	DefaultLevel string // 默认级别：high | medium | low
	DefaultAction string // 默认动作：block | mask | flag | pass
	Note        string // 备注（映射归类规则 / 检出强度说明）
}

// outputCategories 31 类完整清单（唯一事实源 = 附录 A）。
// 顺序与附录 A 一致；新增/删除须经 D8 高敏变更（§5.8 #2 冻结项）。
var outputCategories = []outputCategory{
	// A.1 包含违反社会主义核心价值观的内容（8 项；条目文字经 OG-2② 官方文本逐条核对）
	{ID: "A1-01", Name: "煽动颠覆国家政权、推翻社会主义制度", Family: "A1", DefaultLevel: catLevelHigh, DefaultAction: catActionBlock},
	{ID: "A1-02", Name: "危害国家安全和利益、损害国家形象", Family: "A1", DefaultLevel: catLevelHigh, DefaultAction: catActionBlock},
	{ID: "A1-03", Name: "煽动分裂国家、破坏国家统一和社会稳定", Family: "A1", DefaultLevel: catLevelHigh, DefaultAction: catActionBlock},
	{ID: "A1-04", Name: "宣扬恐怖主义、极端主义", Family: "A1", DefaultLevel: catLevelHigh, DefaultAction: catActionBlock},
	{ID: "A1-05", Name: "宣扬民族仇恨", Family: "A1", DefaultLevel: catLevelHigh, DefaultAction: catActionBlock, Note: "官方 A.1 e) 原文仅\"宣扬民族仇恨\"；与 A2-01\"民族歧视内容\"分列两项，命中归类以\"宣扬仇恨\"优先归 A1-05"},
	{ID: "A1-06", Name: "宣扬暴力、淫秽色情", Family: "A1", DefaultLevel: catLevelHigh, DefaultAction: catActionBlock, Note: "官方 A.1 f) 原文；L1 词库强项（显性类）"},
	{ID: "A1-07", Name: "传播虚假有害信息", Family: "A1", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "检出可靠性与误杀风险均高，默认只标记"},
	{ID: "A1-08", Name: "其他法律、行政法规禁止的内容", Family: "A1", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "官方 A.1 h) 原文；兜底类，不单独建词库，仅作映射落点"},

	// A.2 违法不良信息（歧视类，9 项）
	{ID: "A2-01", Name: "民族歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区：指标须分类目单列；2026-09-27 评审后默认动作由 block 降为 flag（元表述词面高误伤，待 D-LLM-8 误杀定线达标后再评估升回）"},
	{ID: "A2-02", Name: "信仰歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "官方 A.2 b) 原文为\"信仰歧视内容\"（非\"种族歧视\"，OG-2② 核对纠正）；弱检出区；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-03", Name: "国别歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-04", Name: "地域歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区；\"地域黑\"梗文化对抗性强；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-05", Name: "性别歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-06", Name: "年龄歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-07", Name: "职业歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-08", Name: "健康歧视内容", Family: "A2", DefaultLevel: catLevelHigh, DefaultAction: catActionFlag, Note: "弱检出区；2026-09-27 同 A2-01 降为 flag"},
	{ID: "A2-09", Name: "其他方面歧视内容", Family: "A2", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "兜底类"},

	// A.3 商业/权益类（5 项）
	{ID: "A3-01", Name: "侵犯他人知识产权", Family: "A3", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "语境依赖（如正常批评/学术讨论），默认不拦"},
	{ID: "A3-02", Name: "违反商业道德", Family: "A3", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "边界模糊，不建议默认 block"},
	{ID: "A3-03", Name: "泄露他人商业秘密", Family: "A3", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "与 A4-06 邻近，命中以\"秘密\"性质归 A3-03"},
	{ID: "A3-04", Name: "利用算法、数据、平台等优势，实施垄断和不正当竞争行为", Family: "A3", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "语境依赖"},
	{ID: "A3-05", Name: "其他商业违法违规行为", Family: "A3", DefaultLevel: catLevelLow, DefaultAction: catActionFlag, Note: "兜底类"},

	// A.4 民事权益类（7 项）
	{ID: "A4-01", Name: "危害他人身心健康", Family: "A4", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "与 A1-06 部分重叠，显性暴力/色情归 A1-06"},
	{ID: "A4-02", Name: "侵害他人肖像权", Family: "A4", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "民事纠纷属性，网关不宜默认拦截"},
	{ID: "A4-03", Name: "侵害他人名誉权", Family: "A4", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "同上"},
	{ID: "A4-04", Name: "侵害他人荣誉权", Family: "A4", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "同上"},
	{ID: "A4-05", Name: "侵害他人隐私权", Family: "A4", DefaultLevel: catLevelMedium, DefaultAction: catActionFlag, Note: "同上；涉结构化个人信息时归 A4-06"},
	{ID: "A4-06", Name: "侵害他人个人信息权益", Family: "A4", DefaultLevel: catLevelHigh, DefaultAction: catActionMask, Note: "走既有 maskPII 路径，非 block"},
	{ID: "A4-07", Name: "侵犯他人其他合法权益", Family: "A4", DefaultLevel: catLevelLow, DefaultAction: catActionFlag, Note: "兜底类"},

	// A.5 特定服务类型安全需求（2 项）
	{ID: "A5-01", Name: "内容不准确，严重不符合科学常识或主流认知", Family: "A5", DefaultLevel: catLevelLow, DefaultAction: catActionPass, Note: "非违法内容；仅在声明为医疗/心理等高安全服务类型时启用"},
	{ID: "A5-02", Name: "内容不可靠，虽然不包含严重错误的内容，但无法对使用者形成帮助", Family: "A5", DefaultLevel: catLevelLow, DefaultAction: catActionPass, Note: "误伤正常问答风险最高，严禁默认拦截"},
}

// catIDToIndex 内部 ID → 下标（O(1) 查找）。
var catIDToIndex = func() map[string]int {
	m := make(map[string]int, len(outputCategories))
	for i, c := range outputCategories {
		m[c.ID] = i
	}
	return m
}()

// isValidCategory 检查内部 ID 是否在 31 类清单内。
func isValidCategory(id string) bool {
	_, ok := catIDToIndex[id]
	return ok
}

// getCategory 按内部 ID 取类目定义；不存在返回 false。
func getCategory(id string) (outputCategory, bool) {
	idx, ok := catIDToIndex[id]
	if !ok {
		return outputCategory{}, false
	}
	return outputCategories[idx], true
}

// categoryCount 返回类目总数（31；测试断言用）。
func categoryCount() int { return len(outputCategories) }
