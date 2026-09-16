// 输出侧内容审查 — 后端类目 → 内部 31 类映射表（OG-2：类目体系与映射）。
//
// 设计原则（技术方案 §3.1 决策③ / §4.2.3 映射纪律）：
//   - 各后端（L1 规则 / L2 语义模型 / 第三方分类器）的原生类目**必须映射**到
//     内部 31 类（附录 A）；未映射 = 格式错误 = P-DEGRADE 降级（fail-closed）
//   - 映射表随后端版本发布，纳入评测门禁；映射变更走 D8 高敏变更
//   - 多对一允许（后端多个类目映射到同一内部类目）；一对多禁止
//     （分类器单次命中只能归到一个内部类目，命中归类规则写在 Note 里）
//
// M1 范围：L1 规则层 3 个原生类目 → 内部 31 类（pii → A4-06、sql_injection → A1-07、
// prompt_injection → A1-07）；L2 语义模型的映射表随后端选型（M3）落地。
//
// 命名纪律：后端类目名用小写蛇形（如 pii / sql_injection），内部 ID 大写（A1-06）。
package main

// categoryMap 单后端的「原生类目 → 内部 ID」映射。
// key = 后端原生类目名（小写）；value = 内部类目 ID（大写 A1-06 形态）。
type categoryMap map[string]string

// l1CategoryMap L1 规则层类目映射（M1 骨架期；OG-9 词库落地后类目名统一为内部 ID，此表缩减）。
//
// 当前 L1 原生类目（来自 guardrail.go check()）：
//   - pii              → A4-06（侵害他人个人信息权益）
//   - sql_injection    → A1-07（传播虚假有害信息）  — 说明：SQL 注入属于生成有害代码/
//                                                    信息扩散类，归 A1-07「虚假有害信息」
//   - prompt_injection → A1-07（传播虚假有害信息）  — 说明：提示词注入属于绕过安全机制
//                                                    扩散有害内容，归 A1-07
//
// TODO(OG-9 落地后)：词库类目统一使用内部 ID，此表退化为「向后兼容用的旧名→新名」
// 别名表，最终在 M4 前移除。
var l1CategoryMap = categoryMap{
	"pii":              "A4-06",
	"sql_injection":    "A1-07",
	"prompt_injection": "A1-07",
}

// mapCategory 把后端原生类目名映射到内部 31 类 ID。
// 返回：内部 ID + 是否映射成功。未映射 = P-DEGRADE（fail-closed）。
func mapCategory(m categoryMap, backendCat string) (string, bool) {
	id, ok := m[backendCat]
	if !ok {
		return "", false
	}
	// 双重校验：映射落点必须在 31 类清单内（防止映射表写错指向不存在的类目）。
	if !isValidCategory(id) {
		return "", false
	}
	return id, true
}

// mapL1Category L1 规则层类目 → 内部 ID 的便捷函数。
func mapL1Category(l1Cat string) (string, bool) {
	return mapCategory(l1CategoryMap, l1Cat)
}
