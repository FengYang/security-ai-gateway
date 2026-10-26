package group

import "time"

// 本文件承载 P2-4 **T-6.3 阻塞项 C-1/C-2** 的落地实现：把 RTO/RPO 目标值从
// "口头/文档口径"变成**代码里显式标注来源**的基线值。
//
// 口径依据：
//   - **C-1（RTO 目标值）**：两地三中心三场景，取值按行业标准（详见下方常量注释）；
//   - **C-2（RPO 目标值）**：同 RTO 同构落地（`RPOBudget`）。
//
// **产品口径（用户裁定，P2-4）**：本系统是**标准化产品**，不是定制项目。RTO/RPO
// 主要指标由**我方**参照行业竞品/行业标准自主决定，**不以客户要求为前提**；因此
// `BaselineIndustry` 是**我方标准产品承诺值，本身即正式判据**，不需要以客户签字作为
// 前置；客户若签了更严/更松的合同 SLA，属**可选覆盖**（`BaselineCustomerOverride`），
// 不是验收资格开关。
//
// **唯一仍需守住的红线**：不得把"产品基线"在报告里说成"客户已认可/客户确认"——
// 二者来源不同，必须能区分（见 `BaselineSource`）。
//
// **边界**：本文件只提供**基线默认值与来源标注**；RTO/RPO **实测值**仍须由真机
// 演练（T-7 / Wave B）登记，未实测前 `Verdict()` 一律 "pending"，不得宣称达标。

// ---------------------------------------------------------------------------
// 基线来源（C-1：产品基线即判据，客户合同覆盖为可选）
// ---------------------------------------------------------------------------

// BaselineSource 标识 RTO/RPO 阈值/基线的来源。
//
// 三值语义互斥：
//   - `BaselineUnset`：未定值，`MaxRTO`/`MaxRPO` 只是占位（如 `PlaceholderMaxRTO`），
//     **无判据资格**，`Verdict()` 恒 "pending"；
//   - `BaselineIndustry`：**我方产品基线**，按行业标准制定，是标准产品的正式承诺值，
//     **本身即有判据资格**（可直接出 pass/fail，无需任何客户签字）；
//   - `BaselineCustomerOverride`：客户合同 SLA **覆盖**产品基线（可选），仅在合同
//     与产品基线不同时设置；**不是**验收资格开关。
//
// **判据资格由 `IsVerdictEligible()` 白名单判定**（仅 `BaselineIndustry` /
// `BaselineCustomerOverride` 两类；未定值与任何非法/未知字符串一律不 eligible）：
// 报告层请统一用该方法，不要用 `Confirmed` 字段（那是"是否客户合同覆盖"的标记，
// 与资格无关），也不要自行写"非空即有资格"的判断（那是 fail-open，见 P3-3）。
type BaselineSource string

const (
	// BaselineUnset 未定值（仅占位）。零值，保证新建结构默认安全。
	BaselineUnset BaselineSource = ""
	// BaselineIndustry 产品基线（按行业标准制定）。**我方产品承诺值，本身即判据**。
	BaselineIndustry BaselineSource = "industry_default"
	// BaselineCustomerOverride 客户合同覆盖（可选）。仅当合同 SLA 与产品基线不同才设置。
	BaselineCustomerOverride BaselineSource = "customer_override"
)

// Label 返回中文可读标签，供报告/审计输出直接使用。
//
// **注意**：`BaselineIndustry` 的标签**不含"客户"二字**——产品基线不得被表述成
// 客户确认（防止报告文本越界）。
func (s BaselineSource) Label() string {
	switch s {
	case BaselineIndustry:
		return "产品基线（按行业标准制定）"
	case BaselineCustomerOverride:
		return "客户合同覆盖（可选）"
	default:
		return "未定值（占位）"
	}
}

// IsVerdictEligible 报告本阈值是否**具备判据资格**（白名单判定）。
//
// **这是报告层唯一该用的资格判断**：产品基线（`BaselineIndustry`）**即 eligible**，
// 可直接出 pass/fail；只有占位/未定值（`BaselineUnset`）不得判。
// 不要用 `Confirmed` 字段判断资格——它只表示"是否客户合同覆盖"。
//
// **白名单而非"非空"判定（P3-3）**：只认 `BaselineIndustry` / `BaselineCustomerOverride`
// 两个合法值。任何拼错/未来新增但未登记的字符串（如 `"industry-defualt"`）都不得
// 获得判据资格——否则会出现"资格通过但 `Label()` 显示未定值"的自相矛盾（fail-open）。
func (s BaselineSource) IsVerdictEligible() bool {
	return s == BaselineIndustry || s == BaselineCustomerOverride
}

// IsCustomerOverride 报告本阈值是否来自**客户合同覆盖**（可选来源）。
//
// 用于报告层标注"该值已被客户合同改写"，**不得**当作判据资格开关使用。
func (s BaselineSource) IsCustomerOverride() bool {
	return s == BaselineCustomerOverride
}

// ---------------------------------------------------------------------------
// C-1 / C-2：三场景行业标准基线常量（每个常量写明依据）
// ---------------------------------------------------------------------------

// 同城双中心（同步复制）产品基线。
//
// 依据 **GB/T 20988-2007《信息安全技术 信息系统灾难恢复规范》**：
//   - 第 5 级（实时数据传输及完整设备支持）：RTO 数分钟~2 天、RPO 0~30 分钟；
//   - 第 6 级（数据零丢失和远程集群支持）：RPO = 0。
//
// 本系统同城数据面采用同步复制，故取较严的 RPO=0；RTO 取 15 分钟（落在第 5 级
// "数分钟"区间，且与人工 promotion + 双签审批（D-8）的编排耗时可对齐）。
//
// **不在本档口径内**：单集群主备/故障注入切换的 RTO ≤ 30s（P1-5 V-7 判据）是
// 另一个层级，**不得与本档互相套用**（见 dc.go 段头两档表述）。
const (
	// IndustryRTOMetro 同城数据面切换 RTO 目标（产品基线）。
	IndustryRTOMetro = 15 * time.Minute
	// IndustryRPOMetro 同城 RPO=0（同步复制，零数据丢失）。RPO=0 是**合法目标值**。
	IndustryRPOMetro = time.Duration(0)
)

// 异地灾备（异步复制）产品基线。
//
// 依据 **中国人民银行《金融数据中心容灾建设指引》**（核心业务系统异地灾备要求）：
// 核心业务 RTO ≤ 2 小时、RPO ≤ 15 分钟。
const (
	// IndustryRTOGeo 异地灾备 RTO 目标（产品基线）。
	IndustryRTOGeo = 2 * time.Hour
	// IndustryRPOGeo 异地灾备 RPO 目标（产品基线）。
	IndustryRPOGeo = 15 * time.Minute
)

// 管理面异地灾备产品基线。
//
// 依据 **本体 §6.4 A4(6) 裁决**：管理面异地灾备 RTO ≤ 30 分钟、RPO ≤ 5 分钟。
// （管理面不承载数据面流量，故较数据面异地灾备更严的 RTO 是"业务可管理性"要求，
// 与数据面量级不同，**不得**互相套用。）
const (
	// IndustryRTOControl 管理面异地灾备 RTO 目标（产品基线）。
	IndustryRTOControl = 30 * time.Minute
	// IndustryRPOControl 管理面异地灾备 RPO 目标（产品基线）。
	IndustryRPOControl = 5 * time.Minute
)

// ---------------------------------------------------------------------------
// C-2：RPO 预算（与 RTOBudget 同构，最小实现）
// ---------------------------------------------------------------------------

// RPOBudget 数据丢失窗口（RPO）口径与实测记录。
//
// 与 `RTOBudget` 的同构之处：三态判据 `Verdict()`、来源标注 `Source`、显式实测
// `Record`。**关键差异**：
//   - RTO 的 0 是无效值（切换耗时不可能为 0），故 `ConfirmMaxRTO` 用 `d <= 0` 拒绝；
//   - **RPO 的 0 是合法目标值**（同城同步复制零丢失），故 `ConfirmMaxRPO` 只拒绝
//     `d < 0`，**不得**照抄 `d <= 0` 的判断；
//   - 不额外引入 `Confirmed` 布尔字段：来源（`Source`）本身已表达"产品基线 / 客户
//     合同覆盖 / 未定值"，避免两个字段互相矛盾。
type RPOBudget struct {
	MaxRPO     time.Duration
	Measured   time.Duration
	HasMeasure bool
	// Source MaxRPO 的来源。零值 = 未定值（无基线，不得判达标）。
	Source BaselineSource
}

// DefaultRPOBudget 返回**未定基线**的 RPO 预算（`Source=BaselineUnset`）。
//
// 与 `DefaultRTOBudget()` 的占位语义一致：无基线时 `WithinRPO()` 恒 false、
// `Verdict()` 恒 "pending"。需要正式产品基线请用 `DefaultIndustryDRBaseline()`。
func DefaultRPOBudget() RPOBudget {
	return RPOBudget{Source: BaselineUnset}
}

// ConfirmMaxRPO 按客户合同 SLA 覆盖 RPO 目标值（可选，非资格开关）。
//
// **d<0 视为无效**（负的丢失窗口无物理意义）；**d==0 合法**——同城同步复制场景
// 的目标就是零数据丢失，必须接受。
func (b *RPOBudget) ConfirmMaxRPO(d time.Duration) {
	if d < 0 {
		return
	}
	b.MaxRPO = d
	b.Source = BaselineCustomerOverride
}

// SetIndustryBaseline 按**产品基线**设定 RPO 目标（我方标准承诺值，本身即判据）。
//
// d<0 无效（负值无物理意义）；d==0 合法（同城零丢失基线）。
// 调用后 `Source=BaselineIndustry`，报告层可直接据此出 pass/fail。
func (b *RPOBudget) SetIndustryBaseline(d time.Duration) {
	if d < 0 {
		return
	}
	b.MaxRPO = d
	b.Source = BaselineIndustry
}

// Record 记录一次实测的 RPO（即实测数据丢失窗口）。
//
// 负值视为无效测量，直接忽略（保持原有状态），避免把错误数据记成达标依据。
func (b *RPOBudget) Record(measured time.Duration) {
	if measured < 0 {
		return
	}
	b.Measured = measured
	b.HasMeasure = true
}

// WithinRPO 判定实测 RPO 是否达标；**无判据资格或未实测一律返回 false**。
//
// 资格判断与 RTO 侧同构，统一走 `Source.IsVerdictEligible()`（白名单）。
func (b RPOBudget) WithinRPO() bool {
	return b.Source.IsVerdictEligible() && b.HasMeasure && b.Measured <= b.MaxRPO
}

// Verdict RPO 判据三态（供审计/报告输出）。
//
//	pending = 无判据资格（未定值/非法来源）或未实测
//	pass    = 有资格且实测丢失窗口不超目标
//	fail    = 有资格但实测丢失窗口超目标
func (b RPOBudget) Verdict() string {
	if !b.Source.IsVerdictEligible() {
		return "pending" // 无判据资格，不是判据
	}
	if !b.HasMeasure {
		return "pending" // 无实测数据
	}
	if b.Measured <= b.MaxRPO {
		return "pass"
	}
	return "fail"
}

// VerdictWithSource 同时返回 RPO 判据与基线来源（报告层推荐入口）。
func (b RPOBudget) VerdictWithSource() (verdict string, source BaselineSource) {
	return b.Verdict(), b.Source
}

// ---------------------------------------------------------------------------
// 两地三中心基线集合
// ---------------------------------------------------------------------------

// DRPair 单一场景的 RTO + RPO 基线对。
//
// **设计取舍**：`DRBaseline` 采用 `{Metro, Geo, Control DRPair}` 而非三个裸
// `RTOBudget`——因为 C-1（RTO）与 C-2（RPO）总是成对出现在同一场景的 SLA 里，
// 用 `DRPair` 让报告层"一次取一场景的完整口径"，不会漏掉 RPO。
type DRPair struct {
	RTO RTOBudget
	RPO RPOBudget
}

// DRBaseline 两地三中心三场景的产品基线集合（客户合同 SLA 可覆盖）。
//
// 三场景：`Metro` 同城双中心、`Geo` 异地灾备（数据面）、`Control` 管理面异地灾备。
type DRBaseline struct {
	Metro   DRPair
	Geo     DRPair
	Control DRPair
}

// DefaultIndustryDRBaseline 返回三场景的**产品基线**（我方按行业标准制定的承诺值）。
//
// 三场景均为：`Source=BaselineIndustry`、`Confirmed=false`（未做客户合同覆盖）、
// **未实测**（`HasMeasure=false`）。因此 `Verdict()` 全为 "pending"——因为**尚无
// 真机演练实测数据**，与客户签字无关。
//
// 客户合同 SLA 与产品基线不同时，逐场景调 `ConfirmMaxRTO` / `ConfirmMaxRPO` 覆盖。
func DefaultIndustryDRBaseline() DRBaseline {
	metro := DRPair{}
	metro.RTO.SetIndustryBaseline(IndustryRTOMetro)
	metro.RPO.SetIndustryBaseline(IndustryRPOMetro)

	geo := DRPair{}
	geo.RTO.SetIndustryBaseline(IndustryRTOGeo)
	geo.RPO.SetIndustryBaseline(IndustryRPOGeo)

	control := DRPair{}
	control.RTO.SetIndustryBaseline(IndustryRTOControl)
	control.RPO.SetIndustryBaseline(IndustryRPOControl)

	return DRBaseline{Metro: metro, Geo: geo, Control: control}
}
