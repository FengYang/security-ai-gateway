package group

import (
	"strings"
	"testing"
	"time"
)

// 本文件覆盖 P2-4 T-6.3 阻塞项 C-1/C-2 的实现：三场景产品基线、基线来源标注、
// 以及 RPO 预算判据。
//
// **产品口径**：本系统是标准化产品，`BaselineIndustry`（产品基线）**本身即正式判据**，
// 可直接出 pass/fail；客户合同 SLA 属可选覆盖（`BaselineCustomerOverride`），不是资格开关。
//
// **仍须守住的两条**：
//   - 占位态（`Source=BaselineUnset`）永远不得判 pass；
//   - 报告文本不得把产品基线表述成"客户确认/客户要求"。

// 1) 三场景默认基线取值正确，来源为产品基线，未做客户覆盖，且未实测。
func TestDefaultIndustryDRBaseline(t *testing.T) {
	bl := DefaultIndustryDRBaseline()

	cases := []struct {
		name    string
		pair    DRPair
		wantRTO time.Duration
		wantRPO time.Duration
	}{
		{"同城双中心", bl.Metro, IndustryRTOMetro, IndustryRPOMetro},
		{"异地灾备", bl.Geo, IndustryRTOGeo, IndustryRPOGeo},
		{"管理面异地", bl.Control, IndustryRTOControl, IndustryRPOControl},
	}
	for _, c := range cases {
		if c.pair.RTO.MaxRTO != c.wantRTO {
			t.Fatalf("%s RTO 基线应为 %v，实际 %v", c.name, c.wantRTO, c.pair.RTO.MaxRTO)
		}
		if c.pair.RPO.MaxRPO != c.wantRPO {
			t.Fatalf("%s RPO 基线应为 %v，实际 %v", c.name, c.wantRPO, c.pair.RPO.MaxRPO)
		}
		if c.pair.RTO.Source != BaselineIndustry {
			t.Fatalf("%s RTO 来源应为产品基线，实际 %q", c.name, c.pair.RTO.Source)
		}
		if c.pair.RPO.Source != BaselineIndustry {
			t.Fatalf("%s RPO 来源应为产品基线，实际 %q", c.name, c.pair.RPO.Source)
		}
		// 产品基线不是客户合同覆盖（不得标注为已覆盖）。
		if c.pair.RTO.Confirmed {
			t.Fatalf("%s 产品基线不得置 Confirmed=true（产品基线≠客户合同覆盖）", c.name)
		}
		if c.pair.RTO.HasMeasure || c.pair.RPO.HasMeasure {
			t.Fatalf("%s 默认基线不得携带实测值", c.name)
		}
	}

	// 取值本身也要符合依据量级（防常量被误改）。
	if IndustryRPOMetro != 0 {
		t.Fatalf("同城 RPO 基线应为 0（同步复制零丢失），实际 %v", IndustryRPOMetro)
	}
	if IndustryRTOGeo != 2*time.Hour || IndustryRPOGeo != 15*time.Minute {
		t.Fatalf("异地灾备基线应为 RTO=2h/RPO=15min，实际 %v/%v", IndustryRTOGeo, IndustryRPOGeo)
	}
	if IndustryRTOControl != 30*time.Minute || IndustryRPOControl != 5*time.Minute {
		t.Fatalf("管理面基线应为 RTO=30min/RPO=5min，实际 %v/%v",
			IndustryRTOControl, IndustryRPOControl)
	}
}

// 2) 产品基线但未实测 → pending（缺的是实测数据，不是客户签字）。
func TestIndustryBaselineWithoutMeasureIsPending(t *testing.T) {
	bl := DefaultIndustryDRBaseline()
	if got := bl.Metro.RTO.Verdict(); got != "pending" {
		t.Fatalf("产品基线未实测应为 pending，实际 %q", got)
	}
	if got := bl.Geo.RPO.Verdict(); got != "pending" {
		t.Fatalf("RPO 产品基线未实测应为 pending，实际 %q", got)
	}
	if bl.Metro.RTO.WithinRTO() {
		t.Fatal("未实测时 WithinRTO() 应为 false")
	}
	if bl.Metro.RPO.WithinRPO() {
		t.Fatal("未实测时 WithinRPO() 应为 false")
	}
}

// 3) 产品基线 + 实测达标 → pass，且来源**仍是产品基线**（不是客户覆盖）。
func TestIndustryBaselineMeasuredWithinIsPass(t *testing.T) {
	var b RTOBudget
	b.SetIndustryBaseline(IndustryRTOMetro)
	start := time.Now()
	b.Record(start, start.Add(8*time.Minute))

	if !b.WithinRTO() {
		t.Fatalf("产品基线 15min、实测 8min 应达标，实际 Measured=%v", b.Measured)
	}
	verdict, source := b.VerdictWithSource()
	if verdict != "pass" {
		t.Fatalf("应判 pass，实际 %q", verdict)
	}
	if source != BaselineIndustry {
		t.Fatalf("来源应仍为产品基线（不得被冒认为客户覆盖），实际 %q", source)
	}
	if source.IsCustomerOverride() {
		t.Fatal("产品基线不得被判定为客户合同覆盖")
	}
	if b.Confirmed {
		t.Fatal("产品基线不得置 Confirmed=true")
	}
}

// 3b) 产品基线**可直接出判据**：`IsVerdictEligible()` 为 true，无需任何客户签字。
func TestProductBaselineIsVerdictEligible(t *testing.T) {
	if !BaselineIndustry.IsVerdictEligible() {
		t.Fatal("产品基线必须有判据资格（IsVerdictEligible 应为 true）")
	}
	if BaselineIndustry.IsCustomerOverride() {
		t.Fatal("产品基线不是客户合同覆盖")
	}
	if !BaselineCustomerOverride.IsVerdictEligible() {
		t.Fatal("客户合同覆盖同样有判据资格（它只是改写阈值）")
	}
	if !BaselineCustomerOverride.IsCustomerOverride() {
		t.Fatal("BaselineCustomerOverride 应被识别为客户合同覆盖")
	}
	if BaselineUnset.IsVerdictEligible() {
		t.Fatal("未定值不得有判据资格")
	}

	// 端到端：产品基线 + 实测达标即 pass，未发生任何"客户确认"动作。
	b := DefaultIndustryDRBaseline().Control.RTO
	start := time.Now()
	b.Record(start, start.Add(20*time.Minute))
	verdict, source := b.VerdictWithSource()
	if verdict != "pass" {
		t.Fatalf("产品基线实测 20min < 30min 应直接判 pass，实际 %q", verdict)
	}
	if !source.IsVerdictEligible() {
		t.Fatalf("出判据的来源必须有资格，实际 %q", source)
	}
	if b.Confirmed {
		t.Fatal("产品基线出判据不需要 Confirmed=true")
	}
}

// 4) 产品基线 + 实测超阈 → fail。
func TestIndustryBaselineMeasuredExceedIsFail(t *testing.T) {
	var b RTOBudget
	b.SetIndustryBaseline(IndustryRTOControl) // 30min
	start := time.Now()
	b.Record(start, start.Add(45*time.Minute))

	if b.WithinRTO() {
		t.Fatal("实测 45min 超基线 30min，不得判达标")
	}
	if got := b.Verdict(); got != "fail" {
		t.Fatalf("应判 fail，实际 %q", got)
	}

	var r RPOBudget
	r.SetIndustryBaseline(IndustryRPOGeo) // 15min
	r.Record(20 * time.Minute)
	if r.WithinRPO() {
		t.Fatal("RPO 实测 20min 超基线 15min，不得判达标")
	}
	if got := r.Verdict(); got != "fail" {
		t.Fatalf("RPO 应判 fail，实际 %q", got)
	}
}

// 5) 回归保护：来源未定（占位态）+ 实测达标 → pending，且 WithinRTO()==false。
//
// 即"占位值 / 未定基线"永远不得判 pass，即使实测值远小于占位阈值。
func TestUnsetSourceNeverPasses(t *testing.T) {
	b := DefaultRTOBudget() // Source == BaselineUnset
	start := time.Now()
	b.Record(start, start.Add(10*time.Millisecond))

	if b.Source != BaselineUnset {
		t.Fatalf("DefaultRTOBudget 来源应为未定值，实际 %q", b.Source)
	}
	if b.WithinRTO() {
		t.Fatal("来源未定时 WithinRTO() 必须为 false（占位值不是判据）")
	}
	if got := b.Verdict(); got != "pending" {
		t.Fatalf("来源未定时应为 pending，实际 %q", got)
	}

	var r RPOBudget
	r.Record(0)
	if r.Source != BaselineUnset {
		t.Fatalf("零值 RPOBudget 来源应为未定值，实际 %q", r.Source)
	}
	if r.WithinRPO() {
		t.Fatal("RPO 无基线时 WithinRPO() 必须为 false")
	}
	if got := r.Verdict(); got != "pending" {
		t.Fatalf("RPO 无基线时应为 pending，实际 %q", got)
	}
}

// 6) 客户合同覆盖后：Source==BaselineCustomerOverride、Confirmed==true。
func TestConfirmMaxRTOMarksCustomer(t *testing.T) {
	var b RTOBudget
	b.SetIndustryBaseline(IndustryRTOMetro)
	if b.Source != BaselineIndustry {
		t.Fatalf("前置：来源应为产品基线，实际 %q", b.Source)
	}

	b.ConfirmMaxRTO(30 * time.Second)
	if b.Source != BaselineCustomerOverride {
		t.Fatalf("客户合同覆盖后来源应为 customer_override，实际 %q", b.Source)
	}
	if !b.Confirmed {
		t.Fatal("客户合同覆盖后 Confirmed 应为 true")
	}
	if b.MaxRTO != 30*time.Second {
		t.Fatalf("客户合同覆盖后阈值为 30s，实际 %v", b.MaxRTO)
	}
	if !b.Source.IsCustomerOverride() {
		t.Fatal("IsCustomerOverride 应返回 true")
	}
	if !b.Source.IsVerdictEligible() {
		t.Fatal("客户合同覆盖仍须有判据资格")
	}

	// 直接对占位预算覆盖，同样进入客户覆盖态。
	p := DefaultRTOBudget()
	p.ConfirmMaxRTO(45 * time.Second)
	if p.Source != BaselineCustomerOverride || !p.Confirmed {
		t.Fatalf("占位预算覆盖后应转客户覆盖态，实际 source=%q confirmed=%v",
			p.Source, p.Confirmed)
	}
}

// 7) RPO 专项：d==0 合法；未实测 pending；实测 0 达标 pass；实测超 15min fail。
func TestRPOBudgetZeroTargetIsLegal(t *testing.T) {
	var zero RPOBudget
	zero.ConfirmMaxRPO(0) // 同城零丢失：0 是合法目标值，必须被接受
	if zero.Source != BaselineCustomerOverride {
		t.Fatalf("ConfirmMaxRPO(0) 应置客户覆盖来源，实际 %q", zero.Source)
	}
	if zero.MaxRPO != 0 {
		t.Fatalf("ConfirmMaxRPO(0) 后 MaxRPO 应为 0，实际 %v", zero.MaxRPO)
	}
	if got := zero.Verdict(); got != "pending" {
		t.Fatalf("有基线但未实测应为 pending，实际 %q", got)
	}

	// 实测零丢失 → pass。
	zero.Record(0)
	if !zero.WithinRPO() {
		t.Fatal("目标 0、实测 0 应达标")
	}
	if got := zero.Verdict(); got != "pass" {
		t.Fatalf("目标 0、实测 0 应判 pass，实际 %q", got)
	}

	// 实测有丢失 → fail。
	zero.Record(1 * time.Second)
	if zero.WithinRPO() {
		t.Fatal("目标 0、实测 1s 不得判达标")
	}
	if got := zero.Verdict(); got != "fail" {
		t.Fatalf("目标 0、实测 1s 应判 fail，实际 %q", got)
	}

	// 异地 RPO 15min 口径：14min pass、16min fail。
	var geo RPOBudget
	geo.ConfirmMaxRPO(IndustryRPOGeo)
	geo.Record(14 * time.Minute)
	if geo.Verdict() != "pass" {
		t.Fatalf("RPO 实测 14min 应 pass，实际 %q", geo.Verdict())
	}
	geo.Record(16 * time.Minute)
	if geo.Verdict() != "fail" {
		t.Fatalf("RPO 实测 16min 应 fail，实际 %q", geo.Verdict())
	}

	// 负值确认无效（不得清掉/污染基线）。
	var neg RPOBudget
	neg.ConfirmMaxRPO(-time.Second)
	if neg.Source != BaselineUnset {
		t.Fatalf("负值确认应被忽略（来源保持未定），实际 %q", neg.Source)
	}
	// 负值实测无效（不得记成达标依据）。
	neg.ConfirmMaxRPO(0)
	neg.Record(-time.Second)
	if neg.HasMeasure {
		t.Fatal("负值实测应被忽略（HasMeasure 不得置 true）")
	}
	if neg.Verdict() != "pending" {
		t.Fatalf("无效实测后应仍为 pending，实际 %q", neg.Verdict())
	}
}

// 8) RPO 未定基线（Source 空）+ 实测 → pending（即使实测为 0）。
func TestRPOBudgetUnsetBaselineIsPending(t *testing.T) {
	var b RPOBudget
	b.Record(0)
	if b.Source != BaselineUnset {
		t.Fatalf("来源应为未定值，实际 %q", b.Source)
	}
	if b.WithinRPO() {
		t.Fatal("无基线时 WithinRPO() 必须为 false")
	}
	verdict, source := b.VerdictWithSource()
	if verdict != "pending" {
		t.Fatalf("无基线时应为 pending，实际 %q", verdict)
	}
	if source != BaselineUnset {
		t.Fatalf("来源应为未定值，实际 %q", source)
	}
}

// 9) 标签可读性：三种来源标签互不相同，且**产品基线标签不含"客户"二字**。
func TestBaselineSourceLabel(t *testing.T) {
	industry := BaselineIndustry.Label()
	customer := BaselineCustomerOverride.Label()
	unset := BaselineUnset.Label()

	if industry == "" || customer == "" || unset == "" {
		t.Fatalf("标签不得为空：%q / %q / %q", industry, customer, unset)
	}
	if !strings.Contains(industry, "产品基线") {
		t.Fatalf("产品基线标签应含「产品基线」，实际 %q", industry)
	}
	// 关键：产品基线不得被报告文本表述成客户确认/客户要求。
	if strings.Contains(industry, "客户") {
		t.Fatalf("产品基线标签不得含「客户」二字（防误写成客户确认），实际 %q", industry)
	}
	if !strings.Contains(customer, "客户") || !strings.Contains(customer, "可选") {
		t.Fatalf("客户合同覆盖标签应含「客户」「可选」，实际 %q", customer)
	}

	// 原始取值保持稳定（对外字符串契约）。
	if BaselineIndustry != "industry_default" || BaselineCustomerOverride != "customer_override" {
		t.Fatalf("来源字符串契约被改动：%q / %q", BaselineIndustry, BaselineCustomerOverride)
	}
	if BaselineUnset != "" {
		t.Fatalf("零值必须为未定值，实际 %q", BaselineUnset)
	}
}

// 10) SetIndustryBaseline 的无效入参不得污染既有基线（RTO 拒绝 <=0）。
func TestSetIndustryBaselineInvalidIgnored(t *testing.T) {
	var b RTOBudget
	b.SetIndustryBaseline(IndustryRTOMetro)
	b.SetIndustryBaseline(0)
	b.SetIndustryBaseline(-time.Minute)
	if b.MaxRTO != IndustryRTOMetro {
		t.Fatalf("无效入参不得改动 RTO 基线，实际 %v", b.MaxRTO)
	}
	if b.Source != BaselineIndustry {
		t.Fatalf("来源应保持产品基线，实际 %q", b.Source)
	}
	if b.Confirmed {
		t.Fatal("产品基线不得置 Confirmed=true")
	}
}

// 11) **P2-2 红线回归锁**：`Confirmed`（客户合同覆盖标记）**不是**判据资格开关。
//
// 变异保护：若把 `WithinRTO` 改成 `(b.Confirmed || b.Source != BaselineUnset) && ...`
// 或把 `Verdict` 的资格判断改成 `if !b.Confirmed && b.Source == BaselineUnset`（即把
// "客户覆盖标记"误当资格开关——本次改动要防的误用），本测试会立刻报警：
// 这里 `Confirmed=true` 但 `Source` 仍是零值 `BaselineUnset`，两者判定结果相反。
func TestConfirmedFlagAloneIsNotVerdict(t *testing.T) {
	b := RTOBudget{MaxRTO: time.Hour, Confirmed: true} // Source 保持零值 BaselineUnset
	if b.Source != BaselineUnset {
		t.Fatalf("前置：Source 应为零值（BaselineUnset），实际 %q", b.Source)
	}
	s := time.Now()
	b.Record(s, s.Add(time.Minute)) // 实测 1min，远小于阈值 1h

	if got := b.Verdict(); got != "pending" {
		t.Fatalf("Confirmed=true 但无基线时 Verdict 必须 pending，实际 %q", got)
	}
	if b.WithinRTO() {
		t.Fatal("Confirmed=true 但无基线时 WithinRTO 必须 false")
	}
	if b.Source.IsVerdictEligible() {
		t.Fatal("BaselineUnset 不得 eligible")
	}
	// 与占位态（Confirmed=false）行为必须一致：资格只看 Source，不看 Confirmed。
	p := DefaultRTOBudget()
	p.Record(s, s.Add(time.Minute))
	if p.Verdict() != b.Verdict() || p.WithinRTO() != b.WithinRTO() {
		t.Fatalf("Confirmed 真假不得改变判据结果：占位=%q/%v 假确认=%q/%v",
			p.Verdict(), p.WithinRTO(), b.Verdict(), b.WithinRTO())
	}
}

// 12) P3-1：客户合同覆盖后再回落产品基线，必须清掉 `Confirmed`（不留矛盾元数据）。
func TestSetIndustryBaselineClearsConfirmed(t *testing.T) {
	var b RTOBudget
	b.ConfirmMaxRTO(30 * time.Second)
	if !b.Confirmed || b.Source != BaselineCustomerOverride {
		t.Fatalf("前置：应处于客户覆盖态，实际 confirmed=%v source=%q", b.Confirmed, b.Source)
	}

	b.SetIndustryBaseline(IndustryRTOMetro)
	if b.Source != BaselineIndustry {
		t.Fatalf("来源应为产品基线，实际 %q", b.Source)
	}
	if b.Confirmed {
		t.Fatal("回落产品基线后 Confirmed 必须清零（P3-1：否则元数据自相矛盾）")
	}

	s := time.Now()
	b.Record(s, s.Add(8*time.Minute))
	if got := b.Verdict(); got != "pass" {
		t.Fatalf("产品基线实测达标应 pass，实际 %q", got)
	}
	if _, source := b.VerdictWithSource(); source != BaselineIndustry {
		t.Fatalf("判据来源应报产品基线，实际 %q", source)
	}
}

// 13) P3-2：倒序时间戳（时钟回拨/参数写反）不得被记成"负耗时达标"。
func TestRecordReverseTimestampsIgnored(t *testing.T) {
	var b RTOBudget
	b.SetIndustryBaseline(IndustryRTOMetro)
	s := time.Now()
	b.Record(s, s.Add(-time.Hour)) // end 早于 start → 负耗时

	if b.HasMeasure {
		t.Fatalf("倒序时间戳不得置 HasMeasure，实际 Measured=%v", b.Measured)
	}
	if b.WithinRTO() {
		t.Fatal("倒序时间戳不得判达标（负耗时会被当成远小于阈值）")
	}
	if got := b.Verdict(); got != "pending" {
		t.Fatalf("倒序时间戳后应仍为 pending，实际 %q", got)
	}

	// 已有合法实测时，后来的倒序记录不得覆盖它。
	var ok RTOBudget
	ok.SetIndustryBaseline(IndustryRTOMetro)
	ok.Record(s, s.Add(5*time.Minute))
	ok.Record(s, s.Add(-time.Hour))
	if !ok.HasMeasure || ok.Measured != 5*time.Minute {
		t.Fatalf("倒序记录不得覆盖既有合法实测，实际 measured=%v hasMeasure=%v",
			ok.Measured, ok.HasMeasure)
	}
	if got := ok.Verdict(); got != "pass" {
		t.Fatalf("既有合法实测应仍判 pass，实际 %q", got)
	}
}

// 13b) P3-新2：零耗时（`end == start`）同样是无效测量，不得判 pass。
//
// `Record(time.Time{}, time.Time{})` 曾得到 `Measured=0s` + `HasMeasure=true` →
// `Verdict()=="pass"`（假 pass）。切换耗时不可能为 0，与 `ConfirmMaxRTO` 用 `d<=0`
// 拒绝零阈值必须同口径，否则"阈值拒 0、实测收 0 并判通过"自相矛盾。
func TestRecordZeroDurationIgnored(t *testing.T) {
	var b RTOBudget
	b.SetIndustryBaseline(IndustryRTOMetro) // 有判据资格 → pending 只能来自"无实测"
	b.Record(time.Time{}, time.Time{})      // 零值且同一时刻
	if b.HasMeasure {
		t.Fatalf("零耗时不得置 HasMeasure，实际 Measured=%v", b.Measured)
	}
	if b.WithinRTO() {
		t.Fatal("零耗时不得判达标（切换耗时不可能为 0）")
	}
	if got := b.Verdict(); got != "pending" {
		t.Fatalf("零耗时后应为 pending，实际 %q", got)
	}

	// 同一非零时刻同样视为零耗时。
	s := time.Now()
	var same RTOBudget
	same.SetIndustryBaseline(IndustryRTOMetro)
	same.Record(s, s)
	if same.HasMeasure || same.Verdict() != "pending" {
		t.Fatalf("同值时间戳应被忽略，实际 measured=%v hasMeasure=%v verdict=%q",
			same.Measured, same.HasMeasure, same.Verdict())
	}

	// 已有合法实测时，后来的零耗时记录不得覆盖它。
	var ok RTOBudget
	ok.SetIndustryBaseline(IndustryRTOMetro)
	ok.Record(s, s.Add(3*time.Minute))
	ok.Record(s, s)                     // 零耗时
	ok.Record(time.Time{}, time.Time{}) // 零值同时刻
	if !ok.HasMeasure || ok.Measured != 3*time.Minute {
		t.Fatalf("零耗时记录不得覆盖既有合法实测，实际 measured=%v hasMeasure=%v",
			ok.Measured, ok.HasMeasure)
	}
	if got := ok.Verdict(); got != "pass" {
		t.Fatalf("既有合法实测应仍判 pass，实际 %q", got)
	}
}

// 14) P3-3：非法来源字符串不得靠"非空"混过判据资格（白名单判定）。
func TestInvalidSourceStringNotEligible(t *testing.T) {
	bad := BaselineSource("industry-defualt") // 故意拼错
	if bad.IsVerdictEligible() {
		t.Fatal("非法来源字符串不得 eligible（白名单判定，P3-3）")
	}
	if bad.IsCustomerOverride() {
		t.Fatal("非法来源字符串不得被识别为客户合同覆盖")
	}
	if bad.Label() != BaselineUnset.Label() {
		t.Fatalf("非法来源标签应与未定值一致，实际 %q", bad.Label())
	}

	// RTO 侧：非法来源 + 实测达标 → 仍 pending。
	b := RTOBudget{MaxRTO: time.Hour, Source: bad}
	s := time.Now()
	b.Record(s, s.Add(time.Minute))
	if b.WithinRTO() {
		t.Fatal("非法来源时 WithinRTO 必须 false")
	}
	if got := b.Verdict(); got != "pending" {
		t.Fatalf("非法来源时应为 pending，实际 %q", got)
	}

	// RPO 侧：非法来源 + 实测 0 达标 → 仍 pending（同构）。
	r := RPOBudget{MaxRPO: time.Minute, Source: bad}
	r.Record(0)
	if r.WithinRPO() {
		t.Fatal("非法来源时 WithinRPO 必须 false")
	}
	if got := r.Verdict(); got != "pending" {
		t.Fatalf("RPO 非法来源时应为 pending，实际 %q", got)
	}
}
