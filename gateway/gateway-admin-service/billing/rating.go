package billing

import (
	"fmt"
	"math"
	"sort"
)

// ---------- 计价引擎（T4，§6.5） ----------

// RatingEngine 计价引擎接口。
//
// 设计要点：
//   - 唯一取整点：Rate() / RateMonthly() = roundAmount(RateMu(...))（R-16 / A-44）
//   - 入/出分轴：输入输出各占独立的月累计标准 token 轴（A-26）
//   - 标准 token 锁定：std 从账本读取（入账时算好并锁定，A-32/A-39）
//   - 累进阶梯：progressive（R-17 强制）
type RatingEngine interface {
	// RateMu 计算周期亚分金额（千分之一分，未取整）。
	RateMu(u *UsageAgg, tbl *PriceTable) (int64, error)
	// Rate 周期金额 = roundAmount(RateMu)（唯一取整点）。
	Rate(u *UsageAgg, tbl *PriceTable) (Amount, error)
	// RateMonthly 月结权威入口（语义同 Rate，传月聚合）。
	RateMonthly(u *UsageAgg, tbl *PriceTable) (Amount, error)
	// StandardTokens 标准 token 换算（唯一换算入口，A-9）。
	// 仅入账路径调用；计价路径读账本锁定值，不重算。
	StandardTokens(tokensIn, tokensOut int64, mp *ModelPrice) (stdIn, stdOut int64)
	// ExtraAmount 超额计费（套餐级合计基数 + 瀑布归属，A-44）。
	// 返回亚分（未取整），由调用方生成超额账单时单独取整（A-45）。
	ExtraAmount(u *UsageAgg, plan *Plan, tbl *PriceTable) (int64, error)
}

// UsageAgg 计价输入聚合（周期内某租户的用量）。
type UsageAgg struct {
	TenantID string
	Period   string               // "2026-10-01" 日 | "2026-10" 月
	ByModel  map[string]*ModelStd // key=modelKey
}

// ModelStd 单模型的标准 token 用量（来自账本锁定值，A-39）。
type ModelStd struct {
	StdIn     int64 // 标准输入 token
	StdOut    int64 // 标准输出 token
	TokensIn  int64 // 原始输入 token（仅供展示/追溯）
	TokensOut int64 // 原始输出 token
	Requests  int64
	RetryToks int64 // 重试 token（平台成本，不计用户金额，M9）
}

// ---------- 实现 ----------

// MonthStdProvider 月累计标准 token 提供器（供 RatingEngine 查询区间起点累计）。
// 由调用方实现（读账本 + 缓存，A-37）。
type MonthStdProvider interface {
	// MonthStdBefore 返回某租户某模型在 period 起点前的当月累计标准 token（分轴，A-26）。
	// period: "YYYY-MM-DD"（日结：返回当月初至该日前的累计）
	//       | "YYYY-MM"（月结：返回 0，因起点即月初）
	MonthStdBefore(tenant, modelKey, period string) (stdInBefore, stdOutBefore int64)
}

type ratingEngine struct {
	rounding string // half_up | floor
	monthStd MonthStdProvider
}

// NewRatingEngine 构造计价引擎。
// rounding: "half_up"（默认）或 "floor"（R-15）。
// monthStd 可为 nil（测试用：所有 before = 0，等价于全量在本周期）。
func NewRatingEngine(rounding string, monthStd MonthStdProvider) RatingEngine {
	if rounding == "" {
		rounding = "half_up"
	}
	return &ratingEngine{rounding: rounding, monthStd: monthStd}
}

// Rounding 返回配置的舍入法（"half_up" | "floor"）。
// 供展示层（账单明细行）与账单总额取整**同口径**（此前明细行硬编码 half_up，
// 当配置 floor 时明细行之和会与总额不一致）。
func (e *ratingEngine) Rounding() string {
	if e == nil || e.rounding == "" {
		return "half_up"
	}
	return e.rounding
}

// StandardTokens 标准 token 换算（A-9 唯一入口）。
// 入账路径唯一调用点；计价路径从账本读锁定值，不调用此函数（A-39）。
func (e *ratingEngine) StandardTokens(tokensIn, tokensOut int64, mp *ModelPrice) (int64, int64) {
	if mp == nil {
		return tokensIn, tokensOut
	}
	inCoef := mp.InCoef
	if inCoef <= 0 {
		inCoef = 1.0
	}
	outCoef := mp.OutCoef
	if outCoef <= 0 {
		outCoef = 1.0
	}
	stdIn := int64(math.Round(float64(tokensIn) * inCoef))
	stdOut := int64(math.Round(float64(tokensOut) * outCoef))
	if stdIn < 0 {
		stdIn = 0
	}
	if stdOut < 0 {
		stdOut = 0
	}
	return stdIn, stdOut
}

// RateMu 计算亚分金额（千分之一分，未取整）。
func (e *ratingEngine) RateMu(u *UsageAgg, tbl *PriceTable) (int64, error) {
	if u == nil || len(u.ByModel) == 0 {
		return 0, nil
	}
	// 取月份（用于分轴累计起点）
	period := u.Period

	var totalMu int64 // 亚分（千分之一分）
	for mk, mu := range u.ByModel {
		mp, ok := tbl.ModelPriceOf(mk)
		if !ok {
			IncPricingMissing(mk) // 指标 #18（A-46）
			return 0, fmt.Errorf("%w: model %q", ErrPricingMissing, mk)
		}
		// P2-5：任务式（job）单元按次计价，独立于 token 阶梯（B 类无 token）。
		if mp.IsJobUnit() {
			totalMu += mp.JobUnitAmountMu(mu.Requests)
			continue
		}
		// 分轴累计起点（A-26）
		var inBefore, outBefore int64
		if e.monthStd != nil && period != "" {
			inBefore, outBefore = e.monthStd.MonthStdBefore(u.TenantID, mk, period)
		}
		totalMu += rateModel(mu.StdIn, mu.StdOut, inBefore, outBefore, mp)
	}
	return totalMu, nil
}

// Rate 周期金额 = roundAmount(RateMu)（唯一取整点，R-16）。
func (e *ratingEngine) Rate(u *UsageAgg, tbl *PriceTable) (Amount, error) {
	mu, err := e.RateMu(u, tbl)
	if err != nil {
		return 0, err
	}
	return roundAmount(mu, e.rounding), nil
}

// RateMonthly 月结权威入口（语义同 Rate，传月聚合）。
func (e *ratingEngine) RateMonthly(u *UsageAgg, tbl *PriceTable) (Amount, error) {
	return e.Rate(u, tbl)
}

// ExtraAmount 超额计费（A-44：套餐级合计基数 + 瀑布归属 + 亚分返回）。
func (e *ratingEngine) ExtraAmount(u *UsageAgg, plan *Plan, tbl *PriceTable) (int64, error) {
	if plan == nil || plan.MonthlyTokens <= 0 {
		return 0, nil // 不限量套餐，无超额
	}
	if u == nil || len(u.ByModel) == 0 {
		return 0, nil
	}

	period := u.Period

	// 1. 套餐级合计：逐模型取「月前（账本锁定）+ 当次（账本锁定）」std
	type mUsed struct {
		mk      string
		inUsed  int64
		outUsed int64
	}
	var ms []mUsed
	var totIn, totOut int64

	for mk, mu := range u.ByModel {
		mp, ok := tbl.ModelPriceOf(mk)
		if !ok {
			return 0, fmt.Errorf("%w: model %q", ErrPricingMissing, mk)
		}
		var inBefore, outBefore int64
		if e.monthStd != nil && period != "" {
			inBefore, outBefore = e.monthStd.MonthStdBefore(u.TenantID, mk, period)
		}
		inUsed := inBefore + mu.StdIn
		outUsed := outBefore + mu.StdOut
		_ = mp // 保留下游使用
		ms = append(ms, mUsed{mk, inUsed, outUsed})
		totIn += inUsed
		totOut += outUsed
	}

	// 2. 套餐级合计超额（A-44②：基数 = 合计，非逐模型）
	overTotal := max64(0, totIn+totOut-plan.MonthlyTokens)
	if overTotal == 0 {
		return 0, nil
	}

	// 3. 瀑布归属：合计用量降序（并列 modelKey 升序）
	sort.Slice(ms, func(i, j int) bool {
		si, sj := ms[i].inUsed+ms[i].outUsed, ms[j].inUsed+ms[j].outUsed
		if si != sj {
			return si > sj
		}
		return ms[i].mk < ms[j].mk
	})

	remaining := plan.MonthlyTokens
	var totalMu int64 // 亚分

	for _, m := range ms {
		used := m.inUsed + m.outUsed
		if remaining <= 0 {
			// 额度已耗尽，本模型全部超额
			mp, _ := tbl.ModelPriceOf(m.mk)
			totalMu += rateAtTopTier(m.inUsed, m.outUsed, mp)
			continue
		}
		if remaining >= used {
			remaining -= used
			continue // 本模型整段在额度内
		}
		// 本模型部分超额
		consumed := remaining
		remaining = 0
		consumedIn := min64(consumed, m.inUsed) // 入先占额（A-33）
		overIn := m.inUsed - consumedIn
		overOut := m.outUsed - (consumed - consumedIn)
		if overIn < 0 {
			overIn = 0
		}
		if overOut < 0 {
			overOut = 0
		}
		mp, _ := tbl.ModelPriceOf(m.mk) // 前面已校验存在
		totalMu += rateAtTopTier(overIn, overOut, mp)
	}

	return totalMu, nil
}

// ---------- 核心算法 ----------

// rateModel 计算单模型的亚分金额（累进阶梯 + 入/出分轴，A-26）。
// stdIn/stdOut：当周期标准 token 量
// inBefore/outBefore：周期起点前的月累计标准 token（分轴）
// 返回：亚分（千分之一分，int64）
func rateModel(stdIn, stdOut, inBefore, outBefore int64, mp *ModelPrice) int64 {
	if mp == nil {
		return 0
	}
	tiers := effectiveTiers(mp)
	if len(tiers) == 0 {
		return 0
	}

	var mu int64
	for i := range tiers {
		lo := tierLowerBound(i, tiers)
		up := tiers[i].UpToTokens
		// 输入轴独立区段（A-26）
		inSeg := overlap(stdIn, inBefore, lo, up)
		// 输出轴独立区段（A-26）
		outSeg := overlap(stdOut, outBefore, lo, up)
		// 元/千token × token / 1000 × 1000 = 亚分（千分之一分）
		// 推导：金额(元) = tokens/1000 × per1K
		//       金额(分) = tokens/1000 × per1K × 100
		//       亚分(千分之一分) = tokens/1000 × per1K × 100 × 1000 = tokens × per1K × 100
		mu += int64(float64(inSeg) * tiers[i].InPer1K * 100.0)
		mu += int64(float64(outSeg) * tiers[i].OutPer1K * 100.0)
	}
	return mu
}

// rateAtTopTier 按最高档单价计价（超额计费用，A-33/A-44）。
func rateAtTopTier(stdIn, stdOut int64, mp *ModelPrice) int64 {
	if mp == nil || stdIn+stdOut <= 0 {
		return 0
	}
	tiers := effectiveTiers(mp)
	if len(tiers) == 0 {
		return 0
	}
	top := tiers[len(tiers)-1]
	var mu int64
	mu += int64(float64(stdIn) * top.InPer1K * 100.0)
	mu += int64(float64(stdOut) * top.OutPer1K * 100.0)
	return mu
}

// effectiveTiers 返回模型的有效阶梯列表。
//
// 不变量：`Tiers` 必须非空且末档为 ∞（`UpToTokens=0`）——由 `LoadPriceTable` 经
// `validateTiers` 在**加载期 fail-closed 拒载**保证（★ BUG-004）。此处对空 `Tiers`
// 返回 nil 仅作**防御**（不回退为"单档全量"、不静默按 0 价）；调用方应先经价格表校验。
func effectiveTiers(mp *ModelPrice) []Tier {
	if mp == nil || len(mp.Tiers) == 0 {
		return nil
	}
	return mp.Tiers
}

// tierLowerBound 返回第 i 档的下界（左闭右开，最低档含 0）。
func tierLowerBound(i int, tiers []Tier) int64 {
	if i <= 0 {
		return 0
	}
	return tiers[i-1].UpToTokens
}

// overlap 计算 [startBefore, startBefore+length) ∩ [lo, up) 的长度。
// up <= 0 视作 +∞（顶档，A-24）。
func overlap(length, startBefore, lo, up int64) int64 {
	if length <= 0 {
		return 0
	}
	segStart := startBefore
	segEnd := startBefore + length
	if segStart >= segEnd {
		return 0
	}
	intLo := max64(segStart, lo)
	var intHi int64
	if up <= 0 {
		intHi = segEnd // +∞
	} else {
		intHi = min64(segEnd, up)
	}
	if intLo >= intHi {
		return 0
	}
	return intHi - intLo
}

// roundAmount 亚分 → Amount（分）。唯一取整点（R-16 / A-44）。
// mode: "half_up"（默认，四舍五入）或 "floor"（截断）。
// 负数按绝对值对称（C-3：half_up 下 -0.5 → -1，保证 roundAmount(-x) == -roundAmount(x)）。
func roundAmount(mu int64, mode string) Amount {
	if mode == "" {
		mode = "half_up"
	}
	neg := mu < 0
	abs := mu
	if neg {
		abs = -mu
	}
	var result int64
	switch mode {
	case "floor":
		result = abs / 1000
	case "half_up":
		fallthrough
	default:
		// 四舍五入：(abs + 500) / 1000
		result = (abs + 500) / 1000
	}
	if neg {
		return Amount(-result)
	}
	return Amount(result)
}

// ---------- 工具函数 ----------

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// periodMonth 从 period 字符串提取月份（"YYYY-MM"）。
// "YYYY-MM-DD" → 截取前 7 字符；"YYYY-MM" → 直接返回。
func (u *UsageAgg) periodMonth() string {
	if u == nil || len(u.Period) < 7 {
		return ""
	}
	return u.Period[:7]
}
