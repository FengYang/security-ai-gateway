package billing

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ---------- 价格表（§4.1.4 / §5.4 / 附录 D） ----------

// PriceTable 单价表（**JSON** 文件加载，热加载版本随 Version 字段）。
// 注：结构体保留 yaml tag 以便未来引入 YAML 解析；当前加载器为 JSON（★ DOC-003）。
type PriceTable struct {
	Version  string                 `json:"version"  yaml:"version"`                      // 版本号（账期锁定追溯）
	Currency string                 `json:"currency" yaml:"currency"`                     // CNY（P0）
	Models   map[string]*ModelPrice `json:"models"   yaml:"models"`                       // key = model_key（"engine_type/model"）
	Defaults *ModelPrice            `json:"defaults,omitempty" yaml:"defaults,omitempty"` // 未匹配模型的默认档（可选）
}

// ModelPrice 单模型的计价参数。
type ModelPrice struct {
	// 标准 token 换算系数（模型维度 → 标准维度；A-9 唯一换算入口）
	InCoef  float64 `json:"in_coef"  yaml:"in_coef"`  // 输入 token 系数，默认 1.0
	OutCoef float64 `json:"out_coef" yaml:"out_coef"` // 输出 token 系数，默认 1.0
	// 阶梯单价（元 / 千标准 token）
	Tiers []Tier `json:"tiers" yaml:"tiers"`

	// P2-5：任务式（B 类，如蚂蚁隐语 SecretFlow）计价口径。
	//
	// Unit="job" 时按「次」计价：金额 = Requests × PerJob（元/次），忽略 token 阶梯
	// （B 类无 token，token 口径会产出 0 费用假账单，故独立计次口径）。
	// 空 / "token" = 沿用既有 token 阶梯计价（默认，向后兼容：既有价格表无此字段 → token 口径）。
	Unit string `json:"unit,omitempty" yaml:"unit,omitempty"` // "" | "token" | "job"
	// PerJob 单价（元/次），仅 Unit="job" 时生效。0 = 未配置（job 模型漏配单价 →
	// 账单 Unit=job 但 Amount=0，可观测但计 0；由运营在价格表补全，fail-closed 可见）。
	PerJob int64 `json:"per_job,omitempty" yaml:"per_job,omitempty"`
}

// IsJobUnit 是否为任务式（按次）计价单元。
func (mp *ModelPrice) IsJobUnit() bool { return mp != nil && mp.Unit == "job" }

// JobUnitAmountMu 任务式单元亚分金额（千分之一分）。PerJob 单位：元/次。
// 元 → 亚分（千分之一分）= ×100（分）×1000 = ×100000。
func (mp *ModelPrice) JobUnitAmountMu(requests int64) int64 {
	if !mp.IsJobUnit() || requests <= 0 {
		return 0
	}
	return requests * mp.PerJob * 100000
}

// Tier 计价阶梯（progressive 累进；UpToTokens=0 视为 +∞，即顶档）。
type Tier struct {
	UpToTokens int64   `json:"up_to_tokens" yaml:"up_to_tokens"` // 上限（标准 token，含本档；0=∞）
	InPer1K    float64 `json:"in_per_1k"    yaml:"in_per_1k"`    // 输入单价：元 / 千标准 token
	OutPer1K   float64 `json:"out_per_1k"   yaml:"out_per_1k"`   // 输出单价：元 / 千标准 token
}

// ---------- 价格表加载 ----------

// LoadPriceTable 从 JSON 文件加载价格表并做基础校验。
// （P0 用 JSON 避免引入 yaml 依赖；格式与 YAML 等价，仅序列化方式不同）
func LoadPriceTable(path string) (*PriceTable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("billing: read price table: %w", err)
	}
	var tbl PriceTable
	if err := json.Unmarshal(data, &tbl); err != nil {
		return nil, fmt.Errorf("billing: parse price table: %w", err)
	}
	if tbl.Version == "" {
		return nil, fmt.Errorf("billing: price table version is required")
	}
	if tbl.Currency == "" {
		tbl.Currency = "CNY"
	}
	if tbl.Models == nil {
		tbl.Models = map[string]*ModelPrice{}
	}
	// 每个模型校验阶梯（P2-5：任务式 job 单元按次计价，不依赖 token 阶梯，跳过）
	for mk, mp := range tbl.Models {
		if mp == nil {
			return nil, fmt.Errorf("billing: price table model %q is nil", mk)
		}
		if mp.InCoef <= 0 {
			mp.InCoef = 1.0
		}
		if mp.OutCoef <= 0 {
			mp.OutCoef = 1.0
		}
		if mp.IsJobUnit() {
			continue // job 单元：PerJob 计价，无需 token 阶梯
		}
		if err := validateTiers(mp.Tiers); err != nil {
			return nil, fmt.Errorf("billing: price table model %q: %w", mk, err)
		}
	}
	// 默认档（model 未命中时使用）同样必须持有合法且非空的阶梯（★ BUG-004）。
	if tbl.Defaults != nil {
		if tbl.Defaults.InCoef <= 0 {
			tbl.Defaults.InCoef = 1.0
		}
		if tbl.Defaults.OutCoef <= 0 {
			tbl.Defaults.OutCoef = 1.0
		}
		if !tbl.Defaults.IsJobUnit() {
			if err := validateTiers(tbl.Defaults.Tiers); err != nil {
				return nil, fmt.Errorf("billing: price table defaults: %w", err)
			}
		}
	}
	return &tbl, nil
}

// validateTiers 校验阶梯并归一为规范顺序（有限档升序在前，∞ 档在最后）。
//
// 规则（B-6.5-3/4）：
//   - **空阶梯 → 拒绝**（★ BUG-004 fail-closed：无任何单价来源，若放过将静默按 0 金额计价）；
//   - UpToTokens=0 表示顶档（+∞），必须**恰好一个**且位于最后（覆盖全部用量）；
//   - 有限档 UpToTokens 必须 > 0 且严格递增；
//   - 缺失 ∞ 档 → 拒绝（存在未覆盖区间）。
//
// 校验后原地重排 tiers 为规范顺序。
func validateTiers(tiers []Tier) error {
	if len(tiers) == 0 {
		return fmt.Errorf("tiers must not be empty (no price source; fail-closed)")
	}
	var finite []Tier
	var inf *Tier
	for i := range tiers {
		if tiers[i].UpToTokens == 0 {
			if inf != nil {
				return fmt.Errorf("multiple infinite tiers (up_to=0) are not allowed")
			}
			t := tiers[i]
			inf = &t
			continue
		}
		if tiers[i].UpToTokens < 0 {
			return fmt.Errorf("tier up_to must be >= 0, got %d", tiers[i].UpToTokens)
		}
		finite = append(finite, tiers[i])
	}
	sort.Slice(finite, func(i, j int) bool { return finite[i].UpToTokens < finite[j].UpToTokens })
	var prev int64
	for i, t := range finite {
		if t.UpToTokens <= prev {
			return fmt.Errorf("tiers not strictly increasing at index %d: %d <= %d", i, t.UpToTokens, prev)
		}
		prev = t.UpToTokens
	}
	if inf == nil {
		return fmt.Errorf("top tier must be unbounded (up_to_tokens=0) to cover all usage")
	}
	// 原地重排：有限档升序 + ∞ 档
	out := append([]Tier(nil), finite...)
	out = append(out, *inf)
	copy(tiers, out)
	return nil
}

// ModelPriceOf 返回指定模型的价格参数；不存在返回 (nil, false)。
func (t *PriceTable) ModelPriceOf(modelKey string) (*ModelPrice, bool) {
	mp, ok := t.Models[modelKey]
	if ok {
		return mp, true
	}
	if t.Defaults != nil {
		return t.Defaults, true
	}
	return nil, false
}

// HasNonZeroPrice 价格表是否存在**非 0 单价**（任一模型/默认档的任一步梯 in/out 单价非 0，
// 或 job 单元 PerJob 非 0）。供 R-29 交叉约束：`over_quota=charge` 的套餐不得对应"全 0 价"
// （防免费版产出金额账单）。
func (t *PriceTable) HasNonZeroPrice() bool {
	if t == nil {
		return false
	}
	any := func(mp *ModelPrice) bool {
		if mp == nil {
			return false
		}
		if mp.IsJobUnit() {
			return mp.PerJob != 0 // P2-5：任务式按次计价，单价在 PerJob
		}
		for _, tr := range mp.Tiers {
			if tr.InPer1K != 0 || tr.OutPer1K != 0 {
				return true
			}
		}
		return false
	}
	if any(t.Defaults) {
		return true
	}
	for _, mp := range t.Models {
		if any(mp) {
			return true
		}
	}
	return false
}

// ---------- 价格表提供器（静态/热加载） ----------

// staticPriceTable 静态价格表提供器（配置一次性加载）。
type staticPriceTable struct {
	tbl *PriceTable
}

// NewStaticPriceTable 构造静态价格表提供器。
func NewStaticPriceTable(t *PriceTable) PriceTableProvider {
	return &staticPriceTable{tbl: t}
}

func (s *staticPriceTable) Current() *PriceTable { return s.tbl }
