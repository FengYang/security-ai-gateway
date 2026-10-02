package billing

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ---------- 价格表（§4.1.4 / §5.4 / 附录 D） ----------

// PriceTable 单价表（配置文件 YAML 加载，热加载版本随 Version 字段）。
type PriceTable struct {
	Version  string                `json:"version"  yaml:"version"`  // 版本号（账期锁定追溯）
	Currency string                `json:"currency" yaml:"currency"` // CNY（P0）
	Models   map[string]*ModelPrice `json:"models"   yaml:"models"`   // key = model_key（"engine_type/model"）
	Defaults *ModelPrice            `json:"defaults,omitempty" yaml:"defaults,omitempty"` // 未匹配模型的默认档（可选）
}

// ModelPrice 单模型的计价参数。
type ModelPrice struct {
	// 标准 token 换算系数（模型维度 → 标准维度；A-9 唯一换算入口）
	InCoef  float64 `json:"in_coef"  yaml:"in_coef"`  // 输入 token 系数，默认 1.0
	OutCoef float64 `json:"out_coef" yaml:"out_coef"` // 输出 token 系数，默认 1.0
	// 阶梯单价（元 / 千标准 token）
	Tiers []Tier `json:"tiers" yaml:"tiers"`
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
	// 每个模型校验阶梯
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
		if err := validateTiers(mp.Tiers); err != nil {
			return nil, fmt.Errorf("billing: price table model %q: %w", mk, err)
		}
	}
	return &tbl, nil
}

// validateTiers 校验阶梯并归一为规范顺序（有限档升序在前，∞ 档在最后）。
//
// 规则（B-6.5-3/4）：
//   - UpToTokens=0 表示顶档（+∞），必须**恰好一个**且位于最后（覆盖全部用量）；
//   - 有限档 UpToTokens 必须 > 0 且严格递增；
//   - 缺失 ∞ 档 → 拒绝（存在未覆盖区间）。
// 校验后原地重排 tiers 为规范顺序。
func validateTiers(tiers []Tier) error {
	if len(tiers) == 0 {
		return nil // 空 = 单档全量（由调用方以默认档处理）
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

// HasNonZeroPrice 价格表是否存在**非 0 单价**（任一模型/默认档的任一步梯 in/out 单价非 0）。
// 供 R-29 交叉约束：`over_quota=charge` 的套餐不得对应"全 0 价"（防免费版产出金额账单）。
func (t *PriceTable) HasNonZeroPrice() bool {
	if t == nil {
		return false
	}
	any := func(mp *ModelPrice) bool {
		if mp == nil {
			return false
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
