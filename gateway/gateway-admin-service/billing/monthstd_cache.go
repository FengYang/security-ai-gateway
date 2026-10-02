package billing

import (
	"strings"
	"sync"
	"time"
)

// ---------- 月累计标准 token 缓存（A-37 / A-51，性能增强） ----------
//
// 定位：`monthStdBefore` 是计价热路径（每次 Rate/RateMu 调用、每模型一次）。
// 直读账本需扫「当月初至 period 起点」全月条目 → 第 30 天日结时复杂度
// O(月内条目数 × 模型数)。本缓存把该查询变为**月内单调推进的增量查询**：
// 命中同游标即 O(1)；推进时只查 [上次游标, period) 增量段。
//
// 正确性（不影响结果，仅加速）：
//   - 值来源恒为账本**锁定 std**（入账时按当日价表算好，A-32/A-39），故缓存不参与换算；
//   - 失效**仅**由「补账」触发（迟到数据写入 ≤ 已推进游标的某日）——价格表热更新
//     不改变历史 std 值，**不**触发失效（A-51：删除旧版与后半句互斥的失效条件）；
//   - 回退查询（period 早于已推进游标）走全量回源且**不回写**，保持游标单调，避免污染。

// MonthStdSource 月累计缓存的下层数据源（账本）。
type MonthStdSource interface {
	// MonthStdBefore 全量回源：累计 [月初, period)。
	MonthStdBefore(tenant, modelKey, period string) (int64, int64)
	// SumStdRange 区间求和 [fromDay, toDay)（增量推进用）。
	SumStdRange(tenant, modelKey, fromDay, toDay string) (int64, int64, error)
}

// monthStdEntry 单（租户,模型,月）缓存项：截至 upTo（含）的月累计标准 token。
type monthStdEntry struct {
	stdIn  int64
	stdOut int64
	upTo   string // 已累计到的自然日（含）；"" = 仅月初（未推进）
}

// CachedMonthStd 月累计缓存包装器，实现 MonthStdProvider（可直接注入 RatingEngine）。
type CachedMonthStd struct {
	src MonthStdSource

	mu     sync.RWMutex
	items  map[string]monthStdEntry
	hits   int64
	misses int64
}

// monthStdKey 缓存键（租户 + 模型 + 月；用 NUL 分隔避免拼接歧义）。
func monthStdKey(tenant, modelKey, month string) string {
	return tenant + "\x00" + modelKey + "\x00" + month
}

// NewCachedMonthStd 构造缓存包装器（src 为账本存储）。
func NewCachedMonthStd(src MonthStdSource) *CachedMonthStd {
	return &CachedMonthStd{src: src, items: map[string]monthStdEntry{}}
}

// NewRatingEngineWithCache 构造「月累计缓存加速」的计价引擎，并返回缓存句柄供
// 入账侧做补账失效（A-37）。ledger 须同时满足 MonthStdProvider 与区间求和
// （sqliteLedgerStore 满足；他实现只需提供 MonthStdBefore + SumStdRange）。
func NewRatingEngineWithCache(rounding string, ledger MonthStdSource) (RatingEngine, *CachedMonthStd) {
	cache := NewCachedMonthStd(ledger)
	return NewRatingEngine(rounding, cache), cache
}

// MonthStdBefore 实现 MonthStdProvider（语义与直读一致，A-26 分轴）。
func (c *CachedMonthStd) MonthStdBefore(tenant, modelKey, period string) (int64, int64) {
	if len(period) < 7 {
		return 0, 0
	}
	month := period[:7]
	if len(period) == 7 {
		return 0, 0 // 月结：起点即月初
	}
	monthStart := month + "-01"
	if period <= monthStart {
		return 0, 0
	}
	wantUpTo := dayBefore(period) // [月初, period) 的累计上界 = period 前一日
	key := monthStdKey(tenant, modelKey, month)

	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()

	// 命中：游标一致
	if ok && e.upTo == wantUpTo {
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return e.stdIn, e.stdOut
	}

	// 增量推进：缓存游标在目标之前 → 只查增量段（A-37 核心收益）
	if ok && e.upTo != "" && e.upTo < wantUpTo {
		from := dayAfter(e.upTo)
		dIn, dOut, err := c.src.SumStdRange(tenant, modelKey, from, period)
		if err == nil {
			nIn, nOut := e.stdIn+dIn, e.stdOut+dOut
			c.mu.Lock()
			c.items[key] = monthStdEntry{stdIn: nIn, stdOut: nOut, upTo: wantUpTo}
			c.hits++
			c.mu.Unlock()
			return nIn, nOut
		}
		// 增量失败 → 降级为全量回源（不写缓存，保持既有游标）
	}

	// 未命中 / 回退查询：全量回源
	in, out := c.src.MonthStdBefore(tenant, modelKey, period)

	c.mu.Lock()
	c.misses++
	// 仅在「首次」或「游标前进」时回写（防回退污染）
	if !ok || wantUpTo > e.upTo {
		c.items[key] = monthStdEntry{stdIn: in, stdOut: out, upTo: wantUpTo}
	}
	c.mu.Unlock()
	return in, out
}

// InvalidateDayIfBackfill 补账失效：迟到数据写入 day 时，删除覆盖该日的缓存项
// （即该租户该月内、游标 >= day 的项）。正常前进（day 晚于游标）不失效。
//
// 语义依据（A-37/A-51）：只有「写入已推进区间内的历史日」才会改变已有累计；
// 价格表热更新不改变已锁定 std，故不触发任何失效。
func (c *CachedMonthStd) InvalidateDayIfBackfill(tenant, day string) {
	if len(day) < 7 {
		return
	}
	month := day[:7]
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.items {
		parts := strings.Split(k, "\x00")
		if len(parts) != 3 {
			continue
		}
		if parts[0] != tenant || parts[2] != month {
			continue
		}
		if e.upTo != "" && e.upTo >= day {
			delete(c.items, k) // 缓存区间覆盖 day → 值已失效
		}
	}
}

// InvalidateTenant 清空某租户全部缓存（运维/测试用）。
func (c *CachedMonthStd) InvalidateTenant(tenant string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.items {
		parts := strings.Split(k, "\x00")
		if len(parts) == 3 && parts[0] == tenant {
			delete(c.items, k)
		}
	}
}

// Stats 返回 (命中数, 未命中数)（测试/可观测用）。
func (c *CachedMonthStd) Stats() (int64, int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}

// ---------- 日期工具 ----------

// dayBefore 返回 day 的前一日（"2006-01-02"）；解析失败原样返回。
func dayBefore(day string) string { return shiftDay(day, -1) }

// dayAfter 返回 day 的次日；解析失败原样返回。
func dayAfter(day string) string { return shiftDay(day, 1) }

func shiftDay(day string, delta int) string {
	t, err := time.Parse(dayLayout, day)
	if err != nil {
		return day
	}
	return t.AddDate(0, 0, delta).Format(dayLayout)
}
