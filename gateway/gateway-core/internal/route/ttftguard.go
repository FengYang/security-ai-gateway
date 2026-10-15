package route

// ttftguard.go — P1-6 M3.3：上报防护（去重 + 值域钳制 + 白名单 + 内存上限）。
//
// 依据（本体 v1.5 §4.1 M3.3 / §6.2）：
//   - batch_id 去重（至少一次 + 去重兜底；重复批次丢弃计 result=duplicate）；
//   - buckets[i] 单桶上限、单批总样本上限、reported_at 时间窗（TT2-03）；
//   - (tenant,model,endpoint) 必须命中当前路由表已知端点（TT2-08 白名单，防幽灵端点）；
//   - 聚合条目数上限（TTFTRing.maxEntries，超限拒绝新增键，TT2-08）。
//
// 防护缺省为「防伪造/防溢出」安全值，属部署可调口径；本文件只提供机制，HTTP 语义在 M3.4。

import (
	"fmt"
	"sync"
)

// 防护缺省上限（TT2-03/TT2-08；防伪造与防溢出安全值）。
const (
	// TTFTMaxBucketCount 单桶计数上限（单批内任一 buckets[i]）。
	TTFTMaxBucketCount uint64 = 1_000_000
	// TTFTMaxBatchSamples 单批总样本上限（一次上报请求 samples 全量求和）。
	TTFTMaxBatchSamples uint64 = 10_000_000
	// TTFTForwardSkewSec reported_at 允许超前（时钟偏移容忍；= 分片窗口 T）。
	TTFTForwardSkewSec int64 = 25
	// TTFTMaxEntries 聚合条目数上限（tenant×model×endpoint×cache；TT2-08）。
	TTFTMaxEntries = 10000
	// TTFTDedupTTLSec batch_id 去重保留时长（覆盖待确认队列最坏重发窗口，§6.2）。
	TTFTDedupTTLSec int64 = 300
	// TTFTDedupMaxEntries 去重集合容量上限（FIFO 淘汰最旧）。
	TTFTDedupMaxEntries = 65536
)

// ValidateTTFTBucketCounts 值域钳制（TT2-03）：单桶计数 ≤ TTFTMaxBucketCount。
func ValidateTTFTBucketCounts(buckets *[TTFTBucketCount]uint64) error {
	if buckets == nil {
		return fmt.Errorf("buckets 缺失")
	}
	for i, c := range buckets {
		if c > TTFTMaxBucketCount {
			return fmt.Errorf("buckets[%d]=%d 超出单桶上限 %d", i, c, TTFTMaxBucketCount)
		}
	}
	return nil
}

// ValidateTTFTBatchTotal 单批总样本上限（TT2-03）：一次上报全量求和 ≤ TTFTMaxBatchSamples。
func ValidateTTFTBatchTotal(total uint64) error {
	if total > TTFTMaxBatchSamples {
		return fmt.Errorf("单批总样本 %d 超出上限 %d", total, TTFTMaxBatchSamples)
	}
	return nil
}

// TTFTReportedAtInWindow reported_at（秒）时间窗（TT2-03）：
// 不早于 now-window_sec（更早会落出滑窗，属越窗批次），不超前于 now+TTFTForwardSkewSec（时钟偏移容忍）。
func TTFTReportedAtInWindow(reportedAt, now int64, windowSec int) bool {
	if reportedAt <= 0 || now <= 0 {
		return false
	}
	win, _ := normalizeWindow(windowSec)
	if reportedAt < now-int64(win) {
		return false
	}
	if reportedAt > now+TTFTForwardSkewSec {
		return false
	}
	return true
}

// KnowsEndpoint 白名单校验（TT2-08）：(tenant,model) 命中路由且 endpoint 属其端点集合。
// 未配置端点的条目（v1 二元模式）不构成合法上报来源 → 恒 false。
func (t *RouteTable) KnowsEndpoint(tenant, model, endpoint string) bool {
	if t == nil || endpoint == "" {
		return false
	}
	for i := range t.Routes {
		r := &t.Routes[i]
		if r.Tenant != tenant || r.Model != model {
			continue
		}
		for j := range r.Endpoints {
			if r.Endpoints[j].Name == endpoint {
				return true
			}
		}
		return false
	}
	return false
}

// TTFTDedup batch_id 去重集合（§6.2：至少一次上报 + 按 batch_id 去重；并发安全）。
//
// 语义：Seen 首次见到（未过期）batch_id → 登记并返回 false；再次见到 → 返回 true（重复）。
// 过期条目按插入序惰性清理（TTL 统一，过期项恒为队首前缀）；容量超限 FIFO 淘汰最旧。
// 注意：重复 Seen 不刷新 TTL（batch_id 本身含周期起始秒，同 id 属同批次）。
type TTFTDedup struct {
	mu      sync.Mutex
	max     int
	ttlSec  int64
	entries map[string]int64 // batch_id → 过期时间（秒）
	order   []string         // 插入序（FIFO）
}

// NewTTFTDedup 创建去重集合（缺省容量/TTL）。
func NewTTFTDedup() *TTFTDedup {
	return NewTTFTDedupWithLimit(TTFTDedupMaxEntries, TTFTDedupTTLSec)
}

// NewTTFTDedupWithLimit 创建去重集合并指定容量与 TTL（≤0 → 取缺省）。
func NewTTFTDedupWithLimit(maxEntries int, ttlSec int64) *TTFTDedup {
	if maxEntries <= 0 {
		maxEntries = TTFTDedupMaxEntries
	}
	if ttlSec <= 0 {
		ttlSec = TTFTDedupTTLSec
	}
	return &TTFTDedup{max: maxEntries, ttlSec: ttlSec, entries: make(map[string]int64)}
}

// Seen 判定并登记 batch_id：已见（未过期）→ true；否则登记并返回 false。
func (d *TTFTDedup) Seen(batchID string, now int64) bool {
	if batchID == "" || now <= 0 {
		return false // 非法输入不参与去重（API 层已把关）
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prune(now)
	if _, ok := d.entries[batchID]; ok {
		return true
	}
	d.entries[batchID] = now + d.ttlSec
	d.order = append(d.order, batchID)
	if len(d.entries) > d.max {
		// FIFO 淘汰最旧（跳过已被 prune 摘除的悬挂引用）
		for len(d.order) > 0 {
			id := d.order[0]
			d.order = d.order[1:]
			if id == batchID {
				continue // 极端：容量为 1 且刚插入自身，不再淘汰
			}
			if _, ok := d.entries[id]; ok {
				delete(d.entries, id)
				break
			}
		}
	}
	return false
}

// prune 惰性清理队首过期项（调用方持锁）。
func (d *TTFTDedup) prune(now int64) {
	for len(d.order) > 0 {
		id := d.order[0]
		exp, ok := d.entries[id]
		if !ok {
			d.order = d.order[1:]
			continue
		}
		if exp <= now {
			delete(d.entries, id)
			d.order = d.order[1:]
			continue
		}
		break
	}
}
