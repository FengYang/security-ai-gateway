// Package configversion 实现「插件 applied 配置版本」的 core 侧缓存（P2-4 T-3.4）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.2（L270）与评审处置记录 C6(7)：
//
//	插件拉取 /routes 的请求头携带当前生效版本 X-Config-Version
//	  → core 缓存「最近上报版本 + 时间」
//	  → 由 core/心跳上报 applied_config_version 给管理面
//
// 职责边界（本包的硬约束）：
//   - core 侧只**如实记录**插件上报了什么，**不做「是否收敛」的判定**——收敛判定属
//     管理面 sync-status（T-3.3）。core 若在此做判定，等于把「期望 vs 实际」的比较
//     前移到没有期望值的一侧，语义错误。
//   - **无版本头 = 未上报（unknown）**：不写入、不覆盖既有记录（管理面据此标 unknown
//     并告警，禁止以「未见差异」默认收敛）。
//   - **非法版本头 = 忽略**：不影响业务请求（拉取照常返回），只累加拒绝计数。
//   - **单调不回退**：core 下发的路由表版本号本身单调递增（回滚也走
//     `next.Version = cur.Version + 1`，见 api/routes.go handleRouteRollback），
//     故插件上报的版本号同样是单调序列；缓存的生效版本因此**只增不减**——迟到的
//     旧上报（并发/乱序/重试）不得把已采纳的高版本冲回旧值。
//
// 与插件侧的契约（**P1-8 归属，本包不改动插件代码**，仅登记接口契约）：
//
//	请求头：X-Config-Version
//	取值：插件**当前已生效**的路由表版本（即 /routes 响应体中的 version 字段，数字）；
//	      尚未持有任何表时取 0（0 会被如实记录 ⇒ 管理面可见「未生效」而非 unknown）。
//	时机：每次 GET /routes 拉取时携带（无论本次拉取是否拿到新表）。
//
// 生命周期：core 进程内内存态，**不随快照持久化**——快照（T-1.7）覆盖的是策略状态，
// 而 applied 版本是「插件当前持有哪一版」的事实，必须由插件实时上报才有意义；
// 重启后从 unknown 重新积累（管理面在 unknown 期间标 unknown + 告警，符合设计口径）。
package configversion

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// HeaderName 插件上报 applied 配置版本的请求头名（设计 §6.2 / C6(7)）。
	HeaderName = "X-Config-Version"

	// MaxVersionLength 版本串最大长度（防滥用、防日志注入）。
	MaxVersionLength = 64

	// SourceRoutes 路由表拉取通道（设计指定的载体路径：GET /routes）。
	//
	// ⚠️ 限流表（/ratelimits）、A2A ACL 表等是**独立版本命名空间**，其上报不得与
	// 路由表版本混入同一记录（否则收敛核对会把两个命名空间的版本号拿来比较），
	// 故按 source 分槽存放。
	SourceRoutes = "routes"
)

// Record 缓存中一条上报通道的记录（对外 JSON 视图）。
type Record struct {
	// Source 上报通道（当前仅 routes）。
	Source string `json:"source"`
	// Version 当前生效版本（可比数字版本下单调不回退）。
	Version string `json:"applied_config_version"`
	// LastReportedVersion 最近一次**有效**上报的原始取值（即便因陈旧未被采纳也如实保留，
	// 便于排障；不参与收敛判定）。
	LastReportedVersion string `json:"last_reported_version"`
	// ReportedAt Version 最后一次被采纳的时间。
	ReportedAt time.Time `json:"reported_at"`
	// LastSeenAt 最近一次收到有效上报的时间（无论是否采纳）。
	LastSeenAt time.Time `json:"last_seen_at"`
	// Seq 该通道的上报计数（严格单调递增；并发下亦不回退 ⇒ 无丢失更新）。
	Seq uint64 `json:"seq"`
	// Accepted 采纳次数；RejectedInvalid 非法版本头次数；RejectedStale 陈旧版本次数。
	Accepted        uint64 `json:"accepted_count"`
	RejectedInvalid uint64 `json:"rejected_invalid_count"`
	RejectedStale   uint64 `json:"rejected_stale_count"`
}

// Cache 记录各上报通道最近一次上报的 applied 配置版本（进程内状态，线程安全）。
type Cache struct {
	mu      sync.RWMutex
	records map[string]*Record
}

// New 构造空的版本缓存。
func New() *Cache {
	return &Cache{records: make(map[string]*Record)}
}

// Normalize 校验并归一化版本串。
//
// 合法：1..MaxVersionLength 字节的可打印 ASCII（0x21..0x7E，无空格/控制字符）。
// 非法：空、超长、含空白或控制字符（含非 ASCII）——后者既可能是伪造，也可能是
// 日志注入载体，一律拒绝。
func Normalize(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" || len(v) > MaxVersionLength {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x21 || c > 0x7e {
			return "", false
		}
	}
	return v, true
}

// Report 记录一次上报。返回（记录快照，是否被采纳为当前生效版本）。
//
// 采纳规则：
//   - 版本串非法 → 不采纳（RejectedInvalid++），调用方**不得**因此中断业务请求；
//   - 可比数字版本且新值 < 已采纳值 → 不采纳（陈旧/回退保护，RejectedStale++），
//     但 LastReportedVersion 与 LastSeenAt 照实更新；
//   - 其余 → 采纳，Version/ReportedAt 更新。
func (c *Cache) Report(source, raw string, at time.Time) (Record, bool) {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	v, ok := Normalize(raw)
	if !ok {
		return c.rejectInvalid(source, at), false
	}
	if at.IsZero() {
		at = time.Now()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	rec, exists := c.records[source]
	if !exists {
		rec = &Record{Source: source}
		c.records[source] = rec
	}
	rec.Seq++
	rec.LastSeenAt = at
	rec.LastReportedVersion = v
	if exists && !versionNotOlder(v, rec.Version) {
		// 陈旧/回退的上报不覆盖当前生效版本（单调不回退）。
		rec.RejectedStale++
		return *rec, false
	}
	rec.Version = v
	rec.ReportedAt = at
	rec.Accepted++
	return *rec, true
}

// rejectInvalid 记录一次「非法版本头」的拒绝（不改变任何已生效的记录内容）。
func (c *Cache) rejectInvalid(source string, at time.Time) Record {
	if at.IsZero() {
		at = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, exists := c.records[source]
	if !exists {
		rec = &Record{Source: source}
		c.records[source] = rec
	}
	rec.Seq++
	rec.LastSeenAt = at
	rec.RejectedInvalid++
	return *rec
}

// Get 取某通道的记录（不存在或从未采纳过版本时 ok=false ⇒ 视为 unknown）。
func (c *Cache) Get(source string) (Record, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rec, ok := c.records[source]
	if !ok || rec.Version == "" {
		return Record{Source: source}, false
	}
	return *rec, true
}

// Snapshot 返回全部通道的记录副本（状态查询用）。
func (c *Cache) Snapshot() map[string]Record {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]Record, len(c.records))
	for k, v := range c.records {
		out[k] = *v
	}
	return out
}

// versionNotOlder 判断新版本是否**不旧于**当前版本。
//
// 两端都是十进制数字（uint64）时按数值比较；否则视为**不可比**（如哈希型版本），
// 按「最新上报覆盖」处理——不可比时无法判定回退，强行拦截会掩盖真实漂移。
func versionNotOlder(newV, curV string) bool {
	if curV == "" {
		return true
	}
	n, err1 := strconv.ParseUint(newV, 10, 64)
	c, err2 := strconv.ParseUint(curV, 10, 64)
	if err1 != nil || err2 != nil {
		return true // 不可比 → 允许覆盖
	}
	return n >= c
}
