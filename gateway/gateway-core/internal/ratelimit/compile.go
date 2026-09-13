package ratelimit

import (
	"errors"
	"fmt"
)

// 本文件实现设计 v1.1 §2「编译产物形态（方案 A）」：把策略表编译为数据面
// cluster-key-rate-limit 2.0.1 的配置（rule_items / global_threshold）。
//
// 纪律（避免"字段静默失效"——本项目已因 schema 错配吃过一次实境事故）：
//   - 只发射**仓库内已实链验证**的字段（rule_name / rule_items / limit_by_per_header /
//     limit_keys.key / limit_keys.query_per_second / show_limit_quota_header /
//     rejected_code / redis.*）；
//   - 无证据的字段（burst_multiplier、api_key 维度的分桶头名）**一律不下发**，
//     改为返回 Note 如实记录，待 S4 实链验证后再纳入；
//   - global_threshold 有插件报错文本证据、但未实链验证 → 发射并附 Note。

// HeaderTenant 租户分桶头（本项目配置中已实链验证：同窗口 t-a 429 / t-b 200）。
const HeaderTenant = "x-tenant-id"

// ErrNoEffectiveRules 编译后没有任何可下发规则（插件要求至少一项，否则加载失败）。
var ErrNoEffectiveRules = errors.New("ratelimit: 无可下发规则（插件要求至少一项 global_threshold 或 rule_items）")

// CompileOptions 编译期参数（非策略内容，属部署配置）。
type CompileOptions struct {
	RuleName             string
	RedisServiceName     string
	RedisServicePort     int
	RedisTimeoutMs       int
	RedisDatabase        int
	RejectedCode         int
	ShowLimitQuotaHeader bool
}

// DefaultCompileOptions 返回与 deploy/higress/security-plugins.yaml 一致的部署缺省值。
func DefaultCompileOptions() CompileOptions {
	return CompileOptions{
		RuleName:             "otpmask-ratelimit",
		RedisServiceName:     "redis-ratelimit.dns",
		RedisServicePort:     6379,
		RedisTimeoutMs:       500,
		RedisDatabase:        0,
		RejectedCode:         429,
		ShowLimitQuotaHeader: true,
	}
}

// LimitKey 某一分桶键的阈值（key="*" 表示按该头每个不同取值分别计数）。
type LimitKey struct {
	Key            string `json:"key"`
	QueryPerSecond int64  `json:"query_per_second"`
}

// RuleItem 一组按头分桶的限流项（插件 schema 要求嵌在 rule_items[]）。
type RuleItem struct {
	LimitByPerHeader string     `json:"limit_by_per_header"`
	LimitKeys        []LimitKey `json:"limit_keys"`
}

// GlobalThreshold 全局阈值（不按头分桶）。
type GlobalThreshold struct {
	QueryPerSecond int64 `json:"query_per_second"`
}

// RedisConfig 计数后端（集群一致性由 Redis 保证）。
type RedisConfig struct {
	ServiceName string `json:"service_name"`
	ServicePort int    `json:"service_port"`
	Timeout     int    `json:"timeout"`
	Database    int    `json:"database"`
}

// DataPlaneConfig 编译产物：可直接作为 cluster-key-rate-limit 的 matchRule config。
type DataPlaneConfig struct {
	RuleName             string           `json:"rule_name"`
	RuleItems            []RuleItem       `json:"rule_items"`
	GlobalThreshold      *GlobalThreshold `json:"global_threshold,omitempty"`
	ShowLimitQuotaHeader bool             `json:"show_limit_quota_header"`
	RejectedCode         int              `json:"rejected_code"`
	Redis                RedisConfig      `json:"redis"`
}

// RPMToQPS 把每分钟请求数换算为插件所需的每秒值（**向上取整**，宁可略紧不放宽）。
func RPMToQPS(rpm int64) int64 {
	if rpm <= 0 {
		return 0
	}
	qps := (rpm + 59) / 60
	if qps < 1 {
		qps = 1
	}
	return qps
}

// CompileDataPlane 编译数据面配置；返回配置 + 如实说明的 Note 列表。
//
// 仅处理 kind=rate 且 action=reject 的启用规则；tenant/global 维度可下发
// （api_key/model 无 schema 证据或按设计暂不实施 → Note）。
func CompileDataPlane(t *Table, opt CompileOptions) (*DataPlaneConfig, []string, error) {
	if t == nil {
		return nil, nil, fmt.Errorf("ratelimit: 限流表为空")
	}
	if err := t.Validate(); err != nil {
		return nil, nil, err
	}
	if opt.RuleName == "" {
		opt = DefaultCompileOptions()
	}

	notes := make([]string, 0, len(t.Rules))
	tenantKeys := make([]LimitKey, 0, len(t.Rules))
	var global *GlobalThreshold

	for i := range t.Rules {
		r := &t.Rules[i]
		switch {
		case !r.Enabled:
			notes = append(notes, fmt.Sprintf("规则 %s 已禁用：不下发", r.ID))
			continue
		case r.Kind == KindBudget:
			notes = append(notes, fmt.Sprintf("规则 %s 为 kind=budget：执行点在 tee-infer（S3），本编译不下发", r.ID))
			continue
		case r.Action == ActionShadow:
			// 关键正确性：插件无影子模式，若按普通规则发射会**真的拦断**流量。
			notes = append(notes, fmt.Sprintf("规则 %s 为 action=shadow：数据面无法表达（插件无影子模式），本编译不下发；影子计数留待 S3/后续", r.ID))
			continue
		}
		if r.BurstMultiplier != 0 {
			notes = append(notes, fmt.Sprintf("规则 %s 的 burst_multiplier=%d 未纳入：插件 2.0.1 schema 未确认该字段，不发射（避免字段静默失效）", r.ID, r.BurstMultiplier))
		}
		if r.TPM > 0 {
			notes = append(notes, fmt.Sprintf("规则 %s 的 tpm=%d 归 tee-infer（S3）：数据面只执行 RPM", r.ID, r.TPM))
		}
		if r.RPM <= 0 {
			notes = append(notes, fmt.Sprintf("规则 %s 未设 rpm：数据面无下发内容", r.ID))
			continue
		}

		qps := RPMToQPS(r.RPM)
		if r.RPM%60 != 0 {
			notes = append(notes, fmt.Sprintf("规则 %s 的 rpm=%d 非 60 整数倍：插件按 QPS 计数，实际等效 %d/min（向上取整，偏紧）", r.ID, r.RPM, qps*60))
		}
		switch r.Scope {
		case ScopeTenant:
			tenantKeys = append(tenantKeys, LimitKey{Key: r.Target, QueryPerSecond: qps})
		case ScopeGlobal:
			global = &GlobalThreshold{QueryPerSecond: qps}
			notes = append(notes, fmt.Sprintf("规则 %s 使用 global_threshold：字段名来自插件报错文本证据，**尚未实链验证**（S4 判据 3 补验）", r.ID))
		case ScopeAPIKey:
			notes = append(notes, fmt.Sprintf("规则 %s 为 api_key 维度：key-auth 2.x 消费者分桶头名在仓库内**无证据**，不下发（猜错即静默失效）", r.ID))
		case ScopeModel:
			notes = append(notes, fmt.Sprintf("规则 %s 为 model 维度：按设计 v1.1 §10⑤ 暂不实施，不下发", r.ID))
		}
	}

	if len(tenantKeys) == 0 && global == nil {
		return nil, notes, ErrNoEffectiveRules
	}

	cfg := &DataPlaneConfig{
		RuleName:             opt.RuleName,
		RuleItems:            []RuleItem{},
		ShowLimitQuotaHeader: opt.ShowLimitQuotaHeader,
		RejectedCode:         opt.RejectedCode,
		Redis: RedisConfig{
			ServiceName: opt.RedisServiceName,
			ServicePort: opt.RedisServicePort,
			Timeout:     opt.RedisTimeoutMs,
			Database:    opt.RedisDatabase,
		},
	}
	if len(tenantKeys) > 0 {
		cfg.RuleItems = append(cfg.RuleItems, RuleItem{
			LimitByPerHeader: HeaderTenant,
			LimitKeys:        tenantKeys,
		})
	}
	cfg.GlobalThreshold = global
	return cfg, notes, nil
}
