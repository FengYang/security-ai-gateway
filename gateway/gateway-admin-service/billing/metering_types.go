package billing

// ---------- 计量聚合类型（拉取/推送共用） ----------

// ModelAgg 单模型维度用量（净量口径）。
type ModelAgg struct {
	TokensIn  int64 `json:"tokens_in"`  // 输入 token 净量
	TokensOut int64 `json:"tokens_out"` // 输出 token 净量
	Requests  int64 `json:"requests"`
	RetryToks int64 `json:"retry_toks,omitempty"` // 重试 token（平台成本）
}

// TenantAgg 单租户用量聚合（含模型维度）。
type TenantAgg struct {
	TokensIn  int64               `json:"tokens_in"`
	TokensOut int64               `json:"tokens_out"`
	Requests  int64               `json:"requests"`
	RetryToks int64               `json:"retry_toks,omitempty"`
	ByModel   map[string]*ModelAgg `json:"by_model"`
}

// UsageWindow 一次拉取/推送的时间窗口。
type UsageWindow struct {
	FromNs   int64                     `json:"from_ns"`
	ToNs     int64                     `json:"to_ns"`
	Tenants  map[string]*TenantAgg     `json:"tenants"`
	Source   string                    `json:"source"`   // pull | push
	EventKey string                    `json:"event_key"` // 幂等键
}
