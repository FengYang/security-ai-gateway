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
	TokensIn  int64                `json:"tokens_in"`
	TokensOut int64                `json:"tokens_out"`
	Requests  int64                `json:"requests"`
	RetryToks int64                `json:"retry_toks,omitempty"`
	ByModel   map[string]*ModelAgg `json:"by_model"`
}

// UsageWindow 一次拉取/推送的时间窗口。
type UsageWindow struct {
	FromNs int64 `json:"from_ns"`
	ToNs   int64 `json:"to_ns"`
	// Day 归属日（"YYYY-MM-DD"，UTC+8）。非空时覆盖“按 ToNs 推导”（★ BUG-007：
	// 拉取按自然日切分后显式标注，使账本归日与 tee-infer /usage 的按日查询同口径）。
	Day      string                `json:"day,omitempty"`
	Tenants  map[string]*TenantAgg `json:"tenants"`
	Source   string                `json:"source"`    // pull | push
	EventKey string                `json:"event_key"` // 幂等键
	// ClusterID 计费打标：产生本窗口用量的集群（R-4/A5(6)，P2-4 T-1.8）。
	// 由计量上报侧（pull 源 / push 事件）携带；AggToEntries 逐条写入账本的
	// cluster_id **证据列**。空串 = 单集群部署或未打标（默认 ⇒ 既有行为逐字节不变）。
	//
	// 注：event_key 不因打标而改变（幂等键口径冻结）；部署若无法保证 event_id
	// 全局唯一，应在上报侧用 cluster id 前缀化 event_id，而非在此处隐式改写。
	ClusterID string `json:"cluster_id,omitempty"`
}
