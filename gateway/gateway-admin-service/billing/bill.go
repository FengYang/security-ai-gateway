package billing

// ---------- 账单领域类型（T5，§4.1.6 / §5.3） ----------

// 账单状态（D-16 / §7.3）。
const (
	BillStatusDraft         = "draft"          // 草稿（可被重算；对账未过时停留此态）
	BillStatusFrozen        = "frozen"         // 冻结（对账差异超阈值）
	BillStatusIssued        = "issued"         // 已出账（最终态）
	BillStatusVoid          = "void"           // 作废
	BillStatusAssocMismatch = "assoc_mismatch" // 关联校验不符（S-10）
)

// 账单类型（kind）。
const (
	BillKindDaily   = "daily"
	BillKindMonthly = "monthly"
	BillKindOverage = "overage" // A-45：charge 套餐超标单列
)

// Bill 账单（日结/月结/超额）。
type Bill struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant"`
	Kind         string     `json:"kind"`   // daily | monthly | overage
	Period       string     `json:"period"` // "2026-10-01" | "2026-10"
	Items        []BillItem `json:"items"`
	Total        Amount     `json:"total"` // 分
	Currency     string     `json:"currency"`
	PriceVersion string     `json:"price_version"`
	Status       string     `json:"status"` // draft|frozen|issued|void|assoc_mismatch
	Sig          string     `json:"sig,omitempty"`
	LedgerHead   string     `json:"ledger_head"`
	AuditHead    string     `json:"audit_head"`
	GeneratedAt  int64      `json:"generated_at"`
	// ClusterID 计费打标（R-4/A5(6)，P2-4 T-1.8）：本账单用量所属集群。
	//
	// 取值口径：周期内该租户账本条目**唯一**集群标签（未打标或跨集群混合 ⇒ ""）。
	// 空串 = 单集群/未打标（既有行为不变）。混合场景请用 ClusterUsageReport 拆分对账。
	//
	// ★ 与账本 cluster_id 同口径：证据/维度字段，**不进账单签名域**
	// （canonicalBill 已冻结；加入会使既有账单签名失效，§7.2/§7.6）。
	ClusterID string `json:"cluster_id,omitempty"`
}

// BillItem 账单明细行。
type BillItem struct {
	ModelKey       string     `json:"model_key"`
	StandardTokens int64      `json:"standard_tokens"`
	TokensIn       int64      `json:"tokens_in"`
	TokensOut      int64      `json:"tokens_out"`
	RetryToks      int64      `json:"retry_toks"` // 展示"平台承担"，不计入 Amount（M9）
	Amount         Amount     `json:"amount"`
	TierBreakdown  []TierLine `json:"tier_breakdown,omitempty"`
	// Unit P2-5：计量口径分列。"token"（默认，A 类 chat 式）| "job"（B 类任务式，按次）。
	// 空串按 "token" 解释（向后兼容既有账单）。
	Unit string `json:"unit,omitempty"`
}

// TierLine 阶梯分解行（可解释性）。
type TierLine struct {
	UpToTokens int64  `json:"up_to_tokens"`
	Tokens     int64  `json:"tokens"`
	Amount     Amount `json:"amount"`
}

// BillQuery 账单查询条件。
type BillQuery struct {
	TenantID string
	Kind     string // "" = 全部
	From     string
	To       string
	Limit    int
	// ClusterID 按集群过滤（R-4/A5(6) 计费打标）；"" = 不过滤（默认，既有调用行为不变）。
	ClusterID string
	// ClusterUnset true = 仅返回**未打标**账单（cluster_id = ''）；优先于 ClusterID。
	ClusterUnset bool
}

// BillStore 账单持久化接口。
type BillStore interface {
	Put(b *Bill) error
	Get(billID string) (*Bill, error)
	List(q BillQuery) ([]*Bill, error)
	UpdateStatus(billID, status string) error
}
