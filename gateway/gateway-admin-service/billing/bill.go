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
}

// BillStore 账单持久化接口。
type BillStore interface {
	Put(b *Bill) error
	Get(billID string) (*Bill, error)
	List(q BillQuery) ([]*Bill, error)
	UpdateStatus(billID, status string) error
}
