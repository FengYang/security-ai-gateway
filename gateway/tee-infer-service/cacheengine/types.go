// Package cacheengine — 语义缓存引擎（一期精确缓存 + 二期语义缓存）。
//
// 运行位置：tee-infer-service 进程内（TEE 明文域），与现有 ExactCache 装配点一致。
// 信任边界：缓存值（明文）绝不出本进程；形态 B/C 写入 Redis 前整体 AEAD 加密。
//
// 一期（T1/T2）：精确命中 + 负向缓存 + 可配置 TTL + 命中率监控 + 主动失效
// 二期（T4/T5）：embedding 语义检索 + 场景化阈值 + 实体指纹 + 误命中反馈
package cacheengine

import (
	"fmt"
	"strconv"
	"time"
)

// ===== 核心类型 =====

// EntryKind 缓存条目种类。
type EntryKind string

const (
	KindExact    EntryKind = "exact"
	KindSemantic EntryKind = "semantic"
	KindNegative EntryKind = "negative"
)

// TenantPolicy 租户缓存策略。
type TenantPolicy string

const (
	PolicyDefault   TenantPolicy = "default"
	PolicyExactOnly TenantPolicy = "exact_only"
	PolicyOff       TenantPolicy = "off"
)

// SceneClass 场景分类。
type SceneClass string

const (
	SceneFactual SceneClass = "factual"
	SceneGeneral SceneClass = "general"
	SceneCode    SceneClass = "code"
	SceneMath    SceneClass = "math"
)

// CacheMode 缓存模式。
type CacheMode string

const (
	ModeOff      CacheMode = "off"
	ModeExact    CacheMode = "exact"
	ModeSemantic CacheMode = "semantic"
	ModeFull     CacheMode = "full"
)

// SecurityLevel 安全域等级（§7.4 密态路径）。
// plain：明文域（默认） / secure：密态域（TEE 内解密处理）/ hsm：HSM 强安全域
type SecurityLevel string

const (
	SecLevelPlain  SecurityLevel = "plain"
	SecLevelSecure SecurityLevel = "secure"
	SecLevelHSM    SecurityLevel = "hsm"
)

// ===== 生成参数 =====

// GenParams 影响输出的生成参数。全部参与缓存键。
type GenParams struct {
	Temperature      float64
	TopP             float64
	Seed             *int64 // 可空；非空则入键
	PresencePenalty  float64
	FrequencyPenalty float64
}

// Canonical 返回规范化签名，用于缓存键拼接。
func (g GenParams) Canonical() string {
	seed := "-"
	if g.Seed != nil {
		seed = strconv.FormatInt(*g.Seed, 10)
	}
	return fmt.Sprintf("t=%.4f|p=%.4f|s=%s|pp=%.4f|fp=%.4f",
		g.Temperature, g.TopP, seed, g.PresencePenalty, g.FrequencyPenalty)
}

// ===== 查询上下文 =====

// LookupContext 查询上下文（全部字段由 tee-infer 主链在明文域内填充）。
type LookupContext struct {
	TenantID        string
	RequestID       string
	EngineType      string
	Model           string
	ModelVer        string
	MaxNewTokens    int
	Gen             GenParams
	Stream          bool
	TransformedHash string
	PromptText      string
	Scene           SceneClass
	PolicyVer       string
	GuardVer        string
	SecurityLevel   SecurityLevel // 安全域等级（默认 plain）

	// 可缓存性信号（§6.0 判定输入）
	TurnCount     int
	HasToolCall   bool
	TimeSensitive bool
	NoCache       bool
}

// ===== 查询结果 =====

// LookupResult 查询结果。
type LookupResult struct {
	Hit          bool
	Kind         EntryKind
	Entry        *Entry
	Similarity   float64
	TopCandidate float64
	RejectReason string
	Jitter       time.Duration
	FastScan     ScanVerdict
	CacheDecision *CacheDecision
}

// IsNegative 负向命中 = Hit 且 Kind=KindNegative（Entry 无 Text，不可当响应下发）。
func (r LookupResult) IsNegative() bool {
	return r.Hit && r.Kind == KindNegative
}

// CacheDecision 可缓存性判定结论（§6.0）。
type CacheDecision struct {
	Cacheable bool
	Reason    string
}

// ===== 写入上下文 =====

// StoreContext 写入上下文。
type StoreContext struct {
	LookupContext
	Writable bool // 写前审查门禁：由主链依 out.Blocked/finish 计算
}

// InferResult 本轮到源端推理的产出（最小必要集）。
type InferResult struct {
	Text      string
	TokensIn  int
	TokensOut int
	Finish    string
	Negative  *NegativePayload
	Segments  []Segment
}

// Segment 流式分片：文本 + 与首片的相对偏移。
type Segment struct {
	Text string
	At   time.Duration
}

// StoreOutcome 写入结果。
type StoreOutcome struct {
	Stored  bool
	Layer   string // exact|semantic|both|skipped
	Skipped string // 跳过原因
}

// ===== 缓存条目 =====

// Entry 缓存条目（内存态；落 Redis 前整体 AEAD 加密）。
// Text/Segments 标记 json:"-"：默认 JSON 序列化不含载荷，防明文外泄。
type Entry struct {
	Kind       EntryKind `json:"kind"`
	EntryID    string    `json:"id"`
	TenantID   string    `json:"tenant"`
	EngineType string    `json:"engine"`
	Model      string    `json:"model"`

	KeyHash    string `json:"key_hash"`
	PromptHash string `json:"prompt_hash"`

	// 载荷（明文，仅 TEE 内）
	Text     string           `json:"-"`
	Segments []Segment        `json:"-"`
	Negative *NegativePayload `json:"neg,omitempty"`

	TokensIn   int    `json:"tin"`
	TokensOut  int    `json:"tout"`
	HitCount   uint32 `json:"hits"`
	LastHitAt  int64  `json:"lh_at"`

	CreatedAt int64 `json:"created_at"`
	ExpireAt  int64 `json:"expire_at"`

	PolicyVer  string `json:"pver"`
	GuardVer   string `json:"gver"`
	ModelVer   string `json:"mver,omitempty"`
	EmbedModel string `json:"emodel,omitempty"`
	EmbedDim   int    `json:"edim,omitempty"`

	Checksum string `json:"cksum"`
	MAC      []byte `json:"mac,omitempty"`
}

// NegativePayload 负向缓存载荷（不含任何响应内容）。
type NegativePayload struct {
	Reason    string `json:"reason"`
	Stage     string `json:"stage"`
	PolicyVer string `json:"pver"`
	GuardVer  string `json:"gver"`
	CreatedAt int64  `json:"at"`
}

// ===== 向量相关 =====

// VectorMeta 向量元数据。
type VectorMeta struct {
	EntryID         string
	TenantID        string
	EngineType      string
	Model           string
	PolicyVer       string
	GuardVer        string
	Scene           SceneClass
	SecurityLevel   SecurityLevel
	ExpireAt        int64
	FingerprintHash string
}

// VectorHit 向量检索命中。
type VectorHit struct {
	EntryID    string
	Similarity float64
	Meta       VectorMeta
}

// VectorFilter 硬过滤（不经相似度，直接裁剪候选集）。
type VectorFilter struct {
	TenantID      string
	EngineType    string
	Model         string
	PolicyVer     string
	GuardVer      string
	SecurityLevel SecurityLevel
}

// ===== 读时快审 =====

// ScanVerdict 读时快审结论。
type ScanVerdict struct {
	Allow  bool
	Reason string
	Match  string
}

// ===== 失效选择器 =====

// InvalidateSelector 主动失效选择器。
type InvalidateSelector struct {
	KeyHash  string // 非空 = 按键删除
	TenantID string // 非空 = 按租户删除
	Model    string // 非空 = 按模型删除
	All      bool   // 全量清空
}

// ===== 统计快照 =====

// StatsSnapshot 统计快照（只读）。
type StatsSnapshot struct {
	Mode            string
	ExactEntries    int
	NegativeEntries int
	VectorEntries   int
	Evictions       uint64
	Lookups         map[string]uint64 // key: "{kind}:{result}"
	FastCheckBlocks uint64
	SemanticFP      uint64
	SavedTokens     int64
	SavedCostEst    float64
}

// ===== 内部辅助 =====

// nowFunc 时间函数（测试可注入）。
type nowFunc func() time.Time

func defaultNow() time.Time { return time.Now() }

// unixMs 返回毫秒级时间戳。
func unixMs(nowFn nowFunc) int64 {
	return nowFn().UnixMilli()
}
