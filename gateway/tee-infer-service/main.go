// tee-infer-service: TEE 飞地推理服务
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
	"security-ai-gateway/gateway/tee-infer-service/model"
	"security-ai-gateway/gateway/teecore"
	"security-ai-gateway/internal/memzero"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// maskModulus 掩码模 R（与 otpmask-plugin 对齐 2^32）。
const maskModulus uint64 = 1 << 32

// seenTTL 防重放集合的 TTL（秒）：超过此时间的 request_id 被清理。
const seenTTL = 60

// seenCleanupInterval 防重放集合清理间隔。
const seenCleanupInterval = 30 * time.Second

// adminHeader 管理端点认证请求头。
const adminHeader = "X-Admin-Token"

// attestHeader 远程证明令牌请求头。
const attestHeader = "X-Attest-Token"

// unmaskVector 解密向量（与 otpmask-plugin 同 seed 同顺序对称）。
func unmaskVector(seed []byte, r uint64, vec []uint64) ([]uint64, error) {
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(vec))
	for i, c := range vec {
		m := s.Next()
		out[i] = (c + r - m%r) % r
	}
	return out, nil
}

// maskVector 加密向量。
func maskVector(seed []byte, r uint64, vec []uint64) ([]uint64, error) {
	s, err := mask.NewStream(seed, r)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(vec))
	for i, x := range vec {
		m := s.Next()
		out[i] = (x + m) % r
	}
	return out, nil
}

// guardrailTextDomain 文本密文通道域分离标签（与 otpmask-plugin 一致）。
var guardrailTextDomain = []byte("otpmask/guardrail-text/v1")

// unmaskText 解密 guardrail 文本（OTP-Mask 逐字节，R=256，域分离派生流）。
func unmaskText(seed []byte, ct []byte) (string, error) {
	s, err := mask.NewStreamDomain(seed, 256, guardrailTextDomain)
	if err != nil {
		return "", err
	}
	out := make([]byte, len(ct))
	for i, c := range ct {
		m := s.Next() % 256
		out[i] = byte((int(c) + 256 - int(m)) % 256)
	}
	return string(out), nil
}

// toFloat 明文向量 → 浮点（模拟量化反量化：值域缩放，演示精度无损）。
func toFloat(v []uint64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = float64(x) / 1e6 // 缩放避免浮点精度抖动（演示模型）
	}
	return out
}

// keyIssueRequest 密钥签发请求（携带 request_id 用于派生，）。
type keyIssueRequest struct {
	Model     string `json:"model"`
	RequestID string `json:"request_id"`
}

// keyIssueResponse 密钥签发响应（seed 经"加密通道"下发，MVP 简化为 JSON 明文，
// 生产将使用 会话密钥加密）。
type keyIssueResponse struct {
	Seed  string `json:"seed"`
	Nonce string `json:"nonce"`
	// MasterID 主密钥版本（审计/轮换观测）。
	MasterID uint64 `json:"master_id"`
	// ProtocolVersion 南向协议版本。
	ProtocolVersion string `json:"protocol_version"`
}

type teeServer struct {
	km            *teecore.KeyManager            // 默认租户（向后兼容）
	tkm           *teecore.TenantKeyManager      // 二级租户 KEK + 三级会话管理器（P0-4 §6）
	kSig          []byte
	attest        string             // 远程证明共享令牌（MVP）
	enclave       Enclave            // 飞地抽象
	requireAttest bool               // 强制证明模式
	adminToken    string             // 管理端点（/metrics /audit）认证令牌
	model         model.Engine       // 明文域推理引擎
	cmaasEngine   *model.CmaasEngine // 百炼 C-MaaS 引擎（P5；nil = 未配置，请求 fail-closed）
	protoVersion  string             // 南向协议版本声明（C-4：默认 protocol.Version，部署/测试可覆盖）
	// 审计/日志留存期声明（天；0=未声明）。声明式，服务不删除审计数据。
	auditRetentionDays int
	// P2a：PII 处理模式（block = 拦截（默认，fail-closed）/ mask = 脱敏替换后放行）；
	// SQL 注入/提示注入在任何模式下均拦截。
	piiMode string
	// M3-B：Guardrail 运行时降级（高敏变更复核通过后写入；空 = 沿用启动参数）。
	// 只允许在 block/mask 之间切换，不提供"关闭 Guardrail"开关（安全边界）。
	piiModeOverride atomic.Value
	// M3-B：Guardrail 运行时配置持久化文件（-guardrail-config；空 = 不持久化）。
	guardrailCfgPath string
	systemPrompt     string                  // 提示词装饰：非空时插入 system 消息（记录于 transformed_hash）
	usage            map[string]*usageRecord // 租户用量
	quota            map[string]quotaSpec    // 租户 token 配额（S3b 起含窗口；<=0 = 不限）
	quotaDefault     int64                   // 未单独配置租户的默认配额（<=0 = 不限）
	// S3b：窗口配额运行态（键 = "tenant|window"）。窗口标识翻转即重置计数。
	quotaWindowUsage map[string]int64
	quotaWindowKey   map[string]string
	// S5（判据 4）影子运行态（键 = "tenant|dim"，dim = rpm|tpm|daily_budget）。只计数不拒绝。
	shadowWindowUsage map[string]int64
	shadowWindowKey   map[string]string
	// A 项（判据 4 扩展）：数据面明文路由影子的**窗口级汇总上报**幂等状态（nil = 不判重）。
	shadowReports   *shadowReportState
	audit           *auditChain     // 审计哈希链
	guard           *guardrail      // 内容安全检测（M9-4）
	// 输入侧语义分类器侧车探活（2026-09-26；nil = 未配置侧车，此时用进程内关键词分类器，
	// 不存在"不可用"问题）；不健康 → readiness 503。
	guardProbe *guardClassifierProbe
	// GA-输出侧内容审查（OG-3）：off|shadow（enforcing 属 M4，配置即拒绝启动；§2.3 I1–I7）。
	outputGuardMode string
	// S1-5：公众形态锁定——true 时审核总开关不可关闭（mode 不得为 off），
	// 关闭请求返回 400 + 审计；false 时与现网一致（off/shadow/enforcing 均可）。
	// 私有化形态默认 false；SaaS/公众形态须显式置 true。
	publicFacing bool
	// S4-4：租户处置状态检查器（SaaS 模式下由 tenantDispositionStore 实现，OSS 下永远放行）。
	disposition dispositionChecker
	// OG-8：运行时 mode 覆盖（高敏变更复核通过后写入；空 = 沿用 outputGuardMode 启动参数）。
	// 只允许在 off/shadow 之间切换，enforcing 在 M4 前不开放（安全边界）。
	outputGuardModeOverride atomic.Value
	// OG-8：运行时配置持久化文件（-output-guard-config；空 = 不持久化，重启回退启动参数）。
	outputGuardCfgPath string
	// S3-2：策略档位启动参数（P-STRATEGY：A|B|C；空 = 缺省 A）。
	outputGuardStrategy string
	// S3-2：策略档位运行时覆盖（D8 通过后写入；空 = 沿用启动参数/缺省 A）。
	outputGuardStrategyOverride atomic.Value
	// S3-2：停用类目集合运行态（map[string]bool，D8 通过后整体替换；nil = 全类目启用）。
	outputGuardDisabled atomic.Value
	// GA-输出侧内容审查（OG-4）：D 组缓冲参数（启动期 resolve＋validate 后只读）。
	outputGuardParams outputGuardParams
	// GA-输出侧内容审查（OG-13）：级联并发参数（跨 §5.3–5.5 多组；启动期 resolve＋validate 后只读）。
	outputGuardCascade outputGuardCascadeParams
	// GA-输出侧内容审查（OG-18）：PII mask 改写开关（默认 false = block-only 深度，mask 降 flag）。
	outputGuardMaskEnabled bool
	// GA-输出侧内容审查（OG-9）：策略目录（-output-guard-policy-dir；空 = 未配置，
	// /config/policy/reload 将返回 400）。
	outputGuardPolicyDir string
	// S1-4（G21）：策略/词库**版本库**的显式引用运行态（*policyRefState，整体原子替换）。
	// 空值 ＝ 未引用（沿用 policy 根目录 manifest，行为不变）。
	// 版本库为**只读输入**（readOnlyRootFilesystem），发布/快照写入属离线步骤（scripts/policy-publish.ps1）。
	outputGuardPolicyRef atomic.Value
	// GA-输出侧内容审查（M2 OG-12）：L2 语义分类器（nil = 未启用，纯 L1 = 当前行为）。
	// 启用后 shadow 下 L1 未命中再走 L2；L2 不可用该句按 P-DEGRADE fail-closed（不回退 L1 关键词重判）；
	// readiness 不联动 L2 状态（输出侧仍有 L1 规则层可服务，属既有设计）。
	outputGuardL2 OutputClassifier
	// GA-输出侧内容审查（OG-9）：策略/词库注册表（nil = 未配置，此时 L1 走既有 guardrail
	// 包装器，行为与现网一致）。热加载经原子指针无锁换版（请求路径零阻塞）。
	policyReg atomic.Pointer[lexiconRegistry]
	// B1 强标标识（GB 45438-2025）：启动配置（启动期 resolve＋validate 后只读）。
	contentLabelCfg contentLabelConfig
	// B1：运行时覆盖（热切换写入；空 = 沿用启动参数）。标识非拦截语义 → on/off 双向可切。
	contentLabelOverride atomic.Value
	// B1：运行时配置持久化文件（-content-label-config；空 = 不持久化，重启回退启动参数）。
	contentLabelCfgPath string
	metrics         *otpmaskMetrics // Prometheus 指标
	seen            map[string]bool
	seenAt          map[string]int64       // request_id -> 首见时间戳（TTL 清理用）
	sessions        map[string]*teeSession // 挑战-响应会话（session_id -> 会话）
	recomputeStates *recomputeStates       // 补算层序状态机（会话级）
	weightProvider  LayerWeightProvider    // 层权重提供器（掩码像计算）
	route           *RouteConfig           // 双路线路由配置
	tokenizer       Tokenizer              // 计量口径（nil = 字符/4 估算；GF.2.4 真机 tokenizer 接入点）
	cache           model.SemanticCache      // GF.4.1 精确缓存（P0-2：legacy 兜底；仅 cacheEngine==nil 时使用）
	cacheEngine     cacheengine.CacheEngine  // P0-2 原生语义缓存引擎（命中/回填 + /metrics；nil = 未装配）
	cacheEnabled    bool                     // P0-2 B2：原生缓存是否生效（mode != off）；false 时零开销
	cacheReplay     cacheReplayConfig        // P0-2 B2：§6.12 回放节拍参数快照
	billing         *billingWebhook        // GA-计费 P1-1：Webhook 推送（nil = 关闭，拉取为主）
	meterToken      string                 // GA-计费 P1-2：独立只读计量令牌（/usage GET；与 admin-token 分离）
	reconciler      *reconciler            // S5 判据 6：审计-计量对账器（/reconcile 快照数据源）
	mu              sync.Mutex
}

// usageRecord 租户用量计量（token 级）。
type usageRecord struct {
	TokensIn  int `json:"tokens_in"`
	TokensOut int `json:"tokens_out"`
	Requests  int `json:"requests"`
	Denies    int `json:"denies"`
	// X-3（G23）：预占输入的累计回冲量（输出拦截/故障退回），与 TokensIn 净额分离，
	// 使回冲在 /usage 可追溯（否则只是 TokensIn 变小，无法区分"少用"与"被回冲"）。
	RefundedTokensIn int `json:"refunded_tokens_in,omitempty"`
	// GA-计费 P0-1：模型维度计量（key = "engine_type/model"，累计口径）。
	// 配额与租户总额仍以顶层字段为准（预占发生在引擎解析前，模型维度在
	// 请求完成时补记）；出账分价以 from/to 审计事件聚合为权威（billing.go）。
	Models map[string]*modelUsage `json:"by_model,omitempty"`
}

// modelUsage 模型维度用量（GA-计费 P0-1：同租户混用多模型的分价计费基础）。
//
// GA-计费 P0-3（A-27/A-35）：TokensIn/Out 保留原口径（含 retry，向后兼容）；
// TokensInNet/TokensOutNet 为剔除 retry 的净量，RetryTokens 单列（平台成本）。
// 恒等（总量守恒）：tokens_in + tokens_out == tokens_in_net + tokens_out_net + retry_tokens。
type modelUsage struct {
	TokensIn     int `json:"tokens_in"`
	TokensOut    int `json:"tokens_out"`
	Requests     int `json:"requests"`
	Denies       int `json:"denies,omitempty"`
	TokensInNet  int `json:"tokens_in_net,omitempty"`
	TokensOutNet int `json:"tokens_out_net,omitempty"`
	RetryTokens  int `json:"retry_tokens,omitempty"`
}

// tenantHeader 租户标识请求头。
const tenantHeader = "X-Tenant-ID"

// defaultTenant 未指定租户时的默认租户（向后兼容）。
const defaultTenant = "default"

// recordUsage 累加租户用量。
func (s *teeServer) recordUsage(tenant string, tokensIn, tokensOut int, denied bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.usage[tenant]
	if rec == nil {
		rec = &usageRecord{}
		s.usage[tenant] = rec
	}
	rec.TokensIn += tokensIn
	rec.TokensOut += tokensOut
	if denied {
		rec.Denies++
	} else {
		rec.Requests++
	}
}

// ---------- P1：token 配额管控 ----------

// quotaLimit 单维度 enforce 上限（B 项：多维度）。
//
// Window 取值：
//   - ""       累计上限（P1 既有语义，**默认，行为不变**）；
//   - "minute" 每分钟窗口（对应控制面策略的 tpm）；
//   - "day"    UTC+8 自然日窗口（对应控制面策略的 daily_budget_tokens）；
//   - "month"  UTC+8 自然月窗口（GA-计费 P0-3 套餐月配额，A-33）。
type quotaLimit struct {
	Window    string `json:"window,omitempty"`
	MaxTokens int64  `json:"max_tokens"`
}

// quotaSpec 租户配额（B 项：Limits 承载**多维** enforce，任一维度超限即拒绝；空 = 无 enforce）。
type quotaSpec struct {
	Limits []quotaLimit
	// S5：影子配置（判据 4：只计数不拒绝，命中落审计 would_reject）。零值 = 未配置影子。
	Shadow shadowSpec
}

// normalizeLimits 规范化维度列表：丢弃 max_tokens<=0 的条目（该维度视为未配置），保持输入顺序。
func normalizeLimits(in []quotaLimit) []quotaLimit {
	out := make([]quotaLimit, 0, len(in))
	for _, l := range in {
		if l.MaxTokens > 0 {
			out = append(out, l)
		}
	}
	return out
}

// primaryLimit 主维度（兼容单维度视图：/usage 的 quota/window/window_used 与门户）：
// 优先累计维度，否则首个维度；无 enforce 返回 (零值, false)。
func primaryLimit(limits []quotaLimit) (quotaLimit, bool) {
	for _, l := range limits {
		if l.Window == quotaWindowNone {
			return l, true
		}
	}
	if len(limits) > 0 {
		return limits[0], true
	}
	return quotaLimit{}, false
}

// shadowSpec 影子阈值（判据 4）。三个维度各自独立窗口计数：
//
//	RPM              每分钟请求数（minute 窗口）——覆盖经 tee-infer 的**密态链路**（/infer、/v1/infer）
//	TPM              每分钟 token 数（minute 窗口）
//	DailyBudgetTokens 自然日 token 数（day 窗口，UTC+8）
//
// 影子命中**不拒绝**请求，仅在审计链记 would_reject（设计 §5：不得只计数不留痕）。
type shadowSpec struct {
	RPM               int64 `json:"rpm,omitempty"`
	TPM               int64 `json:"tpm,omitempty"`
	DailyBudgetTokens int64 `json:"daily_budget_tokens,omitempty"`
}

// configured 是否配置了任何影子维度。
func (s shadowSpec) configured() bool { return s.RPM > 0 || s.TPM > 0 || s.DailyBudgetTokens > 0 }

// 窗口取值白名单（与 control-plane 策略字段对应）。
const (
	quotaWindowNone   = ""
	quotaWindowMinute = "minute"
	quotaWindowDay    = "day"
	// quotaWindowMonth GA-计费 P0-3（P-2/U-2）：UTC+8 自然月窗口，用于套餐月配额
	// （单位与计费口径统一为标准 token，A-33）。
	quotaWindowMonth = "month"
)

// quotaWindowKeyFor 计算窗口标识：翻转即视为新窗口（触发计数重置）。
// minute = Unix 分钟序号；day = UTC+8 自然日；month = UTC+8 自然月（口径与设计 §3 一致）。
func quotaWindowKeyFor(window string, now time.Time) string {
	switch window {
	case quotaWindowMinute:
		return fmt.Sprintf("%d", now.Unix()/60)
	case quotaWindowDay:
		return now.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01-02")
	case quotaWindowMonth:
		return now.In(time.FixedZone("UTC+8", 8*3600)).Format("2006-01")
	default:
		return ""
	}
}

// validQuotaWindow 校验窗口取值（非法即拒绝，避免"配了不生效"）。
func validQuotaWindow(w string) bool {
	switch w {
	case quotaWindowNone, quotaWindowMinute, quotaWindowDay, quotaWindowMonth:
		return true
	default:
		return false
	}
}

// quotaLimitsOf 返回租户生效的 enforce 维度（持有 s.mu 时必须调用）：
//   - 租户已配置条目 → 用其 Limits（空 = 该租户不限，**不**回落全局默认，与 P1 语义一致）；
//   - 未配置条目 → 全局默认（-token-quota，累计维度；<=0 = 不限）。
func (s *teeServer) quotaLimitsOf(tenant string) []quotaLimit {
	if spec, ok := s.quota[tenant]; ok {
		return spec.Limits
	}
	if s.quotaDefault > 0 {
		return []quotaLimit{{Window: quotaWindowNone, MaxTokens: s.quotaDefault}}
	}
	return nil
}

// dimensionUsed 读取某维度当前已用 token（持有 s.mu 时必须调用；窗口翻转即重置，与判定同规则）。
// window="" = 累计维度（usage.TokensIn+TokensOut）。
func (s *teeServer) dimensionUsed(tenant, window string) int64 {
	if window == quotaWindowNone {
		if rec := s.usage[tenant]; rec != nil {
			return int64(rec.TokensIn) + int64(rec.TokensOut)
		}
		return 0
	}
	uk := tenant + "|" + window
	key := quotaWindowKeyFor(window, time.Now())
	if s.quotaWindowKey[uk] != key {
		s.quotaWindowKey[uk] = key
		s.quotaWindowUsage[uk] = 0
	}
	return s.quotaWindowUsage[uk]
}

// dimensionReserve 窗口维度占位（持有 s.mu；含"窗口翻转即重置"语义）。
func (s *teeServer) dimensionReserve(tenant, window string, tokensIn int64) {
	uk := tenant + "|" + window
	key := quotaWindowKeyFor(window, time.Now())
	if s.quotaWindowKey[uk] != key {
		s.quotaWindowKey[uk] = key
		s.quotaWindowUsage[uk] = 0
	}
	s.quotaWindowUsage[uk] += tokensIn
}

// dimensionRelease 窗口维度退回（持有 s.mu；下限保护不退成负数）。
func (s *teeServer) dimensionRelease(tenant, window string, tokensIn int64) {
	uk := tenant + "|" + window
	if s.quotaWindowUsage[uk] >= tokensIn {
		s.quotaWindowUsage[uk] -= tokensIn
	} else {
		s.quotaWindowUsage[uk] = 0
	}
}

// reserveQuota 预占式配额检查（原子）：在 s.mu 内完成"检查 + 占位"，杜绝并发超卖。
//
// B 项（多维度）：**先全量检查所有维度，全部通过后统一提交占位**——任一维度不足即整单拒绝
// （返回触发拒绝的维度窗口，供指标归因）；因检查阶段不落任何占位，故无需回滚，天然杜绝
// "部分占位泄漏"（与"逐个占位+失败回滚"等价且少一条回滚路径）。
//
// 占位计入 usage.TokensIn（输入侧控制，计费计量不丢）；推理成功后 recordUsage 只补记输出。
// 配额 <=0 = 不限（仍占位累计 TokensIn，仅跳过上限检查）；窗口翻转（分钟/UTC+8 自然日）即自动重置。
// 失败路径（GA-计费 P0-3）：预占后失败且无任何输出交付 → rollbackQuota 退回输入
// 计量（fail-closed 故障不向租户计费）；流中断已有部分输出 → 按实收计费（不回滚）。
// 输出侧配额控制为扩展项（流式输出无法预知）。
func (s *teeServer) reserveQuota(tenant string, tokensIn int64) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limits := s.quotaLimitsOf(tenant)
	for _, l := range limits {
		if l.MaxTokens <= 0 {
			continue
		}
		if s.dimensionUsed(tenant, l.Window)+tokensIn > l.MaxTokens {
			return false, l.Window
		}
	}
	rec := s.usage[tenant]
	if rec == nil {
		rec = &usageRecord{}
		s.usage[tenant] = rec
	}
	rec.TokensIn += int(tokensIn) // 预占（无限额时同样累计计量）
	for _, l := range limits {
		if l.Window != quotaWindowNone {
			s.dimensionReserve(tenant, l.Window, tokensIn)
		}
	}
	return true, quotaWindowNone
}

// quotaOf 读取租户配额上限（展示用；多维度取主维度，见 primaryLimit）。
func (s *teeServer) quotaOf(tenant string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := primaryLimit(s.quotaLimitsOf(tenant)); ok {
		return l.MaxTokens
	}
	return 0
}

// quotaWindowOf 读取租户配额窗口（展示用；多维度取主维度）。
func (s *teeServer) quotaWindowOf(tenant string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := primaryLimit(s.quotaLimitsOf(tenant)); ok {
		return l.Window
	}
	return quotaWindowNone
}

// quotaWindowUsed 读取租户主维度当前窗口已用 token（展示/验证用；窗口翻转时先重置）。
func (s *teeServer) quotaWindowUsed(tenant string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := primaryLimit(s.quotaLimitsOf(tenant))
	if !ok || l.Window == quotaWindowNone {
		return 0
	}
	return s.dimensionUsed(tenant, l.Window)
}

// ---------- S5（判据 4）：影子模式（只计数不拒绝 + would_reject 落审计） ----------

// shadowObserve 影子计数与判定：**只计数不拒绝**；命中即落审计 would_reject 并计数指标。
//
// 调用点＝配额预占通过之后（语义：影子回答"若该规则转为 enforce，这部分流量会被拦"）。
// 三个维度各自独立窗口（rpm/tpm=minute，daily_budget=day UTC+8），窗口翻转即重置。
// engine_type/model 沿用请求声明值（可能为空，如实记录，不做推断）。
// 返回命中的维度名（rpm/tpm/daily_budget），无命中返回 nil。
func (s *teeServer) shadowObserve(tenant, requestID string, tokensIn int, engineType, model, payloadSHA string) []string {
	s.mu.Lock()
	spec, ok := s.quota[tenant]
	if !ok || !spec.Shadow.configured() {
		s.mu.Unlock()
		return nil
	}
	sh := spec.Shadow
	var hits []string
	if sh.RPM > 0 {
		uk := tenant + "|rpm"
		s.rotateShadowWindow(uk, quotaWindowMinute)
		n := s.shadowWindowUsage[uk] + 1
		if n > sh.RPM {
			hits = append(hits, "rpm")
		}
		s.shadowWindowUsage[uk] = n
	}
	if sh.TPM > 0 {
		uk := tenant + "|tpm"
		s.rotateShadowWindow(uk, quotaWindowMinute)
		used := s.shadowWindowUsage[uk] + int64(tokensIn)
		if used > sh.TPM {
			hits = append(hits, "tpm")
		}
		s.shadowWindowUsage[uk] = used
	}
	if sh.DailyBudgetTokens > 0 {
		uk := tenant + "|daily_budget"
		s.rotateShadowWindow(uk, quotaWindowDay)
		used := s.shadowWindowUsage[uk] + int64(tokensIn)
		if used > sh.DailyBudgetTokens {
			hits = append(hits, "daily_budget")
		}
		s.shadowWindowUsage[uk] = used
	}
	s.mu.Unlock()

	if len(hits) == 0 {
		return nil
	}
	for _, r := range hits {
		s.metrics.incShadowWouldReject(tenant, r)
	}
	// 每个命中请求**一条**审计事件（多维度命中合并到 shadow_rule，避免事件放大）
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: "shadow",
		TokensIn: tokensIn, Result: "would_reject", PayloadSHA: payloadSHA,
		HashAlg: hashAlgTag(), // §5.2.2：与 PayloadSHA 同档自述
		EngineType: engineType, Model: model,
		ShadowRule: strings.Join(hits, ","),
	})
	return hits
}

// rotateShadowWindow 影子窗口翻转（翻转即重置该维度计数）。调用方须持 s.mu。
func (s *teeServer) rotateShadowWindow(uk, window string) {
	key := quotaWindowKeyFor(window, time.Now())
	if s.shadowWindowKey[uk] != key {
		s.shadowWindowKey[uk] = key
		s.shadowWindowUsage[uk] = 0
	}
}

// shadowUsage 读取影子各维度当前窗口计数（展示用）。
func (s *teeServer) shadowUsage(tenant string) (rpm, tpm, daily int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	get := func(dim, window string) int64 {
		uk := tenant + "|" + dim
		if s.shadowWindowKey[uk] != quotaWindowKeyFor(window, time.Now()) {
			return 0
		}
		return s.shadowWindowUsage[uk]
	}
	return get("rpm", quotaWindowMinute), get("tpm", quotaWindowMinute), get("daily_budget", quotaWindowDay)
}

// recordModelUsage 模型维度计量（GA-计费 P0-1：分价计费数据基础）。
// 与租户总额（recordUsage）独立累计——预占发生在引擎解析前，模型维度在
// 请求完成时按实际引擎/模型补记；deny（不计费）不入模型维度。
func (s *teeServer) recordModelUsage(tenant, engineType, model string, tokensIn, tokensOut int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.usage[tenant]
	if rec == nil {
		rec = &usageRecord{}
		s.usage[tenant] = rec
	}
	if rec.Models == nil {
		rec.Models = make(map[string]*modelUsage)
	}
	key := modelDimensionKey(engineType, model)
	mu := rec.Models[key]
	if mu == nil {
		mu = &modelUsage{}
		rec.Models[key] = mu
	}
	mu.TokensIn += tokensIn
	mu.TokensOut += tokensOut
	mu.Requests++
}

// rollbackQuota 回滚预占（GA-计费 P0-3）：预占后失败且无任何输出交付时，
// 输入计量退回（fail-closed 故障不向租户计费）。下限保护不退成负数。
// B 项：逐窗口维度同步退回（否则失败请求会白占窗口额度）；维度取当前生效配置
// （与预占同一配置即精确对应；请求处理中途被改配属已知残余边界，与改造前一致）。
func (s *teeServer) rollbackQuota(tenant string, tokensIn int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.usage[tenant]
	if rec == nil || tokensIn <= 0 {
		return
	}
	if int64(rec.TokensIn) < tokensIn {
		tokensIn = int64(rec.TokensIn)
	}
	rec.TokensIn -= int(tokensIn)
	rec.RefundedTokensIn += int(tokensIn) // X-3：回冲单独入账（/usage 可追溯）
	for _, l := range s.quotaLimitsOf(tenant) {
		if l.Window != quotaWindowNone {
			s.dimensionRelease(tenant, l.Window, tokensIn)
		}
	}
	log.Printf("[tee] 配额预占回滚 tenant=%s tokens=%d（fail-closed 故障不计费）", tenant, tokensIn)
}

// tenantOf 读取请求租户（空则默认）。
func tenantOf(r *http.Request) string {
	t := r.Header.Get(tenantHeader)
	if t == "" {
		return defaultTenant
	}
	return t
}

// checkAttest 校验远程证明令牌（模拟模式；TDX Quote 验证待硬件接入）。
func (s *teeServer) checkAttest(r *http.Request) bool {
	token := r.Header.Get(attestHeader)
	if token == "" || s.attest == "" {
		return false
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(s.attest))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// checkAdmin 校验管理端点令牌（/metrics /audit /usage）。
func (s *teeServer) checkAdmin(r *http.Request) bool {
	if s.adminToken == "" {
		return true // 未配置管理令牌时不拦截（开发/测试模式）
	}
	token := r.Header.Get(adminHeader)
	if token == "" {
		return false
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(s.adminToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// checkMetering 校验计量查询凭证（/usage GET，GA-计费 P1-2）：
// 管理令牌，或独立只读计量令牌（meter-token，最小权限——只能读用量，
// 不能写配额 /usage/quota、不能读 /audit /metrics）。
func (s *teeServer) checkMetering(r *http.Request) bool {
	if s.checkAdmin(r) {
		return true
	}
	if s.meterToken == "" {
		return false
	}
	token := r.Header.Get(adminHeader)
	if token == "" {
		return false
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(s.meterToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// seenCleanup 定期清理过期的防重放 request_id（TTL = seenTTL 秒）。
func (s *teeServer) seenCleanup() {
	ticker := time.NewTicker(seenCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		s.mu.Lock()
		for id, ts := range s.seenAt {
			if now-ts > seenTTL {
				delete(s.seen, id)
				delete(s.seenAt, id)
			}
		}
		s.mu.Unlock()
	}
}

// attestChallenge 挑战-响应请求。
type attestChallenge struct {
	Nonce string `json:"nonce"` // 客户挑战（hex，32 字节随机）
}

// attestCompleteRequest complete 请求。
type attestCompleteRequest struct {
	SessionID string `json:"session_id"`
	ClientPub string `json:"client_pub"` // 客户端 ECDH 公钥（hex）
}

// handleAttest 远程证明挑战-响应：
// 1. 接收客户挑战 nonce → 2. 飞地生成证明载荷 → 3. 返回 proof + 服务端 ECDH 公钥 + 会话 ID。
// 向后兼容：旧协议（无 body / token 模式）仍返回 MVP 握手确认。
func (s *teeServer) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 读取挑战（可为空 body = 旧版握手）
	var chal attestChallenge
	body, _ := io.ReadAll(r.Body)
	if len(bytesTrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &chal); err != nil {
			http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
			return
		}
	}
	nonce := make([]byte, 32)
	if chal.Nonce != "" {
		n, err := hex.DecodeString(chal.Nonce)
		if err != nil || len(n) != 32 {
			http.Error(w, "nonce 须为 32 字节 hex", http.StatusBadRequest)
			return
		}
		nonce = n
	} else {
		// 旧版握手：服务端生成挑战（等价 nonce，客户可忽略）
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, "生成 nonce 失败", http.StatusInternalServerError)
			return
		}
	}

	// 先创建会话（服务端临时 ECDH 密钥对），再生成证明——
	// report_data = H(nonce ‖ server_pub) 绑定握手公钥（P1b，RA-TLS 标准做法，
	// 防中间人替换握手公钥劫持加密通道）
	sess, err := newSession(nonce)
	if err != nil {
		http.Error(w, fmt.Sprintf("创建会话失败: %v", err), http.StatusInternalServerError)
		return
	}
	reportData := reportDataBinding(nonce, sess.ServerPub())
	proof, err := s.enclave.Attest(nonce, reportData)
	if err != nil {
		http.Error(w, fmt.Sprintf("生成证明失败: %v", err), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()

	// proof 二进制字段（nonce/report_data/signing_key/signature）以 hex 编码返回，
	// 与插件侧解码约定一致（直接序列化结构体会被 Go 默认编码为 base64）
	proofJSON, err := proof.proofJSON()
	if err != nil {
		http.Error(w, fmt.Sprintf("生成证明JSON失败: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":           "attested",
		"protocol":         "challenge-response",
		"attest_type":      protocol.AttestTypeQuote,
		"protocol_version": s.protoVersion,
		"session_id":       sess.ID,
		"proof":            json.RawMessage(proofJSON),
		"server_pub":       hex.EncodeToString(sess.ServerPub()),
		"session_ttl":      int(sessionTTL.Seconds()),
	})
	log.Printf("[tee] attestation 挑战-响应完成 session=%s platform=%s", sess.ID[:8], proof.Platform)
}

// handleAttestComplete 远程证明 complete：
// 客户端 ECDH 公钥到达 → ECDH + HKDF 派生会话密钥（K_sig/K_enc）。
func (s *teeServer) handleAttestComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req attestCompleteRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("读取请求失败: %v", err), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	clientPub, err := hex.DecodeString(req.ClientPub)
	if err != nil {
		http.Error(w, "client_pub 须为 hex", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "会话不存在或已过期", http.StatusUnauthorized)
		return
	}
	if err := sess.Complete(clientPub); err != nil {
		http.Error(w, fmt.Sprintf("会话密钥派生失败: %v", err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"session_id":  sess.ID,
		"session_ttl": int(sessionTTL.Seconds()),
	})
	log.Printf("[tee] attestation complete session=%s（K_sig/K_enc 已派生）", sess.ID[:8])
}

// sessionK_sig 按请求会话取签名密钥：X-Session-ID 命中 → 会话 K_sig；否则全局 K_sig（MVP 兼容）。
func (s *teeServer) sessionK_sig(r *http.Request) []byte {
	if sess := s.sessionByID(r); sess != nil {
		return sess.K_sig
	}
	return s.kSig
}

// sessionAttested 请求是否携带有效（已完成、未过期）会话。
func (s *teeServer) sessionAttested(r *http.Request) bool {
	return s.sessionByID(r) != nil
}

// sessionByID 按 X-Session-ID 返回有效会话（nil = 无）。
func (s *teeServer) sessionByID(r *http.Request) *teeSession {
	id := r.Header.Get("X-Session-ID")
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || !sess.Completed || time.Since(sess.CreatedAt) > sessionTTL {
		return nil
	}
	return sess
}

// sessionCleanup 定期清理过期/未完成会话（TTL = sessionTTL）。
// P1c：清理时零化会话密钥（K_sig/K_enc 用后零化，best-effort）。
func (s *teeServer) sessionCleanup() {
	ticker := time.NewTicker(seenCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, sess := range s.sessions {
			if !sess.Completed || now.Sub(sess.CreatedAt) > sessionTTL {
				sess.destroy() // 会话密钥零化（best-effort，威胁模型如实声明）
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// bytesTrimSpace 去除首尾空白（io.ReadAll 后判断空 body）。
func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

// sessionPlaintextDev 会话明文兼容开关（仅 dev 调试；生产必须关闭）。
// OTPMASK_SESSION_PLAINTEXT=dev 时，有效会话下的明文载荷不拒绝（降级放行，审计可观测）。
func sessionPlaintextDev() bool {
	return os.Getenv("OTPMASK_SESSION_PLAINTEXT") == "dev"
}

func (s *teeServer) handleKeyIssue(w http.ResponseWriter, r *http.Request) {
	// 会话模式（X-Session-ID 有效会话）或 MVP token 模式，二选一通过
	sess := s.sessionByID(r)
	if sess == nil && !s.checkAttest(r) {
		http.Error(w, "远程证明失败：无效的 attestation 令牌", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("读取请求失败: %v", err), http.StatusBadRequest)
		return
	}
	payloadSHA := payloadHashHex(body) // 审计记录原始 wire 哈希（随 profile：intl=SHA-256 / sm=SM3，§5.2.2）
	// P1c 解密入口：会话建立后请求须为 c2s 信封（fail-closed，防降级攻击）
	if sess != nil {
		pt, oerr := sess.openPayload(protocol.EndpointKeyIssue, body)
		if oerr != nil {
			if !sessionPlaintextDev() {
				s.denyAndAudit(tenantOf(r), "", "keyissue_envelope_error", payloadSHA)
				http.Error(w, "会话请求须为加密信封（fail-closed）", http.StatusBadRequest)
				return
			}
			pt = body // dev 兼容：明文放行（仅调试，生产禁用）
		}
		body = pt
	}
	var req keyIssueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("bad json: %v", err), http.StatusBadRequest)
		return
	}
	if req.RequestID == "" || req.Model == "" {
		http.Error(w, "request_id/model 必填", http.StatusBadRequest)
		return
	}
	// P0-4 §6：三级链签发——KEK(二级)→会话master(三级)→request seed
	tenant := tenantOf(r)
	seed, nonceHex, masterID, err := s.tkm.Issue(tenant, req.RequestID, req.Model)
	if err != nil {
		http.Error(w, fmt.Sprintf("签发密钥失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer wipe(seed)
	log.Printf("[tee] 密钥签发 tenant=%s req=%s master=%d", tenant, req.RequestID[:8], masterID)
	// M9-3：审计
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: req.RequestID, Action: "key_issue",
		Result: "ok", PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
	})
	// M10：指标
	s.metrics.incKeyIssue(tenant)
	respJSON, err := json.Marshal(keyIssueResponse{
		Seed: hex.EncodeToString(seed), Nonce: nonceHex, MasterID: masterID,
		ProtocolVersion: s.protoVersion,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("编码响应失败: %v", err), http.StatusInternalServerError)
		return
	}
	// P1c 加密出口：会话模式下响应整体入 s2c 信封
	if sess != nil {
		sealed, serr := sess.sealPayload(protocol.EndpointKeyIssue, respJSON)
		if serr != nil {
			s.denyAndAudit(tenant, req.RequestID, "keyissue_seal_error", payloadSHA)
			http.Error(w, "响应加密失败（fail-closed）", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(sealed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respJSON)
}

// retryAttemptHeader 数据面下行重试标记请求头（GA-计费 P0-3，A-1：唯一数据面改动）。
const retryAttemptHeader = "X-Otpmask-Retry-Attempt"

// retryAttemptFromHeader 解析重试尝试序号；空/非法/<=0 → 0（非重试）。
// 语义（§6.3.3）：数据面在多端点重试时递增写入，tee-infer 仅解析为重试布尔标记，
// 使重试 token 可归平台成本（M9 不变量）。
func retryAttemptFromHeader(r *http.Request) int {
	v := strings.TrimSpace(r.Header.Get(retryAttemptHeader))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// handleInfer 推理入口。
func (s *teeServer) handleInfer(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("读取请求失败: %v", err), http.StatusBadRequest)
		return
	}
	tenant := tenantOf(r)
	isRetry := retryAttemptFromHeader(r) > 0 // GA-计费 P0-3：重试归因（来自数据面下行头）
	payloadSHA := payloadHashHex(body) // 审计记录原始 wire 哈希（随 profile：intl=SHA-256 / sm=SM3，§5.2.2）
	// P1c 解密入口：有效会话（quote 模式）下请求须为 c2s 信封（fail-closed，防降级攻击）
	sess := s.sessionByID(r)
	if sess != nil {
		pt, oerr := sess.openPayload(protocol.EndpointInfer, body)
		if oerr != nil {
			if !sessionPlaintextDev() {
				s.denyAndAudit(tenant, "", "envelope_error", payloadSHA)
				http.Error(w, "推理请求须为加密信封（fail-closed）", http.StatusBadRequest)
				return
			}
			pt = body // dev 兼容：明文放行（仅调试，生产禁用）
		}
		body = pt
	}
	req, err := protocol.DecodeRequest(body)
	if err != nil {
		s.denyAndAudit(tenant, "", "decode_error", payloadSHA)
		http.Error(w, fmt.Sprintf("协议解码失败: %v", err), http.StatusBadRequest)
		return
	}

	// 验签
	if !cryptoops.VerifyRequest(s.sessionK_sig(r), req) {
		s.denyAndAudit(tenant, req.RequestID, "bad_signature", payloadSHA)
		http.Error(w, "签名无效", http.StatusUnauthorized)
		return
	}
	// 防重放
	s.mu.Lock()
	replayErr := protocol.CheckReplay(req.RequestID, req.TimestampNS, time.Now().UnixNano(), s.seen)
	if replayErr == nil {
		s.seenAt[req.RequestID] = time.Now().Unix() // 记录首见时间（TTL 清理用）
	}
	s.mu.Unlock()
	if replayErr != nil {
		s.denyAndAudit(tenant, req.RequestID, "replay", payloadSHA)
		http.Error(w, replayErr.Error(), http.StatusBadRequest)
		return
	}

	// S4-4：租户处置状态检查（SaaS 模式；OSS 下永远放行）。
	if s.disposition != nil {
		if allowed, reason := s.disposition.Check(tenant); !allowed {
			s.denyAndAudit(tenant, req.RequestID, "tenant_disposition", payloadSHA)
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}

	// 双路线路由校验
	if err := s.route.ValidateRequest(tenant, req.Model, req.EngineType, req.AttestType); err != nil {
		s.denyAndAudit(tenant, req.RequestID, "route_rejected", payloadSHA)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// token 模式流量告警（attest_type=token 计入指标，生产误用可观测）
	if req.AttestType == protocol.AttestTypeToken || req.AttestType == "" {
		s.metrics.incAttestTokenTraffic(tenant)
	}

	// P2/P5（D1）：text 载荷路径——南向统一 text（tee_gpu 流式 / cmaas SDK 通道），
	// 与 vectors 路径（路线 2 保留）在此分流。
	if len(req.TextPayload) > 0 {
		s.handleTextInfer(w, sess, tenant, req, payloadSHA, isRetry)
		return
	}

	// P0-4 §6：按租户 KEK 域回溯请求 seed（无签发记录 -> 拒绝）
	seed, masterID, ok := s.tkm.LookupDetail(tenant, hex.EncodeToString(req.Nonce))
	if !ok {
		s.denyAndAudit(tenant, req.RequestID, "unknown_nonce", payloadSHA)
		http.Error(w, "nonce 未知（密钥未签发或已过期）", http.StatusBadRequest)
		return
	}
	defer wipe(seed)

	// M9-4：内容安全 Guardrail（TEE 内解密明文检测，命中即拒绝推理，fail-closed）
	if len(req.CipherText) > 0 {
		text, err := unmaskText(seed, req.CipherText)
		if err != nil {
			s.denyAndAudit(tenant, req.RequestID, "guardrail_decrypt_error", payloadSHA)
			http.Error(w, "guardrail 文本解密失败", http.StatusBadRequest)
			return
		}
		if hit := s.guard.check(text); hit != nil {
			s.denyAndAudit(tenant, req.RequestID, "guardrail_"+hit.Category, payloadSHA)
			log.Printf("[tee] guardrail 拦截 tenant=%s req=%s category=%s match=%s",
				tenant, req.RequestID, hit.Category, maskForLog(hit.Match))
			http.Error(w, fmt.Sprintf("内容安全拦截（%s）", hit.Category), http.StatusForbidden)
			return
		}
	}

	// P1：配额预占（输入 token 数，超限 429 fail-closed；原子占位防并发超卖）
	if ok, denied := s.reserveQuota(tenant, int64(len(req.CipherVectors))); !ok {
		s.metrics.incQuotaDeny(tenant, denied)
		s.denyAndAudit(tenant, req.RequestID, "quota_exceeded", payloadSHA)
		log.Printf("[tee] 配额超限拒绝 tenant=%s req=%s tokens_in=%d window=%q（空=累计维度）",
			tenant, req.RequestID, len(req.CipherVectors), denied)
		http.Error(w, "租户 token 配额超限（429）", http.StatusTooManyRequests)
		return
	}
	// S5（判据 4）：影子观测（只计数不拒绝；命中落审计 would_reject）
	s.shadowObserve(tenant, req.RequestID, len(req.CipherVectors), req.EngineType, req.Model, payloadSHA)

	// 解密（飞地内明文）→ 模型推理：对每个输入向量采样一个 token（自回归 M8）
	tokens := make([]uint64, 0, len(req.CipherVectors))
	for _, cv := range req.CipherVectors {
		plain, err := unmaskVector(seed, maskModulus, cv.Data)
		if err != nil {
			// GA-计费 P0-3：预占后失败且无输出交付 → 回滚输入计量
			s.rollbackQuota(tenant, int64(len(req.CipherVectors)))
			s.denyAndAudit(tenant, req.RequestID, "decrypt_error", payloadSHA)
			http.Error(w, fmt.Sprintf("解密失败: %v", err), http.StatusBadRequest)
			return
		}
		tokenID := s.model.Predict(toFloat(plain))
		if tokenID < 0 {
			// GA-计费 P0-3：引擎不可用（fail-closed 故障不计费）
			s.rollbackQuota(tenant, int64(len(req.CipherVectors)))
			s.denyAndAudit(tenant, req.RequestID, "engine_unavailable", payloadSHA)
			http.Error(w, "推理引擎不可用（fail-closed）", http.StatusServiceUnavailable)
			return
		}
		tokens = append(tokens, uint64(tokenID))
	}
	log.Printf("[tee] infer tenant=%s request=%s vectors=%d -> %d tokens %v master=%d",
		tenant, req.RequestID, len(req.CipherVectors), len(tokens), tokens, masterID)

	// 加密输出（同 seed）：token ID 序列密文（方案 C：TEE 内采样后加密回传）
	cipherOut, err := maskVector(seed, maskModulus, tokens)
	if err != nil {
		s.rollbackQuota(tenant, int64(len(req.CipherVectors))) // GA-计费 P0-3：无输出交付
		s.denyAndAudit(tenant, req.RequestID, "encrypt_error", payloadSHA)
		http.Error(w, fmt.Sprintf("加密失败: %v", err), http.StatusInternalServerError)
		return
	}

	resp := &protocol.InferenceResponse{
		RequestID:       req.RequestID,
		TimestampNS:     time.Now().UnixNano(),
		Status:          protocol.StatusOK,
		CipherOutput:    protocol.CipherVector{Data: cipherOut},
		TokensGenerated: 1, // M7：单 token 采样（自回归生成 M8）
	}
	cryptoops.SignResponse(s.sessionK_sig(r), resp)
	enc, err := protocol.EncodeResponse(resp)
	if err != nil {
		s.denyAndAudit(tenant, req.RequestID, "encode_error", payloadSHA)
		http.Error(w, fmt.Sprintf("编码响应失败: %v", err), http.StatusInternalServerError)
		return
	}
	// M9-2/M9-3：用量计量（token 级；输入已在配额预占计入，仅补记输出）+ 审计
	s.recordUsage(tenant, 0, len(tokens), false)
	vecEng := req.EngineType // GA-计费 P0-1：模型/引擎维度（vectors 默认本地引擎）
	if vecEng == "" {
		vecEng = protocol.EngineTypeTEEGPU
	}
	s.recordModelUsage(tenant, vecEng, req.Model, len(req.CipherVectors), len(tokens))
	vecEv := s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: req.RequestID, Action: "infer",
		TokensIn: len(req.CipherVectors), TokensOut: len(tokens),
		Result: "ok", PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
		EngineType: vecEng, // GA-计费 P0-1
		Model:      req.Model,
		IsRetry:    isRetry, // GA-计费 P0-3：重试归因（A-23/A-29）
	})
	go s.billing.notify(vecEv) // GA-计费 P1-1：Webhook（nil = no-op）
	// M10：指标
	s.metrics.incRequest(tenant, "ok")
	s.metrics.addTokens(tenant, int64(len(req.CipherVectors)), int64(len(tokens)))
	// 自定义 media type：避免 Envoy wasm wrapper 对 octet-stream 的二进制 body 跳过处理
	// P1c 加密出口：会话模式下协议响应整体入 s2c 信封
	if sess != nil {
		sealed, serr := sess.sealPayload(protocol.EndpointInfer, enc)
		if serr != nil {
			s.denyAndAudit(tenant, req.RequestID, "envelope_seal_error", payloadSHA)
			http.Error(w, "响应加密失败（fail-closed）", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(sealed)
		return
	}
	w.Header().Set("Content-Type", "application/x-otpmask")
	_, _ = w.Write(enc)
}

// ---------- P2/P5：text 载荷推理路径（D1：南向统一 text） ----------

// textStreamChunk 信封内明文分片（与 otpmask-plugin envelope.go 的 streamChunk 一致）。
//
// GA-输出侧内容审查（OG-5 chunk-meta，§4.6.1）：新增可选 guard 字段（omitempty）。
// 不动 wire 信封，所有业务元信息走内层 JSON。旧客户端忽略未知字段即兼容。
type textStreamChunk struct {
	Seq    uint64          `json:"seq"`              // 流内序号（1 起严格递增）
	Delta  string          `json:"delta"`            // 增量文本
	Finish string          `json:"finish,omitempty"` // ""=继续 / "stop"=正常结束 / "error"=引擎失败 / "content_filter"=内容安全终止
	Guard  *chunkGuardMeta `json:"guard,omitempty"`  // 输出侧内容审查元信息（可选；shadow/enforcing 均带）
	// B1 强标标识（GB 45438-2025）：合规标识随标识帧走，独立字段不并入 guard
	//（guard 是审查语义仅终止帧携带；content_label 是合规标识）。wire 键取 content_label：
	// §4.6.1 冻结清单已预留 label{synthetic,provider,content_id}（隐式标识/出处，P-LABEL=none），
	// B1 不占用该冻结键。omitempty，旧插件忽略未知字段。
	Label *chunkLabelMeta `json:"content_label,omitempty"`
}

// chunkLabelMeta 强标标识 chunk-meta（B1；与 otpmask-plugin envelope.go 的 chunkLabel 同构）。
// 不含文案（与 delta 冗余防漂移）、不含用户内容（不触 §4.6.1 红线）。
type chunkLabelMeta struct {
	Std      string `json:"std"`      // 标准号（默认 GB45438-2025）
	Position string `json:"position"` // head | repeat | tail（终止帧固定 tail）
	// 标识**溯源要素**——定位为"溯源要素载体 ＋ 为下游落盘写入文件元数据提供数据"，
	// **非**"文件元数据隐式标识"本身。
	// 硬约束：不得据此宣称"已满足 GB 45438-2025 第 6.1 条"（强标以"文件"为要件，本形态无文件）。
	// 字段语义对应 GB 45438-2025 附录 E：
	Synthetic bool   `json:"synthetic,omitempty"`  // 生成合成标签要素（标识生效时恒 true）
	Producer  string `json:"producer,omitempty"`   // 生成合成服务提供者要素（由客户配置的主体编码）
	ContentID string `json:"content_id,omitempty"` // 内容制作编号要素（本请求 request_id）
}

// chunkGuardMeta 输出侧内容审查 chunk-meta（§4.6.1，M1 冻结项）。
// 所有字段可选（omitempty）；detected=false 时不应出现 category/rule_version。
//
// 红线（§4.6.1）：guard 不得包含命中词、原文片段、正则源码；category 只允许内部类目 ID。
type chunkGuardMeta struct {
	Detected     bool   `json:"detected"`               // 本请求至少一次命中（含 shadow 命中）
	Filtered     bool   `json:"filtered"`               // 实际拦截/遮蔽（enforcing 下的 block/mask）
	Action       string `json:"action,omitempty"`       // block | mask | flag（与 §4.4 动作四态对齐）
	Category     string `json:"category,omitempty"`     // 命中时必填：内部类目 ID（A1-06 等）
	PolicyVersion string `json:"policy_version"`        // 聚合策略版本（manifest.policy_version）
	RuleVersion  string `json:"rule_version,omitempty"` // 命中时必填：命中条目所在词库版本
	Mode         string `json:"mode"`                   // shadow | enforcing
}

// engineFor 按引擎类型返回推理引擎（text 路径）。
func (s *teeServer) engineFor(engineType string) (model.Engine, error) {
	switch engineType {
	case "", protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector:
		return s.model, nil // tee_gpu（vLLM 直连/本地演示）；masked_vector 下 text 为演示语义
	case protocol.EngineTypeCMAAS:
		if s.cmaasEngine == nil {
			return nil, errors.New("cmaas 引擎未配置（-cmaas-url，fail-closed）")
		}
		return s.cmaasEngine, nil
	default:
		return nil, fmt.Errorf("未知引擎类型 %q", engineType)
	}
}

// resolveEngineWithFailover 解析 text 路径的推理引擎（GF.3.3 / D-6）。
//
// 语义（保护 fail-closed 与租户显式选择）：
//   - preferred 非空（请求显式指定，已由 ValidateRequest 校验 ∈ 租户允许集）→ **fail-closed**：
//     引擎不可用直接返回 error，绝不静默降级到其他引擎（避免把敏感明文改道到租户未选引擎）；
//   - preferred 为空（仅当 route.Policy 配置了成本路由时进入）→ 自动择优：按成本排序的
//     候选列表顺序 failover（engineFor 失败才切下一个，流式开始后不切换，避免半截明文）。
func (s *teeServer) resolveEngineWithFailover(tenant, modelName, preferred string) (string, model.Engine, error) {
	allowed, _, err := s.route.Resolve(tenant, modelName)
	if err != nil {
		return "", nil, err
	}
	if preferred != "" {
		eng, err := s.engineFor(preferred)
		if err != nil {
			return "", nil, err
		}
		return preferred, eng, nil
	}
	ordered := s.route.orderEngines(allowed, modelName)
	var lastErr error
	for _, et := range ordered {
		eng, err := s.engineFor(et)
		if err != nil {
			lastErr = err
			log.Printf("[tee] 引擎 failover 跳过 tenant=%s model=%s engine=%s: %v", tenant, modelName, et, err)
			continue
		}
		return et, eng, nil
	}
	if lastErr == nil {
		lastErr = errors.New("无可用推理引擎（fail-closed）")
	}
	return "", nil, lastErr
}

// estimateTokens token 粗略估算（字符数/4，演示计量口径；生产接 tokenizer）。
// 计量口径已抽为 Tokenizer 接口（tokenizer.go，GF.2.4），本函数为默认估算实现。
func estimateTokens(text string) int {
	return (len(text) + 3) / 4
}

// replayEngine 缓存命中回放引擎（GF.4.1 演示）：把缓存文本作为单块流输出，
// 跳过真实推理引擎。仅用于精确缓存命中路径（text 载荷）。
type replayEngine struct{ text string }

// Predict vectors 路径不支持（缓存仅用于 text 路径），返回 -1。
func (replayEngine) Predict([]float64) int { return -1 }

// Generate 单块回放缓存文本（空文本不回调，等价于空生成）。
func (r replayEngine) Generate(_ model.GenerateRequest, onDelta func(string) error) error {
	if r.text == "" {
		return nil
	}
	return onDelta(r.text)
}

// handleTextInfer text 载荷推理：信封内明文 messages → Guardrail → 引擎流式生成 →
// SSE 逐块 s2c 信封（Stream=true）或单信封聚合响应（Stream=false）。
// fail-closed：text 载荷仅限证明会话信封通道（token 模式无信封，拒绝）。
func (s *teeServer) handleTextInfer(w http.ResponseWriter, sess *teeSession,
	tenant string, req *protocol.InferenceRequest, payloadSHA string, isRetry bool) {
	if sess == nil {
		s.denyAndAudit(tenant, req.RequestID, "text_without_session", payloadSHA)
		http.Error(w, "text 载荷须在证明会话信封内（fail-closed）", http.StatusBadRequest)
		return
	}
	var msgs []model.ChatMessage
	if err := json.Unmarshal(req.TextPayload, &msgs); err != nil || len(msgs) == 0 {
		s.denyAndAudit(tenant, req.RequestID, "text_payload_invalid", payloadSHA)
		http.Error(w, "text 载荷无效（须为非空 messages JSON）", http.StatusBadRequest)
		return
	}
	// M9-4 Guardrail：明文检测（C-MaaS 官方明示不提供内容安全，本网关补位）。
	// P2a：pii-mode=mask 时 PII 脱敏替换后放行（数据保护类）；SQL 注入/提示注入
	// 在任何模式下均拦截（攻击类，fail-closed）。
	inputText := strings.Builder{}
	for i := range msgs {
		if hit := s.guard.check(msgs[i].Content); hit != nil {
			if hit.Category == "pii" && s.currentPiiMode() == "mask" {
				masked, n := s.guard.maskPII(msgs[i].Content)
				if n > 0 {
					msgs[i].Content = masked
					log.Printf("[tee] PII 脱敏（text）tenant=%s req=%s hits=%d", tenant, req.RequestID, n)
					inputText.WriteString(masked)
					continue
				}
			}
			s.denyAndAudit(tenant, req.RequestID, "guardrail_"+hit.Category, payloadSHA)
			log.Printf("[tee] guardrail 拦截（text）tenant=%s req=%s category=%s",
				tenant, req.RequestID, hit.Category)
			http.Error(w, fmt.Sprintf("内容安全拦截（%s）", hit.Category), http.StatusForbidden)
			return
		}
		inputText.WriteString(msgs[i].Content)
	}
	// P2a：提示词装饰——非空 system-prompt 时在 messages 头部插入 system 消息。
	// 系统提示词为平台信任内容，不过 Guardrail；装饰结果计入 transformed_hash。
	if s.systemPrompt != "" {
		msgs = append([]model.ChatMessage{{Role: "system", Content: s.systemPrompt}}, msgs...)
	}
	// P2a：transformed_hash = 引擎实收内容（装饰+脱敏后）哈希，供双 hash 审计回溯。
	var txHash string
	{
		var sb strings.Builder
		for _, m := range msgs {
			sb.WriteString(m.Content)
		}
		txHash = sha256hex([]byte(sb.String()))
	}
	// P1：配额预占（输入 token，超限 429 fail-closed；原子占位防并发超卖。
	// 计量口径为 CJK 感知估算（过渡口径，GF.2.4），生产须接入真机 tokenizer，
	// 见 GA-AI网关能力补齐方案 D-3）
	if ok, denied := s.reserveQuota(tenant, int64(s.countTokens(inputText.String()))); !ok {
		s.metrics.incQuotaDeny(tenant, denied)
		s.denyAndAudit(tenant, req.RequestID, "quota_exceeded", payloadSHA)
		log.Printf("[tee] 配额超限拒绝（text）tenant=%s req=%s window=%q（空=累计维度）",
			tenant, req.RequestID, denied)
		http.Error(w, "租户 token 配额超限（429）", http.StatusTooManyRequests)
		return
	}
	// S5（判据 4）：影子观测（只计数不拒绝；命中落审计 would_reject）
	s.shadowObserve(tenant, req.RequestID, s.countTokens(inputText.String()), req.EngineType, req.Model, payloadSHA)
	engType := req.EngineType
	if engType == "" {
		// GF.3.3 / D-6：未显式指定引擎时，若配置了成本路由策略（route.Policy）则自动择优
		// （首选 = 成本排序首候选）；否则回退 tee_gpu（既有缺省行为，向后兼容）。
		if s.route.Policy != "" {
			engType = "" // 交由 resolveEngineWithFailover 的成本择优分支选择
		} else {
			engType = protocol.EngineTypeTEEGPU
		}
	}
	// GF.3.3 / D-6：引擎选择带 failover——首选（请求显式指定或成本路由择优）不可用时，
	// 按候选顺序自动切换（engineFor 失败即失败，绝不产出半截明文；流式阶段不切换）。
	engType, eng, err := s.resolveEngineWithFailover(tenant, req.Model, engType)
	if err != nil {
		// GA-计费 P0-3：预占后引擎不可用（无任何输出交付）→ 输入计量回滚，
		// fail-closed 故障不向租户计费。
		s.rollbackQuota(tenant, int64(s.countTokens(inputText.String())))
		s.denyAndAudit(tenant, req.RequestID, "engine_unavailable", payloadSHA)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	genReq := model.GenerateRequest{Model: req.Model, Messages: msgs, MaxTokens: req.MaxNewTokens}
	// 模型名语义分层（cmaas）：req.Model 是南向协议层网关路由标识（插件
	// config.model，如 "mock"），非上游模型名——透传会被 Phala 以
	// model_not_found 拒绝。cmaas 上游模型取 -cmaas-model 缺省
	// （CmaasEngine.Generate 内 Model=="" 时回退 e.model）；缓存键仍含
	// req.Model（路由维度隔离），审计 Model 字段不变。
	if _, isCMAAS := eng.(*model.CmaasEngine); isCMAAS {
		genReq.Model = ""
	}
	// P0-2 B2：原生语义缓存查询为首选；未装配 cacheEngine 时走 legacy 兜底（GF.4.1 精确缓存）。
	// 命中则跳过真实引擎推理，以缓存回放（原生：§6.12 分段 paced；legacy：单块），不产出半截明文。
	var cacheKey string
	var cacheHit bool
	var cacheReleaseAt time.Time
	var cacheStoreCtx *cacheengine.StoreContext
	if s.cacheEngine != nil && s.cacheEnabled {
		lctx := buildCacheLookupContext(tenant, engType, req.Model, txHash,
			inputText.String(), int(req.MaxNewTokens), req.Stream, s.policyVersion())
		lr := s.cacheEngine.Lookup(lctx)
		// §7.3：抖动注入基准 = 结果就绪时刻 + Jitter（hit/miss 同分布，J-1）。
		cacheReleaseAt = time.Now().Add(lr.Jitter)
		// B2 决策 D-a：负向命中按 miss 处理（fail-open）——Entry 无正文，严禁当正向文本回放。
		if lr.Hit && !lr.IsNegative() && lr.Entry != nil {
			cacheHit = true
			eng = &segmentReplayEngine{
				text: lr.Entry.Text, segs: lr.Entry.Segments, releaseAt: cacheReleaseAt,
				minGap: s.cacheReplay.minGap, maxGap: s.cacheReplay.maxGap,
			}
		}
		sc := cacheengine.StoreContext{LookupContext: lctx}
		cacheStoreCtx = &sc
	} else if s.cache != nil {
		cacheKey = sha256hex([]byte(fmt.Sprintf("%s|%s|%s|%d|%s",
			tenant, engType, req.Model, req.MaxNewTokens, txHash)))
		if cached, ok := s.cache.Get(cacheKey); ok {
			cacheHit = true
			eng = replayEngine{text: cached}
		}
	}
	// 未命中：包装真实引擎采集流式分片（§6.12 写入侧），供回填使用。
	var capture *segmentCapturingEngine
	if cacheStoreCtx != nil && !cacheHit {
		capture = newSegmentCapturingEngine(eng, cacheReleaseAt)
		eng = capture
	}
	log.Printf("[tee] infer(text) tenant=%s request=%s engine=%s stream=%v msgs=%d cache_hit=%v",
		tenant, req.RequestID, engType, req.Stream, len(msgs), cacheHit)

	// 统一 SSE 信封流输出（seq 严格递增 + finish 分片）；stream=false 语义为单分片聚合。
	var agg strings.Builder
	var out streamOutcome
	if serr := s.streamTextInfer(w, sess, eng, genReq, &agg, tenant, req.RequestID, &out); serr != nil {
		// X-3：输出侧整流拦截优先于引擎 error 判定——按实际下发回冲（block+genErr 同此）。
		if out.Blocked {
			s.applyOutputBlockBilling(tenant, req.RequestID, payloadSHA, txHash, engType, req.Model,
				s.countTokens(inputText.String()), out, isRetry)
			return
		}
		log.Printf("[tee] infer(text) 引擎失败 request=%s engine=%s err=%v", req.RequestID, engType, serr)
		// GA-计费 P0-3/P1-3 失败路径计费口径：
		// - 已有部分输出（客户端已收到）→ 按实收计费：输入计量保留，输出按 agg
		//   实际累计补记，审计记 infer/engine_error 事件（带 token 数，供出账聚合）；
		// - 完全无输出 → 整单回滚输入预占（fail-closed 故障不向租户计费）。
		tokensOut := s.countTokens(agg.String())
		if tokensOut > 0 {
			tokensIn := s.countTokens(inputText.String())
			s.recordUsage(tenant, 0, tokensOut, false)
			s.recordModelUsage(tenant, engType, req.Model, tokensIn, tokensOut)
			ev := s.audit.append(AuditEvent{
				TenantID: tenant, RequestID: req.RequestID, Action: "infer",
				TokensIn: tokensIn, TokensOut: tokensOut,
				Result: "engine_error", PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
				EngineType: engType, Model: req.Model,
				TransformedHash: txHash,
				MeteringMode:    s.meteringMode(),
				IsRetry:         isRetry, // GA-计费 P0-3：重试归因
			})
			go s.billing.notify(ev) // GA-计费 P1-1：Webhook（nil = no-op；异步不阻塞主链）
		} else {
			s.rollbackQuota(tenant, int64(s.countTokens(inputText.String())))
			s.denyAndAudit(tenant, req.RequestID, "engine_error", payloadSHA)
		}
		s.metrics.incDeny(tenant, "engine_error")
		return
	}
	// X-3：正常收尾（genErr=nil）但输出侧在 Process/Finish 整流拦截 → 按实际下发回冲。
	if out.Blocked {
		s.applyOutputBlockBilling(tenant, req.RequestID, payloadSHA, txHash, engType, req.Model,
			s.countTokens(inputText.String()), out, isRetry)
		return
	}
	// 未命中回填缓存（命中路径不重复回填）。
	if !cacheHit {
		if cacheStoreCtx != nil {
			// 写前审查门禁（§7.1）：输出侧已放行（未阻塞）才写；分片随条目写入（§6.12）。
			sc := *cacheStoreCtx
			sc.Writable = !out.Blocked
			s.cacheEngine.Store(sc, cacheengine.InferResult{
				Text:      agg.String(),
				TokensIn:  s.countTokens(inputText.String()),
				TokensOut: s.countTokens(agg.String()),
				Finish:    "stop",
				Segments:  capture.segments(),
			})
		} else if s.cache != nil {
			s.cache.Put(cacheKey, agg.String())
		}
	}

	// M9-2/M9-3：计量 + 审计 + 指标（过渡口径见 estimateTokensCJK；输入已在配额预占计入，仅补记输出）
	tokensOut := s.countTokens(agg.String())
	tokensIn := s.countTokens(inputText.String())
	s.recordUsage(tenant, 0, tokensOut, false)
	s.recordModelUsage(tenant, engType, req.Model, tokensIn, tokensOut) // GA-计费 P0-1：模型维度
	// GF.4.2：Key 池计量归属（评审 P1-4）——审计事件附 key 指纹（平台维度消耗
	// 核算，sha256 前 8 hex，不暴露明文 key），与 tenant_id（租户维度配额/计费）
	// 双口径分离。本地引擎/缓存回放无 key，指纹为空。
	keyFP := ""
	if fp, ok := eng.(interface{ LastKeyFingerprint() string }); ok {
		keyFP = fp.LastKeyFingerprint()
	}
	ev := s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: req.RequestID, Action: "infer",
		TokensIn: tokensIn, TokensOut: tokensOut,
		Result: "ok", PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
		// P2a：双 hash 审计——PayloadSHA 为入站密文哈希，TransformedHash 为引擎实收内容哈希
		TransformedHash: txHash,
		EngineType:      engType,          // GA-计费 P0-1：模型/引擎维度（分价计费）
		Model:           req.Model,        // GA-计费 P0-1
		CacheHit:        cacheHit,         // GF.4.1：精确缓存命中标记
		KeyFP:           keyFP,            // GF.4.2：服务商 key 指纹（多账号归属）
		MeteringMode:    s.meteringMode(), // GF.2.4：计量口径标记（estimate=未校准）
		IsRetry:         isRetry,          // GA-计费 P0-3：重试归因（A-23/A-29）
	})
	go s.billing.notify(ev) // GA-计费 P1-1：Webhook（nil = no-op；异步不阻塞主链）
	s.metrics.incRequest(tenant, "ok")
	s.metrics.addTokens(tenant, int64(s.countTokens(inputText.String())), int64(tokensOut))
	// P5：C-MaaS 证明/透明度引用落审计链（含 Rekor 日志引用，SDK 开通后经
	// RecordAttestation 记录；独立审计事件，不动既有哈希链事件结构）
	if engType == protocol.EngineTypeCMAAS && s.cmaasEngine != nil {
		if ref := s.cmaasEngine.LastAttestation(); ref != "" {
			s.audit.append(AuditEvent{
				TenantID: tenant, RequestID: req.RequestID, Action: "cmaas_attest",
				Result: "ok", PayloadSHA: sha256hex([]byte(ref)),
				KeyFP: s.cmaasEngine.LastKeyFingerprint(), // GF.4.2：证明按 key 关联
			})
		}
	}
}

// streamOutcome 一次文本流的交付结果（X-3：供调用方按"实际下发"回冲计费）。
type streamOutcome struct {
	Blocked       bool   // 输出侧是否整流拦截（enforcing content_filter）
	Category      string // 拦截类目（blockCat；空 = 降级终止，无类目）
	EmittedTokens int    // 实际下发（客户端实付）token；不含被拦内容与标识帧
}

// streamTextInfer 流式生成并逐块写出加密 SSE（seq 严格递增；finish 分片终止）。
// 返回非 nil = 流式失败（调用方审计；error 分片已尽力写出）。
//
// GA-输出侧内容审查（OG-3）集成点（§2.3 I1–I3）：og 构造 → 回调经 og.Process → og.Finish。
// mode=off 时 og=nil，走原路径，行为与现网逐字节一致。
func (s *teeServer) streamTextInfer(w http.ResponseWriter, sess *teeSession,
	eng model.Engine, genReq model.GenerateRequest, agg *strings.Builder,
	tenant, requestID string, out *streamOutcome) error {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	var seq uint64
	writeChunk := func(delta, finish string, guard *chunkGuardMeta, label *chunkLabelMeta) error {
		seq++
		chunkJSON, err := json.Marshal(textStreamChunk{Seq: seq, Delta: delta, Finish: finish, Guard: guard, Label: label})
		if err != nil {
			return err
		}
		sealed, err := sess.sealPayload(protocol.EndpointInfer, chunkJSON)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", hex.EncodeToString(sealed)); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	// I1：构造审查管线（mode=off 返回 nil → 下方走原路径，零行为变化）。
	// OG-18：mask 改写开关 + PII 正则（仅 lexiconRegistry 有正则，fallback guardrail 无则不改写）。
	var maskRes []*regexp.Regexp
	if reg, ok := s.l1Classifier().(*lexiconRegistry); ok {
		maskRes = reg.CategoryRegexps("A4-06")
	}
	// S3-2：按当前策略派生判定单元（请求级构造，切换对新请求真实生效），
	// 以启动缓冲参数为基底仅覆盖 Unit（P-UNIT 随 P-STRATEGY 联动）。
	strategy := s.currentOutputGuardStrategy()
	disabled := s.currentDisabledCategories()
	reqParams := s.outputGuardParams
	reqParams.Unit = unitForStrategy(strategy)
	og, ogErr := newOutputGuard(outputGuardConfig{
		Mode:          s.currentOutputGuardMode(),
		PolicyVersion: s.policyVersion(),
		Strategy:      strategy,
		Params:        reqParams,
		Cascade:       s.outputGuardCascade, // OG-13：级联参数（槽位/并发阀/超时/预演开关）
		MaskEnabled:   s.outputGuardMaskEnabled,
		MaskRegexps:   maskRes,
	}, withCategoryGate(s.l1Classifier(), disabled), withCategoryGate(s.outputGuardL2, disabled),
		s.metrics, s.audit, tenant, requestID)
	if ogErr != nil {
		return ogErr // fail-closed：模式非法不得静默放行（启动期已校验，此处兜底）
	}
	if og != nil {
		defer og.Close() // 幂等释放（C4：请求内生命周期）
	}
	// I2 唯一出口：所有写给客户端的内容必须经 emit（防绕过）。
	// OG-19：emittedBuilder 累计已下发明文（不含终止帧空 delta），
	// 用于 blocked 时精确计算 filtered_tokens = 总生成 − 已下发。
	var emittedBuilder strings.Builder
	// emitAccounting 发射记账统一出口：count=true 计入 emittedBuilder（内容帧），
	// count=false 不计（B1 标识帧——标识文本不进 tokens_out / filtered_tokens 口径）。
	// 不旁路 writeChunk：seq 唯一分配点，标识帧经它发射天然 seq 连续。
	emitAccounting := func(delta, finish string, count bool, label *chunkLabelMeta) error {
		if count && finish == "" && delta != "" {
			emittedBuilder.WriteString(delta)
		}
		return writeChunk(delta, finish, nil, label)
	}
	emit := func(delta, finish string) error {
		return emitAccounting(delta, finish, true, nil)
	}
	// B1 强标标识发射：count=false（不写 emittedBuilder → 标识不计费），带 label meta。
	emitLabel := func(text string, meta *chunkLabelMeta) error {
		if s.metrics != nil && meta != nil {
			s.metrics.incContentLabelFrame(meta.Position)
		}
		return emitAccounting(text, "", false, meta)
	}
	// B1：解析当前生效配置（off → nil labeler，全路径零行为变化）。
	lbl := newContentLabeler(s.currentContentLabelConfigPtr(), emitLabel)
	if lbl != nil {
		// 内容制作编号要素＝本请求 request_id（服务端唯一、可追溯）。
		lbl.contentID = requestID
		// 流首标识：先于引擎任何输出（首帧 seq=1）；
		// replayEngine 缓存路径走同一 streamTextInfer，注入点放发射层自动覆盖。
		if err := lbl.emitHead(); err != nil {
			return err
		}
		s.metrics.incContentLabelRequest()
	}
	// emitWrapped：内容帧出口包装——发射后按 repeat 间隔插重复标识帧
	//（og.Process/og.Finish 与 og=nil 原路径统一经此，计数口径与下发口径一致）。
	emitWrapped := func(delta, finish string) error {
		if err := emit(delta, finish); err != nil {
			return err
		}
		return lbl.afterContent(delta, finish)
	}

	genErr := eng.Generate(genReq, func(delta string) error {
		agg.WriteString(delta)
		if og == nil {
			return emitWrapped(delta, "") // 未开审查 == 现状路径（B1 标识经 emitWrapped 注入）
		}
		return og.Process(delta, emitWrapped) // 缓冲 → 判定 → emit（shadow 只记不拦；enforcing 按动作处置）
	})
	if genErr != nil {
		// 200 已发出无法改状态码：以 error finish 分片终止，
		// 插件侧（envelope.go）对非 stop 终止整流 fail-closed（不产出半截明文）。
		// M4：block 优先于 error——若审查已整流终止，终止码合同为 content_filter（§4.6），
		// 违规内容已在 cascade 内拦下无泄漏；genErr 仍上抛供上游审计（与 §2.3 error 分支解耦）。
		finishReason := "error"
		var guard *chunkGuardMeta
		blocked := false
		blockCat := ""
		if og != nil {
			blocked, blockCat = og.BlockInfo()
			if blocked {
				finishReason = "content_filter"
				guard = og.BuildGuardMeta()
			}
		}
		if out != nil {
			out.Blocked, out.Category, out.EmittedTokens = blocked, blockCat, s.countTokens(emittedBuilder.String())
		}
		_ = writeChunk("", finishReason, guard, nil) // B1：error 分支不注入 tail（明文不出，标识无意义）
		fmt.Fprint(w, "data: [DONE]\n\n")
		// OG-19：block 命中 → 在上层发射 output_blocked 审计（携带 filtered_tokens）。
		// cascade 内已记指标；此处补审计事件——在上层可精确算出 filtered_tokens。
		if blocked && blockCat != "" {
			filtered := s.countTokens(agg.String()) - s.countTokens(emittedBuilder.String())
			if filtered < 0 {
				filtered = 0
			}
			s.audit.append(AuditEvent{
				TenantID:       tenant,
				RequestID:      requestID,
				Action:         "output_blocked",
				Result:         "blocked_" + blockCat,
				OGCategory:     blockCat,
				OGMode:         s.currentOutputGuardMode(),
				FilteredTokens: filtered,
				MeteringMode:   s.meteringMode(),
			})
		}
		return genErr
	}
	// I3：收尾——OG-4 把缓冲尾部作为最后一个判定单元送判；enforcing 下句级降级/终止在此收敛。
	if og != nil {
		if err := og.Finish(emitWrapped); err != nil {
			return err
		}
	}
	// B1：流尾标识——必须在 stopChunk 构造之前发射（seq 连续：尾标帧先于终止帧）。
	// 尾标帧若因连接截断丢失，下方终止帧仍恒带 label{position:"tail"} 兜底隐式标识。
	if err := lbl.emitTail(); err != nil {
		return err
	}
	// 终止帧：M4 enforcing 已整流终止 → finish=content_filter，否则维持 stop；
	// 带 chunk-meta guard 字段（§4.6.1；og=nil 时 guard 为 nil，omitempty 与现网逐字节一致）。
	finishReason := "stop"
	var guardMeta *chunkGuardMeta
	blocked := false
	blockCat := ""
	if og != nil {
		blocked, blockCat = og.BlockInfo()
		if blocked {
			finishReason = "content_filter"
		}
		guardMeta = og.BuildGuardMeta()
	}
	if out != nil {
		out.Blocked, out.Category, out.EmittedTokens = blocked, blockCat, s.countTokens(emittedBuilder.String())
	}
	stopChunk := textStreamChunk{Seq: seq + 1, Finish: finishReason, Guard: guardMeta, Label: lbl.tailMeta()}
	stopJSON, err := json.Marshal(stopChunk)
	if err != nil {
		return err
	}
	sealedStop, err := sess.sealPayload(protocol.EndpointInfer, stopJSON)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", hex.EncodeToString(sealedStop)); err != nil {
		return err
	}
	seq++ // 保持 seq 计数一致（供可能的后续帧使用；虽然后面没有帧了，但维持变量状态一致）
	if flusher != nil {
		flusher.Flush()
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	// OG-19：block 命中 → 在上层发射 output_blocked 审计（携带 filtered_tokens）。
	// 正常路径（genErr=nil）的 block 发生在 Finish 或 Process 阶段；D5 降级终止 blockCat 为空，
	// 不发 output_blocked（与既有 degraded 口径一致）。
	if blocked && blockCat != "" {
		filtered := s.countTokens(agg.String()) - s.countTokens(emittedBuilder.String())
		if filtered < 0 {
			filtered = 0
		}
		s.audit.append(AuditEvent{
			TenantID:       tenant,
			RequestID:      requestID,
			Action:         "output_blocked",
			Result:         "blocked_" + blockCat,
			OGCategory:     blockCat,
			OGMode:         s.currentOutputGuardMode(),
			FilteredTokens: filtered,
			MeteringMode:   s.meteringMode(),
		})
	}
	// OG-18：mask 改写命中 → 在上层发射 output_masked 审计（按类目各一条）。
	// 仅当 mask 开关开启且实际命中等价类目标记 mask 动作时才发射；mask 未开启时
	// 即使 PII 类目存在也只计为 flag（由既有 output_flagged 覆盖）。
	if og != nil {
		for _, cat := range og.MaskedCategories() {
			s.audit.append(AuditEvent{
				TenantID:     tenant,
				RequestID:    requestID,
				Action:       "output_masked",
				Result:       "masked_" + cat,
				OGCategory:   cat,
				OGMode:       s.currentOutputGuardMode(),
				MeteringMode: s.meteringMode(),
			})
		}
	}
	return nil
}

// applyOutputBlockBilling X-3（G23）：输出侧整流拦截后的配额回冲与计费。
// 口径①（与 GA-计费 P0-3 故障口径对齐）：
//   - 全拦（零下发）：全额回冲输入预占、计 deny、不出 infer 账（被拦内容零计费、
//     配额即释放）；审计 output_blocked 已由 streamTextInfer 落链（含 filtered_tokens）。
//   - 部分截断（有下发）：输入保留（已发送并消耗），输出仅按实际下发计费；
//     infer 审计 result=content_filter（供 from/to 出账聚合）。
func (s *teeServer) applyOutputBlockBilling(tenant, requestID, payloadSHA, transformedHash,
	engType, modelName string, tokensIn int, out streamOutcome, isRetry bool) {
	delivered := out.EmittedTokens
	if delivered <= 0 {
		s.rollbackQuota(tenant, int64(tokensIn))
		s.recordUsage(tenant, 0, 0, true)
		s.metrics.incDeny(tenant, "content_filter")
		log.Printf("[tee] X-3 全拦回冲 tenant=%s req=%s cat=%s 回冲输入=%d（被拦零计费、配额释放）",
			tenant, requestID, out.Category, tokensIn)
		return
	}
	s.recordUsage(tenant, 0, delivered, false)
	s.recordModelUsage(tenant, engType, modelName, tokensIn, delivered)
	ev := s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: "infer",
		TokensIn: tokensIn, TokensOut: delivered, Result: "content_filter",
		PayloadSHA: payloadSHA, TransformedHash: transformedHash, HashAlg: hashAlgTag(),
		EngineType: engType, Model: modelName,
		MeteringMode: s.meteringMode(),
		IsRetry:      isRetry, // GA-计费 P0-3：重试归因
	})
	go s.billing.notify(ev)
	s.metrics.incRequest(tenant, "content_filter")
	log.Printf("[tee] X-3 部分截断计费 tenant=%s req=%s cat=%s 输入保留=%d 输出按下发=%d",
		tenant, requestID, out.Category, tokensIn, delivered)
}

// denyAndAudit 拒绝路径：用量 deny 计数 + 审计事件（result=拒绝原因）+ 指标。
func (s *teeServer) denyAndAudit(tenant, requestID, reason, payloadSHA string) {
	s.recordUsage(tenant, 0, 0, true)
	s.audit.append(AuditEvent{
		TenantID: tenant, RequestID: requestID, Action: "deny",
		Result: reason, PayloadSHA: payloadSHA, HashAlg: hashAlgTag(),
	})
	s.metrics.incDeny(tenant, reason)
}

// handleHealthz 健康探针。
// readiness 语义：requireAttest 模式下，无有效证明会话 → 503（证明失效即不可服务）；
// 输入侧语义分类器已接线时，侧车不健康 → 503（不可用即 fail-closed 拒答，
// 故实例必须摘流，可用性由"摘流 + 容量保障"解决，而非回退关键词放行）；
// liveness 语义：进程存活即 200（path=/healthz/live）。
func (s *teeServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// liveness：进程存活
	if r.URL.Path == "/healthz/live" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	// readiness：证明状态联动
	if s.requireAttest && !s.hasValidSession() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("attestation required: no valid session"))
		return
	}
	// readiness：输入侧语义分类器侧车健康联动
	if s.guardProbe != nil && !s.guardProbe.Healthy() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("guard classifier sidecar unhealthy: fail-closed, draining"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// hasValidSession 是否存在任意有效证明会话。
func (s *teeServer) hasValidSession() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.Completed && time.Since(sess.CreatedAt) < sessionTTL {
			return true
		}
	}
	return false
}

// currentPiiMode 当前生效的 PII 模式：运行时覆盖（高敏复核后写入）优先，否则启动参数。
func (s *teeServer) currentPiiMode() string {
	if v, ok := s.piiModeOverride.Load().(string); ok && v != "" {
		return v
	}
	return s.piiMode
}

// currentOutputGuardMode 当前生效的输出侧审查模式：运行时覆盖（高敏复核后写入）优先，否则启动参数。
// 与 currentPiiMode 同构（OG-8 运行时覆盖设计对称）。
func (s *teeServer) currentOutputGuardMode() string {
	if v, ok := s.outputGuardModeOverride.Load().(string); ok && v != "" {
		return v
	}
	if s.outputGuardMode == "" {
		return outputGuardOff
	}
	return s.outputGuardMode
}

// outputGuardModeSource 返回当前 mode 来源：startup（启动参数）/ runtime（运行时覆盖）。
func (s *teeServer) outputGuardModeSource() string {
	if v, ok := s.outputGuardModeOverride.Load().(string); ok && v != "" {
		return "runtime"
	}
	return "startup"
}

// currentOutputGuardStrategy 当前生效策略档位：运行时覆盖优先，否则启动参数，缺省 A（S3-2）。
func (s *teeServer) currentOutputGuardStrategy() string {
	if v, ok := s.outputGuardStrategyOverride.Load().(string); ok && v != "" {
		return v
	}
	if s.outputGuardStrategy != "" {
		return s.outputGuardStrategy
	}
	return defaultOutputStrategy
}

// currentDisabledCategories 当前停用类目集合；未设置返回空 map（S3-2）。
// 返回值为只读快照，调用方不得修改。
func (s *teeServer) currentDisabledCategories() map[string]bool {
	if v, ok := s.outputGuardDisabled.Load().(map[string]bool); ok {
		return v
	}
	return map[string]bool{}
}

// disabledCategoryList 返回停用类目的有序列表（消除 map 不确定性，供快照/响应/审计复用）。
func disabledCategoryList(disabled map[string]bool) []string {
	if len(disabled) == 0 {
		return nil
	}
	out := make([]string, 0, len(disabled))
	for cat := range disabled {
		out = append(out, cat)
	}
	sort.Strings(out)
	return out
}

// ---- B1 强标标识（GB 45438-2025）配置访问 ----

// currentContentLabelConfig 当前生效的标识配置：运行时覆盖优先，否则启动参数（均 resolve 兜底）。
func (s *teeServer) currentContentLabelConfig() contentLabelConfig {
	if v, ok := s.contentLabelOverride.Load().(contentLabelConfig); ok {
		return resolveContentLabelConfig(v)
	}
	return resolveContentLabelConfig(s.contentLabelCfg)
}

// currentContentLabelConfigPtr 生效配置指针（Enabled=false → nil，供 newContentLabeler 判空）。
func (s *teeServer) currentContentLabelConfigPtr() *contentLabelConfig {
	c := s.currentContentLabelConfig()
	if !c.Enabled {
		return nil
	}
	return &c
}

// contentLabelSource 返回当前标识配置来源：startup | runtime。
func (s *teeServer) contentLabelSource() string {
	if _, ok := s.contentLabelOverride.Load().(contentLabelConfig); ok {
		return "runtime"
	}
	return "startup"
}

// secConfigView 安全配置只读快照（M3-B 安全中心「密态链路状态 / Guardrail 策略」数据源）。
type secConfigView struct {
	ProtocolVersion  string            `json:"protocol_version"`
	RequireAttest    bool              `json:"require_attest"`
	AdminAuthEnabled bool              `json:"admin_auth_enabled"`
	PIIMode          string            `json:"pii_mode"`
	PIIModeSource    string            `json:"pii_mode_source"` // startup | runtime
	SystemPromptSet  bool              `json:"system_prompt_set"`
	AuditEnabled     bool              `json:"audit_enabled"`
	// 审计/日志留存期声明（天；0=未声明）。声明式，删除由存储层生命周期策略执行。
	AuditRetentionDays int               `json:"audit_retention_days"`
	Guardrail        guardrailSnapshot `json:"guardrail"`
	// GA-输出侧内容审查（OG-3）：当前模式与策略版本（只读；运行时覆盖/持久化归 OG-8）。
	OutputGuard outputGuardSnapshot `json:"output_guard"`
	// B1 强标标识（GB 45438-2025）：只读快照（运行时变更走 POST /config/content-label）。
	ContentLabel contentLabelSnapshot `json:"content_label"`
}

// outputGuardSnapshot 输出侧审查配置只读快照（§2.3 I7 / OG-8）。
// GET /config 返回只读视图；运行时变更走 POST /config/output-guard（OG-8 已实现；
// D8 高敏复核链在 gateway-admin-service，见 change.go output_guard_mode 动作）。
type outputGuardSnapshot struct {
	Mode          string                  `json:"mode"`
	ModeSource    string                  `json:"mode_source"` // startup | runtime（OG-8 运行时覆盖来源）
	PolicyVersion string                  `json:"policy_version"`
	Params        outputGuardParamsSnapshot `json:"params"`
	// Cascade：级联并发参数（OG-13；只读快照，供排障与浸泡脚本核对生效值）
	Cascade outputGuardCascadeSnapshot `json:"cascade"`
	// L1Categories：已加载的 L1 规则类目数（词库注册表装载量；未配置 policy 目录时为 0）
	L1Categories int `json:"l1_categories_loaded"`
	// L1Rules：已加载的 L1 规则总条数（同上）
	L1Rules int `json:"l1_rules_total"`
	// MaskEnabled：PII mask 改写开关（OG-18；默认 false = block-only 深度，mask 类目降 flag）
	MaskEnabled bool `json:"mask_enabled"`
	// OutputDepth：输出处理深度档位（S1-6/G18；**派生视图**＝由 mode＋mask 计算，非独立运行状态）
	OutputDepth string `json:"output_depth"`
	// Strategy：策略档位（S3-2 P-STRATEGY：A|B|C；缺省 A）。
	Strategy string `json:"strategy"`
	// DisabledCategories：停用类目集合（S3-2；空 = 全类目启用）。
	DisabledCategories []string `json:"disabled_categories,omitempty"`
	// S1-4（G21）：策略版本库只读视图（无 versions/index.json 时 VersionsEnabled=false，行为不变）
	VersionsEnabled   bool     `json:"policy_versions_enabled"`
	ReferencedVersion string   `json:"policy_referenced_version,omitempty"` // 显式引用版本（空=根目录 manifest）
	VersionsAvailable []string `json:"policy_versions_available,omitempty"` // 索引内已登记版本号
	// S1-5：公众形态锁定（true 时审核总开关不可关闭）
	PublicFacing bool `json:"public_facing"`
}

// outputGuardParamsSnapshot 缓冲参数只读快照（D 组参数，§5.4）。
type outputGuardParamsSnapshot struct {
	Unit              string `json:"unit"`                // sentence | fixed-window
	MaxUnitRunes      int    `json:"max_unit_runes"`      // P-MAX-UNIT-RUNES
	FirstUnitMaxRunes int    `json:"first_unit_max_runes"` // P-FIRST-UNIT-MAX-RUNES
	MaxBufferBytes    int    `json:"max_buffer_bytes"`    // P-MAX-BUFFER-BYTES
	WindowMargin      int    `json:"window_margin"`       // P-WINDOW-MARGIN
	WindowRunes       int    `json:"window_chars"`        // P-WINDOW-CHARS（派生值）
	MaxKeywordRunes   int    `json:"max_keyword_runes"`   // 词库最长命中长度（P-WINDOW-CHARS 派生输入）
}

// outputGuardCascadeSnapshot 级联参数只读快照（跨 §5.3–5.5 多组；OG-13）。
type outputGuardCascadeSnapshot struct {
	Timeout       string `json:"timeout"`        // P-TIMEOUT（-output-guard-l2-timeout）
	Concurrency   int    `json:"concurrency"`    // P-CONCURRENCY（派生后生效值）
	MaxSlots      int    `json:"max_slots"`      // P-MAX-SLOTS（派生后生效值）
	BlockCancel   bool   `json:"block_cancel"`   // P-BLOCK-CANCEL（M4 生效）
	Degrade       string `json:"degrade"`        // P-DEGRADE：fail-closed | fallback-keyword
	BlockEmission bool   `json:"block_emission"` // 阻塞预演开关（非 §5 参数；默认 false）
}

// currentPolicy 返回当前生效的策略注册表（nil = 未配置词库目录）。
// 热加载经原子指针换版，请求路径无锁读取（OG-9）。
func (s *teeServer) currentPolicy() *lexiconRegistry { return s.policyReg.Load() }

// setPolicy 原子换版策略注册表（启动加载与热加载 applied 的唯一写入点）。
func (s *teeServer) setPolicy(reg *lexiconRegistry) { s.policyReg.Store(reg) }

// policyVersion 返回当前策略版本：词库已加载 → manifest 聚合版本；否则骨架默认版本。
// 用途：审计 OGPolicyVersion、chunk-meta guard.policy_version、mode/policy_version gauge 同源。
func (s *teeServer) policyVersion() string {
	if reg := s.currentPolicy(); reg != nil {
		return reg.PolicyVersion()
	}
	return defaultPolicyVersion
}

// l1Classifier 返回输出侧 L1 分类器：
//   - 已配置 -output-guard-policy-dir → 词库注册表（返回**内部类目 ID**，如 A4-06）；
//   - 未配置 → 既有 guardrail 包装器（返回 L1 原生标签，如 pii）。
//
// 两者都实现 OutputClassifier；差异由 classifyUnit 的"是否已是内部 ID"判定吸收。
func (s *teeServer) l1Classifier() OutputClassifier {
	if reg := s.currentPolicy(); reg != nil {
		return reg
	}
	return l1Classifier{g: s.guard}
}

// handleConfig 安全配置只读查询：GET /config（管理令牌，M3-B）。
//
// 定位：安全中心展示的数据源。**只读**——Guardrail 变更不在此端点，
// 须经门户高敏变更复核（submitter≠reviewer）后由门户执行器调用
// POST /config/guardrail（方案 §3.2/§5.3）。
func (s *teeServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	view := secConfigView{
		ProtocolVersion:  s.protoVersion,
		RequireAttest:    s.requireAttest,
		AdminAuthEnabled: s.adminToken != "",
		PIIMode:          s.currentPiiMode(),
		PIIModeSource:    "startup",
		SystemPromptSet:  s.systemPrompt != "",
		AuditEnabled:     s.audit != nil,
		AuditRetentionDays: s.auditRetentionDays,
	}
	if v, ok := s.piiModeOverride.Load().(string); ok && v != "" {
		view.PIIModeSource = "runtime"
	}
	if s.guard != nil {
		view.Guardrail = s.guard.snapshot()
	}
	ogMode := s.currentOutputGuardMode()
	view.OutputGuard = outputGuardSnapshot{
		Mode:          ogMode,
		ModeSource:    s.outputGuardModeSource(),
		PolicyVersion: s.policyVersion(),
		MaskEnabled:   s.outputGuardMaskEnabled,
		OutputDepth:   deriveOutputDepth(ogMode, s.outputGuardMaskEnabled),
		Strategy:      s.currentOutputGuardStrategy(),
		PublicFacing:  s.publicFacing,
		DisabledCategories: disabledCategoryList(s.currentDisabledCategories()),
		Params: outputGuardParamsSnapshot{
			Unit:              s.outputGuardParams.Unit,
			MaxUnitRunes:      s.outputGuardParams.MaxUnitRunes,
			FirstUnitMaxRunes: s.outputGuardParams.FirstUnitMaxRunes,
			MaxBufferBytes:    s.outputGuardParams.MaxBufferBytes,
			WindowMargin:      s.outputGuardParams.WindowMargin,
			WindowRunes:       s.outputGuardParams.WindowRunes,
			MaxKeywordRunes:   s.outputGuardParams.MaxKeywordRunes,
		},
		Cascade: outputGuardCascadeSnapshot{
			Timeout:       s.outputGuardCascade.Timeout.String(),
			Concurrency:   s.outputGuardCascade.Concurrency,
			MaxSlots:      s.outputGuardCascade.MaxSlots,
			BlockCancel:   s.outputGuardCascade.BlockCancel,
			Degrade:       s.outputGuardCascade.Degrade,
			BlockEmission: s.outputGuardCascade.BlockEmission,
		},
	}
	// 词库已加载时回填实际装载量（OG-9）；未配置 policy 目录则保持 0（走 guardrail 包装器）。
	if reg := s.currentPolicy(); reg != nil {
		view.OutputGuard.L1Categories = reg.CategoryCount()
		view.OutputGuard.L1Rules = reg.RuleCount()
	}
	// S1-4（G21）：策略版本库只读视图（未启用时不报错，enabled=false）。
	if vv := s.buildPolicyVersionsView(); vv.Enabled {
		view.OutputGuard.VersionsEnabled = true
		view.OutputGuard.ReferencedVersion = vv.ReferencedVersion
		if idx, err := loadPolicyVersionIndex(s.outputGuardPolicyDir); err == nil {
			view.OutputGuard.VersionsAvailable = idx.policyVersionNames()
		}
	}
	// B1：强标标识只读快照（enabled/source/text/repeat/std 与生效配置同源）。
	clc := s.currentContentLabelConfig()
	view.ContentLabel = contentLabelSnapshot{
		Enabled:  clc.Enabled,
		Source:   s.contentLabelSource(),
		Text:     clc.Text,
		Repeat:   clc.Repeat,
		Std:      clc.Std,
		Producer: clc.Producer,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// policyReloadResponse POST /config/policy/reload 响应体（OG-9 热加载）。
type policyReloadResponse struct {
	Status        string `json:"status"`                   // applied | rolled_back
	PolicyVersion string `json:"policy_version,omitempty"` // applied：新版本
	OldVersion    string `json:"old_version,omitempty"`    // 换版前在效版本
	Categories    int    `json:"categories,omitempty"`     // applied：加载类目数
	Rules         int    `json:"rules,omitempty"`          // applied：加载规则数
	Reason        string `json:"reason,omitempty"`         // rolled_back：原因枚举（指标 label 同源）
}

// handlePolicyReload 策略/词库热加载（OG-9，§4.7 运行时覆盖 / §4.8 供应链）：
//
//	POST /config/policy/reload（-admin-token 鉴权；无请求体——重读 -output-guard-policy-dir）。
//
// 语义（§3.6.4「热加载失败保留上一有效版本 + 回退审计，不静默」）：
//   - 加载成功 → 原子换版（请求路径零中断）→ 审计 output_guard_policy_reload/applied
//     （policy_version/old_version/sha256）+ 同步 mode/policy_version gauge；
//   - 加载失败 → **保留旧注册表继续服务**，指标 policy_rollback_total{reason} 净增，
//     审计 rolled_back（old_version/sha256），HTTP 409 仅回传原因枚举——
//     **不回传内部错误全文**（§4.11：加载失败只对外给类别+错误码，json 解析片段不落日志面）；
//   - 未配置策略目录 → 400（端点不适用）；GET 等非 POST → 405。
func (s *teeServer) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	actor := r.Header.Get("X-Admin-Actor")
	reqID := r.Header.Get("X-Request-ID")
	oldVersion := s.policyVersion()

	if s.outputGuardPolicyDir == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(policyReloadResponse{
			Status: "not_configured", OldVersion: oldVersion, Reason: "policy_dir_not_configured",
		})
		return
	}

	reg, err := s.loadCurrentPolicySource()
	if err != nil {
		// 回退：旧注册表保持不变（currentPolicy 不动）。
		kind := PolicyLoadErrorKind(err)
		if s.metrics != nil {
			s.metrics.incOGPolicyRollback(kind)
		}
		sha := readPolicyManifestSelfSHA(s.outputGuardPolicyDir)
		log.Printf("[output-guard] 策略热加载失败（保留版本 %s 继续服务）: reason=%s", oldVersion, kind)
		if s.audit != nil {
			s.audit.append(AuditEvent{
				TenantID:        "-",
				UserID:          actor,
				RequestID:       reqID,
				Action:          "output_guard_policy_reload",
				Result:          "rolled_back",
				OGOldVersion:    oldVersion,
				OGPolicySHA256:  sha,
				PayloadSHA:      sha, // 证据锚定（空串即不影响链；不进 hash 的新字段已独立承载）
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(policyReloadResponse{
			Status: "rolled_back", OldVersion: oldVersion, Reason: kind,
		})
		return
	}

	// 成功：原子换版 + gauge 同步 + applied 审计。
	s.setPolicy(reg)
	ogModeMetric := s.currentOutputGuardMode()
	if s.metrics != nil {
		s.metrics.setOutputGuardMode(ogModeMetric, reg.PolicyVersion())
	}
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID:        "-",
			UserID:          actor,
			RequestID:       reqID,
			Action:          "output_guard_policy_reload",
			Result:          "applied",
			OGPolicyVersion: reg.PolicyVersion(),
			OGOldVersion:    oldVersion,
			OGPolicySHA256:  reg.ManifestSHA(),
			PayloadSHA:      reg.ManifestSHA(),
		})
	}
	log.Printf("[output-guard] 策略热加载生效: %s → %s（类目=%d 规则=%d）",
		oldVersion, reg.PolicyVersion(), reg.CategoryCount(), reg.RuleCount())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policyReloadResponse{
		Status: "applied", PolicyVersion: reg.PolicyVersion(), OldVersion: oldVersion,
		Categories: reg.CategoryCount(), Rules: reg.RuleCount(),
	})
}

// handleReconcile 返回最近一次审计-计量对账快照（S5；判据 6）。
// 读权限与 /usage 一致：管理令牌或独立只读计量令牌（控制面看板/计费侧只读消费）。
func (s *teeServer) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkMetering(r) {
		http.Error(w, "计量认证失败", http.StatusUnauthorized)
		return
	}
	if s.reconciler == nil {
		http.Error(w, "对账器未启动", http.StatusServiceUnavailable)
		return
	}
	st := s.reconciler.status()
	if st == nil {
		http.Error(w, "对账尚未执行", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// handleReconcileRun 立即执行一次对账（运维/验收用；有副作用 → 仅管理令牌）。
// 返回 {"ok": 是否一致, "status": 对账快照}。
func (s *teeServer) handleReconcileRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	if s.reconciler == nil {
		http.Error(w, "对账器未启动", http.StatusServiceUnavailable)
		return
	}
	ok := s.reconciler.reconcileOnce(time.Now())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok, "status": s.reconciler.status()})
}

// guardrailConfigRequest Guardrail 运行时变更请求体（M3-B）。
type guardrailConfigRequest struct {
	PIIMode string `json:"pii_mode"` // block | mask
}

// guardrailConfigRecord 运行时 Guardrail 配置持久化记录。
type guardrailConfigRecord struct {
	PIIMode   string `json:"pii_mode"`
	Actor     string `json:"actor"` // 复核通过后的执行人（门户透传，留痕）
	RequestID string `json:"request_id"`
	UpdatedAt int64  `json:"updated_at"`
}

// handleGuardrailConfig Guardrail 运行时降级：POST /config/guardrail（管理令牌，M3-B）。
//
// 语义与边界：
//   - 仅允许 pii_mode 在 block/mask 间切换（数据保护强度档位）；**不提供关闭开关**
//     （SQL 注入/提示注入恒拦截、PII 至少脱敏——安全边界内不放开关）；
//   - 治理链在 gateway-admin-service（高敏变更单 submitter≠reviewer 复核通过后执行）；
//     本端点只做"配置生效 + 持久化 + 落 tee-infer 审计链"；
//   - 持久化文件由 -guardrail-config 指定；未指定则仅进程内生效（重启回退启动参数）；
//   - 审计落链沿用 tee-infer 既有语义（写失败仅告警，数据面可用性优先）；
//     治理级 fail-closed 由门户侧 G1 链承担（见 gateway-admin-service change.go）。
func (s *teeServer) handleGuardrailConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req guardrailConfigRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "请求体须为 JSON", http.StatusBadRequest)
		return
	}
	if req.PIIMode != "block" && req.PIIMode != "mask" {
		http.Error(w, "pii_mode 仅允许 block|mask（不提供 Guardrail 关闭开关）", http.StatusBadRequest)
		return
	}
	actor := r.Header.Get("X-Admin-Actor")
	reqID := r.Header.Get("X-Request-ID")

	// 持久化（可选）：未配置路径则仅进程内生效。
	if s.guardrailCfgPath != "" {
		rec := guardrailConfigRecord{
			PIIMode: req.PIIMode, Actor: actor, RequestID: reqID, UpdatedAt: time.Now().UnixNano(),
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			http.Error(w, "配置序列化失败", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(s.guardrailCfgPath, append(raw, '\n'), 0o600); err != nil {
			http.Error(w, "配置持久化失败", http.StatusInternalServerError)
			return
		}
	}
	s.piiModeOverride.Store(req.PIIMode)
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID:        "-",
			UserID:          actor,
			RequestID:       reqID,
			Action:          "guardrail_config",
			Result:          "ok",
			PayloadSHA:      fmt.Sprintf("%x", sha256.Sum256([]byte("pii_mode="+req.PIIMode))),
			TransformedHash: "pii_mode=" + req.PIIMode,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"pii_mode": req.PIIMode, "status": "applied"})
}

// handleOutputGuardConfig 输出侧审查 mode 运行时切换（OG-8，§4.7 运行时覆盖 / D8 高敏变更）。
//
// 语义与边界（与 handleGuardrailConfig 对称设计）：
//   - 运行时**不允许升为 enforcing**（D4'：仅启动参数可开，待治理闸门就绪后放开）；
//     允许从 enforcing 降级到 shadow/off（OG-20 回滚演练必需，符合 fail-safe 原则）；
//   - 治理链在 gateway-admin-service（高敏变更 submitter≠reviewer 复核通过后执行）；
//     本端点只做"配置生效 + 持久化 + 落 tee-infer 审计链"；
//   - 持久化文件由 -output-guard-config 指定；未指定则仅进程内生效（重启回退启动参数）；
//   - 审计落链沿用 tee-infer 既有语义（写失败仅告警，数据面可用性优先）；
//     治理级 fail-closed 由门户侧 G1 链承担（见 gateway-admin-service change.go）；
//   - 切换同步更新 mode gauge（与 policy_version gauge 配对，指标门禁 #9 required 常驻）。
func (s *teeServer) handleOutputGuardConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req outputGuardConfigRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "请求体须为 JSON", http.StatusBadRequest)
		return
	}
	// 安全闸门（D4'）：
	//   1. 取值必须合法（off | shadow | enforcing），非法值直接拒绝；
	//   2. 运行时不允许升为 enforcing（拦截路径仅启动参数可开，待治理闸门就绪后放开）；
	//   3. 允许从 enforcing 降级到 shadow/off（OG-20 回滚演练必备，fail-safe 原则）。
	if req.Mode != outputGuardOff && req.Mode != outputGuardShadow && req.Mode != outputGuardEnforcing {
		http.Error(w, "mode 非法（仅支持 off|shadow|enforcing）", http.StatusBadRequest)
		return
	}
	oldMode := s.currentOutputGuardMode()
	if req.Mode == outputGuardEnforcing && oldMode != outputGuardEnforcing {
		http.Error(w, "mode 不允许运行时升为 enforcing（拦截仅能经启动参数开启；运行时可从 enforcing 降级到 shadow/off）", http.StatusBadRequest)
		return
	}
	// S1-5：公众形态下审核总开关不可关闭（不得切到 off）。
	if s.publicFacing && req.Mode == outputGuardOff {
		if s.audit != nil {
			s.audit.append(AuditEvent{
				TenantID:  "-",
				UserID:    r.Header.Get("X-Admin-Actor"),
				RequestID: r.Header.Get("X-Request-ID"),
				Action:    "output_guard_mode_change",
				Result:    "rejected_public_facing_lock",
				OGMode:    req.Mode,
			})
		}
		http.Error(w, "公众形态下审核总开关不可关闭（public_facing=true，禁止 mode=off）", http.StatusBadRequest)
		return
	}
	actor := r.Header.Get("X-Admin-Actor")
	reqID := r.Header.Get("X-Request-ID")

	// 持久化（可选）：未配置路径则仅进程内生效。
	// S1-4（G21）：改用**读改写合并**——同一文件还承载策略版本引用，整体覆盖会抹掉后者。
	if s.outputGuardCfgPath != "" {
		if err := writeOutputGuardConfigRecord(s.outputGuardCfgPath, outputGuardConfigRecord{
			Mode: req.Mode, Actor: actor, RequestID: reqID,
		}, false, false); err != nil {
			http.Error(w, "配置持久化失败", http.StatusInternalServerError)
			return
		}
	}
	s.outputGuardModeOverride.Store(req.Mode)
	// 同步 mode gauge（指标门禁 #9：mode/policy_version 常驻）。
	if s.metrics != nil {
		s.metrics.setOutputGuardMode(req.Mode, s.policyVersion())
	}
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID:  "-",
			UserID:    actor,
			RequestID: reqID,
			Action:    "output_guard_mode_change",
			Result:    "applied",
			OGMode:    req.Mode,
			// 证据锚定：mode 变更摘要＋**派生的处理深度档位**（omitempty 字段不进 hash，不影响链完整性）。
			// 档位入证据使"变更单记录对客户备案路径影响判定"可核验（D-LLM-9；本体 §6.7 配置档位）。
			TransformedHash: "output_guard_mode=" + req.Mode + " depth=" + deriveOutputDepth(req.Mode, s.outputGuardMaskEnabled),
		})
	}
	log.Printf("[output-guard] 运行时模式变更: %s → %s (source=runtime, depth=%s)", oldMode, req.Mode, deriveOutputDepth(req.Mode, s.outputGuardMaskEnabled))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"mode":   req.Mode,
		"status": "applied",
		"old_mode": oldMode,
	})
}

// outputGuardStrategyRequest POST /config/output-guard/strategy 请求体（S3-2）。
type outputGuardStrategyRequest struct {
	Strategy string `json:"strategy"`
}

// handleOutputGuardStrategy 策略档位运行时切换（S3-2 P-STRATEGY，D8 高敏变更）：
//
//	POST /config/output-guard/strategy（管理令牌）：{"strategy":"A|B|C"}。
//
// 语义与边界（与 handleOutputGuardConfig 对称）：
//   - 合法取值 A/B/C；切换在请求级管线构造时生效（P-UNIT 由策略派生），不重启、对新请求真实生效；
//   - 诚实门控：策略 C 的启用前置（缓冲层首段预审门已实现 ＋ P-FIRST-CHUNK 已配置 ＋ 法务双通过）
//     未齐备即 400 拒绝（reason=strategy_c_unavailable），**不静默回落、不假装支持**（2026-09-27 用户裁决②）；
//   - 持久化读改写合并（不抹 mode/版本引用）；审计 output_guard_strategy_change（证据走 TransformedHash）。
func (s *teeServer) handleOutputGuardStrategy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req outputGuardStrategyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "请求体须为 JSON", http.StatusBadRequest)
		return
	}
	if err := validateOutputStrategy(req.Strategy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	oldStrategy := s.currentOutputGuardStrategy()
	if !strategyRunnable(req.Strategy) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "rejected", "reason": "strategy_c_unavailable", "old_strategy": oldStrategy,
		})
		return
	}
	actor := r.Header.Get("X-Admin-Actor")
	reqID := r.Header.Get("X-Request-ID")
	if s.outputGuardCfgPath != "" {
		if err := writeOutputGuardConfigRecord(s.outputGuardCfgPath, outputGuardConfigRecord{
			Strategy: req.Strategy, Actor: actor, RequestID: reqID,
		}, false, false); err != nil {
			http.Error(w, "配置持久化失败", http.StatusInternalServerError)
			return
		}
	}
	s.outputGuardStrategyOverride.Store(req.Strategy)
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID: "-", UserID: actor, RequestID: reqID,
			Action: "output_guard_strategy_change", Result: "applied",
			TransformedHash: "output_guard_strategy=" + req.Strategy + " unit=" + unitForStrategy(req.Strategy),
		})
	}
	log.Printf("[output-guard] 运行时策略变更: %s → %s（unit=%s）", oldStrategy, req.Strategy, unitForStrategy(req.Strategy))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"strategy": req.Strategy, "old_strategy": oldStrategy,
		"unit": unitForStrategy(req.Strategy), "status": "applied",
	})
}

// outputGuardCategoriesRequest POST /config/output-guard/categories 请求体（S3-2 类目启停）。
type outputGuardCategoriesRequest struct {
	Disable []string `json:"disable,omitempty"`
	Enable  []string `json:"enable,omitempty"`
}

// handleOutputGuardCategories 类目启停运行时切换（S3-2，D8 高敏变更）：
//
//	POST /config/output-guard/categories（管理令牌）：{"disable":["A2-09"],"enable":["A5-01"]}。
//
// 语义与边界：
//   - 两列表均可选；以当前停用集合为基底：先移除 enable、再加入 disable（同批 enable+disable 以 disable 终态）；
//   - 校验 fail-closed：类目须在 31 类清单内；默认动作 block/mask 的拦截/脱敏底线类目（A1-01..06、A4-06）
//     不允许停用（最高安全边界不放开关）；
//   - 停用集合在请求级经 categoryGate 包装 l1/l2 生效（分类抑制即 block/flag/mask 抑制）；
//   - 持久化整体接管停用集合（含清空为全启用）；审计 output_guard_category_toggle。
func (s *teeServer) handleOutputGuardCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req outputGuardCategoriesRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "请求体须为 JSON", http.StatusBadRequest)
		return
	}
	current := s.currentDisabledCategories()
	next := make(map[string]bool, len(current)+len(req.Disable))
	for cat := range current {
		next[cat] = true
	}
	for _, cat := range req.Enable {
		if !isValidCategory(cat) {
			http.Error(w, fmt.Sprintf("enable 类目 %q 不存在（须为 31 类内部 ID）", cat), http.StatusBadRequest)
			return
		}
		delete(next, cat)
	}
	for _, cat := range req.Disable {
		if !isValidCategory(cat) {
			http.Error(w, fmt.Sprintf("disable 类目 %q 不存在（须为 31 类内部 ID）", cat), http.StatusBadRequest)
			return
		}
		if !categoryDisableAllowed(cat) {
			http.Error(w, fmt.Sprintf("类目 %s 不允许停用（拦截/脱敏安全底线，最高边界不放开关）", cat), http.StatusBadRequest)
			return
		}
		next[cat] = true
	}
	list := disabledCategoryList(next)
	actor := r.Header.Get("X-Admin-Actor")
	reqID := r.Header.Get("X-Request-ID")
	if s.outputGuardCfgPath != "" {
		if err := writeOutputGuardConfigRecord(s.outputGuardCfgPath, outputGuardConfigRecord{
			DisabledCategories: list, Actor: actor, RequestID: reqID,
		}, false, true); err != nil {
			http.Error(w, "配置持久化失败", http.StatusInternalServerError)
			return
		}
	}
	s.outputGuardDisabled.Store(next)
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID: "-", UserID: actor, RequestID: reqID,
			Action: "output_guard_category_toggle", Result: "applied",
			TransformedHash: "disabled_categories=" + strings.Join(list, ","),
		})
	}
	log.Printf("[output-guard] 类目启停生效：当前停用 %d 类（%s）", len(list), strings.Join(list, ","))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"disabled_categories": list, "status": "applied",
	})
}

// loadOutputGuardOverride 启动时恢复运行时输出侧审查配置（OG-8）。
//
// 语义（与 loadGuardrailOverride 同构）：
//   - 文件存在且合法 → 覆盖启动参数（复核结果须跨重启保持，否则 mode 切换会被重启
//     "悄悄回滚"）；
//   - 文件缺失/解析失败/取值非法 → 沿用启动参数（不阻断启动，
//     由 /config 的 mode_source=startup 如实体现）。
func (s *teeServer) loadOutputGuardOverride() {
	if s.outputGuardCfgPath == "" {
		return
	}
	raw, err := os.ReadFile(s.outputGuardCfgPath)
	if err != nil {
		return
	}
	var rec outputGuardConfigRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &rec); err != nil {
		log.Printf("[output-guard] 运行时配置解析失败（沿用启动参数）：%v", err)
		return
	}
	// S1-4（G21）：先恢复策略版本引用运行态——它与 mode 校验互不影响，且必须在启动加载策略之前就位
	//（启动参数 -output-guard-policy-version 为空时以后者为准）。
	if rec.PolicyVersion != "" || rec.PreviousVersion != "" || rec.PreviousIsRoot {
		s.setPolicyRef(policyRefState{
			Version:  rec.PolicyVersion,
			Prev:     rec.PreviousVersion,
			PrevRoot: rec.PreviousIsRoot,
			HasPrev:  rec.PreviousVersion != "" || rec.PreviousIsRoot,
		})
		log.Printf("[output-guard] 策略版本引用已恢复：version=%q previous=%q previous_is_root=%v",
			rec.PolicyVersion, rec.PreviousVersion, rec.PreviousIsRoot)
	}
	// 持久化恢复：
	//   - mode 为空（仅策略/类目写入的记录）＝未设置，不覆盖 mode 运行态；
	//   - enforcing 忽略——enforcing 只能由启动参数开启，运行时通道（含跨重启恢复）不开放（D4'）；
	//   - 仅 off/shadow 合法，其余值记非法（fail-safe）。
	switch rec.Mode {
	case "":
		// 不覆盖
	case outputGuardOff, outputGuardShadow:
		s.outputGuardModeOverride.Store(rec.Mode)
		log.Printf("[output-guard] 运行时配置已恢复：mode=%s actor=%s", rec.Mode, rec.Actor)
	default:
		log.Printf("[output-guard] 运行时配置 mode=%q 非法（沿用启动参数）", rec.Mode)
	}
	// S3-2：恢复策略档位；非法值或策略 C 前置未齐备 ⇒ 忽略（fail-safe，沿用启动参数/缺省 A）。
	if rec.Strategy != "" {
		if err := validateOutputStrategy(rec.Strategy); err != nil {
			log.Printf("[output-guard] 运行时策略 %q 非法（沿用缺省）", rec.Strategy)
		} else if strategyRunnable(rec.Strategy) {
			s.outputGuardStrategyOverride.Store(rec.Strategy)
			log.Printf("[output-guard] 运行时策略已恢复：strategy=%s actor=%s", rec.Strategy, rec.Actor)
		} else {
			log.Printf("[output-guard] 运行时策略 %s 前置未齐备（不恢复，沿用缺省）", rec.Strategy)
		}
	}
	// S3-2：恢复停用集合；逐条过滤——不存在或已不允许停用的类目剔除
	//（防类目模型演进后旧持久化文件带入非法停用）。
	if len(rec.DisabledCategories) > 0 {
		next := make(map[string]bool, len(rec.DisabledCategories))
		for _, cat := range rec.DisabledCategories {
			if isValidCategory(cat) && categoryDisableAllowed(cat) {
				next[cat] = true
			} else {
				log.Printf("[output-guard] 停用类目 %s 不存在或不允许停用（恢复时剔除）", cat)
			}
		}
		s.outputGuardDisabled.Store(next)
		log.Printf("[output-guard] 停用类目集合已恢复：%d 类", len(next))
	}
}

// handleContentLabelConfig 强标标识运行时切换：POST /config/content-label（B1，管理令牌）。
//
// 语义与边界（与 handleOutputGuardConfig 对称，差异在闸门）：
//   - 标识非拦截语义 → **on/off 双向均可热切换**（无 enforcing 式单向闸门）；
//   - 请求体字段全可选：提供的覆盖当前生效值，未提供的保持现状；
//   - 校验 fail-closed：生效配置文案必须同时含"人工智能"与"生成"（GB 45438-2025），
//     非法即 400——不合规文案不得静默生效；
//   - 持久化文件由 -content-label-config 指定；未指定则仅进程内生效（重启回退启动参数）；
//   - 审计 content_label_change（证据走 TransformedHash 摘要，omitempty 不进 hash）；
//   - 切换同步更新 enabled gauge（指标门禁 #9 required 常驻）。
func (s *teeServer) handleContentLabelConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req contentLabelConfigRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "请求体须为 JSON", http.StatusBadRequest)
		return
	}
	// 部分覆盖：以当前生效值为基底，仅替换请求中显式提供的字段。
	next := s.currentContentLabelConfig()
	if req.Enabled != nil {
		next.Enabled = *req.Enabled
	}
	if req.Text != nil {
		next.Text = *req.Text
	}
	if req.Repeat != nil {
		next.Repeat = *req.Repeat
	}
	next = resolveContentLabelConfig(next)
	if err := validateContentLabelConfig(next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	oldEnabled := s.currentContentLabelConfig().Enabled
	actor := r.Header.Get("X-Admin-Actor")
	reqID := r.Header.Get("X-Request-ID")

	// 持久化（可选）：未配置路径则仅进程内生效。
	if s.contentLabelCfgPath != "" {
		rec := contentLabelConfigRecord{
			Enabled: next.Enabled, Text: next.Text, Repeat: next.Repeat, Std: next.Std,
			Actor: actor, RequestID: reqID, UpdatedAt: time.Now().UnixNano(),
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			http.Error(w, "配置序列化失败", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(s.contentLabelCfgPath, append(raw, '\n'), 0o600); err != nil {
			http.Error(w, "配置持久化失败", http.StatusInternalServerError)
			return
		}
	}
	s.contentLabelOverride.Store(next)
	if s.metrics != nil {
		s.metrics.setContentLabelEnabled(next.Enabled)
	}
	if s.audit != nil {
		s.audit.append(AuditEvent{
			TenantID:  "-",
			UserID:    actor,
			RequestID: reqID,
			Action:    "content_label_change",
			Result:    "applied",
			// 证据锚定：变更摘要（omitempty 字段不进 hash，与 output_guard_mode_change 同构）
			TransformedHash: fmt.Sprintf("content_label=%t,text=%q,repeat=%d", next.Enabled, next.Text, next.Repeat),
		})
	}
	log.Printf("[content-label] 运行时配置变更: enabled=%t → %t (source=runtime)", oldEnabled, next.Enabled)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":    next.Enabled,
		"status":     "applied",
		"old_enabled": oldEnabled,
		"text":       next.Text,
		"repeat":     next.Repeat,
		"std":        next.Std,
	})
}

// loadContentLabelOverride 启动时恢复运行时强标标识配置（B1）。
//
// 语义（与 loadOutputGuardOverride 同构，差异在闸门）：
//   - 文件存在且合法 → 覆盖启动参数（热切换结果须跨重启保持）；
//   - 文件缺失/解析失败/取值非法 → 沿用启动参数（不阻断启动，由 /config 的 source=startup 如实体现）；
//   - on/off 双向均可恢复——标识非拦截语义，无 enforcing 式单向闸门。
func (s *teeServer) loadContentLabelOverride() {
	if s.contentLabelCfgPath == "" {
		return
	}
	raw, err := os.ReadFile(s.contentLabelCfgPath)
	if err != nil {
		return
	}
	var rec contentLabelConfigRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &rec); err != nil {
		log.Printf("[content-label] 运行时配置解析失败（沿用启动参数）：%v", err)
		return
	}
	cfg := resolveContentLabelConfig(contentLabelConfig{
		Enabled: rec.Enabled, Text: rec.Text, Repeat: rec.Repeat, Std: rec.Std,
	})
	if err := validateContentLabelConfig(cfg); err != nil {
		log.Printf("[content-label] 运行时配置非法（沿用启动参数）：%v", err)
		return
	}
	s.contentLabelOverride.Store(cfg)
	log.Printf("[content-label] 运行时配置已恢复：enabled=%t actor=%s", cfg.Enabled, rec.Actor)
}

// loadGuardrailOverride 启动时恢复运行时 Guardrail 配置（M3-B）。
//
// 语义：文件存在且合法 → 覆盖启动参数（复核结果须跨重启保持，否则降级会被重启
// "悄悄回滚"）；文件缺失/解析失败/取值非法 → 沿用启动参数（不阻断启动，
// 由 /config 的 pii_mode_source=startup 如实体现）。
func (s *teeServer) loadGuardrailOverride() {
	if s.guardrailCfgPath == "" {
		return
	}
	raw, err := os.ReadFile(s.guardrailCfgPath)
	if err != nil {
		return
	}
	var rec guardrailConfigRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &rec); err != nil {
		log.Printf("[tee] Guardrail 运行时配置解析失败（沿用启动参数）：%v", err)
		return
	}
	if rec.PIIMode != "block" && rec.PIIMode != "mask" {
		log.Printf("[tee] Guardrail 运行时配置 pii_mode=%q 非法（沿用启动参数）", rec.PIIMode)
		return
	}
	s.piiModeOverride.Store(rec.PIIMode)
	log.Printf("[tee] Guardrail 运行时配置已恢复：pii_mode=%s actor=%s", rec.PIIMode, rec.Actor)
}

func (s *teeServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.render(w, s.audit.len())
	// P0-2：缓存指标仅在 mode!=off 时追加，保证默认关闭时 /metrics 输出逐字节不变。
	if s.cacheEngine != nil && s.cacheEngine.Stats().Mode != string(cacheengine.ModeOff) {
		s.cacheEngine.RenderPrometheus(w)
	}
}

// usageView 用量查询响应视图（含配额信息，P1；S3b 起含窗口配额；S5 起含影子配置与计数；
// B 项起含多维 enforce 全量快照）。
type usageView struct {
	*usageRecord
	Quota           int64            `json:"quota"`                       // 主维度配额上限（<=0 = 不限）
	UsedTokens      int64            `json:"used_tokens"`                 // 累计消耗 token（输入+输出）
	QuotaWindow     string           `json:"quota_window,omitempty"`      // S3b：minute | day（缺省 = 累计）
	QuotaWindowUsed int64            `json:"quota_window_used,omitempty"` // S3b：主维度当前窗口内已用 token
	QuotaLimits     []quotaLimitView `json:"quota_limits,omitempty"`      // B 项：多维 enforce 快照
	Shadow          *shadowView      `json:"shadow,omitempty"`            // S5：影子配置与窗口内计数（判据 4）
}

// quotaLimitView 单维度 enforce 视图（B 项：window="" 为累计维度）。
type quotaLimitView struct {
	Window     string `json:"window,omitempty"`
	MaxTokens  int64  `json:"max_tokens"`
	WindowUsed int64  `json:"window_used"`
}

// shadowView 影子视图（判据 4）：阈值 + 当前窗口内已计数。
type shadowView struct {
	RPM               int64 `json:"rpm,omitempty"`
	TPM               int64 `json:"tpm,omitempty"`
	DailyBudgetTokens int64 `json:"daily_budget_tokens,omitempty"`
	RPMUsed           int64 `json:"rpm_used"`
	TPMUsed           int64 `json:"tpm_used"`
	DailyBudgetUsed   int64 `json:"daily_budget_used"`
}

// handleUsage 用量查询：GET /usage（全部租户）或 ?tenant=X（单租户）。
// P1 起响应含配额视图（quota / used_tokens）。
// GA-计费 P0-4：?from=&to= 增量查询——按审计事件时间戳聚合 [from, to)
// （左闭右开，UTC；RFC 3339 或 Unix 秒），免疫进程重启丢失、自带模型维度。
// GA-计费 P1-2：接受管理令牌或独立只读计量令牌（meter-token）。
func (s *teeServer) handleUsage(w http.ResponseWriter, r *http.Request) {
	if !s.checkMetering(r) {
		http.Error(w, "计量查询认证失败", http.StatusUnauthorized)
		return
	}
	if q := r.URL.Query(); q.Get("from") != "" || q.Get("to") != "" {
		s.handleUsageIncremental(w, q)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	view := func(tenant string, rec *usageRecord) *usageView {
		uv := &usageView{usageRecord: rec, Quota: s.quotaDefault}
		if q, ok := s.quota[tenant]; ok {
			// 兼容字段取主维度（累计优先，否则首维度）；多维全量见 quota_limits。
			uv.Quota, uv.QuotaWindow = 0, quotaWindowNone
			if l, has := primaryLimit(q.Limits); has {
				uv.Quota, uv.QuotaWindow = l.MaxTokens, l.Window
			}
			for _, l := range q.Limits {
				// 展示前先做一次窗口翻转（与 reserveQuota 同规则，避免显示上个窗口的旧计数）
				used := s.dimensionUsed(tenant, l.Window)
				uv.QuotaLimits = append(uv.QuotaLimits, quotaLimitView{
					Window: l.Window, MaxTokens: l.MaxTokens, WindowUsed: used,
				})
				if l.Window == uv.QuotaWindow {
					uv.QuotaWindowUsed = used
				}
			}
			// S5（判据 4）：影子配置与当前窗口内计数（同一锁内直接读，避免重入）
			if q.Shadow.configured() {
				uv.Shadow = &shadowView{RPM: q.Shadow.RPM, TPM: q.Shadow.TPM, DailyBudgetTokens: q.Shadow.DailyBudgetTokens}
				rotate := func(dim, window string) int64 {
					uk := tenant + "|" + dim
					key := quotaWindowKeyFor(window, time.Now())
					if s.shadowWindowKey[uk] != key {
						s.shadowWindowKey[uk] = key
						s.shadowWindowUsage[uk] = 0
					}
					return s.shadowWindowUsage[uk]
				}
				uv.Shadow.RPMUsed = rotate("rpm", quotaWindowMinute)
				uv.Shadow.TPMUsed = rotate("tpm", quotaWindowMinute)
				uv.Shadow.DailyBudgetUsed = rotate("daily_budget", quotaWindowDay)
			}
		}
		if rec != nil {
			uv.UsedTokens = int64(rec.TokensIn) + int64(rec.TokensOut)
		}
		return uv
	}
	if t := r.URL.Query().Get("tenant"); t != "" {
		rec := s.usage[t]
		if rec == nil {
			rec = &usageRecord{}
		}
		_ = json.NewEncoder(w).Encode(map[string]*usageView{t: view(t, rec)})
		return
	}
	out := map[string]*usageView{}
	for t, rec := range s.usage {
		out[t] = view(t, rec)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// handleUsageIncremental GA-计费 P0-4：from/to 增量聚合（按审计事件）。
// 时间语义：左闭右开 [from, to)；from 缺省 = 最早事件；to 缺省 = 当前；
// 出账权威口径（累计值跨重启丢基线，事件聚合免疫）。
func (s *teeServer) handleUsageIncremental(w http.ResponseWriter, q url.Values) {
	now := time.Now().UnixNano()
	from, ok := parseBillingTime(q.Get("from"), 0)
	if !ok {
		http.Error(w, "from 须为 RFC 3339（推荐 UTC）或 Unix 秒", http.StatusBadRequest)
		return
	}
	to, ok := parseBillingTime(q.Get("to"), now)
	if !ok {
		http.Error(w, "to 须为 RFC 3339（推荐 UTC）或 Unix 秒", http.StatusBadRequest)
		return
	}
	if from >= to {
		http.Error(w, "from 须早于 to（区间左闭右开）", http.StatusBadRequest)
		return
	}
	tenants := aggregateUsage(s.audit.query(q.Get("tenant")), from, to)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"from":             time.Unix(0, from).UTC().Format(time.RFC3339Nano),
		"to":               time.Unix(0, to).UTC().Format(time.RFC3339Nano),
		"window_semantics": "[from, to) UTC，按审计事件时间戳聚合（免疫重启丢失；deny 不计费）",
		"tenants":          tenants,
	})
}

// quotaRequest 配额设置请求。
//
// 两种写法**互斥**（同时出现即 400，避免"两套口径谁生效"歧义）：
//   - 扁平（S3b 兼容）：{"max_tokens":50000000,"window":"day"}（单维度）
//   - 多维（B 项）：{"limits":[{"window":"minute","max_tokens":200000},{"window":"day","max_tokens":50000000}]}（任一维度超限即拒绝）
//
// limits 为**空数组** ＝ 清除 enforce（保留 shadow）；limits 中 max_tokens<=0 的维度视为未配置。
type quotaRequest struct {
	Tenant    string `json:"tenant"`
	MaxTokens int64  `json:"max_tokens"`       // <=0 = 不限
	Window    string `json:"window,omitempty"` // S3b："" = 累计（默认，行为不变）| minute | day（UTC+8 自然日）
	// B 项：多维 enforce；nil = 未提供（走扁平字段），非 nil（含空数组）= 以 limits 为准。
	Limits []quotaLimit `json:"limits"`
	// S5（判据 4）：影子配置（只计数不拒绝；命中落审计 would_reject）。
	// 传 null/缺省 = 清除该租户的影子（与 max_tokens<=0 清除 enforce 配额同语义）。
	Shadow *shadowSpec `json:"shadow,omitempty"`
}

// quotaLimitsView 某租户**显式配置**的多维快照（不含全局默认；持有 s.mu 时必须调用）。
// 无显式配置返回空切片（序列化为 []，便于消费方直接遍历）。
func (s *teeServer) quotaLimitsView(tenant string) []quotaLimitView {
	spec, ok := s.quota[tenant]
	out := make([]quotaLimitView, 0)
	if !ok {
		return out
	}
	for _, l := range spec.Limits {
		out = append(out, quotaLimitView{
			Window: l.Window, MaxTokens: l.MaxTokens, WindowUsed: s.dimensionUsed(tenant, l.Window),
		})
	}
	return out
}

// handleQuotaReadback 配额回读：GET /usage/quota?tenant=X（★ P-1/M6，只读）。
//
// 返回该租户**当前已生效**的限额（window → max_tokens），供账务侧回读确认：
// POST /usage/quota 返回 2xx **不等于**已生效，M6 判据以本回读为唯一构造点（加计费方案 §6.4.1 2c）。
// 鉴权：计量查询凭证（管理令牌或只读计量令牌；checkMetering 内含 checkAdmin）。
func (s *teeServer) handleQuotaReadback(w http.ResponseWriter, r *http.Request) {
	if !s.checkMetering(r) {
		http.Error(w, "计量查询认证失败", http.StatusUnauthorized)
		return
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		http.Error(w, "bad request（须含 tenant）", http.StatusBadRequest)
		return
	}
	type quotaLimitView struct {
		Window    string `json:"window"`
		MaxTokens int64  `json:"max_tokens"`
	}
	resp := struct {
		Tenant string           `json:"tenant"`
		Limits []quotaLimitView `json:"limits"`
	}{Tenant: tenant, Limits: []quotaLimitView{}}
	s.mu.Lock()
	if q, ok := s.quota[tenant]; ok {
		for _, l := range q.Limits {
			resp.Limits = append(resp.Limits, quotaLimitView{Window: l.Window, MaxTokens: l.MaxTokens})
		}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleQuota 配额设置：POST /usage/quota。
//   - 扁平（S3b）：{"tenant":"acme","max_tokens":1000000,"window":"day"}；max_tokens<=0 解除限制，
//     window 缺省 = 累计上限（P1 既有语义，行为不变）；
//   - 多维（B 项）：{"tenant":"acme","limits":[{"window":"minute","max_tokens":200000},
//     {"window":"day","max_tokens":50000000}]}——任一维度超限即 429，拒绝按维度归因（指标）。
//
// S5：可同时下发 shadow（{rpm,tpm,daily_budget_tokens}，只计数不拒绝）。
// 返回生效主维度（quota/window/window_used，兼容旧消费方）、多维全量（quota_limits）与影子计数。
func (s *teeServer) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handleQuotaReadback(w, r) // ★ P-1/M6：回读确认（只读）
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req quotaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tenant == "" {
		http.Error(w, "bad json（须含 tenant）", http.StatusBadRequest)
		return
	}
	if !validQuotaWindow(req.Window) {
		http.Error(w, "bad window（须为 minute|day 或省略）", http.StatusBadRequest)
		return
	}
	if req.Limits != nil && (req.MaxTokens != 0 || req.Window != "") {
		http.Error(w, "bad request（limits 与 max_tokens/window 互斥，勿同时下发）", http.StatusBadRequest)
		return
	}
	seenWindow := make(map[string]bool, len(req.Limits))
	for _, l := range req.Limits {
		if !validQuotaWindow(l.Window) {
			http.Error(w, "bad limits（window 须为 minute|day 或省略）", http.StatusBadRequest)
			return
		}
		if seenWindow[l.Window] {
			http.Error(w, fmt.Sprintf("bad limits（window=%q 重复）", l.Window), http.StatusBadRequest)
			return
		}
		seenWindow[l.Window] = true
	}
	if req.Shadow != nil && (req.Shadow.RPM < 0 || req.Shadow.TPM < 0 || req.Shadow.DailyBudgetTokens < 0) {
		http.Error(w, "bad shadow（rpm/tpm/daily_budget_tokens 须为非负）", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	// 语义：每次下发为该租户的**完整状态**（缺省 shadow 视为清除；enforce 以 limits 为准，空 = 清除）。
	spec := quotaSpec{}
	if req.Limits != nil {
		spec.Limits = normalizeLimits(req.Limits)
	} else if req.MaxTokens > 0 {
		spec.Limits = normalizeLimits([]quotaLimit{{Window: req.Window, MaxTokens: req.MaxTokens}})
	}
	if req.Shadow != nil {
		spec.Shadow = *req.Shadow
	}
	if len(spec.Limits) == 0 && !spec.Shadow.configured() {
		delete(s.quota, req.Tenant) // 既无 enforce 也无影子 → 移除条目
	} else {
		s.quota[req.Tenant] = spec
	}
	// 兼容字段取主维度；未配置条目时回落全局默认（与 P1 行为一致）。
	effective, window := int64(0), quotaWindowNone
	if l, ok := primaryLimit(s.quotaLimitsOf(req.Tenant)); ok {
		effective, window = l.MaxTokens, l.Window
	}
	limitsView := s.quotaLimitsView(req.Tenant)
	shadow := spec.Shadow
	s.mu.Unlock()
	used := s.quotaWindowUsed(req.Tenant)
	rpmUsed, tpmUsed, dailyUsed := s.shadowUsage(req.Tenant)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tenant":       req.Tenant,
		"quota":        effective,
		"window":       window,
		"window_used":  used,
		"quota_limits": limitsView,
		"shadow": map[string]any{
			"rpm": shadow.RPM, "tpm": shadow.TPM, "daily_budget_tokens": shadow.DailyBudgetTokens,
			"rpm_used": rpmUsed, "tpm_used": tpmUsed, "daily_budget_used": dailyUsed,
		},
	})
	log.Printf("[tee] 配额设置 tenant=%s limits=%v shadow(rpm=%d tpm=%d daily=%d)",
		req.Tenant, limitsView, shadow.RPM, shadow.TPM, shadow.DailyBudgetTokens)
}

// handleAudit 审计查询：GET /audit（全部）或 ?tenant=X（按租户过滤）。
func (s *teeServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.audit.query(r.URL.Query().Get("tenant")))
}

// ---------- A 项（判据 4 扩展）：数据面明文路由影子的**窗口级汇总**上报 ----------

// 汇总上报的幂等保留窗口与容量上限（方案《GA-门禁7-剩余能力边界-实现方案.md》§A.3：默认 10 分钟 / 10k 条）。
const (
	shadowReportTTL = 10 * time.Minute
	shadowReportMax = 10000
)

// shadowReport 一条窗口级影子汇总（= 某 (scope,target,规则) 在某窗口内的聚合）。
//
// 口径与 tee-infer 自身影子一致（判据 4：**只计数不拒绝**）；数据面插件按窗口聚合后上报，
// 而非逐请求（设计 §A.3：审计量 = O(窗口数 × 规则数)，可预期）。
type shadowReport struct {
	ReportID    string   `json:"report_id"`                    // 幂等键（插件生成；重试不重复落链）
	RuleID      string   `json:"rule_id"`                      // 控制面规则 ID
	Scope       string   `json:"scope"`                        // tenant | api_key
	Target      string   `json:"target"`                       // scope=tenant → 租户；scope=api_key → key-auth 消费者名（X-Mse-Consumer）
	Tenant      string   `json:"tenant,omitempty"`             // 请求侧租户（api_key 维度用于审计归属；可空）
	Window      string   `json:"window"`                       // 当前仅 minute
	WindowStart int64    `json:"window_start"`                 // 窗口起点（Unix 秒）
	Threshold   int64    `json:"threshold"`                    // 规则阈值（rpm）
	Observed    int64    `json:"observed"`                     // 窗口内观察到的请求数
	WouldReject int64    `json:"would_reject"`                 // 其中"若转 enforce 会被拦"的请求数
	SampleIDs   []string `json:"sample_request_ids,omitempty"` // 可选，最多 5 条（逐笔核对）
	Source      string   `json:"source,omitempty"`             // 上报方标识（如 data-plane）
}

// shadowReportRequest 上报请求体（批量）。
type shadowReportRequest struct {
	Reports []shadowReport `json:"reports"`
}

// validate 校验单条上报（**非法即整批 400**，不做部分接受——避免"半批已落链"的不可解释状态）。
func (r *shadowReport) validate() error {
	if strings.TrimSpace(r.ReportID) == "" {
		return fmt.Errorf("report_id 必填")
	}
	switch r.Scope {
	case "tenant", "api_key":
	default:
		return fmt.Errorf("scope 非法（须为 tenant|api_key），实际 %q", r.Scope)
	}
	if strings.TrimSpace(r.RuleID) == "" {
		return fmt.Errorf("rule_id 必填")
	}
	if strings.TrimSpace(r.Target) == "" {
		if r.Scope == "tenant" {
			return fmt.Errorf("scope=tenant 时 target（租户）必填")
		}
		return fmt.Errorf("scope=api_key 时 target（消费者名，X-Mse-Consumer）必填")
	}
	if r.Window != quotaWindowMinute {
		return fmt.Errorf("window 非法（当前仅支持 minute），实际 %q", r.Window)
	}
	if r.WindowStart <= 0 {
		return fmt.Errorf("window_start 须为正整数（Unix 秒）")
	}
	if r.Threshold <= 0 {
		return fmt.Errorf("threshold 须为正整数")
	}
	if r.Observed < 0 || r.WouldReject < 0 {
		return fmt.Errorf("observed/would_reject 不得为负")
	}
	if r.WouldReject > r.Observed {
		return fmt.Errorf("would_reject(%d) 不得大于 observed(%d)", r.WouldReject, r.Observed)
	}
	if len(r.SampleIDs) > 5 {
		return fmt.Errorf("sample_request_ids 最多 5 条，实际 %d", len(r.SampleIDs))
	}
	return nil
}

// shadowReportState 窗口级上报的幂等状态（短时集合：TTL + 容量上限，超限按最早淘汰）。
type shadowReportState struct {
	seen map[string]shadowReportSeen
	ttl  time.Duration
	max  int
	seq  uint64 // 单调插入序号：同刻上报（同一请求共用 time.Now()）按 FIFO 确定性淘汰
}

// shadowReportSeen 幂等集合条目：进入时间与全局插入序号。
type shadowReportSeen struct {
	t   time.Time
	seq uint64
}

// newShadowReportState 构造幂等状态（ttl<=0 / max<=0 时用缺省）。
func newShadowReportState(ttl time.Duration, max int) *shadowReportState {
	if ttl <= 0 {
		ttl = shadowReportTTL
	}
	if max <= 0 {
		max = shadowReportMax
	}
	return &shadowReportState{seen: make(map[string]shadowReportSeen, 64), ttl: ttl, max: max}
}

// admit 幂等判定：首次见到返回 true（并入集合）；TTL 内重复返回 false。调用方须持 s.mu。
// nil 接收者（测试以结构体字面量构造的裸 server）视为"无幂等状态"→ 放行，避免误判重与 panic。
func (st *shadowReportState) admit(id string, now time.Time) bool {
	if st == nil {
		return true
	}
	if st.seen == nil {
		st.seen = make(map[string]shadowReportSeen, 64)
	}
	st.evict(now)
	if _, dup := st.seen[id]; dup {
		return false
	}
	st.seq++
	st.seen[id] = shadowReportSeen{t: now, seq: st.seq}
	return true
}

// evict 清理过期项；仍超上限时按最早时间淘汰（保留最新的 max 条）。
// 时间相同（同一请求批量上报共用一个 now）时按插入序号 FIFO，保证确定性——
// 不依赖 Go map 随机遍历序（R8 修复）。
func (st *shadowReportState) evict(now time.Time) {
	for id, e := range st.seen {
		if now.Sub(e.t) > st.ttl {
			delete(st.seen, id)
		}
	}
	for len(st.seen) >= st.max {
		oldestID := ""
		var oldest shadowReportSeen
		for id, e := range st.seen {
			if oldestID == "" || e.t.Before(oldest.t) || (e.t.Equal(oldest.t) && e.seq < oldest.seq) {
				oldestID, oldest = id, e
			}
		}
		delete(st.seen, oldestID)
	}
}

// handleShadowReport POST /audit/shadow：接收**明文路由影子**的窗口级汇总并落审计链（A 项）。
//
// 契约（方案 §A.3）：
//   - 每条 report 落**一条**审计事件：action=shadow、result=would_reject、
//     shadow_rule="<rule_id>@<window>"、payload_hash=sha256(report_id)、tokens_in/out=0
//     （明文本方案不计量 token：无 tokenizer，避免假精度）；
//   - report_id 幂等：TTL（默认 10 分钟）内重复上报 → deduped 计数，**不重复落链**；
//   - 校验：整批先校验，任一非法 → 400（不做部分接受）；管理令牌认证（X-Admin-Token）；
//   - 响应：{"accepted","deduped","chain_events"}；指标 otpmask_shadow_reports_total{result}。
func (s *teeServer) handleShadowReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	var req shadowReportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		s.metrics.incShadowReport("rejected", 1)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if len(req.Reports) == 0 {
		s.metrics.incShadowReport("rejected", 1)
		http.Error(w, "reports 不得为空", http.StatusBadRequest)
		return
	}
	for i := range req.Reports {
		if err := req.Reports[i].validate(); err != nil {
			s.metrics.incShadowReport("rejected", 1)
			http.Error(w, fmt.Sprintf("第 %d 条上报非法: %v", i, err), http.StatusBadRequest)
			return
		}
	}

	now := time.Now()
	newly := make([]*shadowReport, 0, len(req.Reports))
	deduped := 0
	s.mu.Lock()
	for i := range req.Reports {
		rep := &req.Reports[i]
		if s.shadowReports.admit(rep.ReportID, now) {
			newly = append(newly, rep)
		} else {
			deduped++
		}
	}
	s.mu.Unlock()

	for _, rep := range newly {
		tenant := rep.Tenant
		if tenant == "" && rep.Scope == "tenant" {
			tenant = rep.Target // tenant 维度：target 即租户
		}
		sum := sha256.Sum256([]byte(rep.ReportID))
		s.audit.append(AuditEvent{
			TenantID: tenant, RequestID: rep.ReportID, Action: "shadow",
			Result: "would_reject", PayloadSHA: hex.EncodeToString(sum[:]),
			ShadowRule: rep.RuleID + "@" + rep.Window,
		})
	}
	s.metrics.incShadowReport("accepted", int64(len(newly)))
	s.metrics.incShadowReport("deduped", int64(deduped))
	log.Printf("[tee] 影子汇总上报 accepted=%d deduped=%d chain_events=%d",
		len(newly), deduped, len(newly))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted":     len(newly),
		"deduped":      deduped,
		"chain_events": len(newly),
	})
}

// auditVerifyResponse /audit/verify 响应。
type auditVerifyResponse struct {
	OK     bool `json:"ok"`
	Events int  `json:"events"`
}

// handleAuditVerify 哈希链完整性校验：GET /audit/verify。
func (s *teeServer) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	ok, n := s.audit.verify()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(auditVerifyResponse{OK: ok, Events: n})
}

// handleAuditAnchor 触发审计锚定：POST /audit/anchor。
// 返回锚定记录；未启用锚定文件时 400。
func (s *teeServer) handleAuditAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec := s.audit.anchorNow()
	if rec == nil {
		http.Error(w, "锚定未启用（需 -audit-anchor 参数）", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

// orDefault 空串回退。
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// chainHashOf 锚定记录的链尾哈希（空记录返回空串）。
func chainHashOf(r *AnchorRecord) string {
	if r == nil {
		return ""
	}
	return r.ChainHash
}

func wipe(b []byte) {
	memzero.Bytes(b)
}

// mustMeasure 获取飞地测量值（失败 panic，启动阶段不允许失败）。
func mustMeasure(e Enclave) []byte {
	m, err := e.Measure()
	if err != nil {
		panic("enclave: Measure 失败: " + err.Error())
	}
	return m
}

// sealFileHeader 密封文件魔数（版本化格式）。
const sealFileHeader = "OTPMASK-SEAL-V1\n"

// readSealFile 读取密封文件：master_blob + k_sig_blob 两个 length-prefixed blob。
// 文件不存在返回 (nil, nil)；格式损坏返回 nil（按首次启动处理，但保留告警）。
func readSealFile(path string) (masterBlob, sigBlob []byte) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		log.Printf("[seal] 读取密封文件失败（按首次启动处理）: %v", err)
		return nil, nil
	}
	if len(raw) < len(sealFileHeader) || string(raw[:len(sealFileHeader)]) != sealFileHeader {
		log.Printf("[seal] 密封文件格式未知（忽略）: %s", path)
		return nil, nil
	}
	body := raw[len(sealFileHeader):]
	// 两个 length-prefixed blob（big-endian uint32 长度 + 数据）
	if len(body) < 4 {
		return nil, nil
	}
	l1 := int(uint32(body[0])<<24 | uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3]))
	if len(body) < 4+l1+4 {
		return nil, nil
	}
	mb := body[4 : 4+l1]
	rest := body[4+l1:]
	l2 := int(uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3]))
	if len(rest) < 4+l2 {
		return nil, nil
	}
	return mb, rest[4 : 4+l2]
}

// writeSealFile 写入密封文件（master_blob || k_sig_blob，0600 权限）。
func writeSealFile(path string, masterBlob, sigBlob []byte) error {
	buf := make([]byte, 0, len(sealFileHeader)+4+len(masterBlob)+4+len(sigBlob))
	buf = append(buf, sealFileHeader...)
	buf = append(buf, byte(len(masterBlob)>>24), byte(len(masterBlob)>>16), byte(len(masterBlob)>>8), byte(len(masterBlob)))
	buf = append(buf, masterBlob...)
	buf = append(buf, byte(len(sigBlob)>>24), byte(len(sigBlob)>>16), byte(len(sigBlob)>>8), byte(len(sigBlob)))
	buf = append(buf, sigBlob...)
	return os.WriteFile(path, buf, 0o600)
}

// maxRequestBodyBytes 请求体上限（4MiB）：防超大 body 资源耗尽（T-1 评审项）。
const maxRequestBodyBytes = 4 << 20

// limitBody 请求体限制中间件：Content-Length 超限确定性 413；chunked 越限由
// MaxBytesReader 在读取时拦截（处理器读取失败走既有 400 fail-closed 路径）。
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxRequestBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := flag.String("listen", ":19090", "监听地址")
	sigKeyHex := flag.String("sig-key", "", "协议签名密钥 K_sig（32 字节 hex；默认随机生成并打印）")
	attestToken := flag.String("attest-token", "", "远程证明共享令牌（模拟）；默认随机生成并打印")
	adminToken := flag.String("admin-token", "", "管理端点（/metrics /audit /usage）认证令牌；生产必填，为空 = 开发模式不拦截")
	devMode := flag.Bool("dev-mode", false, "开发模式（威胁模型 GAP-01/GAP-05 逃生口）：显式声明后允许 mock 飞地与空管理令牌；生产严禁开启")
	meterToken := flag.String("meter-token", "", "独立只读计量令牌（GA-计费 P1-2）：仅可读 /usage（含 from/to 增量），不可写配额/读审计；为空 = 仅管理令牌可用")
	billingURL := flag.String("billing-url", "", "计费 Webhook 推送地址（GA-计费 P1-1，如 http://billing:8080/events）；为空 = 推送关闭，拉取为主")
	billingSecret := flag.String("billing-secret", "", "计费 Webhook HMAC-SHA256 签名密钥（与 billing-url 同时配置；为空 = 不签名，仅内网明文模式）")
	engineURL := flag.String("engine-url", "", "明文域推理引擎（vLLM OpenAI 兼容地址，如 http://vllm:8000；text 载荷流式直连；为空使用本地模拟引擎）")
	cmaasURL := flag.String("cmaas-url", "", "百炼 C-MaaS openai-proxy 地址（P5，如 http://127.0.0.1:8080；为空 = cmaas 引擎未配置，请求 fail-closed）")
	cmaasAPIKey := flag.String("cmaas-api-key", "", "C-MaaS API Key（DASHSCOPE_API_KEY，Bearer 透传代理；未指定时回退环境变量 CMAAS_API_KEY，推荐经 deploy/secrets/cmaas.env 注入）")
	cmaasModel := flag.String("cmaas-model", "", "C-MaaS 缺省模型 code（cmaas-glm-5.2 等；请求未指定模型时使用）")
	auditFile := flag.String("audit-file", "", "审计事件 WORM 文件路径（JSON Lines 只追加；为空 = 内存模式）")
	auditAnchor := flag.String("audit-anchor", "", "审计锚定文件路径（链尾哈希追加；仅 audit-file 开启时生效）")
	auditRetention := flag.Int("audit-retention-days", defaultAuditRetentionDays, "审计/日志留存期声明（天；0=不声明；>0 须 ≥180 法定硬底）。仅声明：服务不删除审计数据（保 WORM 链完整），删除由存储层生命周期策略按本值执行")
	tsaMode := flag.String("tsa", "mock", "RFC 3161 可信时间戳服务：mock（本地自签）| off（不绑定 TST，）")
	requireAttest := flag.Bool("require-attest", false, "强制证明模式")
	enclaveMode := flag.String("enclave", "mock", "飞地实现：mock|tdx|sgx")
	sealFile := flag.String("seal-file", "", "飞地密封数据文件（主密钥/K_sig 经 Seal 持久化；为空 = 内存模式，重启重新生成）")
	tenantKeyFilePath := flag.String("tenant-key-file", "", "二级租户 KEK 状态密封文件（Snapshot 经 Enclave.Seal 落盘、重启 Unseal 恢复，§6 P1；为空 = 内存模式重启重建）")
	rotateScanInterval := flag.Duration("rotate-scan-interval", 24*time.Hour, "二级租户主密钥轮换扫描周期（§6.4；扫描 last_rotated_at 超 90 天者）")
	// P0-4 §12.3：进程级密码档（intl 逐字节等价；profile 是配置而非编译开关，§11.5）。
	cryptoProfile := flag.String("crypto-profile", "intl", "密码算法档（P0-4 §12.3）：intl|sm-software|sm-module（默认 intl；sm-module 未实现=启动拒，绝不回退冒充）")
	cryptoMaskPRG := flag.String("mask-prg", "", "掩码 PRG 档（P0-4 §5.3.2/R-14）：hmac-sha256|sm4|bridge；为空=随 profile（intl→hmac-sha256，sm→sm4）。bridge 须 sm 档（R-21）")
	routeConfigFile := flag.String("route-config", "", "双路线路由配置 JSON")
	tokenQuota := flag.Int64("token-quota", 0, "每租户 token 配额上限（累计输入+输出；<=0 = 不限，P1；未单独配置租户的默认值）")
	piiMode := flag.String("pii-mode", "block", "PII 处理模式：block（拦截，默认，fail-closed）| mask（脱敏替换后放行，P2a）；SQL 注入/提示注入任何模式均拦截")
	systemPrompt := flag.String("system-prompt", "", "提示词装饰：非空时在 text 载荷 messages 头部插入 system 消息（P2a，记录于审计 transformed_hash）")
	protoVersion := flag.String("protocol-version", protocol.Version, "南向协议版本声明（C-4 版本一致性；默认 protocol.Version）")
	guardrailCfg := flag.String("guardrail-config", "", "Guardrail 运行时配置持久化文件（M3-B：高敏复核写入的 pii_mode）；为空 = 仅进程内生效，重启回退 -pii-mode")
	guardClassURL := flag.String("guard-classifier-url", "", "GF.4.3 语义分类器侧车地址（如 http://127.0.0.1:19091/classify）；为空 = 使用进程内关键词规则分类器（默认，行为不变）；配置后侧车不可用即 fail-closed 拒答，并按同目录 /healthz 探活结果摘流（readiness 503）")
	guardClassKey := flag.String("guard-classifier-key", "", "语义分类器侧车 Bearer 令牌（可选；经环境变量注入，勿写入镜像）")
	guardClassTimeout := flag.Duration("guard-classifier-timeout", 2*time.Second, "语义分类器侧车调用超时（分类器在请求路径上，须有限且小；超时按不可用处理 → fail-closed 拒答）")
	outputGuardMode := flag.String("output-guard", "off", "GA-输出侧内容审查模式：off（缺省，行为与现网逐字节一致）| shadow（跑判定只记不拦）| enforcing（M4：缓冲模式 A 拦截，content_filter 终止；仅启动参数可开，运行时热切换仍限 off|shadow）")
	publicFacing := flag.Bool("public-facing", false, "S1-5 公众形态锁定：true 时审核总开关不可关闭（mode 不得为 off），关闭请求返回 400+审计；私有化形态默认 false")
	outputGuardStrategyFlag := flag.String("output-guard-strategy", "", "S3-2 策略档位（P-STRATEGY）：A（缺省，按句缓冲，命中零下发）| B（固定滑窗截断，窗前内容可能已发出，须法务书面确认）| C（首段预审+流式复审，前置未齐备，配置即拒绝启动）；运行时切换走 POST /config/output-guard/strategy")
	outputGuardCfg := flag.String("output-guard-config", "", "GA-输出侧内容审查运行时配置持久化文件（OG-8：高敏复核写入的 mode）；为空 = 仅进程内生效，重启回退 -output-guard")
	outputGuardPolicyDir := flag.String("output-guard-policy-dir", "", "GA-输出侧内容审查策略/词库目录（OG-9）：含 manifest.json 的 policy 根目录；为空 = 沿用既有 guardrail 规则（行为与现网一致）；加载失败/哈希不匹配即拒绝启动（fail-closed）")
	// S1-4（G21）：策略版本库显式引用。为空 = 沿用 policy 根目录 manifest（行为不变）；
	// 非空则须在 policy/versions/ 版本库内存在且状态 published、且通过 bench 硬门禁，否则拒绝启动。
	outputGuardPolicyVersion := flag.String("output-guard-policy-version", "", "S1-4/G21 策略版本库显式引用版本（-output-guard-policy-dir 下 versions/index.json 登记的 policy_version）；为空 = 沿用 policy 根目录 manifest（行为不变）；指定的版本不存在/为草稿/未过 bench 硬门禁即拒绝启动（fail-closed）")
	outputGuardL2URL := flag.String("output-guard-l2-url", "", "GA-输出侧内容审查 L2 语义分类器侧车地址（M2 OG-12）：HTTP POST JSON，返回 blocked/category/confidence/match；为空 = 不启用 L2，纯 L1 规则（默认，行为零变化）")
	outputGuardL2Key := flag.String("output-guard-l2-key", "", "输出侧 L2 语义分类器侧车 Bearer 令牌（可选；经环境变量注入，勿写入镜像）")
	outputGuardL2Timeout := flag.Duration("output-guard-l2-timeout", 2*time.Second, "输出侧 L2 语义分类器侧车调用超时（在请求路径上，须有限且小；不可用时该句按 P-DEGRADE fail-closed，不回退 L1）")
	outputGuardL2AllowedCIDRs := flag.String("output-guard-l2-allowed-cidrs", "", "P-BACKEND-TARGET 可信域 CIDR 白名单（逗号分隔；默认空＝仅 localhost）：L2 侧车地址须落在回环或白名单内，否则拒绝启动（2026-09-18 裁定 A2，防被审明文外发）")
	outputGuardMaskEnable := flag.Bool("output-guard-mask-enable", false, "OG-18：PII mask 改写开关（默认 false = block-only 深度，A4-06 降为 flag；true = 实打马赛克后下发）；需 -output-guard=shadow/enforcing 时生效")
	outputGuardDepth := flag.String("output-guard-depth", "", "S1-6（G18）：输出处理深度档位 passthrough（透传）| block-only（仅拦截，缺省档）| block+rewrite（拦截＋改写）；缺省＝按 mode/mask 派生。**只做声明＋一致性校验**，不隐式开启拦截/改写（enforcing 仅启动参数可开；改写须属地书面确认 D-LLM-9）")
	// GA-输出侧内容审查（OG-13）：级联参数（跨 §5.3–5.5 多组）。P-TIMEOUT 复用上面的 -output-guard-l2-timeout（单一事实源）。
	outputGuardConcurrency := flag.Int("output-guard-concurrency", 0, "P-CONCURRENCY：单请求在飞 L2 句数上限（OG-13 级联）；0＝未配置，按 CPU 核数派生；超限不排队，直接按 P-DEGRADE")
	outputGuardMaxSlots := flag.Int("output-guard-max-slots", 0, "P-MAX-SLOTS：单请求判定句槽位上限（OG-13 级联，防长输出撑爆内存）；0＝未配置，按 P-MAX-BUFFER-BYTES/平均句长派生")
	outputGuardBlockCancel := flag.Bool("output-guard-block-cancel", false, "P-BLOCK-CANCEL：命中 block 后是否中断引擎生成（M4 生效；M3 仅落配置与只读快照，不改变 shadow 行为）")
	outputGuardDegrade := flag.String("output-guard-degrade", degradeFailClosed, "P-DEGRADE：fail-closed（默认，当前唯一生效值）| fallback-keyword（尚未实现，配置即拒绝启动，不静默按 fail-closed 处置）")
	outputGuardBlockEmission := flag.Bool("output-guard-block-emission", false, "阻塞预演开关（非 §5 参数表参数，仅浸泡期用）：true＝按 enforcing 时序阻塞下发（首帧延迟增量可实测）；false＝shadow 现状（逐 delta 立即放行，业务零影响）")
	// B1 强标标识（GB 45438-2025，2025-09-01 已实施）：默认 off，off 时与现网逐字节一致。
	// 标识落点（纯 API 文本流）与分片策略 → 文案/落点/重复间隔全配置化留口。
	contentLabel := flag.String("content-label", contentLabelOff, "B1 强标标识（GB 45438-2025）开关：off（缺省，零行为变化）| on（流首+流尾双标，终止帧恒带 tail meta 兜底）；运行时热切换走 POST /config/content-label（on/off 双向可切）")
	contentLabelText := flag.String("content-label-text", "", "B1 标识文案（缺省「内容由人工智能生成」；启用时必须同时含「人工智能」与「生成」子串，否则启动失败 fail-closed）")
	contentLabelRepeat := flag.Int("content-label-repeat", 0, "B1 每 N 个内容帧插一次重复标识（0=仅首尾；取值 ∈[0,1000]）")
	contentLabelStd := flag.String("content-label-std", "", "B1 标准号声明（缺省 GB45438-2025；chunkLabelMeta.Std 与 /config 快照同源）")
	contentLabelProducer := flag.String("content-label-producer", "", "标识溯源要素：生成合成服务提供者要素（客户主体编码/名称，随标识帧 content_label.producer 下发；空=不输出）。属溯源要素，非文件元数据隐式标识，不得据此宣称已满足 GB 45438-2025 6.1")
	contentLabelCfg := flag.String("content-label-config", "", "B1 强标标识运行时配置持久化文件（热切换写入的 enabled/text/repeat/std）；为空 = 仅进程内生效，重启回退 -content-label* 启动参数")
	flag.Parse()

	// S5：进程启动时刻（对账判据——链中存在早于此时刻的事件 ⇒ 内存用量计数已在重启时丢失）
	startedAt := time.Now().UnixNano()

	// 启动期安全守卫（威胁模型 GAP-01 mock 飞地 / GAP-05 空管理令牌）：生产形态 fail-closed。
	// 须在飞地初始化与任何监听之前判定，避免"先起服务后校验"的窗口。
	if err := validateStartupSecurity(*enclaveMode, *adminToken, *devMode); err != nil {
		log.Fatalf("%v", err)
	}
	// P0-4 §5.4.4/§12.3：装配进程级密码 provider（intl 逐字节等价；非法组合=启动拒，R-2/R-14/R-21）。
	if err := initCryptoRuntime(*cryptoProfile, *cryptoMaskPRG); err != nil {
		log.Fatalf("%v", err)
	}
	if *devMode {
		log.Printf("⚠️ 开发模式（-dev-mode）：已放行 mock 飞地 / 空管理令牌；生产环境严禁使用")
	}

	// 双路线路由配置
	routeCfg := DefaultRouteConfig()
	if *routeConfigFile != "" {
		data, err := os.ReadFile(*routeConfigFile)
		if err != nil {
			log.Fatalf("读取路由配置失败（fail-closed）: %v", err)
		}
		routeCfg, err = ParseRouteConfig(data)
		if err != nil {
			log.Fatalf("解析路由配置失败（fail-closed）: %v", err)
		}
	}

	// 飞地抽象初始化（mock / tdx / sgx；tdx/sgx 需硬件接入）
	var encl Enclave
	switch *enclaveMode {
	case "mock":
		e, err := NewMockEnclave()
		if err != nil {
			log.Fatalf("初始化 mock 飞地失败: %v", err)
		}
		encl = e
	case "tdx", "sgx", "nv-cc":
		e, err := newPlatformEnclave(*enclaveMode)
		if err != nil {
			log.Fatalf("初始化平台飞地失败: %v", err)
		}
		encl = e
	default:
		log.Fatalf("未知 enclave 模式: %s", *enclaveMode)
	}
	log.Printf("飞地实现: %s（测量值 %s）", encl.Platform(), hex.EncodeToString(mustMeasure(encl)))

	// 密钥驻留：主密钥与 K_sig 经 Enclave.Seal 持久化，重启 Unseal 恢复
	masterBlob, sigBlob := readSealFile(*sealFile) // nil = 首次启动
	var masterKey []byte
	var kSig []byte
	if *sigKeyHex != "" {
		k, err := hex.DecodeString(*sigKeyHex)
		if err != nil || len(k) != 32 {
			log.Fatalf("sig-key 须为 32 字节 hex")
		}
		kSig = k
	} else if sigBlob != nil {
		k, err := encl.Unseal(sigBlob, "k_sig")
		if err != nil {
			log.Fatalf("恢复 K_sig 失败（fail-closed）: %v", err)
		}
		kSig = k
		log.Printf("恢复 K_sig（Enclave.Unseal, %d 字节）", len(kSig))
	} else {
		kSig = make([]byte, 32)
		if _, err := rand.Read(kSig); err != nil {
			log.Fatal(err)
		}
		log.Printf("生成的 K_sig（生产由 TEE 签发，此处 mock）")
	}
	if *attestToken == "" {
		*attestToken = randHex(32)
		log.Printf("生成的 attestation 令牌: %s（模拟凭证，生产环境用 TDX Quote）", *attestToken)
	}

	// 主密钥：密封文件恢复（Unseal）或飞地内生成后 Seal 持久化
	if masterBlob != nil {
		mk, err := encl.Unseal(masterBlob, "master")
		if err != nil {
			log.Fatalf("恢复主密钥失败（fail-closed）: %v", err)
		}
		masterKey = mk
	}
	if masterKey == nil {
		mk := make([]byte, 32)
		if _, err := rand.Read(mk); err != nil {
			log.Fatal(err)
		}
		masterKey = mk
	}
	// 持久化密封数据（主密钥 + K_sig 合并密封，重启可恢复；fail-closed：密封失败拒绝启动）
	if *sealFile != "" && masterBlob == nil {
		blob, err := encl.Seal(masterKey, "master")
		if err != nil {
			log.Fatalf("密封主密钥失败（fail-closed）: %v", err)
		}
		sigBlob2, err := encl.Seal(kSig, "k_sig")
		if err != nil {
			log.Fatalf("密封 K_sig 失败（fail-closed）: %v", err)
		}
		if err := writeSealFile(*sealFile, blob, sigBlob2); err != nil {
			log.Fatalf("写入密封文件失败（fail-closed）: %v", err)
		}
		log.Printf("密钥已 Seal 持久化: %s（重启经 Unseal 恢复）", *sealFile)
	}

	km, err := teecore.NewKeyManagerWithMaster(0, masterKey)
	if err != nil {
		log.Fatalf("初始化 KeyManager 失败: %v", err)
	}

	// M12：引擎可插拔——指定 -engine-url 时经 vLLM OpenAI 兼容接口推理（P2：text 流式直连；
	// vectors 路径经 vLLM 适配器 /generate 兼容保留），否则本地模拟引擎
	var eng model.Engine = model.New()
	if *engineURL != "" {
		eng = model.NewRemoteEngine(*engineURL)
		log.Printf("推理引擎: vLLM OpenAI 兼容 %s", *engineURL)
	}
	// P5：C-MaaS 引擎（openai-proxy 对接；未配置 -cmaas-url 时 cmaas 请求 fail-closed）
	var cmaasEng *model.CmaasEngine
	if *cmaasURL != "" {
		// 密钥优先级：flag > 环境变量 CMAAS_API_KEY。密钥经配置文件/环境注入
		// （避免出现在命令行与进程列表）；两者均缺失时以空 key 构造，
		// 鉴权失败由上游响应 fail-closed。
		cmaasKey := *cmaasAPIKey
		if cmaasKey == "" {
			cmaasKey = os.Getenv("CMAAS_API_KEY")
		}
		cmaasEng = model.NewCmaasEngine(*cmaasURL, cmaasKey, *cmaasModel)
		log.Printf("推理引擎: C-MaaS openai-proxy %s（model=%s）", *cmaasURL, orDefault(*cmaasModel, "-"))
	}

	// C-5：审计 WORM 持久化——指定 -audit-file 时启用文件追加与启动恢复
	// RFC 3161 可信时间戳（-tsa mock|off）
	var tsa TSASigner
	switch *tsaMode {
	case "mock":
		t, err := NewMockTSA()
		if err != nil {
			log.Fatalf("初始化 TSA 失败: %v", err)
		}
		tsa = t
	case "off":
		tsa = nil
	default:
		log.Fatalf("未知 TSA 模式: %q（mock|off）", *tsaMode)
	}
	var audit *auditChain
	if *auditFile != "" {
		audit, err = newAuditChainWORM(*auditFile, *auditAnchor)
		if err != nil {
			log.Fatalf("初始化 WORM 审计失败（fail-closed 拒绝启动）: %v", err)
		}
		audit.tsa = tsa
		rec := audit.anchorNow()
		log.Printf("审计模式: WORM 文件=%s 锚定=%s 恢复事件=%d（锚定 %s, TST=%v）",
			*auditFile, orDefault(*auditAnchor, "-"), audit.len(), orDefault(chainHashOf(rec), "-"), rec != nil && rec.TST != nil)
	} else {
		audit = newAuditChainWithTSA(tsa)
	}

	// P0-2 语义缓存：默认 mode=off（与现网逐字节一致）；经 legacyAdapter 复用既有 Get/Put 接线点。
	cacheCfg := cacheengine.DefaultConfig()
	if p := os.Getenv("CACHE_CONFIG_PATH"); p != "" {
		if c, err := cacheengine.LoadConfig(p); err != nil {
			log.Printf("[tee] 缓存配置加载失败，回退默认（mode=off）：%v", err)
		} else {
			cacheCfg = c
		}
	}
	if err := cacheengine.ApplyEnv(&cacheCfg); err != nil {
		log.Printf("[tee] 缓存环境变量覆盖失败，回退默认（mode=off）：%v", err)
		cacheCfg = cacheengine.DefaultConfig()
	}
	// 启动期维度探针：语义启用时校验 sidecar 维度；失败按 §6.9/B-7.6-1 降级为精确缓存。
	if cacheCfg.Semantic.Enabled && (cacheCfg.Mode == cacheengine.ModeSemantic || cacheCfg.Mode == cacheengine.ModeFull) {
		probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		emb, err := cacheengine.NewSidecarEmbedderFromConfig(cacheCfg.Semantic.Embedder)
		if err == nil {
			err = cacheengine.VerifyEmbedderDim(probeCtx, emb, cacheCfg.Semantic.Embedder.Dim)
		}
		cancel()
		if err != nil {
			log.Printf("[tee] 语义缓存探针失败，降级为精确缓存（mode=exact）：%v", err)
			cacheCfg.Mode = cacheengine.ModeExact
			cacheCfg.Semantic.Enabled = false
		}
	}
	// P5：语义装配（embedder + 向量索引 + SemanticStore）。失败即按 §6.9/B-7.6-1 降级为精确缓存。
	var cacheOpts []cacheengine.EngineOption
	if store, err := cacheengine.BuildSemanticStoreFromConfig(context.Background(), &cacheCfg); err != nil {
		log.Printf("[tee] 语义存储装配失败，禁用语义缓存：%v", err)
		cacheCfg.Semantic.Enabled = false
	} else if store != nil {
		cacheOpts = append(cacheOpts, cacheengine.WithSemanticStore(store))
	}
	cacheEng := cacheengine.NewCacheEngine(cacheCfg, cacheOpts...)

	srv := &teeServer{
		km: km, kSig: kSig, attest: *attestToken,
		enclave:           encl,
		requireAttest:     *requireAttest,
		adminToken:        *adminToken,
		meterToken:        *meterToken,                                    // GA-计费 P1-2：独立只读计量令牌（/usage 最小权限）
		billing:           newBillingWebhook(*billingURL, *billingSecret), // GA-计费 P1-1：nil = 推送关闭（拉取为主）
		model:             eng,
		cmaasEngine:       cmaasEng,
		protoVersion:      *protoVersion,
		piiMode:           *piiMode,
		guardrailCfgPath:  *guardrailCfg,
		systemPrompt:      *systemPrompt,
		seen:              make(map[string]bool),
		seenAt:            make(map[string]int64),
		sessions:          make(map[string]*teeSession),
		recomputeStates:   newRecomputeStates(),
		weightProvider:    NewMockWeightProvider(32),
		route:             routeCfg,
		tokenizer:         nil,                       // GF.2.4：nil = CJK 感知估算（过渡口径，metering_mode=estimate）；真机 tokenizer 注入点
		cache:             cacheengine.NewLegacyAdapter(cacheEng), // P0-2：legacy 兜底（仅 cacheEngine==nil 时使用）
		cacheEngine:       cacheEng,                                // P0-2 B2：原生语义缓存（命中/回填）+ /metrics
		cacheEnabled:      cacheCfg.Mode != cacheengine.ModeOff,    // P0-2 B2：mode=off → 不进原生路径（零开销）
		cacheReplay:       cacheReplayConfig{minGap: cacheCfg.Stream.MinGap.D(), maxGap: cacheCfg.Stream.MaxGap.D()}, // P0-2 B2：§6.12 节拍快照
		usage:             make(map[string]*usageRecord),
		quota:             make(map[string]quotaSpec),
		quotaDefault:      *tokenQuota,
		quotaWindowUsage:  make(map[string]int64),
		quotaWindowKey:    make(map[string]string),
		shadowReports:     newShadowReportState(shadowReportTTL, shadowReportMax), // A 项：上报幂等状态
		shadowWindowUsage: make(map[string]int64),
		shadowWindowKey:   make(map[string]string),
		audit:             audit,
		guard:             newGuardrail(),
		metrics:           newMetrics(),
		disposition:       nilDisposition{}, // S4-4：默认永远放行；SaaS 构建由 initTenantDisposition 替换
	}
	// P0-4 §10.1：跨源 cryptop 指标绑定（须在 srv.metrics 初始化后）
	srv.metrics.SetCryptopCompatMode("mask_bridge", *cryptoMaskPRG == "bridge")
	setEnclaveDualReadHook(srv.metrics.IncEnclaveDualRead)
	// P0-4 §6 B6#9：二级租户 KEK 体系（Root→KEK→会话master→seed 三级链）
	rootKey := encl.rootKey()
	if len(rootKey) != cryptoProvider.SymmetricKeySize() {
		log.Fatalf("[tenant-key] 一级根密钥长度 %d != profile=%s SymmetricKeySize %d（KEK 封装不可用，fail-closed）",
			len(rootKey), cryptoProvider.Profile(), cryptoProvider.SymmetricKeySize())
	}
	rootWrap := &cryptoRootWrapper{prov: cryptoProvider, root: rootKey}
	var persist *tenantKeyPersist
	var changeHook teecore.ChangeHook
	if *tenantKeyFilePath != "" {
		persist = &tenantKeyPersist{path: *tenantKeyFilePath, encl: encl, root: rootWrap}
		changeHook = persist
	}
	tkm := teecore.NewTenantKeyManager(cryptoProvider, 0, srv.metrics, &tenantKeyAudit{chain: audit}, changeHook)
	srv.tkm = tkm
	if persist != nil {
		persist.tkm = tkm
		snaps, err := loadTenantKeyFile(*tenantKeyFilePath, encl)
		if err != nil {
			log.Fatalf("[tenant-key] 恢复密封 KEK 状态失败（fail-closed）: %v", err)
		}
		if len(snaps) > 0 {
			if err := tkm.Restore(snaps, rootWrap); err != nil {
				log.Fatalf("[tenant-key] Restore 失败（fail-closed）: %v", err)
			}
			log.Printf("[tenant-key] 恢复租户 KEK 状态：tenants=%d", len(snaps))
		}
	}
	go runTenantKeyScanner(tkm, *rotateScanInterval)
	// 审计/日志留存期**声明**（校验 fail-closed）。
	// 声明式：仅暴露声明值（启动日志 / GET /config / otpmask_audit_retention_days）；
	// 服务**不删除**审计数据——WORM 只追加，就地裁剪会破坏哈希链完整性（audit-verify 无法从创世重算）。
	// 删除动作由**存储层生命周期策略**按本值执行，二者须保持一致（"声明—执行"可核验对）。
	if err := validateAuditRetentionDays(*auditRetention); err != nil {
		log.Fatalf("[audit-retention] %v", err)
	}
	srv.auditRetentionDays = *auditRetention
	srv.metrics.setAuditRetentionDays(*auditRetention)
	switch {
	case *auditRetention == 0:
		log.Printf("[audit-retention] 未声明留存期（-audit-retention-days=0）——检查/备案时须说明留存策略")
	case *auditFile == "":
		log.Printf("[audit-retention] 已声明留存 %d 天，但未启用 -audit-file（内存模式），声明无实际对象", *auditRetention)
	default:
		log.Printf("[audit-retention] 已声明留存 %d 天（服务不删数据；须由存储层生命周期策略按本值执行删除，二者一致）", *auditRetention)
	}
	// M3-B：恢复运行时 Guardrail 配置（高敏复核写入的 pii_mode，跨重启保持）。
	srv.loadGuardrailOverride()
	// GA-输出侧内容审查（OG-3）：模式校验（非法 / enforcing 未实现 → 拒绝启动，不静默降级）
	// + 落 mode/policy_version gauge（并为 requests_total 预置零值序列，保门禁 #9 required 常驻）。
	if err := validateOutputGuardMode(*outputGuardMode); err != nil {
		log.Fatalf("[output-guard] %v", err)
	}
	// I1（评审缺陷修复）：enforcing 必须配 L2 语义分类器——L1 规则层仅 2 个类目
	//（A4-06 默认 mask、A1-07 默认 flag，block-only 深度下均降为 flag/不拦截），
	// 纯 L1 的 enforcing 零拦截且名字具误导性，属 fail-open 虚假安全感。
	if *outputGuardMode == outputGuardEnforcing && *outputGuardL2URL == "" {
		log.Fatalf("[output-guard] enforcing 模式必须配置 -output-guard-l2-url（L1 规则层无 block 类目，纯 L1 = 零拦截）")
	}
	// B 组（P-BACKEND-TARGET，2026-09-18 裁定 A2）：L2 侧车地址须落在可信域内——
	// 默认仅 localhost，跨主机必须显式声明可信域 CIDR。被审内容是**用户生成明文**，
	// 地址出域即明文外发，故校验失败一律拒绝启动（fail-closed；连接期另有第二层校验）。
	ogAllowedNets, err := parseOutputGuardAllowedCIDRs(*outputGuardL2AllowedCIDRs)
	if err != nil {
		log.Fatalf("[output-guard] %v", err)
	}
	if err := validateOutputGuardBackendParams(outputGuardBackendParams{
		Target:      *outputGuardL2URL,
		AllowedNets: ogAllowedNets,
	}); err != nil {
		log.Fatalf("[output-guard] %v", err)
	}
	srv.outputGuardMode = *outputGuardMode
	srv.publicFacing = *publicFacing
	// S1-5：公众形态下 mode 不得为 off（审核总开关不可关闭）。
	if srv.publicFacing && srv.outputGuardMode == outputGuardOff {
		log.Fatalf("[output-guard] 公众形态（-public-facing=true）下审核总开关不可关闭；须设置 -output-guard=shadow 或 enforcing")
	}
	// S3-2：策略档位启动参数——校验合法值；空 = 缺省 A（不在此赋值，访问器兜底）。
	// 策略 C 前置（首段预审门/P-FIRST-CHUNK/法务双通过）未齐备 ⇒ 拒绝启动（fail-closed，不静默按 A）。
	if *outputGuardStrategyFlag != "" {
		if err := validateOutputStrategy(*outputGuardStrategyFlag); err != nil {
			log.Fatalf("[output-guard] %v", err)
		}
		if !strategyRunnable(*outputGuardStrategyFlag) {
			log.Fatalf("[output-guard] -output-guard-strategy=%s 前置未齐备（首段预审门/P-FIRST-CHUNK/法务双通过）：拒绝启动，不静默回落", *outputGuardStrategyFlag)
		}
		srv.outputGuardStrategy = *outputGuardStrategyFlag
	}
	srv.outputGuardMaskEnabled = *outputGuardMaskEnable
	// S1-6（G18）：输出处理深度档位（透传／仅拦截／拦截+改写）——档位是 mode＋mask 的**派生视图**，
	// 显式声明值必须与生效配置一致（不得由档位参数隐式开启拦截/改写；D-LLM-9：改写须属地书面确认）。
	if err := validateOutputDepth(*outputGuardDepth, deriveOutputDepth(srv.outputGuardMode, srv.outputGuardMaskEnabled)); err != nil {
		log.Fatalf("[output-guard] %v", err)
	}
	srv.outputGuardCfgPath = *outputGuardCfg
	// OG-8：恢复运行时 mode 覆盖（高敏变更复核写入的 mode，跨重启保持）。
	// 注意：放在模式校验之后——恢复的 mode 会另行独立校验，非法则沿用启动参数（不阻断启动）。
	srv.loadOutputGuardOverride()
	// OG-9：策略/词库加载。配置了目录即强校验（schema/哈希/类目/命名），任何失败＝拒绝启动——
	// 不静默降级为"无词库"（否则会以"以为在审、其实没审"的方式悄悄失效）。
	// S1-4（G21）：若显式引用版本（启动参数优先，其次持久化恢复），则加载该版本快照，
	// 且必须通过 bench 硬门禁；版本库不可用/版本非法/未过门禁一律拒绝启动（显式引用不得静默降级）。
	srv.outputGuardPolicyDir = *outputGuardPolicyDir
	if *outputGuardPolicyDir != "" {
		loadDir := *outputGuardPolicyDir
		refVersion := *outputGuardPolicyVersion
		if refVersion == "" {
			refVersion = srv.referencedPolicyVersion()
		}
		if refVersion != "" {
			idx, err := loadPolicyVersionIndex(*outputGuardPolicyDir)
			if err != nil {
				log.Fatalf("[output-guard] 显式引用版本 %s 但版本库不可用（fail-closed，拒绝启动）: reason=%s",
					refVersion, PolicyLoadErrorKind(err))
			}
			dir, err := srv.policySnapshotDir(refVersion)
			if err != nil {
				log.Fatalf("[output-guard] 显式引用版本 %s 非法（fail-closed，拒绝启动）: reason=%s",
					refVersion, PolicyLoadErrorKind(err))
			}
			if err := checkPolicyBenchGate(idx, dir, refVersion); err != nil {
				log.Fatalf("[output-guard] 显式引用版本 %s 未过 bench 硬门禁（fail-closed，拒绝启动）: reason=%s",
					refVersion, PolicyLoadErrorKind(err))
			}
			loadDir = dir
			srv.outputGuardPolicyRef.Store(refVersion)
			log.Printf("[output-guard] 策略版本库：已显式引用 %s（bench 硬门禁通过）", refVersion)
		}
		reg, err := loadPolicyDir(loadDir)
		if err != nil {
			// 只打原因枚举，不打错误全文（§4.11：json 解析片段可能含词库内容）。
			log.Fatalf("[output-guard] 策略/词库加载失败（fail-closed，拒绝启动）: reason=%s", PolicyLoadErrorKind(err))
		}
		srv.setPolicy(reg)
		log.Printf("[output-guard] 策略/词库已加载: policy_version=%s 类目=%d 规则=%d 最长关键词=%d rune",
			reg.PolicyVersion(), reg.CategoryCount(), reg.RuleCount(), reg.MaxKeywordRunes())
	}
	ogModeMetric := srv.currentOutputGuardMode()
	srv.metrics.setOutputGuardMode(ogModeMetric, srv.policyVersion())
	// GA-输出侧内容审查（OG-4）：D 组缓冲参数——先校验原始值（非法＝拒绝启动，§5.4），
	// 再派生（P-WINDOW-CHARS / P-FIRST-UNIT-MAX-RUNES）。词库最长命中长度取"guardrail 关键词"
	// 与"已加载词库"两者的较大值，保证滑窗足以覆盖任一 L1 路径的最长命中（§5.4 派生口径）。
	ogParams := defaultOutputGuardParams()
	ogParams.MaxKeywordRunes = srv.guard.maxKeywordRunes()
	if reg := srv.currentPolicy(); reg != nil {
		if v := reg.MaxKeywordRunes(); v > ogParams.MaxKeywordRunes {
			ogParams.MaxKeywordRunes = v
		}
	}
	if err := validateOutputGuardParams(ogParams); err != nil {
		log.Fatalf("[output-guard] 缓冲参数非法: %v", err)
	}
	srv.outputGuardParams = resolveOutputGuardParams(ogParams)
	// GA-输出侧内容审查（OG-13）：级联参数——先校验（非法＝拒绝启动），再派生
	// （P-CONCURRENCY / P-MAX-SLOTS 兜底列）。P-TIMEOUT 复用 -output-guard-l2-timeout。
	ogCascParams := defaultOutputGuardCascadeParams()
	ogCascParams.Timeout = *outputGuardL2Timeout
	ogCascParams.Concurrency = *outputGuardConcurrency
	ogCascParams.MaxSlots = *outputGuardMaxSlots
	ogCascParams.BlockCancel = *outputGuardBlockCancel
	ogCascParams.Degrade = *outputGuardDegrade
	ogCascParams.BlockEmission = *outputGuardBlockEmission
	if err := validateOutputGuardCascadeParams(ogCascParams); err != nil {
		log.Fatalf("[output-guard] 级联参数非法: %v", err)
	}
	srv.outputGuardCascade = resolveOutputGuardCascadeParams(ogCascParams, srv.outputGuardParams)
	log.Printf("[output-guard] 级联参数（E 组）concurrency=%d max_slots=%d timeout=%s degrade=%s block_cancel=%v",
		srv.outputGuardCascade.Concurrency, srv.outputGuardCascade.MaxSlots, srv.outputGuardCascade.Timeout,
		srv.outputGuardCascade.Degrade, srv.outputGuardCascade.BlockCancel)
	if srv.outputGuardCascade.BlockEmission {
		// 非生产形态：按 enforcing 时序阻塞下发（只做时序、不改内容），仅供浸泡取首帧延迟增量。
		log.Printf("[output-guard] 警告：阻塞预演已开启（-output-guard-block-emission=true）——按 enforcing 时序下发，仅限浸泡期使用，勿用于生产 shadow")
	}
	log.Printf("[output-guard] 输出侧内容审查模式=%s mask=%t；缓冲参数 unit=%s max_unit_runes=%d first_unit_max_runes=%d max_buffer_bytes=%d window_chars=%d（词库最长 %d + 余量 %d）",
		ogModeMetric, srv.outputGuardMaskEnabled, srv.outputGuardParams.Unit, srv.outputGuardParams.MaxUnitRunes,
		srv.outputGuardParams.FirstUnitMaxRunes, srv.outputGuardParams.MaxBufferBytes,
		srv.outputGuardParams.WindowRunes, ogParams.MaxKeywordRunes, srv.outputGuardParams.WindowMargin)
	// B1 强标标识（GB 45438-2025）：先校验原始值（非法＝拒绝启动，fail-closed），再 resolve。
	// 文案子串仅启用时校验（off 态不参与发射）；repeat 范围常校。
	clCfg := defaultContentLabelConfig()
	switch *contentLabel {
	case contentLabelOff:
	case contentLabelOn:
		clCfg.Enabled = true
	default:
		log.Fatalf("[content-label] -content-label=%q 非法（取值：off|on）", *contentLabel)
	}
	clCfg.Text = *contentLabelText
	clCfg.Repeat = *contentLabelRepeat
	clCfg.Std = *contentLabelStd
	clCfg.Producer = *contentLabelProducer
	// 修正（2026-09-26）：原为 validate→resolve，导致 `-content-label on` **未显式给文案**时
	// 因 Text=="" 被误判为"不合规"而启动失败（与 flag help／contentlabel.go 的缺省文案声明矛盾）。
	// 现改为 resolve→validate：缺省文案属"未配置"而非"非法值"；**显式给出的不合规文案仍被拦下**
	// （fail-closed 语义不变，仍符合"resolve 只派生 / validate 只校验"的职责分离）。
	srv.contentLabelCfg = resolveContentLabelConfig(clCfg)
	if err := validateContentLabelConfig(srv.contentLabelCfg); err != nil {
		log.Fatalf("[content-label] %v", err)
	}
	srv.contentLabelCfgPath = *contentLabelCfg
	// B1：恢复运行时覆盖（热切换结果跨重启保持；on/off 双向均可恢复）。
	srv.loadContentLabelOverride()
	srv.metrics.setContentLabelEnabled(srv.currentContentLabelConfig().Enabled)
	log.Printf("[content-label] 强标标识 enabled=%t text=%q repeat=%d std=%s（source=%s）",
		srv.currentContentLabelConfig().Enabled, srv.currentContentLabelConfig().Text,
		srv.currentContentLabelConfig().Repeat, srv.currentContentLabelConfig().Std, srv.contentLabelSource())
	// GF.4.3：语义分类器接线（默认关闭——未配置 URL 即保持关键词规则分类器，行为不变）。
	// 侧车不可用**不回退关键词规则、不回退 L1**，按 fail-closed 拒答（2026-09-26 收口）
	// （类别 classifier_unavailable + guard_failclosed_total{backend,reason} + 告警）；
	// 可用性由侧车健康探活 + readiness 摘流保障，不以静默降级换取可用性。
	if *guardClassURL != "" {
		srv.guard.useClassifier(
			model.NewHTTPClassifier(*guardClassURL, *guardClassKey, *guardClassTimeout,
				func(result, reason string) {
					srv.metrics.incGuardClassifier(model.GuardClassifierBackendHTTP, result)
					if result == "degraded" {
						srv.metrics.incGuardFailClosed(model.GuardClassifierBackendHTTP, reason)
						log.Printf("[guardrail] 语义分类器侧车不可用（%s）：按 fail-closed 拒答该请求（不回退关键词规则）", reason)
					}
				}),
			model.GuardClassifierBackendHTTP,
		)
		probe, probeErr := newGuardClassifierProbe(*guardClassURL, srv.metrics.setGuardSidecarHealthy)
		if probeErr != nil {
			log.Fatalf("[guardrail] 语义分类器健康端点派生失败（url=%s）：%v", *guardClassURL, probeErr)
		}
		srv.guardProbe = probe
		go probe.run()
		log.Printf("[guardrail] 语义分类器接线：backend=%s url=%s timeout=%s health=%s（不可用时 fail-closed 拒答 + readiness 摘流）",
			model.GuardClassifierBackendHTTP, *guardClassURL, guardClassTimeout.String(), probe.healthURL)
	}
	// M2 OG-12：输出侧内容审查 L2 语义分类器接线（默认关闭——未配置 URL 即纯 L1，行为零变化）。
	// 侧车不可用时该句按 P-DEGRADE fail-closed 处置（enforcing 丢该句、不整流终止）+ 记 degraded_total{backend=l2, reason=...}；
	// readiness 不联动 L2 状态（纯 L1 也能服务，安全降水位但不中断）。
	var outputGuardL2 OutputClassifier
	if *outputGuardL2URL != "" {
		outputGuardL2 = newOutputL2HTTPClassifier(*outputGuardL2URL, *outputGuardL2Key, *outputGuardL2Timeout, ogAllowedNets, srv.metrics, nil)
		log.Printf("[output-guard] L2 语义分类器接线：url=%s timeout=%s 可信域白名单=%d 条（不可用时该句按 P-DEGRADE fail-closed 处置，不回退 L1）",
			*outputGuardL2URL, outputGuardL2Timeout.String(), len(ogAllowedNets))
	}
	srv.outputGuardL2 = outputGuardL2
	go srv.seenCleanup()    // 防重放集合 TTL 清理
	go srv.sessionCleanup() // 远程证明会话 TTL 清理
	// S5 判据 6：审计-计量对账（启动即跑一次 → 状态与出账阻断立即可见，随后按 5 分钟周期）
	if srv.billing != nil {
		srv.billing.metrics = srv.metrics // 阻断/抑制计数随 /metrics 暴露
	}
	srv.reconciler = newReconciler(audit, srv.usage, &srv.mu, srv.metrics, srv.billing, startedAt)
	go srv.reconciler.run()
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", srv.handleAttest)
	mux.HandleFunc("/attest/complete", srv.handleAttestComplete)
	mux.HandleFunc("/key/issue", srv.handleKeyIssue)
	mux.HandleFunc("/v1/infer", srv.handleInfer)
	mux.HandleFunc("/v1/recompute", srv.handleRecompute)           // 路线 2 非线性补算
	mux.HandleFunc("/infer", srv.handleInfer)                      // 网关路由别名
	mux.HandleFunc("/usage", srv.handleUsage)                      // M9-2 用量
	mux.HandleFunc("/usage/quota", srv.handleQuota)                // P1 配额设置
	mux.HandleFunc("/audit", srv.handleAudit)                      // M9-3 审计
	mux.HandleFunc("/audit/shadow", srv.handleShadowReport)        // A 项：数据面明文影子窗口级汇总上报（幂等落链）
	mux.HandleFunc("/audit/verify", srv.handleAuditVerify)         // M9-3 哈希链校验
	mux.HandleFunc("/audit/anchor", srv.handleAuditAnchor)         // C-5 审计锚定
	mux.HandleFunc("/metrics", srv.handleMetrics)                  // M10 可观测性
	mux.HandleFunc("/config", srv.handleConfig)                    // M3-B 安全中心：配置只读快照
	mux.HandleFunc("/config/guardrail", srv.handleGuardrailConfig)    // M3-B 高敏复核：Guardrail 降级生效点
	mux.HandleFunc("/config/output-guard", srv.handleOutputGuardConfig) // OG-8 输出侧审查 mode 运行时切换
	mux.HandleFunc("/config/output-guard/strategy", srv.handleOutputGuardStrategy)   // S3-2 策略 A/B/C 切换（C 诚实门控）
	mux.HandleFunc("/config/output-guard/categories", srv.handleOutputGuardCategories) // S3-2 类目启停（拦截/脱敏底线不可停）
	mux.HandleFunc("/config/content-label", srv.handleContentLabelConfig) // B1 强标标识运行时热切换（on/off 双向）
	mux.HandleFunc("/config/policy/reload", srv.handlePolicyReload)  // OG-9 策略/词库热加载（applied/rolled_back）
	// S1-4（G21）策略版本库：只读发现 / 显式引用 / 回滚（版本库为只读输入，发布属离线步骤）
	mux.HandleFunc("/config/policy/versions", srv.handlePolicyVersions) // GET 版本列表（含 bench 结果）
	mux.HandleFunc("/config/policy/activate", srv.handlePolicyActivate) // POST 显式引用版本（bench 硬门禁）
	mux.HandleFunc("/config/policy/rollback", srv.handlePolicyRollback) // POST 回滚（缺省=上一 active，可指定历史版本）
	mux.HandleFunc("/reconcile", srv.handleReconcile)              // S5 判据 6：对账快照（只读）
	mux.HandleFunc("/reconcile/run", srv.handleReconcileRun)       // S5 判据 6：即时对账（管理令牌）
	// S4-4：租户处置状态机（SaaS 构建下注册 /config/tenant-disposition 端点；OSS 构建空操作）
	initTenantDisposition(srv, mux)
	mux.HandleFunc("/healthz", srv.handleHealthz)                  // 探针与证明状态联动
	mux.HandleFunc("/healthz/live", srv.handleHealthz)             // liveness

	defer audit.Close() // WORM 模式落盘文件随进程退出关闭

	log.Printf("tee-infer-service 就绪: %s（KeyManager 主密钥轮换 TTL=%v + attestation 双向）", *addr, teecore.DefaultMasterTTL)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           limitBody(mux),
		ReadHeaderTimeout: 5 * time.Second,  // 防 slowloris（对齐 auth-service 现有实践）
		ReadTimeout:       60 * time.Second, // body 一次性读完；不影响响应
		IdleTimeout:       120 * time.Second,
		// WriteTimeout 不设：SSE 流式响应为长写连接，统一写超时会截断流（P1b 流式语义）
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
