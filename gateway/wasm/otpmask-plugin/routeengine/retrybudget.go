package routeengine

// ============================================================
// RetryBudget：重试预算（令牌桶，按端点独立）
// 设计依据：方案 §6.7 重试预算
//
// 核心参数：
//   - MaxTokens: 最大令牌数（桶容量），默认 10
//   - RefillIntervalMs: 补充间隔（毫秒），默认 10000（10 秒补 1 个）
//   - RefillAmount: 每次补充数量，默认 1
//
// 语义：
//   - 每个端点独立维护一个令牌桶
//   - 每次重试消耗 1 个令牌（TryConsume 成功时）
//   - 每隔 RefillIntervalMs 补充 RefillAmount 个令牌（最多到 MaxTokens）
//   - 令牌耗尽后不再重试（直接返回失败），防止重试风暴
// ============================================================

// RetryBudget 单个端点的重试预算（令牌桶）。
type RetryBudget struct {
	MaxTokens        int   // 最大令牌数（桶容量）
	RefillIntervalMs int64 // 补充间隔（毫秒）
	RefillAmount     int   // 每次补充数量

	Tokens         int   // 当前令牌数
	LastRefillMs   int64 // 上次补充时间（unix 毫秒）
}

// NewRetryBudget 创建重试预算。
//
//	maxTokens: 桶容量，默认 10
//	refillIntervalMs: 补充间隔（毫秒），默认 10000
//	refillAmount: 每次补充数量，默认 1
func NewRetryBudget(maxTokens int, refillIntervalMs int64, refillAmount int) *RetryBudget {
	if maxTokens <= 0 {
		maxTokens = 10
	}
	if refillIntervalMs <= 0 {
		refillIntervalMs = 10000
	}
	if refillAmount <= 0 {
		refillAmount = 1
	}
	return &RetryBudget{
		MaxTokens:        maxTokens,
		RefillIntervalMs: refillIntervalMs,
		RefillAmount:     refillAmount,
		Tokens:           maxTokens, // 初始满桶
	}
}

// TryConsume 尝试消耗 1 个令牌。
// 返回 true 表示消耗成功（可以重试），false 表示令牌不足（禁止重试）。
// 副作用：自动补充到期的令牌。
func (b *RetryBudget) TryConsume(nowMs int64) bool {
	b.refill(nowMs)
	if b.Tokens <= 0 {
		return false
	}
	b.Tokens--
	return true
}

// refill 根据时间补充令牌（惰性补充，调用时检查）。
func (b *RetryBudget) refill(nowMs int64) {
	if b.LastRefillMs == 0 {
		// 首次调用，初始化时间
		b.LastRefillMs = nowMs
		return
	}
	elapsed := nowMs - b.LastRefillMs
	if elapsed < b.RefillIntervalMs {
		return
	}
	// 计算补充了多少个周期
	periods := elapsed / b.RefillIntervalMs
	if periods <= 0 {
		return
	}
	add := periods * int64(b.RefillAmount)
	b.Tokens += int(add)
	if b.Tokens > b.MaxTokens {
		b.Tokens = b.MaxTokens
	}
	// 更新上次补充时间（按整周期推进，避免精度丢失）
	b.LastRefillMs += periods * b.RefillIntervalMs
}

// AvailableTokens 返回当前可用令牌数（带自动补充）。
func (b *RetryBudget) AvailableTokens(nowMs int64) int {
	b.refill(nowMs)
	return b.Tokens
}

// Reset 重置令牌桶（满桶）。
func (b *RetryBudget) Reset(nowMs int64) {
	b.Tokens = b.MaxTokens
	b.LastRefillMs = nowMs
}

// ============================================================
// BudgetManager：多端点重试预算管理
// （按端点 name 独立维护令牌桶）
// ============================================================

// BudgetManager 管理一组端点的重试预算。
type BudgetManager struct {
	budgets map[string]*RetryBudget
	config  RetryBudgetConfig
}

// RetryBudgetConfig 重试预算配置（所有端点共享配置）。
type RetryBudgetConfig struct {
	MaxTokens        int   // 最大令牌数
	RefillIntervalMs int64 // 补充间隔（毫秒）
	RefillAmount     int   // 每次补充数量
}

// NewBudgetManager 创建预算管理器。
func NewBudgetManager(cfg RetryBudgetConfig) *BudgetManager {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 10
	}
	if cfg.RefillIntervalMs <= 0 {
		cfg.RefillIntervalMs = 10000
	}
	if cfg.RefillAmount <= 0 {
		cfg.RefillAmount = 1
	}
	return &BudgetManager{
		budgets: make(map[string]*RetryBudget),
		config:  cfg,
	}
}

// TryConsume 消耗指定端点的 1 个重试令牌。
// 返回 true 表示可以重试，false 表示预算耗尽。
func (m *BudgetManager) TryConsume(endpointName string, nowMs int64) bool {
	b := m.getOrCreate(endpointName)
	return b.TryConsume(nowMs)
}

// Available 获取指定端点的可用令牌数。
func (m *BudgetManager) Available(endpointName string, nowMs int64) int {
	b := m.getOrCreate(endpointName)
	return b.AvailableTokens(nowMs)
}

// AddEndpoint 显式添加端点（也可懒加载）。
func (m *BudgetManager) AddEndpoint(endpointName string, nowMs int64) {
	if _, ok := m.budgets[endpointName]; ok {
		return
	}
	b := NewRetryBudget(m.config.MaxTokens, m.config.RefillIntervalMs, m.config.RefillAmount)
	b.LastRefillMs = nowMs
	m.budgets[endpointName] = b
}

// RemoveEndpoint 移除端点（端点下线时用）。
func (m *BudgetManager) RemoveEndpoint(endpointName string) {
	delete(m.budgets, endpointName)
}

// Reset 重置指定端点的预算（满桶）。
func (m *BudgetManager) Reset(endpointName string, nowMs int64) {
	b := m.getOrCreate(endpointName)
	b.Reset(nowMs)
}

// getOrCreate 获取或创建端点的预算（懒加载）。
func (m *BudgetManager) getOrCreate(name string) *RetryBudget {
	b, ok := m.budgets[name]
	if !ok {
		b = NewRetryBudget(m.config.MaxTokens, m.config.RefillIntervalMs, m.config.RefillAmount)
		m.budgets[name] = b
	}
	return b
}
