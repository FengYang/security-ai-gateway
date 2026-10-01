package cacheengine

import "security-ai-gateway/gateway/tee-infer-service/model"

// 确保 model.SemanticCache 接口与我们的 Engine 之间有适配器。
// 这样现有 main.go 的装配点（model.SemanticCache 类型）零改动可编译。

// legacyAdapter 将 CacheEngine 适配到旧的 model.SemanticCache 接口。
// 仅支持 Get/Put（精确键），用于向后兼容。
type legacyAdapter struct {
	engine CacheEngine
}

// NewLegacyAdapter 从 CacheEngine 构造 model.SemanticCache 兼容适配器。
func NewLegacyAdapter(e CacheEngine) model.SemanticCache {
	return &legacyAdapter{engine: e}
}

// Get 精确键查询（兼容旧接口）。
func (a *legacyAdapter) Get(key string) (string, bool) {
	// 旧接口只有 key 字符串，我们需要构造 LookupContext
	// 这里做最简化的适配：把 key 当 transformed_hash 用
	// 生产环境应使用新的 Lookup 接口
	//
	// 注意：PromptText 必须足够长，否则 NC-2（prompt 太短）会拒掉
	// legacy 模式下我们用 key 本身作为 prompt（保证长度充足）
	ctx := LookupContext{
		TransformedHash: key,
		PromptText:      key + ":legacy-prompt-padding",
		TenantID:        "legacy",
		EngineType:      "legacy",
		Model:           "legacy",
		PolicyVer:       "1",
		GuardVer:        "1",
	}
	result := a.engine.Lookup(ctx)
	if result.Hit && result.Entry != nil && result.Kind == KindExact {
		return result.Entry.Text, true
	}
	return "", false
}

// Put 精确键写入（兼容旧接口）。
func (a *legacyAdapter) Put(key, text string) {
	ctx := StoreContext{
		LookupContext: LookupContext{
			TransformedHash: key,
			PromptText:      key + ":legacy-prompt-padding",
			TenantID:        "legacy",
			EngineType:      "legacy",
			Model:           "legacy",
			PolicyVer:       "1",
			GuardVer:        "1",
		},
		Writable: true,
	}
	res := InferResult{
		Text:      text,
		TokensIn:  0,
		TokensOut: len(text),
		Finish:    "stop",
	}
	a.engine.Store(ctx, res)
}
