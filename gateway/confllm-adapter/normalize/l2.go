package normalize

// MergeVendorOptions 合并 L2 原生参数（§1.3 / §7.8 R2）。
//
// base 为 L1 标准字段（model/messages/stream/...）；vendor 为厂商原生 extra_body。
// allowed 为 capabilities 声明的白名单（如百炼 enable_thinking、方舟 thinking、
// TokenHub reasoning_content、Azure OHTTP）；仅放行声明的 key，其余丢弃，
// 防厂商私有字段污染统一契约。白名单为空（未声明任何 vendor key）→ 直接丢弃 vendor 全部字段（fail-closed）。
func MergeVendorOptions(base map[string]any, vendor map[string]any, allowed []string) map[string]any {
	out := make(map[string]any, len(base)+len(allowed))
	for k, v := range base {
		out[k] = v
	}
	if len(allowed) == 0 {
		return out // 未声明白名单 → 不透传任何 vendor 字段
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, k := range allowed {
		allowSet[k] = struct{}{}
	}
	for k, v := range vendor {
		if _, ok := allowSet[k]; ok {
			out[k] = v
		}
	}
	return out
}
