package confllm

import (
	"context"

	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// ProviderHealth 单上游健康视图（含密态等级，供路由过滤）。
type ProviderHealth struct {
	ID                      string `json:"id"`
	Ready                   bool   `json:"ready"`
	PendingCredential       bool   `json:"pendingCredential,omitempty"`
	MinConfidentialityClass string `json:"minConfidentialityClass,omitempty"`
	Detail                  string `json:"detail,omitempty"`
	// Connectivity 连通性举证状态（§7.5.1：models 与 health **都**必须暴露该字段）。
	// 与 models 同一枚举、同一归一规则：凭据未配置 → pending-credential，其余 never-tested；
	// smoke-ok(<date>) 仅由 -tags=integration + 真实凭据的运行写入（禁 omitempty）。
	Connectivity string `json:"connectivity"`
}

// HealthAggregate 健康聚合（就绪/待凭据计数 + 明细，§7 QA-3）。
type HealthAggregate struct {
	Total             int              `json:"total"`
	Ready             int              `json:"ready"`
	PendingCredential int              `json:"pendingCredential"`
	Providers         []ProviderHealth `json:"providers"`
}

// AggregateHealth 聚合全部上游健康状态（不影响启动；待凭据可见，§7.3）。
func AggregateHealth(ctx context.Context, providers []ConfidentialLLMProvider) HealthAggregate {
	agg := HealthAggregate{Providers: make([]ProviderHealth, 0, len(providers))}
	for _, p := range providers {
		h := p.Health(ctx)
		agg.Total++
		// 连通性举证（§7.5.1）：与 /v1/confllm/models 同一口径，
		// 凭据未配置 → pending-credential；否则 never-tested（无真实冒烟绝不写 smoke-ok）。
		conn := meta.ConnNeverTested
		if h.PendingCredential {
			conn = meta.ConnPendingCredential
		}
		ph := ProviderHealth{
			ID:                      p.ID(),
			Ready:                   h.Ready,
			PendingCredential:       h.PendingCredential,
			MinConfidentialityClass: h.MinConfidentialityClass,
			Detail:                  h.Detail,
			Connectivity:            conn,
		}
		if h.Ready {
			agg.Ready++
		} else if h.PendingCredential {
			agg.PendingCredential++
		}
		agg.Providers = append(agg.Providers, ph)
	}
	return agg
}
