package confllm

import "context"

// ProviderHealth 单上游健康视图（含密态等级，供路由过滤）。
type ProviderHealth struct {
	ID                      string `json:"id"`
	Ready                   bool   `json:"ready"`
	PendingCredential       bool   `json:"pendingCredential,omitempty"`
	MinConfidentialityClass string `json:"minConfidentialityClass,omitempty"`
	Detail                  string `json:"detail,omitempty"`
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
		ph := ProviderHealth{
			ID:                      p.ID(),
			Ready:                   h.Ready,
			PendingCredential:       h.PendingCredential,
			MinConfidentialityClass: h.MinConfidentialityClass,
			Detail:                  h.Detail,
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
