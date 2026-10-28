// Package main — 密态推理数据面薄接线（T04 §2 confllm_wire.go）。
//
// 职责：将 confllm-adapter 库接入 gateway-admin-service 管理面，复用 broker 内存
// 凭据（SecretRef → .env 凭据库）作为密态上游的 SecretResolver，并注册 /v1/confllm/*
// 数据面端点。对 confllm-adapter 仅依赖其导出的统一契约与 Registry（零硬依赖）。
//
// 装配来源（均为可选特性，缺省不装配，向后兼容）：
//   - ADMIN_CONFLLM_PROVIDERS_JSON：[]confllm.ProviderConfig，按 type 选工厂、id 须与
//     CR provider id 对齐、secretRef 指向 broker（见 NewFromConfig + GlobalRegistry）。
//   - ADMIN_CONFLLM_OVERRIDES_JSON：{providerId: {proofReference}}，managed→A 硬护栏
//     证明引用（§7.11 B2）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/attest"
	"security-ai-gateway/gateway/confllm-adapter/meta"

	// 副作用导入：触发各厂商 init() 向 confllm.GlobalRegistry 注册工厂。
	_ "security-ai-gateway/gateway/confllm-adapter/providers"
	// B 类（隐语 SecretFlow）任务式适配器：同样靠 init() 注册类型键 secretflow。
	// 之前它未实现统一契约 → 进不了注册表 → 已声明的 class=B 在 /v1/adminext/models
	// 被富化「未匹配」分支降级为 unknown（B 类声明值被吞）。
	_ "security-ai-gateway/gateway/confllm-adapter/providers/bclass"
)

// confllmManagedOverrides managed→A override 证明引用表（启动期从
// ADMIN_CONFLLM_OVERRIDES_JSON 加载；缺省空 → 不提升密态等级）。
// key = confllm 运行期实例 ID（= CR provider id）。
var confllmManagedOverrides = map[string]meta.ManagedToAOverride{}

// brokerSecretResolver 基于 broker 内存凭据的 SecretResolver 实现（复用 .env 凭据库）。
//
// 设计：§1.4 / §7.3。broker 未启用（bh==nil）或查无 provider → Resolve 返回 error，
// 上层 provider 路径据此返回 pending_credential（503，fail-closed，§7.3 R5）。
type brokerSecretResolver struct {
	bh *brokerHandler
}

// Resolve 按 SecretRef.Name 在 broker 运行态路由表中取凭据（key/upstream/路径白名单）。
func (r *brokerSecretResolver) Resolve(_ context.Context, ref confllm.SecretRef) (*confllm.Credential, error) {
	if r.bh == nil {
		return nil, fmt.Errorf("broker 未启用，无法解析凭据 %q（pending-credential）", ref.Name)
	}
	route, ok := r.bh.currentRoutes()[ref.Name]
	if !ok || route == nil || route.p == nil {
		return nil, fmt.Errorf("broker 无 provider %q 的凭据（pending-credential）", ref.Name)
	}
	p := route.p
	// 凭据字段全部 json:"-"（§7.2）；此处仅内存构造，绝不打印/序列化 Key。
	return &confllm.Credential{
		Key:             p.key,
		Upstream:        p.upstream.String(),
		AllowedPrefixes: p.allowPathPrefixes,
	}, nil
}

// newConfllmHandler 薄接线 ConfllmHandler：注入 broker 凭据解析器 + 日志 + 证明校验器。
//
// 注册表用 confllm.GlobalRegistry（providers 包 init() 注册各厂工厂；实例由
// loadConfllmProviders 按配置装配）。
func newConfllmHandler(bh *brokerHandler) *confllm.ConfllmHandler {
	resolver := &brokerSecretResolver{bh: bh}
	return confllm.NewConfllmHandler(confllm.GlobalRegistry,
		confllm.WithHandlerResolver(resolver),
		confllm.WithHandlerLogger(confllm.NopLogger{}),
		confllm.WithHandlerAttestation(attest.NoopVerifier{}),
	)
}

// loadConfllmProviders 启动期按 ADMIN_CONFLLM_PROVIDERS_JSON 装配密态上游实例（可选特性）。
//
// 未配置 → 不装配（handler 查无实例返回 provider-not-found；catalog 富化降级 unknown）。
// 配置含各厂商 ProviderConfig（type 选工厂 + id 须与 CR provider id 对齐 + secretRef 指向 broker）。
func loadConfllmProviders(bh *brokerHandler) error {
	raw := os.Getenv("ADMIN_CONFLLM_PROVIDERS_JSON")
	if raw == "" {
		return nil
	}
	var cfgs []confllm.ProviderConfig
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		return fmt.Errorf("ADMIN_CONFLLM_PROVIDERS_JSON 解析失败：%w", err)
	}
	resolver := &brokerSecretResolver{bh: bh}
	for _, c := range cfgs {
		if c.ID == "" {
			return fmt.Errorf("confllm ProviderConfig 缺少 id（须与 CR provider id 对齐）")
		}
		// 配置硬护栏（§7.10 QA2-19）：含字面量 key → invalid_secret_literal，拒绝启动。
		if err := confllm.ValidateConfig(c); err != nil {
			return fmt.Errorf("confllm 配置校验失败 provider %q（fail-closed）：%w", c.ID, err)
		}
		inst, err := confllm.GlobalRegistry.NewFromConfig(c, confllm.WithSecretResolver(resolver))
		if err != nil {
			return fmt.Errorf("confllm 装配 provider %q 失败：%w", c.ID, err)
		}
		confllm.GlobalRegistry.Register(inst)
		log.Printf("[confllm] 已装配密态上游：id=%s type=%s region=%s", inst.ID(), c.Type, inst.Region())
	}
	return nil
}

// loadConfllmManagedOverrides 启动期加载 managed→A override 证明引用（§7.11 B2，可选）。
//
// 仅在 env 非空且 JSON 非法时返回错误（fail-closed 拒绝启动）；缺省不加载 → 不提升。
func loadConfllmManagedOverrides() error {
	raw := os.Getenv("ADMIN_CONFLLM_OVERRIDES_JSON")
	if raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), &confllmManagedOverrides); err != nil {
		return fmt.Errorf("ADMIN_CONFLLM_OVERRIDES_JSON 解析失败：%w", err)
	}
	return nil
}

// registerConfllmRoutes 注册密态推理数据面端点（薄接线，挂鉴权中间件）。
//
// 路由（支持 ?provider= 与 /v1/confllm/{id}/... 两种标识提取，见 handler.go）：
//
//	POST /v1/confllm/chat/completions          或 /v1/confllm/{id}/chat/completions
//	POST /v1/confllm/stream/chat/completions    或 /v1/confllm/{id}/stream/chat/completions
//	GET  /v1/confllm/models
//	GET  /v1/confllm/health
//
// 与既有 trace 端点同构：固定路径与带 {id} 通配路径段数不同，ServeMux 不冲突。
func registerConfllmRoutes(mux *http.ServeMux, cfg *config, h *confllm.ConfllmHandler) {
	if h == nil {
		return
	}
	mux.HandleFunc("/v1/confllm/chat/completions", authMiddleware(cfg, h.HandleChat))
	mux.HandleFunc("/v1/confllm/{id}/chat/completions", authMiddleware(cfg, h.HandleChat))
	mux.HandleFunc("/v1/confllm/stream/chat/completions", authMiddleware(cfg, h.HandleStream))
	mux.HandleFunc("/v1/confllm/{id}/stream/chat/completions", authMiddleware(cfg, h.HandleStream))
	mux.HandleFunc("/v1/confllm/models", authMiddleware(cfg, h.HandleModels))
	mux.HandleFunc("/v1/confllm/health", authMiddleware(cfg, h.HandleHealth))
}
