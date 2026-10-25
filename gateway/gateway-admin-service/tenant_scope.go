// Package main — P2-4 T-3.1 策略作用域 scope{global|cluster[]}（设计文档 §6.2）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.2「配置作用域模型
// （贯通既有分发）」+ 主理人裁定：
//
//	① 粒度：顶层（每租户一份 scope）—— 落在 policy_overlays / tenant_provisionings /
//	   model_configs 三张表各一列；DispatchPlan 顶层承载（决策点⑥）。
//	② 存量与默认值：缺省 = global；新列可空，NULL/空视作 global，**不回填**
//	   （满足 T2(6)「注册前无多集群副作用、单集群零中断」）。
//	③ 取值校验：cluster[] 必须来自集群注册表且 status ∈ {active, degraded}；
//	   未注册 / removed / quarantined → 拒绝写入（fail-closed，不静默丢弃）；
//	   **registry 未启用 ⇒ 只允许 global**（无法校验 → 拒绝 cluster[] 写入，不放行）。
//	④ global 与 cluster[] **互斥**（二选一，不做并集）——并集会让"只发 A 集群"的
//	   意图被 global 覆盖，直接产生 V-3 要防的串扰。
//	⑤ scope 变更必须推进 config_version（分发内容变了）。
//	⑥ 载体：DispatchPlan 顶层带 scope（T-3.2 拆分时按 scope 计算目标集群集合）。
//	⑧ 拉式（core 侧）不需要 scope：各集群 core 只拉本集群配置。
//
// 空 cluster 列表：按"**不下发**"（非 global）处理；写路径显式传空数组 → **拒绝**
// （fail-closed，避免"误传空 = 变成全局"）。
//
// 聚合口径（文档未规定，本文件显式定义并单测锁定）：
// 一个租户的配置由 3 张表派生 4 类下发目标，故计划级 scope 由三者**交集**得出：
// global 视为全集（不限制），任一 cluster 作用域都会**收窄**目标集群集合。
// 交集为空 ⇒ 不下发（fail-closed，不退化为 global）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// DispatchScope 策略作用域（§6.2）：global 与 clusters 互斥。
type DispatchScope struct {
	Global   bool     `json:"global"`
	Clusters []string `json:"clusters,omitempty"`
}

// dispatchScopeGlobalJSON 全局作用域的存储形态（最简）。
const dispatchScopeGlobalJSON = `{"global":true}`

// 作用域相关错误（写路径 fail-closed）。
var (
	// errScopeGlobalAndClusters global 与 clusters 同时出现（互斥，决策点④）。
	errScopeGlobalAndClusters = errors.New("scope: global 与 clusters 互斥（二选一）")
	// errScopeEmptyClusters 显式空 cluster 列表（按"不下发"处理，但写路径拒绝）。
	errScopeEmptyClusters = errors.New("scope: clusters 不得为空数组（空集合按不下发处理，写入请拒绝）")
	// errScopeNoRegistry 集群注册表未启用 → 无法校验 cluster[] → 只允许 global。
	errScopeNoRegistry = errors.New("scope: 集群注册表未启用，只允许 global 作用域")
	// errScopeIncomplete 未给出完整作用域（既非 global 也无 clusters）。
	errScopeIncomplete = errors.New("scope: 须给 clusters 列表或 global=true")
)

// scopeWriteRequest 作用域写请求（同时用作响应回显）。
//
// Clusters 用切片而非指针即可区分「字段缺省」（nil = 保持既有 scope，不变更）与
// 「显式空数组」（非 nil 且长度 0 = 按"不下发"处理，写路径拒绝）：encoding/json
// 对缺省字段保持 nil、对 `[]` 产出非 nil 空切片，两者可判别。
type scopeWriteRequest struct {
	Global   bool     `json:"global"`
	Clusters []string `json:"clusters,omitempty"`
}

// specified 作用域字段是否出现在请求中（缺省 = 不变更）。
func (s scopeWriteRequest) specified() bool {
	return s.Global || s.Clusters != nil
}

// resolve 解析为待写入的作用域。
//   - 缺省（specified=false）→ 返回 (nil, nil)：调用方保持既有 scope 不动；
//   - 显式 global → 全局；
//   - 显式 cluster[] → 定向集合（空数组 → 报错，不静默降级为 global）。
func (s scopeWriteRequest) resolve() (*DispatchScope, error) {
	if !s.specified() {
		return nil, nil
	}
	if s.Global {
		if len(s.Clusters) > 0 {
			return nil, errScopeGlobalAndClusters
		}
		return &DispatchScope{Global: true}, nil
	}
	if s.Clusters == nil {
		// global=false 且未给 clusters → 语义不完整 → 拒绝（fail-closed）。
		return nil, errScopeIncomplete
	}
	ids, err := normalizeClusterIDs(s.Clusters)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errScopeEmptyClusters
	}
	return &DispatchScope{Global: false, Clusters: ids}, nil
}

// normalizeClusterIDs 规范化集群 ID 列表（去空白、去重、排序；空项报错）。
func normalizeClusterIDs(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		id := strings.TrimSpace(raw)
		if id == "" {
			return nil, errors.New("scope: clusters 含空集群 ID")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// marshalDispatchScope 序列化为存储形态（空作用域 = global）。
func marshalDispatchScope(sc DispatchScope) string {
	if sc.Global || len(sc.Clusters) == 0 {
		return dispatchScopeGlobalJSON
	}
	b, err := json.Marshal(sc)
	if err != nil {
		return dispatchScopeGlobalJSON
	}
	return string(b)
}

// parseDispatchScope 解析存储形态。
//
// 空串 / NULL / "{}" → global（存量兼容：缺 scope 视作 global，决策点②）。
// 非法 JSON → 报错（fail-closed，不得把坏数据当 global 放行）。
func parseDispatchScope(raw string) (DispatchScope, error) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "null" || s == "{}" {
		return DispatchScope{Global: true}, nil
	}
	var sc DispatchScope
	if err := json.Unmarshal([]byte(s), &sc); err != nil {
		return DispatchScope{}, fmt.Errorf("scope: 解析失败: %w", err)
	}
	if sc.Global && len(sc.Clusters) > 0 {
		return DispatchScope{}, errScopeGlobalAndClusters
	}
	if !sc.Global {
		ids, err := normalizeClusterIDs(sc.Clusters)
		if err != nil {
			return DispatchScope{}, err
		}
		sc.Clusters = ids
	}
	return sc, nil
}

// effectiveDispatchScope 汇总各策略对象的 scope → 计划级 scope。
//
// 规则（交集，global 视为全集）：任一 cluster 作用域收窄目标集群集合；
// 交集为空 ⇒ 空集合（不下发，fail-closed，不退化为 global）。
func effectiveDispatchScope(parts ...string) (DispatchScope, error) {
	var narrowed [][]string
	for _, raw := range parts {
		sc, err := parseDispatchScope(raw)
		if err != nil {
			return DispatchScope{}, err
		}
		if sc.Global {
			continue // 全集：不收窄
		}
		narrowed = append(narrowed, sc.Clusters)
	}
	if len(narrowed) == 0 {
		return DispatchScope{Global: true}, nil
	}
	set := map[string]bool{}
	for _, id := range narrowed[0] {
		set[id] = true
	}
	for _, ids := range narrowed[1:] {
		next := map[string]bool{}
		for _, id := range ids {
			if set[id] {
				next[id] = true
			}
		}
		set = next
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return DispatchScope{Global: false, Clusters: out}, nil
}

// clusterScopeChecker 集群注册表校验接口（T-3.1 scope 写入校验）。
//
// ClusterStore 天然满足（List(ctx) ([]*ClusterRecord, error)）。
type clusterScopeChecker interface {
	List(ctx context.Context) ([]*ClusterRecord, error)
}

// validateDispatchScope 校验 cluster[] 取值（决策点③）。
//
// 必须已注册且 status ∈ {active, degraded}；removed / quarantined / 未注册 → 拒绝。
// checker == nil（registry 未启用）→ 只允许 global。
func validateDispatchScope(ctx context.Context, checker clusterScopeChecker, sc DispatchScope) error {
	if sc.Global {
		return nil
	}
	if len(sc.Clusters) == 0 {
		return errScopeEmptyClusters
	}
	if checker == nil {
		return errScopeNoRegistry
	}
	records, err := checker.List(ctx)
	if err != nil {
		if errors.Is(err, errScopeNoRegistry) {
			return errScopeNoRegistry
		}
		return fmt.Errorf("scope: 查询集群注册表失败（fail-closed）: %w", err)
	}
	byID := make(map[string]*ClusterRecord, len(records))
	for _, rec := range records {
		if rec != nil {
			byID[rec.ID] = rec
		}
	}
	for _, id := range sc.Clusters {
		rec, ok := byID[id]
		if !ok {
			return fmt.Errorf("scope: 集群 %q 未注册（fail-closed）", id)
		}
		if rec.Status != ClusterStatusActive && rec.Status != ClusterStatusDegraded {
			return fmt.Errorf("scope: 集群 %q 状态 %s 不可用于下发（fail-closed）", id, rec.Status)
		}
	}
	return nil
}

// scopeTargetClusters 计算该作用域下的目标集群集合。
//
//	global → 返回 nil（= 全部集群，由调用方按"未限定"处理）；
//	cluster[] → 返回集合；
//	空集合 → 不下发（调用方须跳过投递，不得退化为 global）。
func scopeTargetClusters(sc DispatchScope) ([]string, bool) {
	if sc.Global {
		return nil, true
	}
	if len(sc.Clusters) == 0 {
		return nil, false
	}
	return sc.Clusters, true
}

// ---------- 下发输入的 scope 取值（实体 → 原始存储形态）----------

// provisioningScopeRaw 开通配置的 scope 原始值（实体为 nil → 空 = global）。
func provisioningScopeRaw(p *TenantProvisioning) string {
	if p == nil {
		return ""
	}
	return p.ScopeJSON
}

// policyScopeRaw 策略 overlay 的 scope 原始值（实体为 nil → 空 = global）。
func policyScopeRaw(p *PolicyOverlay) string {
	if p == nil {
		return ""
	}
	return p.ScopeJSON
}

// modelsScopeRaw 模型配置的 scope 原始值（实体为 nil → 空 = global）。
func modelsScopeRaw(m *ModelConfig) string {
	if m == nil {
		return ""
	}
	return m.ScopeJSON
}

// scopeRawOfPolicy 策略 overlay 的 scope 原始值（实体为 nil → 空 = global）。
func scopeRawOfPolicy(p *PolicyOverlay) string {
	return policyScopeRaw(p)
}

// scopeRawOfProvisioning 开通配置的 scope 原始值（实体为 nil → 空 = global）。
func scopeRawOfProvisioning(p *TenantProvisioning) string {
	return provisioningScopeRaw(p)
}

// ---------- 租户写路径接入 ----------

// setScopeResolver 注入集群注册表校验器（装配层调用）。
//
// 未注入时按配置懒加载（见 scopeChecker）；两者都不可用 ⇒ registry 视为未启用
// ⇒ 只允许 global（决策点③）。
func (h *tenantHandler) setScopeResolver(c clusterScopeChecker) {
	h.scopeResolver = c
}

// scopeChecker 返回集群注册表校验器（nil = 注册表未启用 ⇒ 只允许 global）。
func (h *tenantHandler) scopeChecker() clusterScopeChecker {
	if h.scopeResolver != nil {
		return h.scopeResolver
	}
	if h.cfg == nil {
		return nil
	}
	h.scopeLazyOnce.Do(func() {
		h.scopeLazy = newConfigScopeChecker(h.cfg)
	})
	return h.scopeLazy
}

// resolveScopeWrite 解析写请求的作用域并完成校验（决策点③）。
//
//   - req == nil（请求未带 scope）→ 保持既有 scope（存量兼容，决策点②）；
//   - 解析失败 / global 与 clusters 并存 / 显式空数组 / 集群未注册或状态不可用
//     → 报错（fail-closed，写入一律拒绝）。
//
// 返回 (待写入作用域, 是否发生变更, error)。
func (h *tenantHandler) resolveScopeWrite(ctx context.Context, req *scopeWriteRequest, currentRaw string) (DispatchScope, bool, error) {
	current, err := parseDispatchScope(currentRaw)
	if err != nil {
		// 既有数据损坏时不得静默按 global 放行（否则可能误发到全部集群）。
		return DispatchScope{}, false, fmt.Errorf("scope: 既有作用域数据非法（fail-closed）: %w", err)
	}
	if req == nil {
		return current, false, nil
	}
	next, err := req.resolve()
	if err != nil {
		return DispatchScope{}, false, err
	}
	if next == nil {
		return current, false, nil
	}
	if err := validateDispatchScope(ctx, h.scopeChecker(), *next); err != nil {
		return DispatchScope{}, false, err
	}
	return *next, true, nil
}

// scopeResponseOf 把作用域映射为响应视图（回显用）。
func scopeResponseOf(sc DispatchScope) *scopeWriteRequest {
	if sc.Global {
		return &scopeWriteRequest{Global: true}
	}
	ids := append([]string(nil), sc.Clusters...)
	return &scopeWriteRequest{Global: false, Clusters: ids}
}

// ---------- 按配置懒加载集群注册表（scope 校验用）----------

// configScopeChecker 按配置懒加载集群注册表，作为 scope 写入校验器。
//
// 仅在未显式注入校验器时使用（装配层可调 setScopeResolver 复用同一句柄）。
type configScopeChecker struct {
	cfg   *config
	once  sync.Once
	store ClusterStore
	err   error
}

// newConfigScopeChecker 构造懒加载校验器。
func newConfigScopeChecker(cfg *config) *configScopeChecker {
	return &configScopeChecker{cfg: cfg}
}

// List 列出集群（注册表未启用 → errScopeNoRegistry）。
func (c *configScopeChecker) List(ctx context.Context) ([]*ClusterRecord, error) {
	c.once.Do(func() {
		c.store, c.err = openScopeClusterStore(c.cfg)
	})
	if c.err != nil {
		return nil, c.err
	}
	if c.store == nil {
		return nil, errScopeNoRegistry
	}
	return c.store.List(ctx)
}

// openScopeClusterStore 打开集群注册表用于 scope 校验。
//
// 注意：sqlite 打开不存在的路径会**新建空库**——"registry 未启用"的部署若在此
// 被凭空造出空注册表，会把"集群未注册"误判为"校验通过/未校验"。故 sqlite 必须
// 先判文件存在再打开（与迁移工具 `-from-cluster` 的同口径约束一致）。
func openScopeClusterStore(cfg *config) (ClusterStore, error) {
	if cfg == nil {
		return nil, errScopeNoRegistry
	}
	if cfg.clusterStorePGDSN != "" {
		st, err := OpenClusterStore(sqlutil.Postgres, cfg.clusterStorePGDSN)
		if err != nil {
			return nil, fmt.Errorf("scope: 打开集群注册表（PG）失败: %w", err)
		}
		return st, nil
	}
	if cfg.clusterStorePath != "" {
		if _, err := os.Stat(cfg.clusterStorePath); err != nil {
			if os.IsNotExist(err) {
				return nil, errScopeNoRegistry
			}
			return nil, fmt.Errorf("scope: 探测集群注册表文件失败: %w", err)
		}
		st, err := OpenClusterStore(sqlutil.SQLite, cfg.clusterStorePath)
		if err != nil {
			return nil, fmt.Errorf("scope: 打开集群注册表（SQLite）失败: %w", err)
		}
		return st, nil
	}
	return nil, errScopeNoRegistry
}
