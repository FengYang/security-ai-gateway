// Package ratelimitcache — 限流表本地缓存（Phase 1 门禁 #7 / 判据 5）。
//
// 定位：插件侧「策略源」缓存——周期 tick 从 gateway-core `GET /ratelimits` 拉取**已签名**的
// 限流表，验签通过且版本不倒退才入缓存；**失败保留旧表**（可用性优先，与 routecache 同策略）。
//
// 与 gateway-core 的 `internal/ratelimit` **故意不共享代码**（插件不能 import 控制面 internal 包），
// 故此处复刻其 JSON 形状与 CanonicalBytes 字段序；`canon` 的一致性由固定向量测试锁死
// （见 ratelimitcache_test.go，与 routecache 的 canon 固定夹具同一做法）。
//
// 范围（如实）：本包交付**拉取与失败语义**（判据 5）。数据面限流执行仍走控制面编译产物
// （cluster-key-rate-limit 配置）；本缓存的规则可供影子计数/后续下发适配器消费。
package ratelimitcache

import (
	"encoding/json"
	"sync"
)

// Rule 限流规则（字段与 gateway-core internal/ratelimit.Rule 的 JSON 标签对齐）。
type Rule struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Scope             string `json:"scope"`
	Target            string `json:"target"`
	TargetFingerprint string `json:"target_fingerprint,omitempty"`
	RPM               int64  `json:"rpm,omitempty"`
	TPM               int64  `json:"tpm,omitempty"`
	DailyBudgetTokens int64  `json:"daily_budget_tokens,omitempty"`
	BurstMultiplier   int64  `json:"burst_multiplier,omitempty"`
	Action            string `json:"action"`
	Enabled           bool   `json:"enabled"`
}

// Table 限流表（JSON 与 gateway-core internal/ratelimit.Table 对齐）。
type Table struct {
	Version   int    `json:"version"`
	IssuedAt  string `json:"issued_at"`
	Rules     []Rule `json:"rules"`
	Signature []byte `json:"signature,omitempty"`
}

// canon 生成不含签名的规范字节（字段序须与 gateway-core Table.CanonicalBytes 一致）。
func (t *Table) canon() []byte {
	payload := struct {
		Version  int    `json:"version"`
		IssuedAt string `json:"issued_at"`
		Rules    []Rule `json:"rules"`
	}{t.Version, t.IssuedAt, t.Rules}
	b, _ := json.Marshal(payload)
	return b
}

// Verifier 表签名校验接缝（P0-4 §4.7 分层：本包为纯逻辑，**不 import 密码/hostcall**）。
// 插件注入经 cryptop sidecar（`/v1/hmac` 出 MAC + 常量时间比较，密钥字节恒驻 sidecar）的实现；
// 单测注入**同步**实现，令 CPS 调用同步完成（同 cryptoseam_test.go 手法）。
type Verifier interface {
	// VerifySym 校验 canon 字节 data 的对称 MAC sig（keyRef = K_rx 句柄，§6.3 命名）。
	// cb(ok, err)：err 非空 = 校验不可用（fail-closed，调用方须拒绝该表）。
	VerifySym(keyRef string, data, sig []byte, cb func(ok bool, err error))
}

// Cache 限流表缓存（单表 + 版本单调准入）。
type Cache struct {
	mu       sync.RWMutex
	verifier Verifier
	keyRef   string
	table    *Table
}

// New 构造缓存（keyRef = K_rx 句柄，与路由表同一密钥族；verifier 为 §4.7 注入的验签接缝）。
func New(verifier Verifier, keyRef string) *Cache {
	return &Cache{verifier: verifier, keyRef: keyRef}
}

// Update 验签 + 防回滚（版本必须严格递增）后写入缓存（CPS 交付）。
// 拒绝情形：验签失败/不可用 / 版本未递增（重复或回退）→ 调用方保留旧表并计数。
func (c *Cache) Update(t *Table, cb func(accepted bool)) {
	if t == nil || c.verifier == nil {
		cb(false)
		return
	}
	c.verifier.VerifySym(c.keyRef, t.canon(), t.Signature, func(ok bool, err error) {
		if err != nil || !ok {
			cb(false)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.table != nil && t.Version <= c.table.Version {
			cb(false)
			return
		}
		c.table = t
		cb(true)
	})
}

// Loaded 是否已有可用的已验签表（false = 从未拉到 → 按设计 §6 放行 + 告警）。
func (c *Cache) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.table != nil
}

// Version 当前生效版本（无表返回 0）。
func (c *Cache) Version() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.table == nil {
		return 0
	}
	return c.table.Version
}

// Rules 返回当前规则副本（供影子计数/下发适配器消费；无表返回 nil）。
func (c *Cache) Rules() []Rule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.table == nil {
		return nil
	}
	out := make([]Rule, len(c.table.Rules))
	copy(out, c.table.Rules)
	return out
}
