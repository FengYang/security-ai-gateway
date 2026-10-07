package cacheengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound Redis 未命中（区别于其他错误，调用方按 miss 处理）。
var ErrNotFound = errors.New("cache: redis not found")

// ErrRedisDisabled Redis 后端未启用。
var ErrRedisDisabled = errors.New("cache: redis backend disabled")

// MetaRec = og:c:1:meta:{key_hash} 的明文元数据（不含载荷；§5.3）。
// 相对详设 §5.3.1 增补 Kind/Model 两个非敏感字段：§6.8 的批量失效（按租户/模型）
// 需要在不读密文载荷的前提下定位并删除对应条目，故随元数据一并存储。
type MetaRec struct {
	Tenant    string `json:"tenant"`
	ExpireAt  int64  `json:"expire_at"`
	Hits      uint32 `json:"hits"`
	PolicyVer string `json:"pver"`
	GuardVer  string `json:"gver"`
	KindDim   int    `json:"kdim"`
	Kind      string `json:"kind,omitempty"`  // exact | negative（§6.8 批量失效定位用）
	Model     string `json:"model,omitempty"` // 模型名（§6.8 按模型失效定位用）
}

// InvalidateEvent 失效指令（§6.8.3；幂等键 (op,target,issued_at)）。
type InvalidateEvent struct {
	Op       string `json:"op"` // key | tenant | model | all
	Target   string `json:"target"`
	IssuedAt int64  `json:"issued_at"`
}

// redisOps 仅覆盖本模块需要的命令（便于单测注入 fake；生产由 goRedisOps 实现）。
type redisOps interface {
	Get(ctx context.Context, key string) ([]byte, error) // 未命中返回 ErrNotFound
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) (int64, error)
	Scan(ctx context.Context, match string, count int64) ([]string, error)
	Ping(ctx context.Context) error
	Publish(ctx context.Context, channel string, msg []byte) error
	Subscribe(ctx context.Context, channel string, fn func(msg []byte)) error
	Do(ctx context.Context, args ...any) (any, error)
	Close() error
}

// RedisBackend 密文 blob 读写 + 失效广播（形态 B/C；§5.3.1）。
// 只存 AEAD 密文与明文元数据（§5.3），绝不出明文；密钥由 TEE 内派生根提供。
type RedisBackend interface {
	// Get 读取并解封指定条目；未命中返回 ok=false。
	Get(ctx context.Context, kind EntryKind, keyHash string) (*Entry, MetaRec, bool, error)
	// Put 封装条目并写入（Redis TTL = 内存 TTL + ttl_slack）。
	Put(ctx context.Context, kind EntryKind, keyHash string, e *Entry, meta MetaRec, ttl time.Duration) error
	// Delete 删除指定条目（载荷 + 元数据）。
	Delete(ctx context.Context, kind EntryKind, keyHash string) (bool, error)
	// DeleteByTenant 按租户批量失效（§6.8；部分失败返回 err 且计数为成功数）。
	DeleteByTenant(ctx context.Context, tenant string) (int, error)
	// DeleteByModel 按模型批量失效（§6.8）。
	DeleteByModel(ctx context.Context, model string) (int, error)
	// Ping 健康探测（§6.9 降级判定）。
	Ping(ctx context.Context) error
	// Publish 发布失效指令到 og:c:inv:{policy_version}；指令不含明文。
	Publish(ctx context.Context, ev InvalidateEvent) error
	// Subscribe 订阅失效指令并回调（调用方在本副本执行同一 Delete*）。
	Subscribe(ctx context.Context, fn func(InvalidateEvent)) error
	Close() error
}

// redisBackend RedisBackend 默认实现。
type redisBackend struct {
	ops       redisOps
	kp        KeyProvider
	scope     string
	keyPrefix string
	ttlSlack  time.Duration
	channel   string
	nowFn     nowFunc
}

// NewRedisBackend 构造 Redis 后端（ops 为命令通道，kp 为密钥提供者）。
func NewRedisBackend(cfg *CacheConfig, ops redisOps, kp KeyProvider) (RedisBackend, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cache: redis backend: cfg is nil")
	}
	if ops == nil {
		return nil, fmt.Errorf("cache: redis backend: ops is nil")
	}
	if kp == nil {
		return nil, fmt.Errorf("cache: redis backend: key provider is nil")
	}
	prefix := cfg.Redis.KeyPrefix
	if prefix == "" {
		prefix = "og:c:1:"
	}
	scope := "per_tenant"
	if cfg.Scope == "per_engine_model" {
		scope = "per_engine_model"
	}
	return &redisBackend{
		ops:       ops,
		kp:        kp,
		scope:     scope,
		keyPrefix: prefix,
		ttlSlack:  cfg.Redis.TTLSlack.D(),
		channel:   prefix + "inv:" + cfg.PolicyVersion,
		nowFn:     defaultNow,
	}, nil
}

// ===== 键空间（§5.3）=====

func (b *redisBackend) payloadKey(kind EntryKind, scopeOrTenant, keyHash string) string {
	if kind == KindNegative {
		return b.keyPrefix + "n:" + scopeOrTenant + ":" + keyHash
	}
	return b.keyPrefix + "e:" + scopeOrTenant + ":" + keyHash
}

func (b *redisBackend) metaKey(keyHash string) string { return b.keyPrefix + "meta:" + keyHash }

// scopeOf 计算精确条目的 scope 段（per_tenant → 租户隔离；per_engine_model → "*"）。
func (b *redisBackend) scopeOf(meta MetaRec) string {
	if b.scope == "per_engine_model" {
		return "*"
	}
	return meta.Tenant
}

// ===== 持久化编解码 =====

// persistEntry 落盘 DTO：Entry 的 Text/Segments 在 Entry 上为 json:"-"（防日志泄漏），
// 但在密文内部必须包含，故显式补回。
type persistEntry struct {
	Entry
	Text     string    `json:"text"`
	Segments []Segment `json:"segments,omitempty"`
}

func (b *redisBackend) seal(kind EntryKind, keyHash string, e *Entry, meta MetaRec) ([]byte, error) {
	raw, err := json.Marshal(persistEntry{Entry: *e, Text: e.Text, Segments: e.Segments})
	if err != nil {
		return nil, fmt.Errorf("cache: marshal entry: %w", err)
	}
	key, err := b.kp.Key(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cache: key unavailable: %w", err)
	}
	aad := BuildAAD(keyHash, meta.ExpireAt, meta.PolicyVer)
	blob, err := AEADSeal(key, aad, raw)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func (b *redisBackend) open(keyHash string, meta MetaRec, blob []byte) (*Entry, error) {
	key, err := b.kp.Key(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cache: key unavailable: %w", err)
	}
	aad := BuildAAD(keyHash, meta.ExpireAt, meta.PolicyVer)
	plain, err := AEADOpen(key, aad, blob)
	if err != nil {
		return nil, err
	}
	var p persistEntry
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("cache: unmarshal entry: %w", err)
	}
	e := p.Entry
	e.Text = p.Text
	e.Segments = p.Segments
	return &e, nil
}

// ===== RedisBackend 实现 =====

// Put 封装条目并写入；Redis TTL = 内存 TTL + ttl_slack（§5.3）。
func (b *redisBackend) Put(ctx context.Context, kind EntryKind, keyHash string, e *Entry, meta MetaRec, ttl time.Duration) error {
	if e == nil {
		return fmt.Errorf("cache: put nil entry")
	}
	meta.Kind = string(kind)
	if meta.Model == "" {
		meta.Model = e.Model
	}
	blob, err := b.seal(kind, keyHash, e, meta)
	if err != nil {
		return err
	}
	metaRaw, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("cache: marshal meta: %w", err)
	}
	redisTTL := ttl + b.ttlSlack
	payload := b.payloadKey(kind, b.scopeOf(meta), keyHash)
	if err := b.ops.Set(ctx, payload, blob, redisTTL); err != nil {
		return err
	}
	return b.ops.Set(ctx, b.metaKey(keyHash), metaRaw, redisTTL)
}

// Get 读取并解封；AAD 不匹配即失败（防密文搬运，§7.4）。
func (b *redisBackend) Get(ctx context.Context, kind EntryKind, keyHash string) (*Entry, MetaRec, bool, error) {
	// 先用元数据定位 scope（per_tenant 时仅能按未知 scope 试探两态）。
	metaRaw, err := b.ops.Get(ctx, b.metaKey(keyHash))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, MetaRec{}, false, nil
		}
		return nil, MetaRec{}, false, err
	}
	var meta MetaRec
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, MetaRec{}, false, fmt.Errorf("cache: unmarshal meta: %w", err)
	}
	blob, err := b.ops.Get(ctx, b.payloadKey(kind, b.scopeOf(meta), keyHash))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, meta, false, nil
		}
		return nil, meta, false, err
	}
	e, err := b.open(keyHash, meta, blob)
	if err != nil {
		return nil, meta, false, err
	}
	return e, meta, true, nil
}

// Delete 删除载荷 + 元数据。
func (b *redisBackend) Delete(ctx context.Context, kind EntryKind, keyHash string) (bool, error) {
	metaRaw, err := b.ops.Get(ctx, b.metaKey(keyHash))
	scopeOrTenant := "*"
	if err == nil {
		var meta MetaRec
		if json.Unmarshal(metaRaw, &meta) == nil {
			scopeOrTenant = b.scopeOf(meta)
		}
	}
	n, err := b.ops.Del(ctx, b.payloadKey(kind, scopeOrTenant, keyHash), b.metaKey(keyHash))
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteByTenant 按租户批量失效：SCAN meta 键 → 过滤 tenant → 删除载荷 + meta（§6.8）。
func (b *redisBackend) DeleteByTenant(ctx context.Context, tenant string) (int, error) {
	return b.deleteBy(ctx, func(m MetaRec) bool { return m.Tenant == tenant })
}

// DeleteByModel 按模型批量失效。
func (b *redisBackend) DeleteByModel(ctx context.Context, model string) (int, error) {
	return b.deleteBy(ctx, func(m MetaRec) bool { return m.Model == model })
}

// deleteBy 通用批量失效：遍历 meta 键，匹配者删除对应载荷与 meta。
func (b *redisBackend) deleteBy(ctx context.Context, match func(MetaRec) bool) (int, error) {
	keys, err := b.ops.Scan(ctx, b.keyPrefix+"meta:*", 1000)
	if err != nil {
		return 0, err
	}
	count := 0
	var firstErr error
	for _, mk := range keys {
		raw, err := b.ops.Get(ctx, mk)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var meta MetaRec
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if !match(meta) {
			continue
		}
		keyHash := strings.TrimPrefix(mk, b.keyPrefix+"meta:")
		kind := EntryKind(meta.Kind)
		if kind == "" {
			kind = KindExact
		}
		if _, err := b.ops.Del(ctx, b.payloadKey(kind, b.scopeOf(meta), keyHash), mk); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		count++
	}
	return count, firstErr
}

// Ping 健康探测。
func (b *redisBackend) Ping(ctx context.Context) error { return b.ops.Ping(ctx) }

// Publish 发布失效指令（不含明文）。
func (b *redisBackend) Publish(ctx context.Context, ev InvalidateEvent) error {
	if ev.IssuedAt == 0 {
		ev.IssuedAt = b.nowFn().UnixMilli()
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("cache: marshal invalidate event: %w", err)
	}
	return b.ops.Publish(ctx, b.channel, raw)
}

// Subscribe 订阅失效指令。
func (b *redisBackend) Subscribe(ctx context.Context, fn func(InvalidateEvent)) error {
	return b.ops.Subscribe(ctx, b.channel, func(msg []byte) {
		var ev InvalidateEvent
		if err := json.Unmarshal(msg, &ev); err != nil {
			return
		}
		fn(ev)
	})
}

// Close 关闭底层连接。
func (b *redisBackend) Close() error { return b.ops.Close() }
