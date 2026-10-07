package cacheengine

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// goRedisOps 基于 go-redis/v9 的 redisOps 实现（生产通道）。
type goRedisOps struct{ cli *redis.Client }

// NewGoRedisOps 按配置构造 go-redis 通道。
// 注：PasswordRef 为密钥引用（§5.3 密钥分级），P0 暂不解析（部署侧通过受限网络访问）。
func NewGoRedisOps(cfg RedisConfig) *goRedisOps {
	return &goRedisOps{cli: redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		PoolTimeout:  cfg.PoolTimeout.D(),
		DialTimeout:  cfg.DialTimeout.D(),
		ReadTimeout:  cfg.ReadTimeout.D(),
		WriteTimeout: cfg.WriteTimeout.D(),
		MaxRetries:   cfg.MaxRetries,
	})}
}

// NewGoRedisBackend 便捷构造：go-redis 通道 + 密钥提供者。
func NewGoRedisBackend(cfg *CacheConfig, kp KeyProvider) (RedisBackend, error) {
	return NewRedisBackend(cfg, NewGoRedisOps(cfg.Redis), kp)
}

func (o *goRedisOps) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := o.cli.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	return b, err
}

func (o *goRedisOps) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	return o.cli.Set(ctx, key, val, ttl).Err()
}

func (o *goRedisOps) Del(ctx context.Context, keys ...string) (int64, error) {
	return o.cli.Del(ctx, keys...).Result()
}

func (o *goRedisOps) Scan(ctx context.Context, match string, count int64) ([]string, error) {
	var out []string
	var cursor uint64
	for {
		keys, next, err := o.cli.Scan(ctx, cursor, match, count).Result()
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

func (o *goRedisOps) Ping(ctx context.Context) error { return o.cli.Ping(ctx).Err() }

func (o *goRedisOps) Publish(ctx context.Context, channel string, msg []byte) error {
	return o.cli.Publish(ctx, channel, msg).Err()
}

func (o *goRedisOps) Subscribe(ctx context.Context, channel string, fn func([]byte)) error {
	ps := o.cli.Subscribe(ctx, channel)
	defer func() { _ = ps.Close() }()
	if _, err := ps.Receive(ctx); err != nil { // 等待订阅确认，避免丢首条消息
		return err
	}
	ch := ps.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			fn([]byte(msg.Payload))
		}
	}
}

func (o *goRedisOps) Do(ctx context.Context, args ...any) (any, error) {
	return o.cli.Do(ctx, args...).Result()
}

func (o *goRedisOps) Close() error { return o.cli.Close() }
