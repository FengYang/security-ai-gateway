package cacheengine

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// 集成测试：需要真实 Redis（形态 B 密文读写 + 失效广播）。
// 未设置 CACHE_REDIS_TEST_ADDR 时自动跳过（本地/CI 无 Redis 时不影响门禁）。
//
// 运行示例：
//   CACHE_REDIS_TEST_ADDR=127.0.0.1:6379 CACHE_REDIS_TEST_DB=15 \
//     go test ./gateway/tee-infer-service/cacheengine/ -run Integration -v
func TestGoRedisBackend_Integration(t *testing.T) {
	addr := os.Getenv("CACHE_REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("CACHE_REDIS_TEST_ADDR not set; skipping Redis integration test")
	}
	db := 15
	if v := os.Getenv("CACHE_REDIS_TEST_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			db = n
		}
	}

	cfg := DefaultConfig()
	cfg.Redis = RedisConfig{
		Enabled: true, Addr: addr, DB: db, KeyPrefix: "og:c:test:",
		TTLSlack: Duration(30 * time.Second), PoolSize: 4,
		PoolTimeout: Duration(time.Second), DialTimeout: Duration(time.Second),
		ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), MaxRetries: 0,
	}
	cfg.Scope = "per_tenant"

	kp, err := NewStaticKeyProvider(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	ops := NewGoRedisOps(cfg.Redis)
	defer func() { _ = ops.Close() }()
	back, err := NewRedisBackend(&cfg, ops, kp)
	if err != nil {
		t.Fatalf("NewRedisBackend: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := back.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	const kh = "kh-integration"
	payloadKey := cfg.Redis.KeyPrefix + "e:t-int:" + kh
	metaKey := cfg.Redis.KeyPrefix + "meta:" + kh
	_, _ = ops.Del(ctx, payloadKey, metaKey) // 预清理

	e := &Entry{Kind: KindExact, TenantID: "t-int", Model: "m-int", Text: "integration-text",
		TokensIn: 2, TokensOut: 3, ExpireAt: 1, PolicyVer: "v1", GuardVer: "g1"}
	meta := MetaRec{Tenant: "t-int", ExpireAt: 1, PolicyVer: "v1", GuardVer: "g1", Model: "m-int"}

	if err := back.Put(ctx, KindExact, kh, e, meta, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// 明文不得落 Redis（抓取原始字节断言）
	raw, err := ops.Get(ctx, payloadKey)
	if err != nil {
		t.Fatalf("raw get: %v", err)
	}
	if bytes.Contains(raw, []byte("integration-text")) {
		t.Fatal("plaintext leaked to Redis")
	}

	got, _, hit, err := back.Get(ctx, KindExact, kh)
	if err != nil || !hit {
		t.Fatalf("Get: hit=%v err=%v", hit, err)
	}
	if got.Text != "integration-text" {
		t.Fatalf("decrypted mismatch: %q", got.Text)
	}

	if ok, err := back.Delete(ctx, KindExact, kh); err != nil || !ok {
		t.Fatalf("Delete: ok=%v err=%v", ok, err)
	}
}

// TestDetectRediSearch_Integration 真实环境探测（仅记录，不硬断言）。
func TestDetectRediSearch_Integration(t *testing.T) {
	addr := os.Getenv("CACHE_REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("CACHE_REDIS_TEST_ADDR not set; skipping Redis integration test")
	}
	db := 15
	if v := os.Getenv("CACHE_REDIS_TEST_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			db = n
		}
	}
	ops := NewGoRedisOps(RedisConfig{Addr: addr, DB: db, DialTimeout: Duration(time.Second), ReadTimeout: Duration(time.Second)})
	defer func() { _ = ops.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	has := DetectRediSearch(ctx, ops)
	t.Logf("RediSearch available = %v (addr=%s)", has, addr)
}
