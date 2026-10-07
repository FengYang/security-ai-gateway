package cacheengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===== fakeOps：内存实现的 redisOps（单测用，不走网络） =====

type fakeOps struct {
	mu      sync.Mutex
	data    map[string][]byte
	ttlSeen map[string]time.Duration
	subFn   func([]byte)
	doFn    func(args ...any) (any, error)
	pingErr error
	closed  bool
}

func newFakeOps() *fakeOps {
	return &fakeOps{data: map[string][]byte{}, ttlSeen: map[string]time.Duration{}}
}

func (f *fakeOps) Get(ctx context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.data[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (f *fakeOps) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(val))
	copy(cp, val)
	f.data[key] = cp
	f.ttlSeen[key] = ttl
	return nil
}

func (f *fakeOps) Del(ctx context.Context, keys ...string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, k := range keys {
		if _, ok := f.data[k]; ok {
			delete(f.data, k)
			n++
		}
	}
	return n, nil
}

func (f *fakeOps) Scan(ctx context.Context, match string, count int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := strings.TrimSuffix(match, "*")
	var out []string
	for k := range f.data {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeOps) Ping(ctx context.Context) error { return f.pingErr }

func (f *fakeOps) Publish(ctx context.Context, channel string, msg []byte) error {
	f.mu.Lock()
	fn := f.subFn
	f.mu.Unlock()
	if fn != nil {
		fn(append([]byte(nil), msg...))
	}
	return nil
}

func (f *fakeOps) Subscribe(ctx context.Context, channel string, fn func([]byte)) error {
	f.mu.Lock()
	f.subFn = fn
	f.mu.Unlock()
	return nil
}

func (f *fakeOps) Do(ctx context.Context, args ...any) (any, error) {
	if f.doFn != nil {
		return f.doFn(args...)
	}
	return nil, errors.New("fakeOps: Do not configured")
}

func (f *fakeOps) Close() error {
	f.closed = true
	return nil
}

// ===== helpers =====

func newTestRedisBackend(t *testing.T) (RedisBackend, *fakeOps) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Scope = "per_tenant"
	kp, err := NewStaticKeyProvider(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	ops := newFakeOps()
	b, err := NewRedisBackend(&cfg, ops, kp)
	if err != nil {
		t.Fatalf("NewRedisBackend: %v", err)
	}
	return b, ops
}

func sampleEntry() *Entry {
	return &Entry{
		Kind:      KindExact,
		TenantID:  "t1",
		Model:     "m1",
		Text:      "secret-answer",
		TokensIn:  3,
		TokensOut: 5,
		ExpireAt:  12345,
		PolicyVer: "v1",
		GuardVer:  "g1",
	}
}

// ===== 测试 =====

func TestRedisBackend_PutGet_RoundTrip(t *testing.T) {
	b, ops := newTestRedisBackend(t)
	ctx := context.Background()
	e := sampleEntry()
	meta := MetaRec{Tenant: "t1", ExpireAt: 12345, PolicyVer: "v1", Model: "m1"}

	if err := b.Put(ctx, KindExact, "kh1", e, meta, 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}

	payloadKey := "og:c:1:e:t1:kh1"
	raw, ok := ops.data[payloadKey]
	if !ok {
		t.Fatalf("payload key %q absent; keys=%v", payloadKey, keysOf(ops))
	}
	if bytes.Contains(raw, []byte("secret-answer")) {
		t.Fatal("Redis payload must be AEAD ciphertext, found plaintext")
	}
	if _, ok := ops.data["og:c:1:meta:kh1"]; !ok {
		t.Fatal("meta key absent")
	}
	// Redis TTL = 内存 TTL + ttl_slack（默认 300s）
	if got := ops.ttlSeen[payloadKey]; got != 330*time.Second {
		t.Fatalf("redis ttl = %v, want 330s", got)
	}

	got, gm, hit, err := b.Get(ctx, KindExact, "kh1")
	if err != nil || !hit {
		t.Fatalf("Get: hit=%v err=%v", hit, err)
	}
	if got.Text != "secret-answer" || got.TokensIn != 3 {
		t.Fatalf("decrypted entry mismatch: %+v", got)
	}
	if gm.Tenant != "t1" {
		t.Fatalf("meta tenant = %q", gm.Tenant)
	}
}

func TestRedisBackend_Get_Miss(t *testing.T) {
	b, _ := newTestRedisBackend(t)
	if _, _, hit, err := b.Get(context.Background(), KindExact, "nope"); err != nil || hit {
		t.Fatalf("expected clean miss, got hit=%v err=%v", hit, err)
	}
}

func TestRedisBackend_Get_AADMismatchAfterTamper(t *testing.T) {
	b, ops := newTestRedisBackend(t)
	ctx := context.Background()
	if err := b.Put(ctx, KindExact, "kh1", sampleEntry(), MetaRec{Tenant: "t1", ExpireAt: 12345, PolicyVer: "v1"}, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// 篡改 meta.expire_at → AAD 不匹配 → 解封失败（防密文搬运/投毒）
	var m MetaRec
	_ = json.Unmarshal(ops.data["og:c:1:meta:kh1"], &m)
	m.ExpireAt = 999
	tampered, _ := json.Marshal(m)
	ops.data["og:c:1:meta:kh1"] = tampered

	if _, _, hit, err := b.Get(ctx, KindExact, "kh1"); err == nil || hit {
		t.Fatalf("expected AEAD failure after tamper, got hit=%v err=%v", hit, err)
	}
}

func TestRedisBackend_Delete(t *testing.T) {
	b, ops := newTestRedisBackend(t)
	ctx := context.Background()
	_ = b.Put(ctx, KindExact, "kh1", sampleEntry(), MetaRec{Tenant: "t1", ExpireAt: 1, PolicyVer: "v1"}, time.Minute)

	ok, err := b.Delete(ctx, KindExact, "kh1")
	if err != nil || !ok {
		t.Fatalf("Delete: ok=%v err=%v", ok, err)
	}
	if len(ops.data) != 0 {
		t.Fatalf("expected all keys removed, got %v", keysOf(ops))
	}
	if ok, _ := b.Delete(ctx, KindExact, "kh1"); ok {
		t.Fatal("second delete should report not found")
	}
}

func TestRedisBackend_DeleteByTenantAndModel(t *testing.T) {
	b, ops := newTestRedisBackend(t)
	ctx := context.Background()
	put := func(kh, tenant, model string) {
		if err := b.Put(ctx, KindExact, kh, sampleEntry(), MetaRec{Tenant: tenant, ExpireAt: 1, PolicyVer: "v1", Model: model}, time.Minute); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	put("kh1", "t1", "m1")
	put("kh2", "t1", "m2")
	put("kh3", "t2", "m1")

	n, err := b.DeleteByTenant(ctx, "t1")
	if err != nil || n != 2 {
		t.Fatalf("DeleteByTenant = (%d, %v), want (2, nil)", n, err)
	}
	if _, ok := ops.data["og:c:1:meta:kh1"]; ok {
		t.Fatal("kh1 meta should be deleted")
	}
	if _, ok := ops.data["og:c:1:meta:kh3"]; !ok {
		t.Fatal("kh3 must remain")
	}

	n, err = b.DeleteByModel(ctx, "m1")
	if err != nil || n != 1 {
		t.Fatalf("DeleteByModel = (%d, %v), want (1, nil)", n, err)
	}
	if len(ops.data) != 0 {
		t.Fatalf("expected empty store, got %v", keysOf(ops))
	}
}

func TestRedisBackend_PublishSubscribe(t *testing.T) {
	b, ops := newTestRedisBackend(t)
	ctx := context.Background()

	var got InvalidateEvent
	if err := b.Subscribe(ctx, func(ev InvalidateEvent) { got = ev }); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := b.Publish(ctx, InvalidateEvent{Op: "tenant", Target: "t1"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got.Op != "tenant" || got.Target != "t1" {
		t.Fatalf("subscriber got %+v", got)
	}
	if got.IssuedAt == 0 {
		t.Fatal("IssuedAt should be auto-filled")
	}
	_ = ops
}

func TestRedisBackend_KeyProviderUnavailable(t *testing.T) {
	cfg := DefaultConfig()
	ops := newFakeOps()
	b, err := NewRedisBackend(&cfg, ops, failingKeyProvider{})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if err := b.Put(context.Background(), KindExact, "kh1", sampleEntry(), MetaRec{}, time.Minute); err == nil {
		t.Fatal("expected Put to fail when key unavailable (fail-closed)")
	}
}

func TestNewRedisBackend_Validation(t *testing.T) {
	cfg := DefaultConfig()
	kp, _ := NewStaticKeyProvider(bytes.Repeat([]byte{1}, 32))
	if _, err := NewRedisBackend(nil, newFakeOps(), kp); err == nil {
		t.Fatal("expected error for nil cfg")
	}
	if _, err := NewRedisBackend(&cfg, nil, kp); err == nil {
		t.Fatal("expected error for nil ops")
	}
	if _, err := NewRedisBackend(&cfg, newFakeOps(), nil); err == nil {
		t.Fatal("expected error for nil key provider")
	}
}

// failingKeyProvider 永远失败（模拟 TEE 密钥不可用）。
type failingKeyProvider struct{}

func (failingKeyProvider) Key(ctx context.Context) ([]byte, error) {
	return nil, errors.New("key unavailable")
}

func keysOf(f *fakeOps) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.data))
	for k := range f.data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
