package a2aproxy

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// rlCounter is the fixed-window counting backend for the rate-limit engine.
//
// allow increments the counter for key in the current fixed window and
// reports whether the request is within limit. retryAfter is the number of
// seconds until the window resets (0 when allowed).
type rlCounter interface {
	allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, retryAfter int)
}

// rlMemCounter is the in-memory fixed-window counter (dev / no-Redis mode).
//
// Each (key, windowStart) cell counts hits; when the count reaches the
// limit the call is throttled and retryAfter is the seconds left in the
// window. Cells are not actively evicted — the window start is recomputed
// on each access and a stale cell is reset, so memory is bounded by the
// cardinality of live keys (acceptable for the data-plane MVP).
type rlMemCounter struct {
	mu    sync.Mutex
	cells map[string]*rlMemCell
}

type rlMemCell struct {
	start int64 // unix seconds of the current window start
	count int
}

func newRLMemCounter() *rlMemCounter {
	return &rlMemCounter{cells: map[string]*rlMemCell{}}
}

func (m *rlMemCounter) allow(_ context.Context, key string, limit int, window time.Duration) (bool, int) {
	now := time.Now().Unix()
	w := int64(window.Seconds())
	if w <= 0 {
		w = 60
	}
	start := now - (now % w)
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cells[key]
	if c == nil || c.start != start {
		c = &rlMemCell{start: start}
		m.cells[key] = c
	}
	if c.count >= limit {
		ra := int(start + w - now)
		if ra < 1 {
			ra = 1
		}
		return false, ra
	}
	c.count++
	return true, 0
}

// rlRedisCounter is the Redis-backed fixed-window counter. Keys are prefixed
// with A2ARLRedisPrefix (a2a:rl:), isolated from the MCP domain key space.
//
// INCR + EXPIRE implements the window; TTL yields the Retry-After. On Redis
// failure the backend fails OPEN (allows) so a Redis outage cannot take down
// the data plane — rate limiting is availability-protective, not a
// security-deny control.
type rlRedisCounter struct {
	client *redis.Client
	prefix string
}

// NewRLRedisCounter constructs a Redis-backed counter.
func NewRLRedisCounter(client *redis.Client) *rlRedisCounter {
	return &rlRedisCounter{client: client, prefix: A2ARLRedisPrefix}
}

func (r *rlRedisCounter) allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int) {
	full := r.prefix + key
	n, err := r.client.Incr(ctx, full).Result()
	if err != nil {
		// Redis 不可用 → 放行（fail open），避免数据面雪崩。
		return true, 0
	}
	if n == 1 {
		_ = r.client.Expire(ctx, full, window).Err()
	}
	if int(n) > limit {
		ttl, terr := r.client.TTL(ctx, full).Result()
		ra := 1
		if terr == nil {
			if s := int(ttl.Seconds()); s > ra {
				ra = s
			}
		}
		return false, ra
	}
	return true, 0
}
