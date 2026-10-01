package cacheengine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSingleFlight_Basic 基本请求合并：并发相同 key 只执行一次。
func TestSingleFlight_Basic(t *testing.T) {
	cfg := SingleFlightConfig{
		Enabled:       true,
		MaxWait:       3 * time.Second,
		FailurePolicy: "independent",
	}
	sf := NewSingleFlight(cfg)

	var execCount int32
	fn := func() (LookupResult, error) {
		atomic.AddInt32(&execCount, 1)
		time.Sleep(20 * time.Millisecond) // 模拟耗时
		return LookupResult{Hit: true, Kind: KindExact}, nil
	}

	var wg sync.WaitGroup
	n := 10
	results := make([]LookupResult, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = sf.Do("same-key", fn)
		}(i)
	}
	wg.Wait()

	// 只应执行一次
	if atomic.LoadInt32(&execCount) != 1 {
		t.Fatalf("expected 1 execution, got %d", execCount)
	}

	// 所有请求都应拿到结果
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("unexpected error at %d: %v", i, errs[i])
		}
		if !results[i].Hit {
			t.Fatalf("expected hit at %d", i)
		}
	}
}

// TestSingleFlight_DifferentKeys 不同 key 不合并。
func TestSingleFlight_DifferentKeys(t *testing.T) {
	cfg := SingleFlightConfig{Enabled: true, MaxWait: time.Second}
	sf := NewSingleFlight(cfg)

	var execCount int32
	fn := func() (LookupResult, error) {
		atomic.AddInt32(&execCount, 1)
		time.Sleep(10 * time.Millisecond)
		return LookupResult{}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			sf.Do(key, fn)
		}(string(rune('a' + i)))
	}
	wg.Wait()

	if atomic.LoadInt32(&execCount) != 5 {
		t.Fatalf("expected 5 executions for 5 different keys, got %d", execCount)
	}
}

// TestSingleFlight_Disabled 关闭时行为（仍然能工作，只是不合并——这里接口不区分，Do 始终可用）。
func TestSingleFlight_Disabled(t *testing.T) {
	cfg := SingleFlightConfig{Enabled: false, MaxWait: time.Second}
	sf := NewSingleFlight(cfg)

	count := 0
	fn := func() (LookupResult, error) {
		count++
		return LookupResult{}, nil
	}

	sf.Do("k", fn)
	if count != 1 {
		t.Fatalf("expected 1 call, got %d", count)
	}
}
