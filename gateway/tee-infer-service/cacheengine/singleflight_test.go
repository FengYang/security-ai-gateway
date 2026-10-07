package cacheengine

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSingleFlight_Basic 基本请求合并：并发相同 key 只执行一次。
func TestSingleFlight_Basic(t *testing.T) {
	cfg := SingleFlightConfig{
		Enabled:       true,
		MaxWait:       Duration(3 * time.Second),
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
	sharedFlags := make([]bool, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], sharedFlags[idx], errs[idx] = sf.Do("same-key", fn)
		}(i)
	}
	wg.Wait()

	// 只应执行一次
	if atomic.LoadInt32(&execCount) != 1 {
		t.Fatalf("expected 1 execution, got %d", execCount)
	}

	// 所有请求都应拿到结果；恰好一个 leader（shared=false），其余为跟随者（shared=true）
	leaders := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("unexpected error at %d: %v", i, errs[i])
		}
		if !results[i].Hit {
			t.Fatalf("expected hit at %d", i)
		}
		if !sharedFlags[i] {
			leaders++
		}
	}
	if leaders != 1 {
		t.Fatalf("expected exactly 1 leader, got %d", leaders)
	}
}

// TestSingleFlight_DifferentKeys 不同 key 不合并。
func TestSingleFlight_DifferentKeys(t *testing.T) {
	cfg := SingleFlightConfig{Enabled: true, MaxWait: Duration(time.Second)}
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
			_, _, _ = sf.Do(key, fn)
		}(string(rune('a' + i)))
	}
	wg.Wait()

	if atomic.LoadInt32(&execCount) != 5 {
		t.Fatalf("expected 5 executions for 5 different keys, got %d", execCount)
	}
}

// TestSingleFlight_MaxWaitFallback 跟随者等待超过 max_wait → 返回超时哨兵（§6.13 B-6.13-3 / T-6.13-4）。
func TestSingleFlight_MaxWaitFallback(t *testing.T) {
	cfg := SingleFlightConfig{Enabled: true, MaxWait: Duration(20 * time.Millisecond)}
	sf := NewSingleFlight(cfg)

	release := make(chan struct{})
	leaderStarted := make(chan struct{})
	fn := func() (LookupResult, error) {
		close(leaderStarted)
		<-release // 阻塞 leader，制造跟随者等待超时
		return LookupResult{Hit: true, Kind: KindExact}, nil
	}

	type out struct {
		res LookupResult
		err error
	}
	leaderCh := make(chan out, 1)
	go func() {
		r, _, e := sf.Do("k", fn)
		leaderCh <- out{r, e}
	}()
	<-leaderStarted

	// 跟随者：leader 仍阻塞，应在 max_wait 后超时返回哨兵
	if _, shared, err := sf.Do("k", func() (LookupResult, error) { return LookupResult{}, nil }); !errors.Is(err, ErrSingleFlightTimeout) {
		t.Fatalf("expected ErrSingleFlightTimeout, got %v", err)
	} else if shared {
		t.Fatal("timeout 跟随者不应标记为 shared")
	}

	close(release)
	if lo := <-leaderCh; lo.err != nil || !lo.res.Hit {
		t.Fatalf("leader should succeed: res=%+v err=%v", lo.res, lo.err)
	}
}

// TestSingleFlight_Disabled 关闭时行为（仍然能工作，只是不合并——这里接口不区分，Do 始终可用）。
func TestSingleFlight_Disabled(t *testing.T) {
	cfg := SingleFlightConfig{Enabled: false, MaxWait: Duration(time.Second)}
	sf := NewSingleFlight(cfg)

	count := 0
	fn := func() (LookupResult, error) {
		count++
		return LookupResult{}, nil
	}

	if _, shared, _ := sf.Do("k", fn); shared {
		t.Fatal("首次调用应为 leader（shared=false）")
	}
	if count != 1 {
		t.Fatalf("expected 1 call, got %d", count)
	}
}
