package cryptopmodule

// session_test.go —— 会话池测试（B-6.1-7 / GM2-05）。

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestPool(t *testing.T, max, queue int) (*SessionPool, *int64) {
	t.Helper()
	var created, closed int64
	p, err := NewSessionPool(max, queue,
		func() (Session, error) {
			atomic.AddInt64(&created, 1)
			return Session(atomic.LoadInt64(&created)), nil
		},
		func(Session) error {
			atomic.AddInt64(&closed, 1)
			return nil
		})
	if err != nil {
		t.Fatalf("NewSessionPool: %v", err)
	}
	return p, &created
}

func TestSessionPoolReuseAndMax(t *testing.T) {
	p, created := newTestPool(t, 2, 4)
	defer p.Close()

	s1, err := p.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	s2, err := p.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if s1 == s2 {
		t.Fatal("两个会话应不同")
	}
	if got := atomic.LoadInt64(created); got != 2 {
		t.Fatalf("created=%d, want 2", got)
	}
	// 池满（2/2）：第三个 Acquire 应排队等待而非立即返回。
	done := make(chan error, 1)
	go func() {
		_, err := p.Acquire()
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("池满时应排队等待而非立即返回（err=%v）", err)
	case <-time.After(100 * time.Millisecond):
	}
	// 释放 s1 → 排队者获得 s1（并持有）。
	if err := p.Release(s1); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("释放后排队者应获得会话: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("释放后排队者未获会话（死锁？）")
	}
	// 此时 s1（排队者持有）+ s2（主线程持有）均在途；释放 s2 后再取 → 复用 s2。
	if err := p.Release(s2); err != nil {
		t.Fatalf("Release: %v", err)
	}
	s3, err := p.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if s3 != s2 {
		t.Fatalf("应复用空闲会话 s2=%d, got %d", s2, s3)
	}
	st := p.Stats()
	if st.InUse != 2 || st.Idle != 0 || st.Max != 2 {
		t.Fatalf("池状态异常: %+v", st)
	}
}

func TestSessionPoolQueueExhausted(t *testing.T) {
	p, _ := newTestPool(t, 1, 1)
	defer p.Close()

	s1, err := p.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	// 占满池（1/1）；queue=1 → 第 1 个排队者占位，第 2 个立即 ErrSessionExhausted。
	firstDone := make(chan error, 1)
	go func() { _, err := p.Acquire(); firstDone <- err }()
	time.Sleep(50 * time.Millisecond) // 确保第一个进入等待
	_, err = p.Acquire()
	if !errors.Is(err, ErrSessionExhausted) {
		t.Fatalf("排队超限应 ErrSessionExhausted, got %v", err)
	}
	// 释放后排队者成功。
	if err := p.Release(s1); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("排队者应成功: %v", err)
	}
}

func TestSessionPoolConcurrentAcquireRelease(t *testing.T) {
	p, _ := newTestPool(t, 4, 16)
	defer p.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s, err := p.Acquire()
				if err != nil {
					errs <- err
					return
				}
				if err := p.Release(s); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发取还会话出错: %v", err)
	}
	st := p.Stats()
	if st.InUse != 0 || st.Waiters != 0 {
		t.Fatalf("结束后池应空闲: %+v", st)
	}
}

func TestSessionPoolClose(t *testing.T) {
	var closed int64
	p, _ := NewSessionPool(2, 2,
		func() (Session, error) { return Session(1), nil },
		func(Session) error { atomic.AddInt64(&closed, 1); return nil })

	s, err := p.Acquire()
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := p.Release(s); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := atomic.LoadInt64(&closed); got != 1 {
		t.Fatalf("Close 应销毁空闲会话（closed=%d）", got)
	}
	if _, err := p.Acquire(); !errors.Is(err, ErrModuleUnavailable) {
		t.Fatalf("关闭后 Acquire 应 ErrModuleUnavailable, got %v", err)
	}
	// 关闭后 Release 直接关闭会话（不回流）。
	if err := p.Release(Session(99)); err != nil {
		t.Fatalf("关闭后 Release: %v", err)
	}
	if got := atomic.LoadInt64(&closed); got != 2 {
		t.Fatalf("关闭后 Release 应关闭该会话（closed=%d）", got)
	}
}

func TestSessionPoolFactoryErrorReleasesSlot(t *testing.T) {
	p, _ := NewSessionPool(1, 0,
		func() (Session, error) { return 0, errors.New("boom") },
		func(Session) error { return nil })
	defer p.Close()

	if _, err := p.Acquire(); err == nil {
		t.Fatal("factory 失败应传播")
	}
	// 占位应已释放：再次 Acquire 仍走 factory（而非 ErrSessionExhausted）。
	if _, err := p.Acquire(); err == nil {
		t.Fatal("factory 仍失败")
	}
	st := p.Stats()
	if st.InUse != 0 {
		t.Fatalf("factory 失败应释放占位: %+v", st)
	}
}
