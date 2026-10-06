package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:30000/infer", "target URL")
	concurrency := flag.Int("c", 10, "concurrency")
	duration := flag.Int("d", 10, "duration in seconds")
	apiKey := flag.String("key", "CHANGE_ME_API_KEY_A", "X-API-Key")
	tenant := flag.String("tenant", "tenant-a", "X-Tenant-ID")
	model := flag.String("model", "qwen-plus", "X-Otp-Model")
	flag.Parse()

	var totalReq int64
	var totalErr int64
	var totalLatency int64 // microseconds
	var minLatency int64 = 1<<63 - 1
	var maxLatency int64

	var wg sync.WaitGroup
	stop := make(chan struct{})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
	}

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			req, err := http.NewRequest("GET", *url, nil)
			if err != nil {
				atomic.AddInt64(&totalErr, 1)
				continue
			}
			req.Header.Set("X-API-Key", *apiKey)
			req.Header.Set("X-Tenant-ID", *tenant)
			req.Header.Set("X-Otp-Model", *model)
			resp, err := client.Do(req)
			latency := time.Since(start).Microseconds()
			if err != nil {
				atomic.AddInt64(&totalErr, 1)
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			atomic.AddInt64(&totalReq, 1)
			atomic.AddInt64(&totalLatency, latency)
			for {
				old := atomic.LoadInt64(&minLatency)
				if latency >= old {
					break
				}
				if atomic.CompareAndSwapInt64(&minLatency, old, latency) {
					break
				}
			}
			for {
				old := atomic.LoadInt64(&maxLatency)
				if latency <= old {
					break
				}
				if atomic.CompareAndSwapInt64(&maxLatency, old, latency) {
					break
				}
			}
		}
	}

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker()
	}

	fmt.Printf("Running %ds @ c=%d → %s\n", *duration, *concurrency, *url)
	time.Sleep(time.Duration(*duration) * time.Second)
	close(stop)
	wg.Wait()

	req := atomic.LoadInt64(&totalReq)
	errs := atomic.LoadInt64(&totalErr)
	avgLat := float64(0)
	if req > 0 {
		avgLat = float64(atomic.LoadInt64(&totalLatency)) / float64(req) / 1000.0
	}
	minLat := float64(atomic.LoadInt64(&minLatency)) / 1000.0
	maxLat := float64(atomic.LoadInt64(&maxLatency)) / 1000.0
	qps := float64(req) / float64(*duration)

	fmt.Println("\n=== 结果 ===")
	fmt.Printf("总请求:   %d\n", req)
	fmt.Printf("错误:     %d\n", errs)
	fmt.Printf("QPS:      %.1f\n", qps)
	fmt.Printf("平均延迟: %.2f ms\n", avgLat)
	fmt.Printf("最小延迟: %.2f ms\n", minLat)
	fmt.Printf("最大延迟: %.2f ms\n", maxLat)
}
