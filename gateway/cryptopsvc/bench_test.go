package cryptopsvc

// T-8.2 / T-8.3 基准（§8.3）：sidecar 真实 HTTP over loopback（httptest）+ JSON，
// 连接复用（对齐 §8.2② Envoy cluster 承担连接复用）。

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"testing"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

const (
	sidecarP99Budget = 10 * time.Millisecond // §4.5-④：S2 唯一硬延迟指标
	sidecarSamples   = 4096
	sidecarGroup     = 64 // 组计时（~8ms/组）：本机单调钟读数粒度大，逐次调用多被读 0
	sidecarWarmup    = 64
	sidecarPayload   = 1024 // 1KB
	batchOpsCount    = 64
)

// benchProfiles §8.3 矩阵两档。
var benchProfiles = []cryptop.Profile{cryptop.ProfileIntl, cryptop.ProfileSMSW}

func newSidecarClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}}
}

func sealRequestRaw() []byte {
	raw, err := json.Marshal(map[string]string{
		"key_ref":   "static/aead",
		"aad":       base64.StdEncoding.EncodeToString([]byte("otpmask/bench")),
		"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7A}, sidecarPayload)),
	})
	if err != nil {
		panic(fmt.Sprintf("marshal seal request: %v", err)) // 固定 map 不会失败
	}
	return raw
}

// postSidecar 发送一次 POST 并读完响应体（延迟含真实网络 + 序列化）。
func postSidecar(client *http.Client, baseURL, path string, raw []byte) error {
	resp, err := client.Post(baseURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s 返回状态 %d", path, resp.StatusCode)
	}
	return nil
}

// latencyPercentiles 复制后排序，以最近秩（nearest-rank）取 P50/P99。
func latencyPercentiles(ds []time.Duration) (p50, p99 time.Duration) {
	sorted := append([]time.Duration(nil), ds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	nearestRank := func(q float64) time.Duration {
		idx := int(q*float64(len(sorted))+0.999999) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx]
	}
	return nearestRank(0.50), nearestRank(0.99)
}

func reportSidecarPercentiles(b *testing.B, ds []time.Duration) {
	b.Helper()
	p50, p99 := latencyPercentiles(ds)
	b.ReportMetric(float64(p50), "p50-ns")
	b.ReportMetric(float64(p99), "p99-ns")
}

// TestSidecarSealLatencyP99 T-8.2：两档 sidecar seal(1KB) 各 4096 次，组计时均摊，P99 ≤ 10ms。
// 硬指标随 go test 生效，不仅依赖手工 -bench。
func TestSidecarSealLatencyP99(t *testing.T) {
	for _, profile := range benchProfiles {
		_, ts, _ := newTestServer(t, profile)
		client := newSidecarClient()
		raw := sealRequestRaw()
		for i := 0; i < sidecarWarmup; i++ {
			if err := postSidecar(client, ts.URL, "/v1/seal", raw); err != nil {
				t.Fatalf("profile=%s warmup: %v", profile, err)
			}
		}
		groups := sidecarSamples / sidecarGroup
		durations := make([]time.Duration, groups)
		for g := range durations {
			start := time.Now()
			for k := 0; k < sidecarGroup; k++ {
				if err := postSidecar(client, ts.URL, "/v1/seal", raw); err != nil {
					t.Fatalf("profile=%s seal: %v", profile, err)
				}
			}
			durations[g] = time.Since(start) / sidecarGroup
		}
		p50, p99 := latencyPercentiles(durations)
		t.Logf("T-8.2 profile=%s sidecar seal(1KB) P50=%v P99=%v（n=%d，%d/组均摊）",
			profile, p50, p99, sidecarSamples, sidecarGroup)
		if p99 > sidecarP99Budget {
			t.Errorf("T-8.2 profile=%s sidecar P99=%v > 预算 %v", profile, p99, sidecarP99Budget)
		}
	}
}

// batchRequestRaw 构造含 64 个 seal op 的 /v1/batch 请求体。
func batchRequestRaw() []byte {
	aadB64 := base64.StdEncoding.EncodeToString([]byte("otpmask/bench"))
	ptB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7A}, sidecarPayload))
	ops := make([]map[string]string, 0, batchOpsCount)
	for i := 0; i < batchOpsCount; i++ {
		ops = append(ops, map[string]string{
			"id":        strconv.Itoa(i),
			"op":        "seal",
			"key_ref":   "static/aead",
			"aad":       aadB64,
			"plaintext": ptB64,
		})
	}
	raw, err := json.Marshal(map[string]any{"ops": ops})
	if err != nil {
		panic(fmt.Sprintf("marshal batch request: %v", err))
	}
	return raw
}

// TestBatchVsSequential T-8.3：64 seal op——/v1/batch 单次 vs 64 次顺序单调用，报耗时对比。
func TestBatchVsSequential(t *testing.T) {
	for _, profile := range benchProfiles {
		_, ts, _ := newTestServer(t, profile)
		client := newSidecarClient()
		sealRaw := sealRequestRaw()
		batchRaw := batchRequestRaw()

		if err := postSidecar(client, ts.URL, "/v1/batch", batchRaw); err != nil {
			t.Fatalf("profile=%s batch warmup: %v", profile, err)
		}
		for i := 0; i < 10; i++ {
			if err := postSidecar(client, ts.URL, "/v1/seal", sealRaw); err != nil {
				t.Fatalf("profile=%s seal warmup: %v", profile, err)
			}
		}

		start := time.Now()
		if err := postSidecar(client, ts.URL, "/v1/batch", batchRaw); err != nil {
			t.Fatalf("profile=%s batch: %v", profile, err)
		}
		batchDur := time.Since(start)

		start = time.Now()
		for i := 0; i < batchOpsCount; i++ {
			if err := postSidecar(client, ts.URL, "/v1/seal", sealRaw); err != nil {
				t.Fatalf("profile=%s sequential seal %d: %v", profile, i, err)
			}
		}
		sequentialDur := time.Since(start)

		speedup := float64(sequentialDur) / float64(batchDur)
		t.Logf("T-8.3 profile=%s 64×seal(1KB)：batch=%v sequential=%v 加速比=%.2fx",
			profile, batchDur, sequentialDur, speedup)
		if batchDur >= sequentialDur {
			t.Errorf("T-8.3 profile=%s batch=%v 不优于 sequential=%v", profile, batchDur, sequentialDur)
		}
	}
}

// BenchmarkSidecarSeal sidecar seal 基准（吞吐 + P50/P99）。
func BenchmarkSidecarSeal(b *testing.B) {
	for _, profile := range benchProfiles {
		_, ts, _ := newTestServer(b, profile)
		client := newSidecarClient()
		raw := sealRequestRaw()
		b.Run(string(profile), func(b *testing.B) {
			for i := 0; i < sidecarWarmup; i++ {
				if err := postSidecar(client, ts.URL, "/v1/seal", raw); err != nil {
					b.Fatalf("warmup: %v", err)
				}
			}
			groups := b.N / sidecarGroup
			if groups < 1 {
				groups = 1
			}
			durations := make([]time.Duration, groups)
			b.SetBytes(sidecarPayload)
			b.ResetTimer()
			for g := 0; g < groups; g++ {
				start := time.Now()
				for k := 0; k < sidecarGroup; k++ {
					if err := postSidecar(client, ts.URL, "/v1/seal", raw); err != nil {
						b.Fatalf("seal: %v", err)
					}
				}
				durations[g] = time.Since(start) / sidecarGroup
			}
			b.StopTimer()
			reportSidecarPercentiles(b, durations)
		})
	}
}

// BenchmarkBatchVsSequential 每次迭代处理 64 个 seal op：/v1/batch 单请求 vs 顺序 64 请求。
func BenchmarkBatchVsSequential(b *testing.B) {
	for _, profile := range benchProfiles {
		_, ts, _ := newTestServer(b, profile)
		client := newSidecarClient()
		sealRaw := sealRequestRaw()
		batchRaw := batchRequestRaw()

		b.Run(string(profile)+"/Batch", func(b *testing.B) {
			if err := postSidecar(client, ts.URL, "/v1/batch", batchRaw); err != nil {
				b.Fatalf("warmup: %v", err)
			}
			b.SetBytes(batchOpsCount * sidecarPayload)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := postSidecar(client, ts.URL, "/v1/batch", batchRaw); err != nil {
					b.Fatalf("batch: %v", err)
				}
			}
		})

		b.Run(string(profile)+"/Sequential", func(b *testing.B) {
			for i := 0; i < 10; i++ {
				if err := postSidecar(client, ts.URL, "/v1/seal", sealRaw); err != nil {
					b.Fatalf("warmup: %v", err)
				}
			}
			b.SetBytes(batchOpsCount * sidecarPayload)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < batchOpsCount; j++ {
					if err := postSidecar(client, ts.URL, "/v1/seal", sealRaw); err != nil {
						b.Fatalf("seal %d: %v", j, err)
					}
				}
			}
		})
	}
}
