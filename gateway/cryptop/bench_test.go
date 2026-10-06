package cryptop

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// T-8.1 微基准（§8.3）：矩阵 {intl, sm-software} × {Seal/Open, Hash, HMAC, Sign/Verify, KDF} × {1KB, 64KB}。
// 每项报吞吐（go test 依 SetBytes 自动计算 MB/s）+ P50/P99 延迟（自定义指标）。
// sm-software 不设与 AES 的吞吐硬比值（§8.1 F-P1-6），结果如实报告。

const (
	bench1KB  = 1024
	bench64KB = 64 * 1024
)

// benchOp 执行 b.N 次 fn 并报告 P50/P99；bytes > 0 时同时报吞吐。
// 自适应组计时：先以倍增探针估单次耗时（本机 Windows 单调钟在紧循环下读数粒度可达数 ms，
// 小组耗时会被读成 0），再按每组 ≥ 5ms 定组大小，组计时均摊为单次耗时。
func benchOp(b *testing.B, bytes int, fn func()) {
	b.Helper()
	if bytes > 0 {
		b.SetBytes(int64(bytes))
	}

	probeN := 128
	var probeDur time.Duration
	for {
		start := time.Now()
		for i := 0; i < probeN; i++ {
			fn()
		}
		probeDur = time.Since(start)
		if probeDur > 0 || probeN >= b.N {
			break
		}
		probeN *= 8
	}
	perOp := time.Duration(int64(probeDur) / int64(probeN))
	if perOp < 1 {
		perOp = 1
	}
	group := int((5 * time.Millisecond) / perOp)
	if group < 1 {
		group = 1
	}
	if group > b.N {
		group = b.N
	}
	groups := b.N / group
	if groups < 1 {
		group, groups = b.N, 1
	}

	durations := make([]time.Duration, groups)
	b.ResetTimer()
	for g := 0; g < groups; g++ {
		start := time.Now()
		for k := 0; k < group; k++ {
			fn()
		}
		durations[g] = time.Since(start) / time.Duration(group)
	}
	b.StopTimer()
	reportLatencyPercentiles(b, durations)
}

// reportLatencyPercentiles 排序后以最近秩（nearest-rank）取 P50/P99，单位 ns。
func reportLatencyPercentiles(b *testing.B, ds []time.Duration) {
	b.Helper()
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	nearestRank := func(q float64) time.Duration {
		idx := int(q*float64(len(ds))+0.999999) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(ds) {
			idx = len(ds) - 1
		}
		return ds[idx]
	}
	b.ReportMetric(float64(nearestRank(0.50)), "p50-ns")
	b.ReportMetric(float64(nearestRank(0.99)), "p99-ns")
}

// benchmarkProfile 构造单档 Provider 并跑全部原语 × 尺寸子基准。
func benchmarkProfile(b *testing.B, profile Profile) {
	p, err := New(profile)
	if err != nil {
		b.Fatalf("New(%s): %v", profile, err)
	}
	key := make([]byte, p.SymmetricKeySize())
	nonce := make([]byte, p.NonceSize())
	signPriv, signPub, err := p.GenerateSignKeyPair()
	if err != nil {
		b.Fatalf("GenerateSignKeyPair: %v", err)
	}
	aad := []byte("otpmask/bench")

	for _, size := range []int{bench1KB, bench64KB} {
		in := make([]byte, size)
		kdfSecret := make([]byte, size)
		ct, err := p.Seal(key, nonce, in, aad) // 仅供 Open；基准固定 nonce，仅测性能
		if err != nil {
			b.Fatalf("Seal prepare: %v", err)
		}
		sig, err := p.Sign(signPriv, in)
		if err != nil {
			b.Fatalf("Sign prepare: %v", err)
		}

		label := func(op string) string { return fmt.Sprintf("%s/%s/%d", profile, op, size) }

		b.Run(label("Seal"), func(b *testing.B) {
			benchOp(b, size, func() { _, _ = p.Seal(key, nonce, in, aad) })
		})
		b.Run(label("Open"), func(b *testing.B) {
			benchOp(b, size, func() { _, _ = p.Open(key, nonce, ct, aad) })
		})
		b.Run(label("Hash"), func(b *testing.B) {
			benchOp(b, size, func() { _ = p.Hash(in) })
		})
		b.Run(label("HMAC"), func(b *testing.B) {
			benchOp(b, size, func() { _ = p.HMAC(key, in) })
		})
		b.Run(label("Sign"), func(b *testing.B) {
			benchOp(b, size, func() { _, _ = p.Sign(signPriv, in) })
		})
		b.Run(label("Verify"), func(b *testing.B) {
			benchOp(b, size, func() { _ = p.Verify(signPub, in, sig) })
		})
		b.Run(label("KDF"), func(b *testing.B) {
			// KDF 输出固定 32B（真实密钥派生口径；HKDF 上限 8160B 无法按 64KB 出长流），
			// 成本随 secret 尺寸变化，两档同口径可比。
			benchOp(b, size, func() {
				_, _ = p.KDF(kdfSecret, []byte("salt"), []byte("otpmask/kdf/bench"), 32)
			})
		})
	}
}

func BenchmarkIntl(b *testing.B) { benchmarkProfile(b, ProfileIntl) }

func BenchmarkSMSW(b *testing.B) { benchmarkProfile(b, ProfileSMSW) }
