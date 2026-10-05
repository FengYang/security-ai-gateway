package mask

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"testing"
)

func randomSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return seed
}

func TestStreamDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	s1, err := NewStream(seed, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewStream(seed, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	buf1 := make([]uint64, 64)
	buf2 := make([]uint64, 64)
	if err := s1.Fill(buf1); err != nil {
		t.Fatal(err)
	}
	if err := s2.Fill(buf2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uint64sToBytes(buf1), uint64sToBytes(buf2)) {
		t.Fatal("同种子掩码流不一致")
	}
}

func TestStreamDifferentSeeds(t *testing.T) {
	s1, _ := NewStream(bytes.Repeat([]byte{1}, 32), 1<<32)
	s2, _ := NewStream(bytes.Repeat([]byte{2}, 32), 1<<32)
	b1 := make([]uint64, 32)
	b2 := make([]uint64, 32)
	_ = s1.Fill(b1)
	_ = s2.Fill(b2)
	diff := 0
	for i := range b1 {
		if b1[i] != b2[i] {
			diff++
		}
	}
	if diff < 8 {
		t.Fatalf("不同种子掩码流相关度过高: 差异 %d/32", diff)
	}
}

func TestStreamRange(t *testing.T) {
	seed := randomSeed(t)
	mod := uint64(1 << 32)
	s, err := NewStream(seed, mod)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		v := s.Next()
		if v >= mod {
			t.Fatalf("掩码越界: %d >= %d", v, mod)
		}
	}
}

func TestStreamInvalidParams(t *testing.T) {
	if _, err := NewStream(nil, 1<<32); err == nil {
		t.Fatal("空种子应报错")
	}
	// 16 字节种子低于新下限 32 字节，应报错
	if _, err := NewStream(bytes.Repeat([]byte{1}, 16), 1<<32); err == nil {
		t.Fatal("短种子应报错")
	}
	if _, err := NewStream(make([]byte, 32), 1); err == nil {
		t.Fatal("R<2 应报错")
	}
	if _, err := NewStream(make([]byte, 32), 0); err == nil {
		t.Fatal("R=0 应报错")
	}
}

// TestStreamLargeModulus 回归测试：r > 2^63 时拒绝采样不再死循环（阻断 bug）。
func TestStreamLargeModulus(t *testing.T) {
	seed := randomSeed(t)
	for _, r := range []uint64{1 << 63, 1<<63 + 1, ^uint64(0)} {
		s, err := NewStream(seed, r)
		if err != nil {
			t.Fatalf("r=%d: NewStream 失败: %v", r, err)
		}
		for i := 0; i < 1000; i++ {
			v := s.Next()
			if v >= r {
				t.Fatalf("r=%d: 掩码越界 %d", r, v)
			}
		}
	}
}

// TestStreamDomainSeparation 域分离：不同 domain 产生不同掩码流，同 domain 相同。
func TestStreamDomainSeparation(t *testing.T) {
	seed := randomSeed(t)
	sA1, _ := NewStreamDomain(seed, 1<<32, []byte("self-mask"))
	sA2, _ := NewStreamDomain(seed, 1<<32, []byte("self-mask"))
	sB, _ := NewStreamDomain(seed, 1<<32, []byte("pair-mask"))

	bA1 := make([]uint64, 32)
	bA2 := make([]uint64, 32)
	bB := make([]uint64, 32)
	_ = sA1.Fill(bA1)
	_ = sA2.Fill(bA2)
	_ = sB.Fill(bB)

	if !bytes.Equal(uint64sToBytes(bA1), uint64sToBytes(bA2)) {
		t.Fatal("同 domain 掩码流应一致")
	}
	if bytes.Equal(uint64sToBytes(bA1), uint64sToBytes(bB)) {
		t.Fatal("不同 domain 掩码流不应一致")
	}
}

// TestStreamConcurrent 并发安全：多 goroutine 共享同一 Stream，-race 检测数据竞争。
// 只验证掩码范围与 -race 干净（不检查唯一性——2^32 空间内样本碰撞是概率性的）。
func TestStreamConcurrent(t *testing.T) {
	seed := randomSeed(t)
	s, err := NewStream(seed, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	const goroutines = 16
	const perGoroutine = 2000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if v := s.Next(); v >= 1<<32 {
					t.Errorf("掩码越界 %d", v)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestStreamUniformity 卡方均匀性检验：输出应均匀分布（α=0.05 下不应拒绝）。
func TestStreamUniformity(t *testing.T) {
	seed := randomSeed(t)
	const buckets = 256
	const samples = 65536
	s, err := NewStream(seed, uint64(buckets))
	if err != nil {
		t.Fatal(err)
	}
	counts := make([]int, buckets)
	for i := 0; i < samples; i++ {
		counts[s.Next()]++
	}
	// 卡方统计量：Σ (observed - expected)^2 / expected
	expected := samples / buckets
	var chi2 float64
	for _, c := range counts {
		d := float64(c - expected)
		chi2 += d * d / float64(expected)
	}
	// 自由度为 255 时，α=0.05 的临界值约为 293.25
	const critical = 293.25
	if chi2 > critical {
		t.Fatalf("卡方检验失败: chi2=%.2f > 临界值 %.2f", chi2, critical)
	}
}

func BenchmarkNext(b *testing.B) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	s, _ := NewStream(seed, 1<<32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Next()
	}
}

func BenchmarkFill(b *testing.B) {
	seed := bytes.Repeat([]byte{0xAB}, 32)
	s, _ := NewStream(seed, 1<<32)
	buf := make([]uint64, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Fill(buf)
	}
}

// TestZeroize 清零后 PRG 与缓冲被断开。
func TestZeroize(t *testing.T) {
	seed := randomSeed(t)
	s, _ := NewStream(seed, 1<<32)
	_ = s.Next()
	s.Zeroize()
	// Zeroize 后 prg/buf 被置 nil；再次调用 Next 会 panic（nil prg），
	// 但测试只验证 Zeroize 本身不 panic 且内部引用被断开。
	if s.prg != nil || s.buf != nil {
		t.Fatal("Zeroize 未清理内部状态")
	}
}

// uint64sToBytes 大端序序列化（测试辅助）。
func uint64sToBytes(in []uint64) []byte {
	out := make([]byte, len(in)*8)
	for i, v := range in {
		binary.BigEndian.PutUint64(out[i*8:], v)
	}
	return out
}
