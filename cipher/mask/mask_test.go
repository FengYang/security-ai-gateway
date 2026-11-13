package mask

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
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

// uniformitySeedCount 均匀性检验使用的固定种子组数（组数越多覆盖面越广，
// 代价是每组一次 65536 次抽样）。
const uniformitySeedCount = 8

// uniformitySeed 返回第 i 组**固定**测试种子（纯哈希派生，不引入随机源）。
// 域串含版本号：若检验范围/判据变更须升版本，避免新旧基准混用。
func uniformitySeed(i int) []byte {
	h := sha256.Sum256([]byte("security-ai-gateway/cipher/mask/uniformity/v1/" + strconv.Itoa(i)))
	return h[:]
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
//
// 判据未放宽：仍是自由度 255、α=0.05、临界值 293.25，逐组独立判定、任一组
// 越界即失败。改动只在**取样方式**：原实现每组用 new 随机种子跑单次检验，
// 而良态实现本身就有 5% 概率落入拒绝域（第一类错误，检验固有性质，不是缺陷），
// 故每轮 CI 约 1/20 概率误红（KI#2）。改用固定种子矩阵后判定完全确定：
// 良态实现恒通过、退化实现恒失败，无随机误拒，且 8 组种子比单组覆盖面更广。
func TestStreamUniformity(t *testing.T) {
	const buckets = 256
	const samples = 65536
	// 自由度为 255 时，α=0.05 的临界值约为 293.25
	const critical = 293.25
	for i := 0; i < uniformitySeedCount; i++ {
		s, err := NewStream(uniformitySeed(i), uint64(buckets))
		if err != nil {
			t.Fatal(err)
		}
		counts := make([]int, buckets)
		for k := 0; k < samples; k++ {
			counts[s.Next()]++
		}
		// 卡方统计量：Σ (observed - expected)^2 / expected
		expected := samples / buckets
		var chi2 float64
		for _, c := range counts {
			d := float64(c - expected)
			chi2 += d * d / float64(expected)
		}
		t.Logf("固定种子#%d：chi2=%.4f（临界 %.2f）", i, chi2, critical)
		if chi2 > critical {
			t.Fatalf("卡方检验失败 seed#%d: chi2=%.2f > 临界值 %.2f", i, chi2, critical)
		}
	}
}

// streamKAT 固定种子 → 前 8 个 Next() 输出的指纹（大端序拼接后 SHA-256）。
// 用途：卡方只验证「分布形状」，对「底层原语变了但分布依旧均匀」这类改动
// 无检出力；掩码序列一旦变化会破坏已分发密文的互操作性，必须被显式发现。
var streamKAT = []string{
	"1a6aa8ebc34354d8731e4176771acba38f9403a83ccb32565b0e3a88438e6d8b",
	"6f5223904790eb1f96fdffe785f0b21ae39acff7099440b48b0423d477ec87ad",
	"c57db7970ca0fc5dd87ee07382e87dc7abe701027e00a875c050251db6f51bce",
	"5eaeef381d1d8e78c12a7f8de3ddb95427817e26509371aa6f1d93e2360549d4",
	"6bf0b9c4da9e1cdd7422b3d6b16043fc1786d29750884815bdfec03914df0cc3",
	"09e2d0e83eb1ae6c50aa1dd135c275b5addbe05112caf1a5aec84c8dbfd77376",
	"16ed783c9b47b8fb2c8e602edf4609df2ee58ca73b5773479a09bd609842e6a2",
	"93fd6e7cda90feb0444fddb8f7627915b132b22e2b3a076df2d83b95632a5f17",
}

// TestStreamKnownAnswer 掩码序列逐位回归（已知答案测试）。
// 与 TestStreamUniformity 用同一组固定种子（域串 v1），二者基准一一对应；
// 若断言失败，说明输出序列已变：须先确认是否属有意的算法版本升级，再连同
// uniformitySeed 的版本号一起更新基准——不得直接改期望值掩盖回归。
func TestStreamKnownAnswer(t *testing.T) {
	if len(streamKAT) != uniformitySeedCount {
		t.Fatalf("KAT 条数 %d 与种子组数 %d 不一致", len(streamKAT), uniformitySeedCount)
	}
	for i, want := range streamKAT {
		s, err := NewStream(uniformitySeed(i), 1<<32)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]uint64, 8)
		for k := range out {
			out[k] = s.Next()
		}
		sum := sha256.Sum256(uint64sToBytes(out))
		got := hex.EncodeToString(sum[:])
		if got != want {
			t.Fatalf("掩码序列变更 seed#%d: got %s want %s（输出序列与基准不符，\n"+
				"若为有意的算法版本升级，须同步升 uniformitySeed 域串版本并更新本基准）", i, got, want)
		}
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
