package mask

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"security-ai-gateway/gateway/cryptop"
)

// legacyStream 现役（旧）算法参考实现：candidate_k = HMAC-SHA256(seed, BE64(k)‖domain) 前 8 字节，
// 经与 mask.go 相同的拒绝采样映射到 [0, r)。用于回归锚：新 hmacPRG / intl Provider.Keystream
// 必须与之逐字节一致（§5 改造不换协议语义）。
type legacyStream struct {
	seed, domain []byte
	r, ctr       uint64
}

func (s *legacyStream) next() uint64 {
	threshold := ^uint64(0) - (^uint64(0) % s.r)
	for {
		mac := hmac.New(sha256.New, s.seed)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], s.ctr)
		s.ctr++
		_, _ = mac.Write(buf[:])
		if len(s.domain) > 0 {
			_, _ = mac.Write(s.domain)
		}
		out := mac.Sum(nil)
		v := binary.BigEndian.Uint64(out[:8])
		if v < threshold {
			return v % s.r
		}
	}
}

// TestHMACPRGMatchesLegacy 回归锚：NewStreamDomain（hmacPRG）逐字节复现现役算法（保 intl 灰度兼容）。
func TestHMACPRGMatchesLegacy(t *testing.T) {
	seed := bytes.Repeat([]byte{0x37}, 32)
	domain := []byte("otpmask/layer/1/v1")
	s, err := NewStreamDomain(seed, 1<<32, domain)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &legacyStream{seed: seed, domain: domain, r: 1 << 32}
	for k := 0; k < 2048; k++ {
		want := legacy.next()
		if got := s.Next(); got != want {
			t.Fatalf("第 %d 个元素不符：got=%d want=%d", k, got, want)
		}
	}
}

// TestHMACPRGEqualsIntlProviderKeystream T-5.3-8 前半：hmacPRG 与 intlProvider.Keystream 逐字节等价。
func TestHMACPRGEqualsIntlProviderKeystream(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, 32)
	domain := []byte("otpmask/recompute-seed/v1")
	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 8, 9, 32, 64, 100} {
		g, err := newHMACPRG(seed, domain)
		if err != nil {
			t.Fatal(err)
		}
		got := g.Keystream(n)
		want, err := p.Keystream(seed, domain, 0, n)
		if err != nil {
			t.Fatalf("intl Keystream(%d): %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("n=%d：hmacPRG 与 intlProvider.Keystream 不一致", n)
		}
	}
	// 连续性：两次 8 字节 == 一次 16 字节（跨块递增语序一致）。
	g1, _ := newHMACPRG(seed, domain)
	twoStep := append(g1.Keystream(8), g1.Keystream(8)...)
	g2, _ := newHMACPRG(seed, domain)
	oneStep := g2.Keystream(16)
	if !bytes.Equal(twoStep, oneStep) {
		t.Fatal("hmacPRG 跨块连续性不符")
	}
}

// TestIntlStreamWithProviderEqualsStreamDomain T-5.3-8 后半：intl 默认格（NewStreamWithProvider(intl)）
// 与 HMAC 构造器（NewStreamDomain）产出同一掩码序列。
func TestIntlStreamWithProviderEqualsStreamDomain(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, 32)
	domain := []byte("pair-mask")
	p, _ := cryptop.New(cryptop.ProfileIntl)
	a, err := NewStreamDomain(seed, 1<<32, domain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStreamWithProvider(p, seed, domain, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 512; i++ {
		if x, y := a.Next(), b.Next(); x != y {
			t.Fatalf("第 %d 个元素不一致：StreamDomain=%d StreamWithProvider=%d", i, x, y)
		}
	}
}

// TestSM4StreamDeterministic T-5.3-1：SM4 路径确定性（同 key/domain → 同流）。
func TestSM4StreamDeterministic(t *testing.T) {
	p, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x0f}, p.SymmetricKeySize())
	domain := []byte("self-mask")
	a, err := NewStreamWithProvider(p, key, domain, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStreamWithProvider(p, key, domain, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 512; i++ {
		if x, y := a.Next(), b.Next(); x != y {
			t.Fatalf("SM4 流不确定：第 %d 元素 %d != %d", i, x, y)
		}
	}
}

// TestSM4VsHMACNotInteroperable T-5.3-5：SM4 与 HMAC 版不互操作（防误配静默错乱）。
func TestSM4VsHMACNotInteroperable(t *testing.T) {
	seed := bytes.Repeat([]byte{0x22}, 32) // 32B，同时满足 hmac 与（截断给 sm 误配场景）
	pSM, _ := cryptop.New(cryptop.ProfileSMSW)
	keySM := seed[:pSM.SymmetricKeySize()] // sm 需 16B
	domain := []byte("pair-mask")
	sm, err := NewStreamWithProvider(pSM, keySM, domain, 1<<32)
	if err != nil {
		t.Fatal(err)
	}
	hm, err := NewStreamDomain(seed, 1<<32, domain)
	if err != nil {
		t.Fatal(err)
	}
	diff := 0
	for i := 0; i < 64; i++ {
		if sm.Next() != hm.Next() {
			diff++
		}
	}
	if diff < 32 {
		t.Fatalf("SM4 与 HMAC 流相关度过高（应不互操作）：差异 %d/64", diff)
	}
}

// TestNewStreamWithProviderKeySize：provider 密钥长度不符 → 构造失败（fail-closed）。
func TestNewStreamWithProviderKeySize(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileSMSW) // SymmetricKeySize=16
	if _, err := NewStreamWithProvider(p, bytes.Repeat([]byte{1}, 32), nil, 1<<32); err == nil {
		t.Fatal("32B key 用于 SM4 provider 应报错")
	}
}
