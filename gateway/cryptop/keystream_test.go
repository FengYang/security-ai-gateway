package cryptop

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// Keystream 原语（P0-4 §5.3.2，Provider 19→20 方法）一致性测试。
//
// 本原语只产确定性密钥流、不做认证（掩码"打散"用）。两条实现路径：
//   - intl：HMAC-SHA256 PRG，**逐字节等价 cipher/mask 现役实现**（保 intl 灰度滚动升级兼容）；
//   - sm  ：SM4-CTR keystream（IV = HMAC/SM3(domain)[:8]‖BE64(counter)）。
// 两档均须确定性、域分离、密钥敏感，且跨档**不互操作**（防误配静默错乱）。

// TestKeystreamDeterministic 确定性：同 key/domain/counter → 同流；长度精确等于 n。
func TestKeystreamDeterministic(t *testing.T) {
	for _, prof := range conformanceProfiles {
		t.Run(string(prof), func(t *testing.T) {
			p := providerFor(t, prof)
			key, _ := p.Rand(p.SymmetricKeySize())
			domain := []byte("otpmask/self-mask/v1")
			a, err := p.Keystream(key, domain, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			b, err := p.Keystream(key, domain, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Error("同参数 Keystream 应确定性")
			}
			if len(a) != 64 {
				t.Errorf("Keystream 长度应为 64，实际 %d", len(a))
			}
		})
	}
}

// TestKeystreamDomainSeparation 域分离：不同 domain 产生不同流（B-5.3-3）。
func TestKeystreamDomainSeparation(t *testing.T) {
	for _, prof := range conformanceProfiles {
		t.Run(string(prof), func(t *testing.T) {
			p := providerFor(t, prof)
			key, _ := p.Rand(p.SymmetricKeySize())
			a, err := p.Keystream(key, []byte("otpmask/self-mask/v1"), 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			b, err := p.Keystream(key, []byte("otpmask/pair-mask/v1"), 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(a, b) {
				t.Error("不同 domain 的 Keystream 不应相同（域分离失效）")
			}
		})
	}
}

// TestKeystreamKeySensitive 密钥敏感：不同 key 产生不同流。
func TestKeystreamKeySensitive(t *testing.T) {
	for _, prof := range conformanceProfiles {
		t.Run(string(prof), func(t *testing.T) {
			p := providerFor(t, prof)
			k1, _ := p.Rand(p.SymmetricKeySize())
			k2, _ := p.Rand(p.SymmetricKeySize())
			domain := []byte("otpmask/self-mask/v1")
			a, _ := p.Keystream(k1, domain, 0, 64)
			b, _ := p.Keystream(k2, domain, 0, 64)
			if bytes.Equal(a, b) {
				t.Error("不同 key 的 Keystream 不应相同")
			}
		})
	}
}

// TestKeystreamCounterContinuation 计数器语义：按块连续拼接 == 一次取更大长度。
//
//   - intl：每块 8 字节（每候选 = HMAC 前 8B）⇒ K(c,0..8)‖K(c,1..8) == K(c,0..16)；
//   - sm  ：每块 16 字节（SM4 分组）  ⇒ K(c,0..16)‖K(c,1..16) == K(c,0..32)。
//
// 这保证 provPRG 增量取流与一次性取流一致（跨块语序一致）。
func TestKeystreamCounterContinuation(t *testing.T) {
	blockOf := func(prof Profile) int {
		if prof == ProfileIntl {
			return 8
		}
		return 16
	}
	for _, prof := range conformanceProfiles {
		t.Run(string(prof), func(t *testing.T) {
			p := providerFor(t, prof)
			key, _ := p.Rand(p.SymmetricKeySize())
			domain := []byte("otpmask/self-mask/v1")
			blk := blockOf(prof)

			b0, _ := p.Keystream(key, domain, 0, blk)
			b1, _ := p.Keystream(key, domain, 1, blk)
			twoStep := append(append([]byte(nil), b0...), b1...)
			oneStep, err := p.Keystream(key, domain, 0, 2*blk)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(twoStep, oneStep) {
				t.Errorf("counter 连续拼接与一次取流不一致（块大小 %d）", blk)
			}
		})
	}
}

// TestIntlKeystreamMatchesHMACPRG intl 档 Keystream 必须逐字节复现现行掩码算法
// （candidate_k = HMAC-SHA256(key, BE64(counter+k)‖domain) 前 8 字节）——这是 cipher/mask
// 现役实现，保 intl 灰度滚动升级兼容（§5.3.2 不变量、T-5.3-8 的被比对方）。
func TestIntlKeystreamMatchesHMACPRG(t *testing.T) {
	p := providerFor(t, ProfileIntl)
	key := bytes.Repeat([]byte{0x37}, 32)
	domain := []byte("otpmask/recompute-seed/v1")
	const n = 40 // 5 个候选块（非整倍数，附截断）
	got, err := p.Keystream(key, domain, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	var ctr [8]byte
	for k := uint64(0); len(want) < n; k++ {
		binary.BigEndian.PutUint64(ctr[:], k)
		mac := hmac.New(sha256.New, key)
		mac.Write(ctr[:])
		mac.Write(domain)
		want = append(want, mac.Sum(nil)[:8]...)
	}
	if !bytes.Equal(got, want[:n]) {
		t.Fatal("intl Keystream 与 HMAC-SHA256 PRG 参考实现不一致（破坏灰度兼容）")
	}
}

// TestKeystreamLengthBoundary n=0 返回空且无错；n<0 报错（两档一致）。
func TestKeystreamLengthBoundary(t *testing.T) {
	for _, prof := range conformanceProfiles {
		t.Run(string(prof), func(t *testing.T) {
			p := providerFor(t, prof)
			key, _ := p.Rand(p.SymmetricKeySize())
			if got, err := p.Keystream(key, []byte("d"), 0, 0); err != nil || len(got) != 0 {
				t.Errorf("n=0 应返回空且无错：got=%v err=%v", got, err)
			}
			if _, err := p.Keystream(key, []byte("d"), 0, -1); err == nil {
				t.Error("n<0 应报错")
			}
		})
	}
}

// TestKeystreamKeySizeValidated 密钥长度须随 profile（intl 32B / sm 16B）；不符 → fail-closed，
// 不得静默截断/零填充（防止误把 sm 密钥当 intl 用，反之亦然）。
func TestKeystreamKeySizeValidated(t *testing.T) {
	intl := providerFor(t, ProfileIntl)
	sm := providerFor(t, ProfileSMSW)

	if _, err := intl.Keystream(bytes.Repeat([]byte{1}, 16), []byte("d"), 0, 16); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("intl 档 16B 密钥应返回 ErrInvalidKeySize，实际 %v", err)
	}
	if _, err := sm.Keystream(bytes.Repeat([]byte{1}, 32), []byte("d"), 0, 16); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("sm 档 32B 密钥应返回 ErrInvalidKeySize，实际 %v", err)
	}
}

// TestKeystreamCrossProfileNotInteroperable 跨档不互操作：同 key/domain/counter 下，
// intl（HMAC-SHA256）与 sm（SM4-CTR）输出必须显著不同（防误配静默错乱，对齐 T-5.3-5）。
func TestKeystreamCrossProfileNotInteroperable(t *testing.T) {
	intl := providerFor(t, ProfileIntl)
	sm := providerFor(t, ProfileSMSW)
	key := bytes.Repeat([]byte{0x22}, 32) // 32B 供 intl；sm 取前 16B
	domain := []byte("otpmask/self-mask/v1")
	intlOut, err := intl.Keystream(key, domain, 0, 128)
	if err != nil {
		t.Fatal(err)
	}
	smOut, err := sm.Keystream(key[:sm.SymmetricKeySize()], domain, 0, 128)
	if err != nil {
		t.Fatal(err)
	}
	diff := 0
	for i := range intlOut {
		if intlOut[i] != smOut[i] {
			diff++
		}
	}
	if diff < 96 { // 128 字节中至少 ~75% 不同
		t.Fatalf("intl 与 sm Keystream 相关度过高（应不互操作）：差异 %d/128", diff)
	}
}
