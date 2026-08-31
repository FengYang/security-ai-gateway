package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"

	"security-ai-gateway/internal/memzero"
)

// MinSeedLen 种子最小长度（字节）。
// 256 位种子与 HMAC-SHA256 输出强度对齐，满足现代密码学与量子安全余量要求。
const MinSeedLen = 32

// Stream 基于 HMAC-SHA256 的确定性掩码流。
//
// 每个元素 = HMAC-SHA256(seed, counter||domain) 前 8 字节，
// 经拒绝采样映射到 [0, r)，保证均匀性（对应论文 PRG(s_u,v) 掩码扩展）。
//
// 并发安全：Stream 内部使用互斥锁保护计数器，可安全跨 goroutine 复用。
// 生命周期：单个 Stream 最多产生 2^64 个元素，超出后行为未定义
// （实际应用中 1GHz 频率下也需 584 年才能达到，安全余量充足）。
type Stream struct {
	mu     sync.Mutex
	seed   []byte
	r      uint64
	ctr    uint64
	domain []byte // 可选域分离标签（nil 表示无域分离）
	mac    hash.Hash
}

// NewStream 以 seed 构造 [0, r) 上的掩码流（无域分离）。
func NewStream(seed []byte, r uint64) (*Stream, error) {
	return NewStreamDomain(seed, r, nil)
}

// NewStreamDomain 以 seed 构造 [0, r) 上的掩码流，并绑定域分离标签。
//
// domain 用于区分同一种子在不同用途下派生的掩码流（如自掩码 b_u 与
// 成对掩码 seed_{v,u} 使用不同 domain），防止跨用途掩码流碰撞。
// 不同用途必须传入不同的非空 domain。
func NewStreamDomain(seed []byte, r uint64, domain []byte) (*Stream, error) {
	if len(seed) < MinSeedLen {
		return nil, fmt.Errorf("mask: seed length %d below minimum %d", len(seed), MinSeedLen)
	}
	if r < 2 {
		return nil, errors.New("mask: modulus R must be >= 2")
	}
	return &Stream{
		seed:   append([]byte(nil), seed...),
		r:      r,
		domain: append([]byte(nil), domain...),
		mac:    hmac.New(sha256.New, seed),
	}, nil
}

// Next 返回下一个 [0, r) 掩码元素（拒绝采样保证均匀）。
func (s *Stream) Next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	threshold := ^uint64(0) - (^uint64(0) % s.r)
	for {
		counter := s.ctr
		s.ctr++

		s.mac.Reset()
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], counter)
		_, _ = s.mac.Write(buf[:]) // hash.Hash.Write 按规范永不返回错误
		if len(s.domain) > 0 {
			_, _ = s.mac.Write(s.domain)
		}
		out := s.mac.Sum(nil)

		v := binary.BigEndian.Uint64(out[:8])
		// 拒绝采样：丢弃使分布偏移的最高区间。
		// 标准公式：threshold = 2^64 - (2^64 mod r)，接受 v < threshold。
		// 注意：不能用 (2^64-1-r+1)/r*r 的写法，r > 2^63 时该式为 0 导致无限循环。
		if v < threshold {
			return v % s.r
		}
		// v >= threshold：丢弃，用下一个 counter 重试
	}
}

// Fill 填充 buf 的前 n 个掩码元素。
func (s *Stream) Fill(buf []uint64) error {
	if len(buf) == 0 {
		return nil
	}
	for i := range buf {
		buf[i] = s.Next()
	}
	return nil
}

// Modulus 返回掩码模 R。
func (s *Stream) Modulus() uint64 { return s.r }

// Zeroize 清零敏感内存（种子），释放锁后调用。
// 调用后 Stream 不可再使用。
func (s *Stream) Zeroize() {
	s.mu.Lock()
	defer s.mu.Unlock()
	memzero.Bytes(s.seed)
	memzero.Bytes(s.domain)
	s.seed = nil
	s.domain = nil
}
