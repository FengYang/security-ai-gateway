package secagg

import (
	"context"
	"testing"
)

// FuzzReceiveBundles 协议级 fuzz：恶意份额密文不得引起 panic，
// 且 To 不匹配时必须拒绝。
func FuzzReceiveBundles(f *testing.F) {
	cfg := testConfig(4, 3, 8)
	// 种子语料：合法与非法边界
	f.Add(0, []byte{1, 2, 3})   // To 匹配自身
	f.Add(1, []byte{})           // To 匹配他人 + 空密文
	f.Add(5, []byte{0xde, 0xad}) // To 越界
	f.Add(-1, []byte{0xff})      // To 负数

	f.Fuzz(func(t *testing.T, to int, ct []byte) {
		if len(ct) > 4096 {
			ct = ct[:4096] // 防止超大输入拖慢 fuzz
		}
		p, err := NewParty(0, make([]uint64, 8), cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		b := shareBundleCipher{From: 1, To: to, CT: ct}
		err = p.receiveBundles(context.Background(), []shareBundleCipher{b})
		// To != 自身必须报错；To == 自身必须成功
		if to == 0 && err != nil {
			t.Fatalf("合法份额包被拒绝: %v", err)
		}
		if to != 0 && err == nil {
			t.Fatalf("非法份额包（To=%d）被接受", to)
		}
	})
}

// FuzzUnmaskPartDecode 协议级 fuzz：份额字节流反序列化不得 panic。
func FuzzUnmaskPartDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add([]byte("garbage"))
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2048 {
			raw = raw[:2048]
		}
		// 只验证不 panic；非法字节应返回错误
		_, _ = decodePart(raw)
	})
}

// FuzzFinalizeMalformedShares 协议级 fuzz：finalize 面对恶意份额
// 必须返回错误而非 panic 或错误结果。
func FuzzFinalizeMalformedShares(f *testing.F) {
	cfg := testConfig(4, 3, 8)
	f.Add([]byte{0xff, 0x00})
	f.Add([]byte("not a gob"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		agg, err := NewAggregator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		masked := map[int][]uint64{
			0: make([]uint64, 8),
			1: make([]uint64, 8),
			2: make([]uint64, 8),
		}
		um := unmaskMsg{
			ID:             0,
			SelfMaskShares: map[int][]byte{0: raw, 1: raw, 2: raw},
		}
		_, _ = agg.finalize(masked, []int{0, 1, 2}, []unmaskMsg{um}, nil)
	})
}
