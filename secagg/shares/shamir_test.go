package shares

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestSplitReconstruct(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef") // 32 字节
	for _, tc := range []struct{ t, n int }{
		{2, 3}, {3, 5}, {5, 5}, {4, 10}, {10, 10},
	} {
		parts, err := Split(secret, tc.t, tc.n)
		if err != nil {
			t.Fatalf("t=%d n=%d Split 失败: %v", tc.t, tc.n, err)
		}
		if len(parts) != tc.n {
			t.Fatalf("份额数 %d != n=%d", len(parts), tc.n)
		}
		for _, p := range parts {
			if p.X == nil || p.Y == nil {
				t.Fatal("份额字段缺失")
			}
		}
		got, err := Reconstruct(parts[:tc.t], tc.t)
		if err != nil {
			t.Fatalf("t=%d n=%d 重构失败: %v", tc.t, tc.n, err)
		}
		if !bigEqualBytes(got, secret) {
			t.Fatalf("t=%d n=%d 重构不一致: got=%x want=%x", tc.t, tc.n, got, secret)
		}
	}
}

func TestReconstructAnySubset(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-seed!!")
	parts, err := Split(secret, 3, 6)
	if err != nil {
		t.Fatal(err)
	}
	// 任意 3 份组合均可重构（选择 4 种组合）
	combos := [][3]int{{0, 1, 2}, {0, 3, 5}, {1, 2, 4}, {3, 4, 5}}
	for _, c := range combos {
		subset := []*Part{parts[c[0]], parts[c[1]], parts[c[2]]}
		got, err := Reconstruct(subset, 3)
		if err != nil {
			t.Fatalf("组合 %v 重构失败: %v", c, err)
		}
		if !bigEqualBytes(got, secret) {
			t.Fatalf("组合 %v 结果不一致", c)
		}
	}
}

func TestInvalidParams(t *testing.T) {
	secret := make([]byte, 32)
	cases := []struct {
		name   string
		t, n   int
		secret []byte
	}{
		{"t>n", 3, 2, secret},
		{"t=0", 0, 5, secret},
		{"n=0", 1, 0, secret},
		{"空秘密", 2, 3, nil},
		{"秘密超出域模数", 2, 3, bytes.Repeat([]byte{0xFF}, 33)}, // 33 字节全 0xFF > 256 位域
	}
	for _, tc := range cases {
		if _, err := Split(tc.secret, tc.t, tc.n); err == nil {
			t.Fatalf("%s 应报错", tc.name)
		}
	}
}

func TestThresholdOne(t *testing.T) {
	secret := []byte("t1-scheme-secret-32byte-val") // ≤32 字节
	parts, err := Split(secret, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Reconstruct(parts[:1], 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bigEqualBytes(got, secret) {
		t.Fatal("t=1 重构应等于原秘密")
	}
}

func TestLessThanThresholdFails(t *testing.T) {
	secret := []byte("threshold-check-secret-32byte") // ≤32 字节
	parts, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	// t-1=2 份不足以重构；显式安全失败。
	if _, err := Reconstruct(parts[:2], 3); err == nil {
		t.Fatal("份额不足应报错")
	}
}

func TestFuzz(t *testing.T) {
	f := func(secretLen, thresh, num int) {
		if thresh < 1 || num < thresh || num > 64 || secretLen < 1 || secretLen > 32 {
			return
		}
		secret := make([]byte, secretLen)
		if _, err := rand.Read(secret); err != nil {
			return
		}
		parts, err := Split(secret, thresh, num)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Reconstruct(parts[:thresh], thresh)
		if err != nil {
			t.Fatal(err)
		}
		if !bigEqualBytes(got, secret) {
			t.Fatalf("fuzz 重构不一致: len=%d t=%d n=%d", secretLen, thresh, num)
		}
	}
	for i := 0; i < 200; i++ {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		f(int(b[0])%64+1, int(b[1])%6+1, int(b[2])%6+1)
	}
}

// bigEqualBytes 按数值语义比较两个字节表示的大整数
// （Reconstruct 输出定长 32 字节，与输入秘密的前导零差异不影响数值）。
func bigEqualBytes(a, b []byte) bool {
	return new(big.Int).SetBytes(a).Cmp(new(big.Int).SetBytes(b)) == 0
}
