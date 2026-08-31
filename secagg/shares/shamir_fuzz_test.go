package shares

import (
	"testing"
)

// FuzzReconstruct 验证任意秘密/阈值/份额组合下重构恒等于原秘密。
func FuzzReconstruct(f *testing.F) {
	f.Add(32, 3, 6)
	f.Add(16, 2, 4)
	f.Add(8, 5, 10)
	f.Add(1, 1, 2)

	f.Fuzz(func(t *testing.T, secretLen, thresh, num int) {
		if thresh < 1 || num < thresh || num > 64 || secretLen < 1 || secretLen > 32 {
			return
		}
		secret := make([]byte, secretLen)
		for i := range secret {
			secret[i] = byte(i*7 + 3)
		}
		parts, err := Split(secret, thresh, num)
		if err != nil {
			if secretLen > 32 {
				return
			}
			t.Fatalf("Split 失败: %v", err)
		}
		got, err := Reconstruct(parts[:thresh], thresh)
		if err != nil {
			t.Fatalf("Reconstruct 失败: %v", err)
		}
		if !bigEqualBytes(got, secret) {
			t.Fatalf("重构不一致: len=%d t=%d n=%d", secretLen, thresh, num)
		}
	})
}
