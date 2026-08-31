package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// FuzzDecrypt 验证任意畸形密文不会导致 panic 或静默错误结果。
func FuzzDecrypt(f *testing.F) {
	// 种子输入：合法密钥下的小密文、边界值
	pub, priv, err := GenerateKey(rand.Reader, MinBits)
	if err != nil {
		f.Fatal(err)
	}
	c, _ := NewCipher(pub, priv)
	m := big.NewInt(1)
	valid, _ := c.Encrypt(m)

	f.Add(valid.Bytes())
	f.Add([]byte{0})
	f.Add([]byte{1})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip("输入过大")
		}
		ct := new(big.Int).SetBytes(data)
		got, err := c.Decrypt(ct)
		if err != nil {
			return // 显式错误是允许的
		}
		if got == nil {
			t.Fatal("解密返回 nil 明文且无错误")
		}
		if got.Sign() < 0 || got.Cmp(pub.N) >= 0 {
			t.Fatalf("解密结果超出明文范围: %v", got)
		}
	})
}
