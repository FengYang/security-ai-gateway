package paillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

var (
	benchPub2048, benchPriv2048 = mustGenKey(2048)
	benchPub3072, benchPriv3072 = mustGenKey(3072)
	benchCipher2048, _          = NewCipher(benchPub2048, benchPriv2048)
	benchCipher3072, _          = NewCipher(benchPub3072, benchPriv3072)
	benchMsg                    = big.NewInt(123456789)
	benchCt2048, _              = benchCipher2048.Encrypt(benchMsg)
	benchCt3072, _              = benchCipher3072.Encrypt(benchMsg)
)

func mustGenKey(bits int) (*PublicKey, *PrivateKey) {
	pub, priv, err := GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func BenchmarkKeyGen2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKey(rand.Reader, 2048); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyGen3072(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKey(rand.Reader, 3072); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := benchCipher2048.Encrypt(benchMsg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt3072(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := benchCipher3072.Encrypt(benchMsg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := benchCipher2048.Decrypt(benchCt2048); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt3072(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := benchCipher3072.Decrypt(benchCt3072); err != nil {
			b.Fatal(err)
		}
	}
}
