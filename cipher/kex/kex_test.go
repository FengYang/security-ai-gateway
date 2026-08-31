package kex

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDeriveSeedSymmetry(t *testing.T) {
	a, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	seedAB, err := a.DeriveSeed(b.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	seedBA, err := b.DeriveSeed(a.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(seedAB, seedBA) {
		t.Fatal("双方派生的种子不一致")
	}
	if len(seedAB) != 32 {
		t.Fatalf("种子长度 %d != 32", len(seedAB))
	}
}

func TestDeriveSeedDifferentPair(t *testing.T) {
	a, _ := Generate(rand.Reader)
	b, _ := Generate(rand.Reader)
	c, _ := Generate(rand.Reader)

	seedAB, _ := a.DeriveSeed(b.PublicBytes())
	seedAC, _ := a.DeriveSeed(c.PublicBytes())
	if bytes.Equal(seedAB, seedAC) {
		t.Fatal("不同对端派生种子不应相同")
	}
}

func TestDeriveSeedInvalidPeer(t *testing.T) {
	a, _ := Generate(rand.Reader)
	if _, err := a.DeriveSeed([]byte{0x01, 0x02}); err == nil {
		t.Fatal("无效公钥应报错")
	}
	if _, err := a.DeriveSeed(nil); err == nil {
		t.Fatal("nil 公钥应报错")
	}
}
