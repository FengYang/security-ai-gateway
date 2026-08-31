package consttime

import (
	"math/big"
	"testing"
)

func TestCompareBigIntEqual(t *testing.T) {
	a := big.NewInt(1234567890123456789)
	b := new(big.Int).Set(a)
	if !CompareBigInt(a, b) {
		t.Fatal("相等的 big.Int 应比较为 true")
	}
}

func TestCompareBigIntDifferentValues(t *testing.T) {
	a := big.NewInt(1234567890123456789)
	b := big.NewInt(1234567890123456790)
	if CompareBigInt(a, b) {
		t.Fatal("不同值的 big.Int 应比较为 false")
	}
}

func TestCompareBigIntDifferentLength(t *testing.T) {
	// 不同位长（前导零补位路径）
	a := big.NewInt(255) // 1 字节
	b := big.NewInt(511) // 2 字节
	if CompareBigInt(a, b) {
		t.Fatal("不同位长的 big.Int 应比较为 false")
	}
	// 值相等但长度不同不可能（big.Int 无前导零），此处验证不 panic
	c := big.NewInt(256)
	d := big.NewInt(256)
	if !CompareBigInt(c, d) {
		t.Fatal("同值同长应相等")
	}
}

func TestCompareBigIntZero(t *testing.T) {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if CompareBigInt(zero, one) {
		t.Fatal("0 与 1 不应相等")
	}
	if !CompareBigInt(zero, big.NewInt(0)) {
		t.Fatal("0 与 0 应相等")
	}
}

func TestCompareBigIntNil(t *testing.T) {
	if CompareBigInt(nil, big.NewInt(1)) {
		t.Fatal("nil 与非 nil 不应相等")
	}
	if !CompareBigInt(nil, nil) {
		t.Fatal("nil 与 nil 应相等")
	}
}

func TestCompareBytes(t *testing.T) {
	if !CompareBytes([]byte("abc"), []byte("abc")) {
		t.Fatal("相同字节应相等")
	}
	if CompareBytes([]byte("abc"), []byte("abd")) {
		t.Fatal("不同字节不应相等")
	}
	if CompareBytes([]byte("abc"), []byte("abcd")) {
		t.Fatal("不同长度不应相等")
	}
	if !CompareBytes(nil, nil) {
		t.Fatal("nil 与 nil 同为 0 长度，应相等（与 crypto/subtle 语义一致）")
	}
}
