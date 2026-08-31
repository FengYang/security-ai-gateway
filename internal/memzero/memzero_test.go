package memzero

import "testing"

func TestBytesZeroesBuffer(t *testing.T) {
	buf := []byte("super-secret-mask-value")
	Bytes(buf)
	for i, v := range buf {
		if v != 0 {
			t.Fatalf("字节 %d 未被清零: %v", i, v)
		}
	}
}

func TestBytesEmpty(t *testing.T) {
	Bytes(nil) // 不应 panic
	Bytes([]byte{})
}
