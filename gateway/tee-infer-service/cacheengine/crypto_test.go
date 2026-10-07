package cacheengine

import (
	"bytes"
	"context"
	"testing"
)

func testAESKey() []byte { return bytes.Repeat([]byte{0x2a}, 32) }

func TestAEAD_SealOpen_RoundTrip(t *testing.T) {
	key := testAESKey()
	aad := BuildAAD("kh1", 1700000000000, "v1")
	plain := []byte(`{"text":"hello-secret"}`)

	blob, err := AEADSeal(key, aad, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(blob, []byte("hello-secret")) {
		t.Fatal("ciphertext must not contain plaintext")
	}
	got, err := AEADOpen(key, aad, blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestAEAD_NonceRandomized(t *testing.T) {
	key := testAESKey()
	b1, _ := AEADSeal(key, []byte("a"), []byte("x"))
	b2, _ := AEADSeal(key, []byte("a"), []byte("x"))
	if bytes.Equal(b1, b2) {
		t.Fatal("ciphertext must differ across calls (random nonce)")
	}
}

func TestAEAD_AADMismatchFails(t *testing.T) {
	key := testAESKey()
	blob, _ := AEADSeal(key, BuildAAD("kh1", 1, "v1"), []byte("p"))
	if _, err := AEADOpen(key, BuildAAD("kh2", 1, "v1"), blob); err == nil {
		t.Fatal("expected AAD mismatch failure (anti-relocation, §7.4)")
	}
}

func TestAEAD_WrongKeyFails(t *testing.T) {
	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)
	blob, _ := AEADSeal(k1, []byte("a"), []byte("p"))
	if _, err := AEADOpen(k2, []byte("a"), blob); err == nil {
		t.Fatal("expected failure with wrong key")
	}
}

func TestAEAD_ShortBlobFails(t *testing.T) {
	if _, err := AEADOpen(testAESKey(), []byte("a"), []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestNewStaticKeyProvider_Validation(t *testing.T) {
	if _, err := NewStaticKeyProvider([]byte("short")); err == nil {
		t.Fatal("expected key length error")
	}
	p, err := NewStaticKeyProvider(testAESKey())
	if err != nil {
		t.Fatalf("NewStaticKeyProvider: %v", err)
	}
	k, err := p.Key(context.Background())
	if err != nil || len(k) != 32 {
		t.Fatalf("Key() = (%d bytes, %v)", len(k), err)
	}
}

func TestBuildAAD(t *testing.T) {
	if got, want := string(BuildAAD("kh", 123, "v9")), "kh|123|v9"; got != want {
		t.Fatalf("BuildAAD = %q, want %q", got, want)
	}
}
