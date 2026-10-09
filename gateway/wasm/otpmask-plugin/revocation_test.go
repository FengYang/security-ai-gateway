package main

import "testing"

func TestIsKeyRevoked(t *testing.T) {
	// 复位运行态
	keyRevocationRuntime.mu.Lock()
	keyRevocationRuntime.revoked = map[string]struct{}{}
	keyRevocationRuntime.loaded = false
	keyRevocationRuntime.mu.Unlock()

	if isKeyRevoked("j1") {
		t.Error("未成功拉到前不应拦截（TTL 兜底，§8）")
	}
	if isKeyRevoked("") {
		t.Error("空 jti 不应拦截")
	}

	keyRevocationRuntime.mu.Lock()
	keyRevocationRuntime.revoked["j1"] = struct{}{}
	keyRevocationRuntime.loaded = true
	keyRevocationRuntime.mu.Unlock()

	if !isKeyRevoked("j1") {
		t.Error("命中吊销集应拦截")
	}
	if isKeyRevoked("j2") {
		t.Error("未命中不应拦截")
	}
}

func TestRevocationItoa(t *testing.T) {
	cases := map[int64]string{0: "0", 1: "1", 60: "60", 1712345678: "1712345678", -5: "-5"}
	for in, want := range cases {
		if got := revocationItoa(in); got != want {
			t.Errorf("revocationItoa(%d)=%q want=%q", in, got, want)
		}
	}
}
