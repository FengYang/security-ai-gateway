package keymgmt

import (
	"testing"
	"time"
)

// ---------- KeyManager ----------

func TestKeyIssueDerive(t *testing.T) {
	km, err := NewKeyManager(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	seed1, nonce1, err := km.Issue("req-1", "mock")
	if err != nil {
		t.Fatal(err)
	}
	seed2, nonce2, err := km.Issue("req-2", "mock")
	if err != nil {
		t.Fatal(err)
	}
	if nonce1 == nonce2 {
		t.Fatal("nonce 重复")
	}
	if len(seed1) != 32 || len(seed2) != 32 {
		t.Fatal("请求密钥长度 != 32")
	}
	// 不同请求派生不同密钥
	same := true
	for i := range seed1 {
		if seed1[i] != seed2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("不同请求的派生密钥相同")
	}

	// 回溯一致性
	got, ok := km.Lookup(nonce1)
	if !ok {
		t.Fatal("nonce 回溯失败")
	}
	for i := range got {
		if got[i] != seed1[i] {
			t.Fatal("回溯密钥不一致")
		}
	}
	// 未知 nonce
	if _, ok := km.Lookup("deadbeef"); ok {
		t.Fatal("未知 nonce 应回溯失败")
	}
}

func TestKeyRotationForwardSecrecy(t *testing.T) {
	km, err := NewKeyManager(50 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	before := km.MasterID()
	time.Sleep(120 * time.Millisecond)
	after := km.MasterID()
	if after <= before {
		t.Fatalf("主密钥未轮换: %d -> %d", before, after)
	}
}

func TestKeyIssueDeterministicDerive(t *testing.T) {
	// 验证派生是 HMAC(master, reqID||model||ts) —— 相同入参结果相同（内部一致性）
	km, err := NewKeyManager(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()
	km.mu.Lock()
	a := km.deriveLocked("req-x", "mock", 12345)
	b := km.deriveLocked("req-x", "mock", 12345)
	km.mu.Unlock()
	if string(a) != string(b) {
		t.Fatal("相同入参派生结果不一致")
	}
}
