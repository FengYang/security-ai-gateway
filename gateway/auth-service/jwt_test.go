package main

// C-6 JWT 单元测试：签发/校验/过期/篡改/错误密钥。

import (
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestSignVerifyRoundTrip(t *testing.T) {
	tok, err := signJWT(testSecret, "acme", time.Hour)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	c, err := verifyJWT(testSecret, tok)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if c.Tenant != "acme" || c.Sub != "acme" {
		t.Fatalf("声明不符: %+v", c)
	}
	if c.EXP <= time.Now().Unix() {
		t.Fatal("exp 应大于当前时间")
	}
}

func TestVerifyExpired(t *testing.T) {
	tok, _ := signJWT(testSecret, "acme", -time.Minute) // 负 TTL → exp 已过
	if _, err := verifyJWT(testSecret, tok); err == nil || !strings.Contains(err.Error(), "过期") {
		t.Fatalf("过期 token 应被拒，got %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	tok, _ := signJWT(testSecret, "acme", time.Hour)
	// 篡改载荷段（tenant 改成 attacker）
	parts := strings.Split(tok, ".")
	attacker := strings.Replace(parts[1], "YWNtZQ", "YXR0YWNrZXI", 1) // acme→attacker 的 b64 前缀
	if attacker == parts[1] {
		// 直接翻转一个字符更可靠
		attacker = parts[1][:len(parts[1])-2] + "XX"
	}
	tampered := parts[0] + "." + attacker + "." + parts[2]
	if _, err := verifyJWT(testSecret, tampered); err == nil || !strings.Contains(err.Error(), "签名无效") {
		t.Fatalf("篡改 token 应被拒（签名无效），got %v", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	tok, _ := signJWT(testSecret, "acme", time.Hour)
	if _, err := verifyJWT([]byte("ffffffffffffffffffffffffffffffff"), tok); err == nil {
		t.Fatal("错误密钥应校验失败")
	}
}

func TestVerifyMalformed(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a.b.c.d", "xxx.yyy.zzz"} {
		if _, err := verifyJWT(testSecret, bad); err == nil {
			t.Fatalf("畸形 token %q 应被拒", bad)
		}
	}
}
