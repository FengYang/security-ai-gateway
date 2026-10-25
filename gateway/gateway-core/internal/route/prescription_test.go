package route

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef") // 32 字节
}

func TestIssueVerifyRoundtrip(t *testing.T) {
	s, err := NewSigner(testKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1725500000, 0)
	tok, err := s.Issue(&RoutePrescription{
		PrescriptionID: "rx_1",
		Tenant:         "tenant-a",
		Model:          "qwen-plus",
		CreatedAt:      now.Unix(),
		Policy:         &RoutePolicy{PreferredEngine: "cmaas", FallbackEngine: "vllm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("token 应三段式，got: %s", tok)
	}
	p, err := s.Verify(tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Tenant != "tenant-a" || p.Model != "qwen-plus" {
		t.Fatalf("处方字段不符: %+v", p)
	}
	if p.Policy.PreferredEngine != "cmaas" {
		t.Fatalf("policy 不符: %+v", p.Policy)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	s1, _ := NewSigner(testKey())
	s2, _ := NewSigner([]byte("fedcba9876543210fedcba9876543210"))
	now := time.Unix(1725500000, 0)
	tok, _ := s1.Issue(&RoutePrescription{Tenant: "a", Model: "m", CreatedAt: now.Unix()})
	if _, err := s2.Verify(tok, now); err == nil {
		t.Fatal("错误密钥应验签失败")
	}
}

func TestVerifyExpired(t *testing.T) {
	s, _ := NewSigner(testKey())
	now := time.Unix(1725500000, 0)
	tok, _ := s.Issue(&RoutePrescription{Tenant: "a", Model: "m", CreatedAt: now.Unix()})
	// 超过过期时间
	if _, err := s.Verify(tok, now.Add(31*time.Second)); err == nil {
		t.Fatal("过期处方应拒绝")
	}
}

func TestVerifyTimeSkew(t *testing.T) {
	s, _ := NewSigner(testKey())
	now := time.Unix(1725500000, 0)
	tok, _ := s.Issue(&RoutePrescription{Tenant: "a", Model: "m", CreatedAt: now.Unix()})
	// 超出签发时间窗（未来 31s）
	if _, err := s.Verify(tok, now.Add(-31*time.Second)); err == nil {
		t.Fatal("超时间窗处方应拒绝")
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	s, _ := NewSigner(testKey())
	now := time.Unix(1725500000, 0)
	tok, _ := s.Issue(&RoutePrescription{Tenant: "tenant-a", Model: "qwen-plus", CreatedAt: now.Unix()})
	// 篡改 payload 中 tenant 为 evil-tenant（与签名不匹配，应验签失败）
	// 注：JWT 三段切分与 base64url 编解码改为测试内联——原用的包内私有助手
	// （splitToken/b64）已随处方算法迁移到共享包 gateway/rxroute。
	parts := strings.Split(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload 解码失败: %v", err)
	}
	evil := strings.Replace(string(b), "tenant-a", "evil-tenant", 1)
	if evil == string(b) {
		t.Fatal("替换未生效，测试无效")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(evil))
	tampered := strings.Join(parts, ".")
	if _, err := s.Verify(tampered, now); err == nil {
		t.Fatal("篡改 payload 应验签失败")
	}
}
