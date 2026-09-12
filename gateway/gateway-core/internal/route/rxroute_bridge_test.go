package route

import (
	"testing"
	"time"

	"security-ai-gateway/gateway/rxroute"
)

// TestPrescriptionSharedImplementation 锁死"签发端（gateway-core）与验签端（wasm 数据面
// 插件）共用同一份处方算法"——这正是抽出共享包 gateway/rxroute 的目的。
//
// 做法：用 gateway-core 的 route.Signer 签发，直接调用共享包 rxroute.VerifyWith 验签；
// 并断言异密钥被拒（若两端将来各自实现，本测试会立刻失败）。
func TestPrescriptionSharedImplementation(t *testing.T) {
	now := time.Unix(1725500000, 0)
	s, err := NewSigner(testKey())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Issue(&RoutePrescription{Tenant: "tenant-a", Model: "qwen-plus", CreatedAt: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rxroute.VerifyWith(testKey(), tok, now)
	if err != nil {
		t.Fatalf("共享包验签应通过（两端同源）：%v", err)
	}
	if p.Tenant != "tenant-a" || p.Model != "qwen-plus" {
		t.Fatalf("处方载荷不符：%+v", p)
	}
	if _, err := rxroute.VerifyWith([]byte("ffffffffffffffffffffffffffffffff"), tok, now); err == nil {
		t.Fatal("异密钥验签应失败")
	}
	if _, err := rxroute.VerifyWith(testKey(), tok, now.Add(31*time.Second)); err == nil {
		t.Fatal("超出签发时间窗应失败")
	}
}
