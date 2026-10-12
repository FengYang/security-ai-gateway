package cryptopmodule

// mock_test.go —— MockBackend 契约测试（§6.1 方法表 + KAT 交叉验签 + 故障注入）。
//
// KAT 判据（对齐 P1-5 V-4）：mock 与软件国密库（gmsm）参数一致——SM4/SM3 逐字节
// 一致、SM2 交叉验签；uid 不一致必须验签失败（GM2-06）。

import (
	"bytes"
	"testing"
)

// errInjected 故障注入用的任意错误。
var errInjected = &injectedErr{}

type injectedErr struct{}

func (*injectedErr) Error() string { return "mock: 故障注入" }

func initMock(t *testing.T) *MockBackend {
	t.Helper()
	m := NewMockBackend()
	cfg := DefaultConfig()
	cfg.Backend = BackendMock
	cfg.MaxSessions = 4
	cfg.SessionQueueSize = 8
	if err := m.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestMockInitCapabilityCheck(t *testing.T) {
	m := NewMockBackend()
	cfg := DefaultConfig()
	cfg.Backend = BackendMock
	// R-S3-11：RequiredMechanisms 全合法但 mock 恒全覆盖 → 通过。
	if err := m.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// 未知机制名 → Init 失败（配置校验拦截）。
	cfg.RequiredMechanisms = []string{"sm9-gcm"}
	if err := m.Init(cfg); err == nil {
		t.Fatal("未知机制名应 Init 失败")
	}
	// FailInit 注入。
	m2 := NewMockBackend()
	m2.FailInit = errInjected
	if err := m2.Init(cfg); err == nil {
		t.Fatal("FailInit 注入应失败")
	}
}

func TestMockSymmetricKAT(t *testing.T) {
	m := initMock(t)
	// 生成 KEK 与 DEK。
	kek, err := m.GenerateKey("sm4-128", "kek-1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dek, err := m.GenerateKey("sm4-128", "dek-1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Seal/Open 往返。
	nonce := bytes.Repeat([]byte{0x07}, 12)
	pt := []byte("hello-国密-SM4-GCM")
	aad := []byte("cryptop/test/v1")
	ct, err := m.Seal(kek, nonce, pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := m.Open(kek, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("Seal/Open 往返不一致: %q", got)
	}
	// AAD 篡改必须失败（AEAD 语义）。
	if _, err := m.Open(kek, nonce, ct, []byte("tampered")); err == nil {
		t.Fatal("AAD 篡改应解密失败")
	}
	// Hash 与 gmsm 逐字节一致。
	sum, err := m.Hash(pt)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	wantSum, _ := mockHash(pt)
	if !bytes.Equal(sum, wantSum) {
		t.Fatal("Hash 与 gmsm 不一致")
	}
	// HMAC 往返 + 与 gmsm 一致。
	mac, err := m.HMAC(kek, pt)
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	wantMac, _ := mockHMAC(mustKeyBytes(t, m, kek), pt)
	if !bytes.Equal(mac, wantMac) {
		t.Fatal("HMAC 与 gmsm 不一致")
	}
	// KDF 确定性与 gmsm 一致。
	d1, err := m.KDF(kek, []byte("salt"), []byte("info"), 32, "")
	if err != nil {
		t.Fatalf("KDF: %v", err)
	}
	d2, _ := m.KDF(kek, []byte("salt"), []byte("info"), 32, "")
	if !bytes.Equal(d1, d2) {
		t.Fatal("KDF 应确定性")
	}
	wantD, _ := mockKDF(mustKeyBytes(t, m, kek), []byte("salt"), []byte("info"), 32)
	if !bytes.Equal(d1, wantD) {
		t.Fatal("KDF 与 gmsm 不一致")
	}
	// WrapKey/UnwrapKey 往返（AAD 绑定用途标签；dek 为待封装字节——三级会话域材料）。
	dekBytes := mustKeyBytes(t, m, dek)
	wrapped, err := m.WrapKey(kek, dekBytes)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	unwrapped, err := m.UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(unwrapped, dekBytes) {
		t.Fatal("Wrap/Unwrap 往返不一致")
	}
	// Rand 长度。
	r, err := m.Rand(16)
	if err != nil || len(r) != 16 {
		t.Fatalf("Rand(16) 异常: %v len=%d", err, len(r))
	}
}

// mustKeyBytes 仅测试用：mock 内部取密钥字节做交叉比对（生产无此路径）。
func mustKeyBytes(t *testing.T, m *MockBackend, ref KeyRef) []byte {
	t.Helper()
	k, err := m.lookup(ref)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return append([]byte(nil), k.bytes...)
}

func TestMockSM2KATAndCrossVerify(t *testing.T) {
	m := initMock(t)
	signRef, signPub, err := m.GenerateKeyPair(UsageSign)
	if err != nil {
		t.Fatalf("GenerateKeyPair(sign): %v", err)
	}
	ecdhRef, ecdhPub, err := m.GenerateKeyPair(UsageECDH)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ecdh): %v", err)
	}
	msg := []byte("cross-verify-国密")
	// 默认 uid 签名 → 默认 uid 验签通过。
	sig, err := m.Sign(signRef, msg, "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := m.Verify(signPub, msg, sig, ""); err != nil {
		t.Fatalf("Verify（默认 uid）: %v", err)
	}
	// 自定义 uid 签名 → 同 uid 验签通过、异 uid 失败（GM2-06）。
	sig2, err := m.Sign(signRef, msg, "tenant-a")
	if err != nil {
		t.Fatalf("Sign(uid): %v", err)
	}
	if err := m.Verify(signPub, msg, sig2, "tenant-a"); err != nil {
		t.Fatalf("Verify（同 uid）: %v", err)
	}
	if err := m.Verify(signPub, msg, sig2, "tenant-b"); err == nil {
		t.Fatal("异 uid 验签应失败")
	}
	// 消息篡改必须失败。
	if err := m.Verify(signPub, []byte("tampered"), sig, ""); err == nil {
		t.Fatal("篡改消息验签应失败")
	}
	// 交叉验签（V-4）：mock 签 → gmsm 直验；gmsm 直签 → mock 验。
	if err := mockVerify(signPub, msg, sig, ""); err != nil {
		t.Fatalf("gmsm 直验 mock 签名失败: %v", err)
	}
	directSig, err := mockSign(mustKeyBytes(t, m, signRef), msg, "")
	if err != nil {
		t.Fatalf("gmsm 直签: %v", err)
	}
	if err := m.Verify(signPub, msg, directSig, ""); err != nil {
		t.Fatalf("mock 验 gmsm 直签失败: %v", err)
	}
	// ECDH 双方协商一致（G3-02）。
	peerPriv, peerPub, err := mockGenerateKeyPair()
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	ss1, err := m.ECDH(ecdhRef, peerPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	ss2, err := mockECDH(peerPriv, ecdhPub)
	if err != nil {
		t.Fatalf("peer ECDH: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("ECDH 双方共享秘密不一致")
	}
	// 用途隔离：签名私钥不得用于协商。
	if _, err := m.ECDH(signRef, peerPub); err == nil {
		t.Fatal("签名密钥用于 ECDH 应被拒")
	}
	// 私钥不得经模块外泄（B-6.1-4：token 不含字节）。
	if bytes.Contains(signRef, mustKeyBytes(t, m, signRef)) {
		t.Fatal("KeyRef token 不应包含密钥字节")
	}
}

func TestMockKeyLifecycleAndErrors(t *testing.T) {
	m := initMock(t)
	ref, err := m.GenerateKey("sm4-128", "life-1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// 未知名 ref → ErrKeyNotFound。
	if _, err := m.Seal(KeyRef("mock:nope"), []byte("n"), []byte("p"), nil); err == nil {
		t.Fatal("未知 ref 应失败")
	}
	// Destroy 后再用 → ErrKeyNotFound。
	if err := m.DestroyKey(ref); err != nil {
		t.Fatalf("DestroyKey: %v", err)
	}
	if _, err := m.Seal(ref, []byte("n"), []byte("p"), nil); err == nil {
		t.Fatal("销毁后应不可用")
	}
	// 重复 Destroy → ErrKeyNotFound。
	if err := m.DestroyKey(ref); err == nil {
		t.Fatal("重复 Destroy 应失败")
	}
	// RotateKey：旧 ref 生成新 ref（规格延续）。
	old, _ := m.GenerateKey("sm4-128", "rot-1")
	newRef, err := m.RotateKey(old, "")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if bytes.Equal(old, newRef) {
		t.Fatal("轮换应产生新 ref")
	}
	if _, err := m.Seal(newRef, bytes.Repeat([]byte{0x01}, 12), []byte("p"), nil); err != nil {
		t.Fatalf("新 ref 应可用: %v", err)
	}
}

func TestMockFaultInjection(t *testing.T) {
	m := initMock(t)
	ref, _ := m.GenerateKey("sm4-128", "f-1")
	m.FailSeal = errInjected
	if _, err := m.Seal(ref, []byte("n"), []byte("p"), nil); err == nil {
		t.Fatal("FailSeal 注入应失败")
	}
	m.FailSeal = nil
	m.FailRand = errInjected
	if _, err := m.Rand(8); err == nil {
		t.Fatal("FailRand 注入应失败")
	}
	m.FailRand = nil
	m.FailHealth = true
	if m.Health() != HealthDown {
		t.Fatal("FailHealth 注入应 HealthDown")
	}
}

func TestMockSessions(t *testing.T) {
	m := initMock(t) // max=4
	var held []Session
	for i := 0; i < 4; i++ {
		s, err := m.AcquireSession()
		if err != nil {
			t.Fatalf("AcquireSession %d: %v", i, err)
		}
		held = append(held, s)
	}
	// 池满：在途会话数经 PoolStats 验证（max=4）。
	st := m.PoolStats()
	if st.InUse != 4 {
		t.Fatalf("在途会话应 4: %+v", st)
	}
	// 释放全部后可再取（复用）。
	for _, s := range held {
		if err := m.ReleaseSession(s); err != nil {
			t.Fatalf("ReleaseSession: %v", err)
		}
	}
	s, err := m.AcquireSession()
	if err != nil {
		t.Fatalf("释放后再取: %v", err)
	}
	if err := m.ReleaseSession(s); err != nil {
		t.Fatalf("ReleaseSession: %v", err)
	}
}

func TestMockHealthLevels(t *testing.T) {
	m := initMock(t)
	if m.Health() != HealthOK {
		t.Fatal("初始应 OK")
	}
	if got := HealthDegraded.String(); got != "degraded" {
		t.Fatalf("HealthLevel.String: %q", got)
	}
}
