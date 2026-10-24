package cryptopmodule

// bench_test.go —— P1-5 M6-2：模块适配层基准（性能矩阵，§5.3 必测项①②）。
//
// 用途：为 scripts/cryptop-module-poc.sh 提供**可复现**的基准入口。
//   - 未设 MODULE_BACKEND 时默认用 MockBackend（**适配层开销基线**）；
//   - 真机 POC 时经 MODULE_BACKEND/MODULE_LIB_PATH 切换真实厂商后端。
//
// 口径：mock 数据仅为适配层基线，**非厂商模块性能**，不得用于选型打分或合规声明。
//
// TestPOCConfigValidate 亦供 POC 脚本调用（需 CRYPTOP_POC=1 门控，避免污染常规套件）。

import (
	"os"
	"testing"
)

// benchBackend 构造基准后端：默认 mock 基线；设了 MODULE_BACKEND 则按其加载。
func benchBackend(b *testing.B) ModuleBackend {
	b.Helper()
	cfg := LoadConfig()
	if os.Getenv(EnvBackend) == "" {
		cfg.Backend = BackendMock // 本地默认：适配层基线
	}
	bk, err := NewBackend(cfg)
	if err != nil {
		// 真机不可用时跳过（不 fail 常规套件）。
		b.Skipf("backend=%s 不可用: %v", cfg.Backend, err)
	}
	if err := bk.Init(cfg); err != nil {
		b.Skipf("backend=%s 初始化失败: %v", cfg.Backend, err)
	}
	b.Cleanup(func() { _ = bk.Close() })
	return bk
}

// benchBackendSM 仅适用于 SM 算法基线（mock/软件实现）；配置了真实 HSM 后端
// （pkcs11/sdf）时跳过——真实 HSM 无 SM 机制（SoftHSM 实测），SM 基准无意义。
func benchBackendSM(b *testing.B) ModuleBackend {
	b.Helper()
	if be := os.Getenv(EnvBackend); be != "" && be != string(BackendMock) {
		b.Skipf("SM 基准仅 mock/软件基线，配置的后端=%s 无 SM 机制，跳过", be)
	}
	return benchBackend(b)
}

// benchBackendPKCS11 仅真实 PKCS#11 后端（MODULE_BACKEND=pkcs11）；mock 仅实现 SM 算法，
// 不支持 AES/EC，跳过。用于 M6-2 真机复测（软件 HSM 口径，非厂商硬件）。
func benchBackendPKCS11(b *testing.B) ModuleBackend {
	b.Helper()
	if os.Getenv(EnvBackend) != string(BackendPKCS11) {
		b.Skip("PKCS#11 原生基准仅 MODULE_BACKEND=pkcs11 真机运行（mock 跳过）")
	}
	return benchBackend(b)
}

// ---- PKCS#11 原生基准组（M6-2 真机复测；SoftHSMv2 软件 HSM 口径）----
// 仅 MODULE_BACKEND=pkcs11 真机运行；数据口径=软件 HSM，**非厂商硬件**，
// 不得用于选型打分或合规声明（厂商硬件性能待 S3-a 到货验收复测）。

// BenchmarkModulePKCS11AESGCMSeal1K PKCS#11 AES-256-GCM 加密 1KB 吞吐。
func BenchmarkModulePKCS11AESGCMSeal1K(b *testing.B) {
	bk := benchBackendPKCS11(b)
	key, err := bk.GenerateKey("aes-256-enc", "bench-aes-1k")
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := make([]byte, 1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Seal(key, nonce, pt, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModulePKCS11AESGCMSeal64K PKCS#11 AES-256-GCM 加密 64KB 吞吐。
func BenchmarkModulePKCS11AESGCMSeal64K(b *testing.B) {
	bk := benchBackendPKCS11(b)
	key, err := bk.GenerateKey("aes-256-enc", "bench-aes-64k")
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := make([]byte, 64*1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Seal(key, nonce, pt, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModulePKCS11SHA256Hash1K PKCS#11 SHA-256 摘要 1KB 吞吐。
func BenchmarkModulePKCS11SHA256Hash1K(b *testing.B) {
	bk := benchBackendPKCS11(b)
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Hash(data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModulePKCS11ECDSASign PKCS#11 ECDSA(P-256) 签名 QPS。
func BenchmarkModulePKCS11ECDSASign(b *testing.B) {
	bk := benchBackendPKCS11(b)
	priv, _, err := bk.GenerateKeyPair(UsageSign)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("bench-sign-message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Sign(priv, msg, ""); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModulePKCS11ECDSAVerify PKCS#11 ECDSA(P-256) 验签 QPS。
func BenchmarkModulePKCS11ECDSAVerify(b *testing.B) {
	bk := benchBackendPKCS11(b)
	priv, pub, err := bk.GenerateKeyPair(UsageSign)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("bench-verify-message")
	sig, err := bk.Sign(priv, msg, "")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bk.Verify(pub, msg, sig, ""); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModulePKCS11SealConcurrent 并发 Seal 吞吐（会话池 + 多核；§5.3 必测项⑤并发配额）。
func BenchmarkModulePKCS11SealConcurrent(b *testing.B) {
	bk := benchBackendPKCS11(b)
	key, err := bk.GenerateKey("aes-256-enc", "bench-aes-conc")
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := make([]byte, 1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := bk.Seal(key, nonce, pt, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestPOCConfigValidate 由 scripts/cryptop-module-poc.sh 设置 CRYPTOP_POC=1 触发：
// 按 MODULE_* 环境变量校验配置（§6.4 / R-S3-1/2/7/11）。
func TestPOCConfigValidate(t *testing.T) {
	if os.Getenv("CRYPTOP_POC") == "" {
		t.Skip("POC-only：由 scripts/cryptop-module-poc.sh 设 CRYPTOP_POC=1 触发")
	}
	cfg := LoadConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("配置校验失败: %v", err)
	}
}

// BenchmarkModuleSM4GCMSeal1K 必测项①：SM4-GCM 加密 1KB 吞吐。
func BenchmarkModuleSM4GCMSeal1K(b *testing.B) {
	bk := benchBackendSM(b)
	key, err := bk.GenerateKey("sm4-128", "bench-seal-1k")
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := make([]byte, 1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Seal(key, nonce, pt, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModuleSM4GCMSeal64K 必测项①：SM4-GCM 加密 64KB 吞吐。
func BenchmarkModuleSM4GCMSeal64K(b *testing.B) {
	bk := benchBackendSM(b)
	key, err := bk.GenerateKey("sm4-128", "bench-seal-64k")
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, 12)
	pt := make([]byte, 64*1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Seal(key, nonce, pt, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModuleSM3Hash1K SM3 摘要 1KB 吞吐。
func BenchmarkModuleSM3Hash1K(b *testing.B) {
	bk := benchBackendSM(b)
	data := make([]byte, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Hash(data); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModuleSM2Sign 必测项②：SM2 签名 QPS。
func BenchmarkModuleSM2Sign(b *testing.B) {
	bk := benchBackendSM(b)
	priv, _, err := bk.GenerateKeyPair(UsageSign)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("bench-sign-message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.Sign(priv, msg, "1234567812345678"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkModuleSM2Verify 必测项②：SM2 验签 QPS。
func BenchmarkModuleSM2Verify(b *testing.B) {
	bk := benchBackendSM(b)
	priv, pub, err := bk.GenerateKeyPair(UsageSign)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("bench-verify-message")
	sig, err := bk.Sign(priv, msg, "1234567812345678")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bk.Verify(pub, msg, sig, "1234567812345678"); err != nil {
			b.Fatal(err)
		}
	}
}
