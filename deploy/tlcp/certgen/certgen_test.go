package main

// certgen_test.go —— B6#10 SM2 双证书生成器测试（对应 T-12.4-2 证书链可在仓库内核验）。

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func testOpts() certOptions {
	return certOptions{
		commonName: "tlcp.example.com",
		org:        "OTPMask Test",
		dnsNames:   []string{"tlcp.example.com", "tlcp-alt.example.com"},
		ipAddrs:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.5")},
		validity:   365 * 24 * time.Hour,
	}
}

func TestGenerateWritesFivePEMs(t *testing.T) {
	dir := t.TempDir()
	if err := generate(dir, testOpts()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := map[string]string{
		"ca.crt":   "CERTIFICATE",
		"sign.crt": "CERTIFICATE",
		"sign.key": "PRIVATE KEY",
		"enc.crt":  "CERTIFICATE",
		"enc.key":  "PRIVATE KEY",
	}
	for name, typ := range want {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("读取 %s: %v", name, err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("%s 非合法 PEM", name)
		}
		if block.Type != typ {
			t.Fatalf("%s PEM 类型=%q 期望 %q", name, block.Type, typ)
		}
	}
}

func TestCertificatesProfileAndChain(t *testing.T) {
	dir := t.TempDir()
	if err := generate(dir, testOpts()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	root := parseCertFile(t, filepath.Join(dir, "ca.crt"))
	sign := parseCertFile(t, filepath.Join(dir, "sign.crt"))
	enc := parseCertFile(t, filepath.Join(dir, "enc.crt"))

	// 根：SM2 CA
	if !root.IsCA || root.KeyUsage&(smx509.KeyUsageCertSign|smx509.KeyUsageCRLSign) == 0 {
		t.Fatal("根证书 CA 属性/KeyUsage 不正确")
	}
	assertSM2(t, root, "root")

	// 签名证书：digitalSignature + serverAuth
	if sign.IsCA {
		t.Fatal("签名证书不得为 CA")
	}
	if sign.KeyUsage&smx509.KeyUsageDigitalSignature == 0 {
		t.Fatal("签名证书缺 digitalSignature")
	}
	if !hasEKU(sign, smx509.ExtKeyUsageServerAuth) {
		t.Fatal("签名证书缺 EKU serverAuth")
	}
	assertSM2(t, sign, "sign")
	if sign.SignatureAlgorithm != smx509.SM2WithSM3 {
		t.Fatalf("签名证书签名算法=%v", sign.SignatureAlgorithm)
	}

	// 加密证书：三类加密 KeyUsage 齐备，无 EKU
	if enc.KeyUsage&(smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment|smx509.KeyUsageKeyAgreement) !=
		smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment|smx509.KeyUsageKeyAgreement {
		t.Fatalf("加密证书 KeyUsage=%v", enc.KeyUsage)
	}
	if len(enc.ExtKeyUsage) != 0 {
		t.Fatal("加密证书不应设置 EKU")
	}
	assertSM2(t, enc, "enc")

	// 两张叶子证书密钥不同（双证书 = 两对密钥）
	if bytes.Equal(spki(t, sign), spki(t, enc)) {
		t.Fatal("签名/加密证书公钥不得相同")
	}

	// SAN
	for _, dns := range testOpts().dnsNames {
		if !contains(sign.DNSNames, dns) {
			t.Fatalf("签名证书缺 DNS SAN %s", dns)
		}
	}
	for _, ip := range testOpts().ipAddrs {
		if !containsIP(sign.IPAddresses, ip) {
			t.Fatalf("签名证书缺 IP SAN %s", ip)
		}
	}

	// 双链均可验证至 SM2 根（T-12.4-2 的仓库内部分）
	pool := smx509.NewCertPool()
	pool.AddCert(root)
	if _, err := sign.Verify(smx509.VerifyOptions{Roots: pool, DNSName: "tlcp.example.com"}); err != nil {
		t.Fatalf("签名证书链验证失败: %v", err)
	}
	if _, err := enc.Verify(smx509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("加密证书链验证失败: %v", err)
	}
}

func TestPrivateKeysMatchCertificates(t *testing.T) {
	dir := t.TempDir()
	if err := generate(dir, testOpts()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	cases := []struct{ cert, key string }{
		{"sign.crt", "sign.key"},
		{"enc.crt", "enc.key"},
	}
	for _, c := range cases {
		cert := parseCertFile(t, filepath.Join(dir, c.cert))
		keyDER := readPEMBytes(t, filepath.Join(dir, c.key), "PRIVATE KEY")
		key, err := smx509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			t.Fatalf("解析 %s: %v", c.key, err)
		}
		sm2Key, ok := key.(*sm2.PrivateKey)
		if !ok {
			t.Fatalf("%s 非 SM2 私钥: %T", c.key, key)
		}
		certSPKI := spki(t, cert)
		keySPKI, err := smx509.MarshalPKIXPublicKey(&sm2Key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(certSPKI, keySPKI) {
			t.Fatalf("%s 与 %s 密钥不匹配", c.cert, c.key)
		}
	}
}

// ---- 辅助 ----

func parseCertFile(t *testing.T, path string) *smx509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := smx509.ParseCertificatePEM(raw)
	if err != nil {
		t.Fatalf("解析证书 %s: %v", path, err)
	}
	return cert
}

func readPEMBytes(t *testing.T, path, typ string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != typ {
		t.Fatalf("%s PEM 类型不符", path)
	}
	return block.Bytes
}

func assertSM2(t *testing.T, cert *smx509.Certificate, label string) {
	t.Helper()
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != sm2.P256() {
		t.Fatalf("%s 公钥非 SM2: %T", label, cert.PublicKey)
	}
}

func spki(t *testing.T, cert *smx509.Certificate) []byte {
	t.Helper()
	b, err := smx509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hasEKU(cert *smx509.Certificate, want smx509.ExtKeyUsage) bool {
	for _, e := range cert.ExtKeyUsage {
		if e == want {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func containsIP(list []net.IP, want net.IP) bool {
	for _, ip := range list {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}
