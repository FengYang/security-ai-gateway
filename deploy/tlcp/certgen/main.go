// certgen —— P0-4 §12.4 SM2 TLCP 双证书生成器（B6#10）。
//
// 生成：SM2 自签根（ca.crt）+ SM2 签名证书（sign.crt/sign.key，握手签名用）
//      + SM2 加密证书（enc.crt/enc.key，密钥交换用）。全部 SM2-SM3 签名，
//      证书 PEM（CERTIFICATE），私钥 PKCS8 PEM（PRIVATE KEY）。
//
// 证书用途（GM/T 0024 / GB/T 38636，Tongsuo NTLS 互通）：
//   - 签名证书：KeyUsage critical digitalSignature；ExtKeyUsage serverAuth
//   - 加密证书：KeyUsage critical keyEncipherment|dataEncipherment|keyAgreement
//     （静态 ECC-SM2 与 ECDHE-SM2 两类套件均可识别）
//
// 仅复用 github.com/emmansun/gmsm（仓库既有依赖，MIT），无自研密码。
package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// certOptions 证书生成参数。
type certOptions struct {
	commonName string
	org        string
	dnsNames   []string
	ipAddrs    []net.IP
	validity   time.Duration
}

func main() {
	outDir := flag.String("out", "deploy/tlcp/certs", "证书输出目录")
	commonName := flag.String("cn", "tlcp-gateway.local", "服务器证书 CN（同时写入 SAN DNS）")
	org := flag.String("org", "OTPMask", "证书主体 Organization")
	dns := flag.String("dns", "", "额外 SAN DNS（逗号分隔）")
	ips := flag.String("ips", "127.0.0.1", "SAN IP（逗号分隔；置空不写 IP SAN）")
	days := flag.Int("days", 3650, "证书有效期（天）")
	flag.Parse()

	if *commonName == "" {
		fatal("CN 不能为空")
	}
	if *days <= 0 {
		fatal("days 必须为正数")
	}
	dnsNames := []string{*commonName}
	for _, d := range splitList(*dns) {
		dnsNames = append(dnsNames, d)
	}
	var ipAddrs []net.IP
	for _, s := range splitList(*ips) {
		ip := net.ParseIP(s)
		if ip == nil {
			fatal("非法 IP: %s", s)
		}
		ipAddrs = append(ipAddrs, ip)
	}

	opts := certOptions{
		commonName: *commonName,
		org:        *org,
		dnsNames:   dnsNames,
		ipAddrs:    ipAddrs,
		validity:   time.Duration(*days) * 24 * time.Hour,
	}
	if err := generate(*outDir, opts); err != nil {
		fatal("%v", err)
	}
}

// generatedCerts 为一次生成的产物（供同包测试直接消费，免落盘）。
type generatedCerts struct {
	rootDER, signDER, encDER []byte
	signKeyDER, encKeyDER    []byte
	rootKey                  *sm2.PrivateKey
	signKey, encKey          *sm2.PrivateKey
}

// generate 生成整套证书并写入 dir。
func generate(dir string, o certOptions) error {
	certs, err := buildCerts(o)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录: %w", err)
	}
	files := []struct {
		name string
		typ  string
		der  []byte
		perm os.FileMode
	}{
		{"ca.crt", "CERTIFICATE", certs.rootDER, 0o644},
		{"sign.crt", "CERTIFICATE", certs.signDER, 0o644},
		{"sign.key", "PRIVATE KEY", certs.signKeyDER, 0o600},
		{"enc.crt", "CERTIFICATE", certs.encDER, 0o644},
		{"enc.key", "PRIVATE KEY", certs.encKeyDER, 0o600},
	}
	for _, f := range files {
		if err := writePEM(filepath.Join(dir, f.name), f.typ, f.der, f.perm); err != nil {
			return err
		}
	}
	return nil
}

// buildCerts 在内存中构造根与双叶子证书。
func buildCerts(o certOptions) (*generatedCerts, error) {
	rootKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("根密钥生成: %w", err)
	}
	signKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("签名密钥生成: %w", err)
	}
	encKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("加密密钥生成: %w", err)
	}

	now := time.Now()
	rootTpl := &smx509.Certificate{
		SerialNumber:          serial(),
		Subject:               subject(o.org, "OTPMask TLCP Root CA"),
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(o.validity),
		SignatureAlgorithm:    smx509.SM2WithSM3,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              smx509.KeyUsageCertSign | smx509.KeyUsageCRLSign,
	}
	rootDER, err := smx509.CreateCertificate(rand.Reader, rootTpl, rootTpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("根证书签发: %w", err)
	}

	leafBase := func(cn string) *smx509.Certificate {
		return &smx509.Certificate{
			SerialNumber:       serial(),
			Subject:            subject(o.org, cn),
			NotBefore:          now.Add(-time.Minute),
			NotAfter:           now.Add(o.validity),
			SignatureAlgorithm: smx509.SM2WithSM3,
			DNSNames:           o.dnsNames,
			IPAddresses:        o.ipAddrs,
		}
	}

	signTpl := leafBase(o.commonName)
	signTpl.KeyUsage = smx509.KeyUsageDigitalSignature
	signTpl.ExtKeyUsage = []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth}
	signDER, err := smx509.CreateCertificate(rand.Reader, signTpl, rootTpl, signKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("签名证书签发: %w", err)
	}

	encTpl := leafBase(o.commonName)
	encTpl.KeyUsage = smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment | smx509.KeyUsageKeyAgreement
	encDER, err := smx509.CreateCertificate(rand.Reader, encTpl, rootTpl, encKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("加密证书签发: %w", err)
	}

	signKeyDER, err := smx509.MarshalPKCS8PrivateKey(signKey)
	if err != nil {
		return nil, fmt.Errorf("签名私钥 PKCS8: %w", err)
	}
	encKeyDER, err := smx509.MarshalPKCS8PrivateKey(encKey)
	if err != nil {
		return nil, fmt.Errorf("加密私钥 PKCS8: %w", err)
	}

	return &generatedCerts{
		rootDER: rootDER, signDER: signDER, encDER: encDER,
		signKeyDER: signKeyDER, encKeyDER: encKeyDER,
		rootKey: rootKey, signKey: signKey, encKey: encKey,
	}, nil
}

// ---- 辅助 ----

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	block := &pem.Block{Type: typ, Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), perm); err != nil {
		return fmt.Errorf("写 %s: %w", path, err)
	}
	return nil
}

func serial() *big.Int {
	// 正序列号，128bit 随机空间（RFC 5280 ≤20 字节）
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("序列号随机失败: %v", err))
	}
	return n
}

func subject(org, cn string) pkix.Name {
	return pkix.Name{Country: []string{"CN"}, Organization: []string{org}, CommonName: cn}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "certgen: "+format+"\n", args...)
	os.Exit(1)
}
