package secagg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// T-01 mTLS 双向认证：服务端要求客户端证书，完整握手 + RPC 成功。
func TestMTLSMutualAuth(t *testing.T) {
	dir := genTestPKI(t)
	serverCreds, err := ServerTLS(
		filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	clientCreds, err := ClientTLS(
		filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"),
		"localhost", filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	addr := startTLSPartyServer(t, serverCreds)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(clientCreds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 完整调用一次协议 RPC，验证 mTLS 链路可用
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out advertiseRsp
	if err := conn.Invoke(ctx, "/"+partyServiceName+"/Advertise", &advertiseReq{}, &out, grpc.ForceCodec(jsonCodec{})); err != nil {
		t.Fatalf("mTLS 下 RPC 失败: %v", err)
	}
	if out.Adv == nil {
		t.Fatal("Advertise 返回空响应")
	}
}

// T-02 缺少客户端证书：RequireAndVerifyClientCert 下握手必须失败。
func TestMTLSRejectsMissingClientCert(t *testing.T) {
	dir := genTestPKI(t)
	serverCreds, err := ServerTLS(
		filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	// 客户端仅带 CA（无证书）→ 应被服务端拒绝
	noCertCreds, err := ClientTLS("", "", "localhost", filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	addr := startTLSPartyServer(t, serverCreds)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(noCertCreds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = conn.Invoke(ctx, "/"+partyServiceName+"/Advertise", &advertiseReq{}, &advertiseRsp{}, grpc.ForceCodec(jsonCodec{}))
	if err == nil {
		t.Fatal("无客户端证书的调用应失败")
	}
}

// T-03 服务端单向 TLS（无 clientCA）：不要求客户端证书，连接成功。
func TestTLSWithoutClientAuth(t *testing.T) {
	dir := genTestPKI(t)
	serverCreds, err := ServerTLS(
		filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), "")
	if err != nil {
		t.Fatal(err)
	}
	clientCreds, err := ClientTLS("", "", "localhost", filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	addr := startTLSPartyServer(t, serverCreds)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(clientCreds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out advertiseRsp
	if err := conn.Invoke(ctx, "/"+partyServiceName+"/Advertise", &advertiseReq{}, &out, grpc.ForceCodec(jsonCodec{})); err != nil {
		t.Fatalf("单向 TLS 下 RPC 失败: %v", err)
	}
}

// startTLSPartyServer 在真实 TCP 上启动带 TLS 的参与方服务，返回地址。
func startTLSPartyServer(t *testing.T, creds credentials.TransportCredentials) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewParty(0, make([]uint64, 8), testConfig(4, 3, 8), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	RegisterPartyServiceServer(s, NewPartyServer(p))
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

// genTestPKI 生成测试 CA、服务端证书（SAN=localhost）、客户端证书，
// 返回存放 PEM 文件的目录。
func genTestPKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "otpmask-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(dir, "ca.key"), "EC PRIVATE KEY", mustMarshalECKey(t, caKey))

	// 服务端证书
	writeSignedCert(t, dir, "server", "localhost", []string{"localhost"}, caCert, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	// 客户端证书
	writeSignedCert(t, dir, "client", "otpmask-aggregator", nil, caCert, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return dir
}

func writeSignedCert(t *testing.T, dir, name, cn string, dnsNames []string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, ekus []x509.ExtKeyUsage) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, name+".crt"), "CERTIFICATE", der)
	writePEM(t, filepath.Join(dir, name+".key"), "EC PRIVATE KEY", mustMarshalECKey(t, key))
}

func mustMarshalECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}
