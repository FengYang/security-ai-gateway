package secagg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// 本文件提供 mTLS 传输凭证构造（P1 mTLS 支持）：
//
// - ServerTLS：参与方服务端启用双向 TLS，要求客户端（聚合服务器）
// 出示由 clientCA 签发的证书，并校验证书身份。
// - ClientTLS：聚合服务器客户端加载自身证书与 CA，双向认证。
//
// 生产部署应通过证书管理平台（如内部 PKI / Vault）分发证书，
// 私钥权限建议 0600，且禁止将私钥提交到版本库。

// ServerTLS 构造服务端 mTLS 凭证。
//
//	certFile/keyFile 服务端证书与私钥（PEM）；
//	clientCAFile    签发客户端证书的 CA（PEM），非空则强制要求并校验客户端证书。
func ServerTLS(certFile, keyFile, clientCAFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("secagg: 加载服务端证书失败: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCAFile != "" {
		pool, err := loadCAPool(clientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(cfg), nil
}

// ClientTLS 构造客户端 mTLS 凭证。
//
//	certFile/keyFile 客户端证书与私钥（PEM），可为空（仅服务端认证）；
//	serverName       服务端证书 SAN/CN（gRPC 校验 ServerName，不可为空）；
//	caFile          校验服务端证书的 CA（PEM），为空时使用系统根证书。
func ClientTLS(certFile, keyFile, serverName, caFile string) (credentials.TransportCredentials, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("secagg: 加载客户端证书失败: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if caFile != "" {
		pool, err := loadCAPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return credentials.NewTLS(cfg), nil
}

// loadCAPool 读取 PEM CA 文件构造证书池。
func loadCAPool(caFile string) (*x509.CertPool, error) {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("secagg: 读取 CA 文件失败: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("secagg: CA 文件 %s 未包含有效证书", caFile)
	}
	return pool, nil
}
