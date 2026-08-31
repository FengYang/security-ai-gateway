// Command party 启动参与方 gRPC 服务（M4 服务化）。
//
// 用法示例：
//
//	party -listen :9000 -id 0 -n 4 -t 3 -dim 8 -input '[100,200,300,400,500,600,700,800]'
//	party -listen :9000 -id 0 -n 4 -t 3 -dim 8 -input '...' -sign-key /path/to/ed25519.key
//
// 参与方进程持有私有输入与密钥材料，仅通过 PartyService 接口
// 响应聚合服务器的协议驱动（服务器不可见明文与掩码）。
//
// 恶意敌手模式：通过 -sign-key 指定 Ed25519 身份私钥（PEM 格式），
// 并将对应公钥预置到聚合服务器的可信密钥表中。
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"security-ai-gateway/secagg"
)

func main() {
	listen := flag.String("listen", ":9000", "gRPC 监听地址")
	id := flag.Int("id", 0, "参与方 ID")
	n := flag.Int("n", 4, "参与方总数")
	t := flag.Int("t", 3, "秘密共享阈值 t (> n/2)")
	dim := flag.Int("dim", 8, "输入向量维度")
	inputJSON := flag.String("input", "", "输入向量 JSON，如 [100,200,300]")
	signKeyPath := flag.String("sign-key", "", "Ed25519 身份私钥文件路径（PEM 格式）；为空则自动生成（半诚实模式）")
	sessionIDHex := flag.String("session-id", "", "会话 ID（十六进制）；为空时由聚合器生成并分发")
	tlsCert := flag.String("tls-cert", "", "服务端 TLS 证书（PEM）；为空则明文传输")
	tlsKey := flag.String("tls-key", "", "服务端 TLS 私钥（PEM）")
	tlsClientCA := flag.String("tls-client-ca", "", "客户端 CA（PEM）；设置后强制 mTLS 双向认证")
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatalf("-tls-cert 与 -tls-key 必须同时提供")
	}

	var x []uint64
	if err := json.Unmarshal([]byte(*inputJSON), &x); err != nil {
		log.Fatalf("解析输入失败: %v", err)
	}

	cfg := secagg.Config{
		NumParties: *n,
		Threshold:  *t,
		Modulus:    secagg.DefaultModulus,
		Dimension:  *dim,
	}
	if *sessionIDHex != "" {
		sid, err := hexDecode(*sessionIDHex)
		if err != nil {
			log.Fatalf("解析 session-id 失败: %v", err)
		}
		cfg.SessionID = sid
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("配置非法: %v", err)
	}

	// 加载或生成身份私钥
	var signKey ed25519.PrivateKey
	if *signKeyPath != "" {
		data, err := os.ReadFile(*signKeyPath)
		if err != nil {
			log.Fatalf("读取身份私钥失败: %v", err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "ED25519 PRIVATE KEY" {
			log.Fatalf("无效的身份私钥 PEM")
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("解析身份私钥失败: %v", err)
		}
		var ok bool
		signKey, ok = k.(ed25519.PrivateKey)
		if !ok {
			log.Fatalf("私钥不是 Ed25519 类型")
		}
	}

	p, err := secagg.NewParty(*id, x, cfg, signKey)
	if err != nil {
		log.Fatalf("构造参与方失败: %v", err)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *listen, err)
	}
	var opts []grpc.ServerOption
	opts = append(opts, secagg.DefaultServerOptions()...)
	if *tlsCert != "" {
		creds, err := secagg.ServerTLS(*tlsCert, *tlsKey, *tlsClientCA)
		if err != nil {
			log.Fatalf("构造 mTLS 凭证失败: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Printf("参与方 %d 启用 TLS（clientCA=%v）", *id, *tlsClientCA != "")
	}
	s := grpc.NewServer(opts...)
	secagg.RegisterPartyServiceServer(s, secagg.NewPartyServer(p))
	log.Printf("参与方 %d 服务就绪: %s", *id, *listen)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("gRPC 服务退出: %v", err)
	}
}

// hexDecode 解码十六进制字符串。
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("十六进制长度为奇数")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := hexVal(s[i])
		low := hexVal(s[i+1])
		if high < 0 || low < 0 {
			return nil, fmt.Errorf("无效十六进制字符")
		}
		b[i/2] = byte(high<<4 | low)
	}
	return b, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
