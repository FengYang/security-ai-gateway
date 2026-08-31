// Command aggregator 启动聚合服务器（M4 服务化）。
//
// 用法示例：
//
//	aggregator -n 4 -t 3 -dim 8 -addr :9000,:9001,:9002,:9003
//
// 聚合服务器通过 gRPC 驱动各参与方完成安全聚合协议，
// 输出 = 在线参与方输入之和（模 R）；服务器不可见任何单方明文。
package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"security-ai-gateway/secagg"
)

func main() {
	n := flag.Int("n", 4, "参与方总数")
	t := flag.Int("t", 3, "秘密共享阈值 t (> n/2)")
	dim := flag.Int("dim", 8, "输入向量维度")
	addrList := flag.String("addr", "", "参与方 gRPC 地址列表，逗号分隔")
	tlsCert := flag.String("tls-cert", "", "客户端 TLS 证书（PEM）；为空则明文传输")
	tlsKey := flag.String("tls-key", "", "客户端 TLS 私钥（PEM）")
	tlsCA := flag.String("tls-ca", "", "服务端证书 CA（PEM）；为空使用系统根证书")
	tlsServerName := flag.String("tls-server-name", "", "服务端证书校验名（SAN/CN），TLS 模式下必填")
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatalf("-tls-cert 与 -tls-key 必须同时提供")
	}
	tlsEnabled := *tlsCert != "" || *tlsCA != ""
	if tlsEnabled && *tlsServerName == "" {
		log.Fatalf("TLS 模式下 -tls-server-name 必填")
	}

	cfg := secagg.Config{
		NumParties: *n,
		Threshold:  *t,
		Modulus:    secagg.DefaultModulus,
		Dimension:  *dim,
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("配置非法: %v", err)
	}

	addrs := strings.Split(*addrList, ",")
	if len(addrs) != *n {
		log.Fatalf("参与方地址数 %d 与配置 %d 不符", len(addrs), *n)
	}

	var dialOpts []grpc.DialOption
	if tlsEnabled {
		creds, err := secagg.ClientTLS(*tlsCert, *tlsKey, *tlsServerName, *tlsCA)
		if err != nil {
			log.Fatalf("构造 mTLS 凭证失败: %v", err)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
		log.Printf("启用 TLS 连接（serverName=%s）", *tlsServerName)
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	drivers := make([]secagg.PartyDriver, *n)
	for i, addr := range addrs {
		conn, err := grpc.NewClient(strings.TrimSpace(addr), dialOpts...)
		if err != nil {
			log.Fatalf("连接参与方 %d (%s) 失败: %v", i, addr, err)
		}
		defer conn.Close()
		drivers[i] = secagg.NewRemoteParty(conn, i)
	}

	agg, err := secagg.NewAggregator(cfg)
	if err != nil {
		log.Fatalf("构造聚合器失败: %v", err)
	}
	res, err := agg.Run(drivers)
	if err != nil {
		log.Fatalf("协议执行失败: %v", err)
	}
	fmt.Printf("在线参与方: %v\n", res.OnlineIDs)
	fmt.Printf("安全求和结果: %v\n", res.Sum)
}
