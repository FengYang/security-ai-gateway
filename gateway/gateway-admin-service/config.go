// Package main — 配置加载。
//
// 管理门户业务服务（gateway-admin-service）配置一律经环境变量注入
// （docs/管理门户-细化方案.md §3.2：ConfigMap/Secret + 环境变量），不读本地文件。
package main

import (
	"fmt"
	"os"
)

// config 运行配置（env 注入，带默认值；密钥类无默认，缺失即拒绝启动 = fail-closed）。
type config struct {
	listen      string // 监听地址
	jwtSecret   []byte // 内部服务令牌共享密钥（Java 控制台 ↔ Go 服务，来自 Secret）
	jwtIssuer   string // 允许的签发方（缺省 higress-console）
	jwtAudience string // 本服务 audience（缺省 gateway-admin-service）
}

// defaultIssuer / defaultAudience 内部令牌的签发方与本服务受众默认值。
const (
	defaultIssuer   = "higress-console"
	defaultAudience = "gateway-admin-service"
)

// loadConfig 从环境变量加载配置。
func loadConfig() (*config, error) {
	secret := os.Getenv("ADMIN_SVC_JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("配置缺失：ADMIN_SVC_JWT_SECRET 未设置（内部服务令牌共享密钥，禁止空密钥启动）")
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("配置错误：ADMIN_SVC_JWT_SECRET 过短（<16 字节）")
	}

	issuer := os.Getenv("ADMIN_SVC_JWT_ISSUER")
	if issuer == "" {
		issuer = defaultIssuer
	}
	audience := os.Getenv("ADMIN_SVC_JWT_AUD")
	if audience == "" {
		audience = defaultAudience
	}
	listen := os.Getenv("ADMIN_SVC_LISTEN")
	if listen == "" {
		listen = ":19095"
	}

	return &config{
		listen:      listen,
		jwtSecret:   []byte(secret),
		jwtIssuer:   issuer,
		jwtAudience: audience,
	}, nil
}
