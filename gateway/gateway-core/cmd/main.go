// gateway-core 控制面服务入口。
//
// 职责（MVP，Step 1）：提供路由处方（X-Otp-Route）的签发/查询/吊销 HTTP API，
// 作为网关数据面（otpmask 插件）的路由决策事实源。
// Step 1 只做处方签发（推路径 L1）；默认路由表拉取（拉路径 L2）与冷启动（L3）见设计文档后续 Step。
package main

import (
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/api"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

func main() {
	sigKeyHex := os.Getenv("OTP_CORE_SIG_KEY")
	if sigKeyHex == "" {
		log.Fatal("OTP_CORE_SIG_KEY 未设置（处方签名密钥，32 字节 hex）")
	}
	key, err := hex.DecodeString(sigKeyHex)
	if err != nil || len(key) < 32 {
		log.Fatal("OTP_CORE_SIG_KEY 无效：须为 ≥32 字节的 hex")
	}

	authToken := os.Getenv("OTP_CORE_AUTH_TOKEN") // 内网静态 token；空则禁用鉴权（仅限内部测试）
	addr := os.Getenv("OTP_CORE_ADDR")
	if addr == "" {
		addr = ":8085"
	}

	signer, err := route.NewSigner(key)
	if err != nil {
		log.Fatalf("构造签名器失败: %v", err)
	}
	msigner, err := mcpsec.NewSigner(key) // MCP 工具目录/策略共用同一对称密钥族
	if err != nil {
		log.Fatalf("构造 MCP 签名器失败: %v", err)
	}
	st := store.NewMemory()
	rt := defaultRouteTable(signer)
	srv := api.New(signer, msigner, st, authToken, rt)

	log.Printf("gateway-core 启动: addr=%s 鉴权=%v 路由版本=%d", addr, authToken != "", rt.Version)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Fatalf("HTTP 服务退出: %v", err)
	}
}

// defaultRouteTable 构造并签发默认路由表（MVP 从固定配置；后续改环境变量/DB 动态加载）。
func defaultRouteTable(signer *route.Signer) *route.RouteTable {
	now := time.Now().Unix()
	tbl := route.NewRouteTable(1, now)
	// MVP 占位：演示用固定 tenant→engine 映射；生产由控制面/DB 注入。
	tbl.Routes = []route.TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", FallbackEngine: "vllm"},
	}
	if err := signer.SignTable(tbl); err != nil {
		log.Fatalf("路由表签名失败: %v", err)
	}
	return tbl
}