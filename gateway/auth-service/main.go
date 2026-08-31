// Package main — 租户鉴权服务（C-6，JWT HS256 签发/校验）
//
// 为网关插件签发带 tenant 声明的 JWT，插件校验后以声明租户覆盖客户端自声明头，
// 落实"租户由网关鉴权签发"的生产边界（替代 X-Tenant-ID 自声明）。
//
// API：
// POST /issue {"tenant":"acme"} -> {"token":"eyJ..."}
// GET  /verify?token=...        -> {"ok":true,"tenant":"acme","exp":...}
//
// 运行：go run ./gateway/auth-service [-listen :19200] -secret <32字节hex> [-ttl 24h]
// 说明：HS256 手写实现（RFC 7515，base64url 无 padding），零外部依赖；
// 生产可替换为外部 IdP（Keycloak/AS）签发，插件校验逻辑不变。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	listen := flag.String("listen", ":19200", "监听地址")
	secretHex := flag.String("secret", "", "JWT 签名密钥（32 字节 hex；默认随机生成并打印）")
	ttl := flag.Duration("ttl", 24*time.Hour, "token 有效期")
	flag.Parse()

	var secret []byte
	if *secretHex != "" {
		k, err := hex.DecodeString(*secretHex)
		if err != nil || len(k) != 32 {
			log.Fatalf("secret 须为 32 字节 hex")
		}
		secret = k
	} else {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			log.Fatal(err)
		}
		log.Printf("生成的 JWT secret: %s（生产经 Secret/Vault 注入）", hex.EncodeToString(secret))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Tenant string `json:"tenant"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tenant == "" {
			http.Error(w, "tenant 必填", http.StatusBadRequest)
			return
		}
		tok, err := signJWT(secret, req.Tenant, *ttl)
		if err != nil {
			http.Error(w, fmt.Sprintf("签发失败: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifyJWT(secret, r.URL.Query().Get("token"))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":false,"error":"` + err.Error() + `"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tenant": claims.Tenant, "exp": claims.EXP})	})

	log.Printf("auth-service 就绪: %s ttl=%s", *listen, *ttl)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
