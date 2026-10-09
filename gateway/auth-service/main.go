// Package main — 租户鉴权服务（C-6，JWT HS256 签发/校验）
//
// 为网关插件签发带 tenant 声明的 JWT，插件校验后以声明租户覆盖客户端自声明头，
// 落实"租户由网关鉴权签发"的生产边界（替代 X-Tenant-ID 自声明）。
//
// API：
//
//	POST /v1/issue {"tenant":"acme"[,"sub","role","jti","ttl_seconds"]} -> {"token":"eyJ..."}
//	POST /issue     （旧路径别名，行为同上；仅传 tenant 时 sub=tenant）
//	GET  /verify?token=... -> {"ok":true,"tenant":"acme","exp":...}
//
// 签名密钥（§8 依赖 5，M3 定档）：
//   - 配置 CRYPTOPSVC_URL → **CPS KeyRef 模式**：密钥字节恒驻 cryptopsvc，本服务经
//     `/v1/hmac` 求 MAC（C-5）；启动即 Ping，CPS 不可达/KeyRef 无效 → fail-closed 拒启动。
//   - 未配置 → **本地 secret 模式**（-secret / 随机生成；兼容既有部署，非生产口径）。
//
// 运行：go run ./gateway/auth-service [-listen :19200] [-secret <32字节hex>] [-ttl 24h]
// 环境：CRYPTOPSVC_URL（如 http://ai-gateway-cryptopsvc:19300）、CPS_KEYREF_JWT（缺省 otpmask/jwt/v1）
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// defaultKeyRefJWT CPS 中租户 JWT 密钥的 KeyRef（§6.3 命名规范）。
const defaultKeyRefJWT = "otpmask/jwt/v1"

func main() {
	listen := flag.String("listen", ":19200", "监听地址")
	secretHex := flag.String("secret", "", "JWT 签名密钥（32 字节 hex；CPS 模式下忽略）")
	ttl := flag.Duration("ttl", 24*time.Hour, "token 默认有效期（请求未指定 ttl_seconds 时）")
	flag.Parse()

	signer := buildSigner(*secretHex)

	mux := http.NewServeMux()

	// 签发端点（/v1/issue 为 §6.11 口径；/issue 为旧路径别名）
	issue := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Tenant     string `json:"tenant"`
			Sub        string `json:"sub"`
			Role       string `json:"role"`
			JTI        string `json:"jti"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || req.Tenant == "" {
			http.Error(w, "tenant 必填", http.StatusBadRequest)
			return
		}
		sub := req.Sub
		if sub == "" {
			sub = req.Tenant // 兼容：仅传 tenant 时 sub 取 tenant（既有行为）
		}
		ttlSec := req.TTLSeconds
		if ttlSec <= 0 {
			ttlSec = int64(ttl.Seconds())
		}
		now := time.Now().Unix()
		tok, err := signJWTClaims(signer, Claims{
			Sub: sub, Tenant: req.Tenant, Role: req.Role, JTI: req.JTI,
			IAT: now, EXP: now + ttlSec,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("签发失败: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
	}
	mux.HandleFunc("/v1/issue", issue)
	mux.HandleFunc("/issue", issue)

	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifyJWTWith(signer, r.URL.Query().Get("token"))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":false,"error":` + jsonString(err.Error()) + `}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tenant": claims.Tenant, "exp": claims.EXP})
	})

	log.Printf("auth-service 就绪: %s ttl=%s", *listen, *ttl)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}

// buildSigner 选择签名器：CPS KeyRef 优先（fail-closed），否则本地 secret（兼容）。
func buildSigner(secretHex string) jwtSigner {
	cpsURL := strings.TrimRight(os.Getenv("CRYPTOPSVC_URL"), "/")
	if cpsURL != "" {
		keyRef := os.Getenv("CPS_KEYREF_JWT")
		if keyRef == "" {
			keyRef = defaultKeyRefJWT
		}
		cc := newCPSClient(cpsURL, keyRef, 5*time.Second)
		if err := cc.Ping(); err != nil {
			log.Fatalf("CPS 不可达或 KeyRef 无效（fail-closed，§8 依赖 5）：%v", err)
		}
		log.Printf("auth-service 签名模式=CPS url=%s keyRef=%s", cpsURL, keyRef)
		return cpsSigner{client: cc}
	}

	var secret []byte
	if secretHex != "" {
		k, err := hex.DecodeString(secretHex)
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
	log.Printf("auth-service 签名模式=本地 secret（未配置 CRYPTOPSVC_URL；非生产口径）")
	return localSigner{secret: secret}
}

// jsonString 把字符串安全编码为 JSON 字面量（用于错误响应拼装）。
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
