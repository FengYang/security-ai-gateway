// cryptopsvc —— cryptop sidecar 可执行入口（P0-4 §4.3/§12.1/§12.3，B6#14）。
//
// 装配：cryptop.New(profile) → cryptopsvc.NewServer（§4.3 十三端点 + /metrics）
// → http 监听（与 wasm 插件同 Pod，R-9/R-20 须 loopback）。
//
// 配置（§12.3；flags 与 env 两种载体，静态密钥经 env 注入避免落命令行/历史）：
//
//	cryptopsvc [-listen 127.0.0.1:8082] [-profile intl|sm-software|sm-module]
//	           [-mask-prg hmac-sha256|sm4|bridge] [-call-timeout-ms 50]
//	环境变量 CRYPTO_STATIC_KEYS = JSON {"<KeyRef>":"<hex>",...}（crypto_static_keys）
//
// 失败一律启动拒（log.Fatal exit 1）：非法 profile / sm-module 未实现 / R-14/R-16/R-20/R-21，
// 绝不静默回退软件实现冒充合规。
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/cryptopsvc"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8082", "监听地址 crypto_listen（R-9/R-20：必须 loopback）")
	profile := flag.String("profile", "intl", "密码算法档 crypto_profile：intl|sm-software|sm-module")
	maskPRG := flag.String("mask-prg", "", "掩码 PRG mask_prg：hmac-sha256|sm4|bridge；空=随 profile")
	callTimeoutMS := flag.Int("call-timeout-ms", 0, "单次调用超时 crypto_call_timeout_ms（0=库缺省 50ms）")
	flag.Parse()

	prov, err := cryptop.New(cryptop.Profile(*profile))
	if err != nil {
		// sm-module = ErrNotImplemented；绝不回退 sm-software 冒充合规。
		log.Fatalf("[cryptopsvc] profile=%q 不可用（启动拒）: %v", *profile, err)
	}

	staticKeys, err := loadStaticKeys(os.Getenv("CRYPTO_STATIC_KEYS"))
	if err != nil {
		log.Fatalf("[cryptopsvc] CRYPTO_STATIC_KEYS 解析失败（启动拒）: %v", err)
	}

	srv, err := cryptopsvc.NewServer(prov, cryptopsvc.Config{
		Profile:     prov.Profile(),
		MaskPRG:     *maskPRG,
		StaticKeys:  staticKeys,
		CallTimeout: time.Duration(*callTimeoutMS) * time.Millisecond,
		ListenAddr:  *listen,
	})
	if err != nil {
		log.Fatalf("[cryptopsvc] 装配失败（启动拒 R-14/16/20/21）: %v", err)
	}

	log.Printf("[cryptopsvc] 监听 %s profile=%s mask_prg=%s 静态密钥数=%d note=%q",
		*listen, prov.Profile(), effectiveMaskPRG(*maskPRG, prov.Profile()), len(staticKeys), prov.ComplianceNote())
	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("[cryptopsvc] HTTP 服务退出: %v", err)
	}
}

// loadStaticKeys 解析 crypto_static_keys（JSON {KeyRef:hex}）；空值 = 无静态密钥。
func loadStaticKeys(raw string) (map[string][]byte, error) {
	if raw == "" {
		return nil, nil
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil {
		return nil, err
	}
	keys := make(map[string][]byte, len(encoded))
	for ref, hexKey := range encoded {
		k, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, &keyDecodeError{ref: ref, err: err}
		}
		keys[ref] = k
	}
	return keys, nil
}

// effectiveMaskPRG 仅用于日志展示缺省派生结果（真实分派在库内）。
func effectiveMaskPRG(prg string, p cryptop.Profile) string {
	if prg != "" {
		return prg
	}
	if p == cryptop.ProfileIntl {
		return "hmac-sha256"
	}
	return "sm4"
}

type keyDecodeError struct {
	ref string
	err error
}

func (e *keyDecodeError) Error() string {
	return "静态密钥 " + e.ref + " hex 解码失败: " + e.err.Error()
}
