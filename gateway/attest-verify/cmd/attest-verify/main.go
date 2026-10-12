// attest-verify —— 证明验证 sidecar 可执行入口（P1-8 T1/T2，部署接线）。
//
// 装配：根据 -verifier 选择 BuiltinVerifier / DcapVerifier → attestverify.NewServer
// → http 监听回环地址（与 wasm 插件同 Pod）。
//
// 配置（flags 与 env 两种载体；共享令牌经 env 注入避免落命令行/历史）：
//
//	attest-verify [-listen 127.0.0.1:19191] [-verifier builtin|dcap]
//	              [-allowlist <path>] [-measurement-mode enforce|shadow]
//	              [-get-collateral true|false] [-collateral-ttl 1h]
//	环境变量 ATTEST_VERIFY_TOKEN = 共享验证令牌（X-Verify-Token）
//
// 失败一律启动拒（log.Fatal exit 1）：verifier 未知 / allowlist 加载失败 / 监听失败，
// 绝不静默降级。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"security-ai-gateway/gateway/attest-verify"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19191", "监听地址（必须 loopback）")
	verifierType := flag.String("verifier", "builtin", "验证器类型：builtin|dcap")
	allowlistPath := flag.String("allowlist", "", "度量白名单配置文件路径（空 = 仅验签 + report_data，不验度量）")
	measurementMode := flag.String("measurement-mode", "enforce", "度量校验模式：enforce|shadow")
	getCollateral := flag.String("get-collateral", "true", "dcap 模式是否从 PCS 拉取 collateral：true|false（离线/测试设 false）")
	collateralTTL := flag.Duration("collateral-ttl", time.Hour, "dcap collateral 缓存 TTL")
	flag.Parse()

	token := os.Getenv("ATTEST_VERIFY_TOKEN")

	// --- 构造验证器 ---
	var verifier attestverify.AttestationVerifier
	switch strings.ToLower(*verifierType) {
	case "builtin":
		verifier = buildBuiltinVerifier(*allowlistPath)
	case "dcap":
		verifier = buildDcapVerifier(*allowlistPath, *measurementMode, *getCollateral, *collateralTTL)
	default:
		log.Fatalf("[attest-verify] 未知 verifier=%q（启动拒）", *verifierType)
	}

	srv := attestverify.NewServer(verifier, token, *listen)
	log.Printf("[attest-verify] 监听 %s verifier=%s allowlist=%q mode=%s",
		*listen, *verifierType, *allowlistPath, *measurementMode)

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("[attest-verify] HTTP 服务退出: %v", err)
	}
}

// buildBuiltinVerifier 构造 BuiltinVerifier（自家协议，mock/CI/开发用）。
// allowlist 为空 = 仅验签 + report_data 绑定，不验 app_hash 度量。
func buildBuiltinVerifier(allowlistPath string) attestverify.AttestationVerifier {
	var allowlist *attestverify.Allowlist
	if allowlistPath != "" {
		allowlist = loadBuiltinAllowlist(allowlistPath)
	}
	return attestverify.NewBuiltinVerifier(allowlist)
}

// loadBuiltinAllowlist 从 JSON 文件加载 app_hash 白名单（["hex1", "hex2"]）。
func loadBuiltinAllowlist(path string) *attestverify.Allowlist {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[attest-verify] 读取 builtin allowlist 失败（启动拒）: %v", err)
	}
	var hashes []string
	if err := json.Unmarshal(raw, &hashes); err != nil {
		log.Fatalf("[attest-verify] 解析 builtin allowlist 失败（启动拒）: %v", err)
	}
	al := attestverify.NewAllowlist()
	for _, h := range hashes {
		al.Add(h)
	}
	log.Printf("[attest-verify] builtin allowlist 加载完成，共 %d 个 app_hash", len(hashes))
	return al
}

// buildDcapVerifier 构造 DcapVerifier（真机 TDX，生产用）。
// allowlist 为空 = 仅验签名链 + report_data + TCB，不验 MRTD/RTMR 度量。
func buildDcapVerifier(allowlistPath, measurementMode, getCollateral string, collateralTTL time.Duration) attestverify.AttestationVerifier {
	mode, err := attestverify.MeasurementModeFromString(measurementMode)
	if err != nil {
		log.Fatalf("[attest-verify] measurement-mode 非法（启动拒）: %v", err)
	}

	opts := []attestverify.DcapOption{
		attestverify.WithCollateralTTL(collateralTTL),
	}
	if strings.EqualFold(getCollateral, "false") {
		opts = append(opts, attestverify.WithGetCollateral(false))
	}
	if allowlistPath != "" {
		ml, err := attestverify.NewMeasurementAllowlist(allowlistPath, mode)
		if err != nil {
			log.Fatalf("[attest-verify] 加载度量白名单失败（启动拒）: %v", err)
		}
		opts = append(opts, attestverify.WithMeasurementAllowlist(ml))
		log.Printf("[attest-verify] dcap measurement allowlist 加载完成（mode=%s, definition=%s）",
			measurementMode, ml.Definition())
	}

	return attestverify.NewDcapVerifier(opts...)
}
