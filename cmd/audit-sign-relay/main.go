// P1-7 T2c（D-20 候选 ii）：审计回灌「极薄签名器」（audit-sign-relay）。
//
// 定位：**投递适配器**，不是采集引擎。职责单一——
//
//	读取 Fluent Bit 的一个批次 → 整形为 /audit/report 契约结构 → HMAC 签名 → POST 上报。
//
// 之所以需要它：Fluent Bit 的 HTTP output 在**输出阶段重新序列化**载荷，Lua 过滤器
// 无法对最终字节签名，其内置 http output 亦不能产出 {"reports":[...]} 包裹结构
// （详见 deploy/logging/audit-report-pipeline.yaml 的「签名缺口」与本体决策 D-20）。
// 选型 (ii) 不改 tee-infer 既有上报契约，因而**不破坏 T12 已 PASS 的四域安全测试判定**
// （V-2 / D-13 / A3-10 / A3-14）。
//
// ⚠️ 部署约束（D-20 已登记）：
//  1. 只监听 **localhost**（默认 127.0.0.1:9090），与 Fluent Bit 同 Pod 本地通信，
//     **不得跨节点明文暴露**；
//  2. 上报令牌由环境变量注入（Secret），**不落日志**；日志**不打印请求体**（防敏感泄漏，
//     对齐 V-2「链上/日志无原文」精神）；
//  3. 失败**不补链**——丢弃并计数，并入 §6.5 队列三要素的丢弃率告警（A3-14 精神）。
package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"
)

type config struct {
	ListenAddr string        // 监听地址，默认 127.0.0.1:9090（**仅本地**）
	Endpoint   string        // 上游 /audit/report 完整 URL
	Token      string        // 上报令牌（与 tee-infer -audit-report-token 一致）
	MaxRetry   int           // 5xx/网络失败重试次数（4xx 不重试）
	Backoff    time.Duration // 重试退避基数
	Timeout    time.Duration // 单次上游请求超时
	// Transform 是否把「Higress 访问日志」整形为契约记录（D-18/D-20 联调下沉，见 relay.go）。
	// 默认 off（输入已是契约结构）；接 Fluent Bit 原始日志时置 on。
	Transform bool
	// MapPath consumer → tenant_id 映射表路径（TRANSFORM 模式必填，D-18 A 层解析依据）。
	MapPath string
}

func loadConfig() (config, error) {
	c := config{
		ListenAddr: envOr("LISTEN_ADDR", "127.0.0.1:9090"),
		Endpoint:   envOr("AUDIT_REPORT_URL", "http://tee-infer-service.otpmask.svc.cluster.local:19090/audit/report"),
		Token:      os.Getenv("AUDIT_REPORT_TOKEN"),
		MaxRetry:   envIntOr("MAX_RETRY", 3),
		Backoff:    time.Duration(envIntOr("BACKOFF_MS", 200)) * time.Millisecond,
		Timeout:    time.Duration(envIntOr("UPSTREAM_TIMEOUT_MS", 5000)) * time.Millisecond,
		Transform:  envBoolOr("TRANSFORM", false),
		MapPath:    envOr("MAP_PATH", "/etc/audit-report/consumer-tenant.json"),
	}
	if c.Token == "" {
		return c, errMissingToken
	}
	if c.Transform && c.MapPath == "" {
		return c, errors.New("TRANSFORM=on 时 MAP_PATH 必填（D-18 租户解析依据）")
	}
	return c, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("audit-sign-relay 启动失败: %v", err)
	}
	r := newRelay(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/audit/batch", r.handleBatch)
	mux.HandleFunc("/healthz", r.handleHealthz)
	mux.HandleFunc("/metrics", r.handleMetrics)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("audit-sign-relay 监听 %s → 上游 %s（仅本地通道，令牌已注入）", cfg.ListenAddr, cfg.Endpoint)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("audit-sign-relay 退出: %v", err)
	}
}
