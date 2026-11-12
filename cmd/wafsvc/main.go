// cmd/wafsvc — 明文 Provider 入口 WAF sidecar 可执行入口（M3-1，技术实现方案 §2.3 sidecar 形态）。
//
// 部署：上游 Higress 将 /provider/* 路由指向本服务 → 过滤后反向代理到真实 Provider 上游。
// 密态路径不经过本服务（防护边界不变）；P1-8 红线：不修改 deploy/higress/* 既有文件。
//
// 安装期参数（参数名·默认值·覆写点·未填行为）：
//   - WAF_LISTEN·:8080·env·未填=默认值
//   - WAF_UPSTREAM_URL·空·env·未填=fail-closed 拒绝启动（必须显式指向受信 Provider 上游）
//
// 其余参数见 gateway/wafsvc/config.go（WAF_MODE/CRS_VERSION/PARANOIA/BODY_MAX/EXCLUDES/FAIL_MODE）。
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"security-ai-gateway/gateway/wafsvc"
)

func main() {
	cfg, err := wafsvc.ConfigFromEnv()
	if err != nil {
		log.Fatalf("wafsvc: 安装期参数非法（fail-closed 拒绝启动）: %v", err)
	}
	upstreamRaw := strings.TrimSpace(os.Getenv("WAF_UPSTREAM_URL"))
	upstream, err := url.Parse(upstreamRaw)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		log.Fatalf("wafsvc: WAF_UPSTREAM_URL 未填或非法（fail-closed 拒绝启动）")
	}
	listen := strings.TrimSpace(os.Getenv("WAF_LISTEN"))
	if listen == "" {
		listen = ":8080"
	}

	engine, err := wafsvc.NewEngine(cfg)
	if err != nil {
		log.Fatalf("wafsvc: 规则集加载失败（fail-closed 拒绝启动）: %v", err)
	}
	audit := func(ev wafsvc.WafAuditEvent) {
		// 结构化审计输出（部署侧采集/落链；不记录请求正文，§2.1 只记录命中/阻断/调优事件）。
		b, _ := json.Marshal(ev)
		log.Printf("[waf-audit] %s", b)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	filter := wafsvc.NewFilter(engine, proxy, cfg, audit)

	mux := http.NewServeMux()
	mux.Handle("/provider/", filter)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok", "mode": cfg.Mode, "version": engine.Version(),
			"crs_checksum": engineChecksum(engine), "stats": filter.Stats(),
		})
	})
	// 非 /provider/ 路径不走 WAF（防护边界），直接代理。
	mux.Handle("/", proxy)

	log.Printf("wafsvc 启动 listen=%s upstream=%s mode=%s version=%s", listen, upstreamRedacted(upstream), cfg.Mode, engine.Version())
	srv := &http.Server{Addr: listen, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("wafsvc: 服务退出: %v", err)
	}
}

// engineChecksum 取引擎校验和（接口未暴露 Checksum，用类型断言保持 WafEngine 解耦）。
func engineChecksum(e wafsvc.WafEngine) string {
	if c, ok := e.(interface{ Checksum() string }); ok {
		return c.Checksum()
	}
	return ""
}

func upstreamRedacted(u *url.URL) string { return u.Scheme + "://" + u.Host }
