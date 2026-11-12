package wafsvc

// filter.go — 明文 Provider 入口 HTTP 过滤器（sidecar 形态，M3-1）。
// 仅 `/provider/<name>/...` 进入评估；密态路径与其余入口直接放行（防护边界不变）。

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// ProviderPathPrefix 明文 Provider 入口前缀（§2.1 防护边界）。
const ProviderPathPrefix = "/provider/"

// TenantHeader per-tenant 归属头（部署期由上游网关注入；不可由客户端伪造时须在入口复核）。
const TenantHeader = "X-Tenant-Id"

// TenantPolicy per-tenant 开关与模式覆写（M3-2 下发字段的落地形态）。
type TenantPolicy struct {
	Enabled bool
	Mode    string // "" = 跟随全局 WAF_MODE；否则 off|detection|blocking
}

// WafAuditEvent 命中/阻断/调优事件（变更与命中均落审计，§2.1 判据 3）。
type WafAuditEvent struct {
	Action  string
	Tenant  string
	Path    string
	Version string
	Reason  string
	RuleIDs []string
}

// FilterStats 指标快照（原子计数；供 /healthz 与压测对账）。
type FilterStats struct {
	Evaluated   int64
	Allowed     int64
	Detected    int64
	Blocked     int64
	Errors      int64
	BodySkipped int64
}

// Filter HTTP 过滤器。
type Filter struct {
	engine WafEngine
	next   http.Handler
	cfg    Config
	audit  func(WafAuditEvent)

	mu      sync.RWMutex
	tenants map[string]TenantPolicy

	evaluated   atomic.Int64
	allowed     atomic.Int64
	detected    atomic.Int64
	blocked     atomic.Int64
	errs        atomic.Int64
	bodySkipped atomic.Int64
}

// NewFilter 构造过滤器（audit 可为 nil；next 为上游转发 handler）。
func NewFilter(engine WafEngine, next http.Handler, cfg Config, audit func(WafAuditEvent)) *Filter {
	return &Filter{
		engine: engine, next: next, cfg: cfg, audit: audit,
		tenants: map[string]TenantPolicy{},
	}
}

// SetTenantPolicy 下发 per-tenant 开关（M3-2 租户插件策略接入点）。
func (f *Filter) SetTenantPolicy(tenant string, p TenantPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants[tenant] = p
}

// ReloadExcludes 排除表变更（原子换入规则集快照；变更落审计，§2.1 判据 3）。
func (f *Filter) ReloadExcludes(xs []WafExclusion) error {
	if err := f.engine.Reload(RuleSetBundle{Paranoia: f.cfg.Paranoia, Excludes: xs}); err != nil {
		return err
	}
	f.emit(WafAuditEvent{Action: "excludes_reload", Reason: "误杀调优通道变更", Version: f.engine.Version()})
	return nil
}

// Stats 指标快照。
func (f *Filter) Stats() FilterStats {
	return FilterStats{
		Evaluated: f.evaluated.Load(), Allowed: f.allowed.Load(), Detected: f.detected.Load(),
		Blocked: f.blocked.Load(), Errors: f.errs.Load(), BodySkipped: f.bodySkipped.Load(),
	}
}

func (f *Filter) emit(ev WafAuditEvent) {
	if f.audit != nil {
		f.audit(ev)
	}
}

func (f *Filter) tenantPolicy(tenant string) TenantPolicy {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if p, ok := f.tenants[tenant]; ok {
		return p
	}
	return TenantPolicy{Enabled: true}
}

// failAction 引擎故障时的处置（§2.1 判据 5：不静默放行）。
// auto = 检测模式放行+告警，阻断模式拒绝；显式 open/block 覆写。
func (f *Filter) failAction(mode string) bool { // true = 拒绝请求
	switch f.cfg.FailMode {
	case "open":
		return false
	case "block":
		return true
	default:
		return mode == ModeBlocking
	}
}

// ServeHTTP 评估并转发（或阻断）。
func (f *Filter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, ProviderPathPrefix) || f.cfg.Mode == ModeOff {
		f.next.ServeHTTP(w, r)
		return
	}
	tenant := strings.TrimSpace(r.Header.Get(TenantHeader))
	p := f.tenantPolicy(tenant)
	mode := f.cfg.Mode
	if p.Mode != "" {
		mode = p.Mode
	}
	if !p.Enabled || mode == ModeOff {
		f.next.ServeHTTP(w, r)
		return
	}
	f.evaluated.Add(1)

	// body 读取：最多 max+1 字节；超限跳过 body 检查但完整还原给上游（不丢请求、不无限缓冲）。
	var body []byte
	skipBody := false
	if r.Body != nil {
		limit := f.cfg.BodyMaxBytes
		if limit <= 0 {
			limit = 262144
		}
		buf, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
		if err != nil {
			f.handleEngineError(w, r, tenant, mode, err)
			return
		}
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
		if len(buf) > limit {
			skipBody = true
			f.bodySkipped.Add(1)
		} else {
			body = buf
		}
	}

	getArgs := map[string][]string(r.URL.Query())
	req := WafRequest{
		Method: r.Method, URI: r.URL.RequestURI(), Host: r.Host,
		Headers: map[string][]string(r.Header), GetArgs: getArgs,
		Body: body, Tenant: tenant, Path: r.URL.Path,
	}
	if skipBody {
		// 超限：传 nil body 让引擎跳过 phase:2 body 检查；GET 参数与头部仍受检。
		req.Body = nil
	}
	dec, err := f.engine.Eval(req)
	if err != nil {
		f.handleEngineError(w, r, tenant, mode, err)
		return
	}
	ev := WafAuditEvent{Action: dec.Action, Tenant: tenant, Path: r.URL.Path, Version: dec.Version, RuleIDs: dec.RuleIDs}
	switch dec.Action {
	case WafActionBlock:
		f.blocked.Add(1)
		f.emit(ev)
		w.Header().Set("X-WAF-Decision", WafActionBlock)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "request blocked by waf", "mode": mode,
			"rule_ids": dec.RuleIDs, "version": dec.Version,
		})
	case WafActionDetect:
		f.detected.Add(1)
		f.emit(ev)
		w.Header().Set("X-WAF-Decision", WafActionDetect)
		f.next.ServeHTTP(w, r)
	default:
		f.allowed.Add(1)
		f.next.ServeHTTP(w, r)
	}
}

// handleEngineError 引擎异常：告警 + 按 WAF_FAIL_MODE 处置（检测→放行，阻断→403）。
func (f *Filter) handleEngineError(w http.ResponseWriter, r *http.Request, tenant, mode string, cause error) {
	f.errs.Add(1)
	log.Printf("[wafsvc] 引擎异常（fail-closed 策略处置）tenant=%s path=%s mode=%s: %v", tenant, r.URL.Path, mode, cause)
	deny := f.failAction(mode)
	ev := WafAuditEvent{
		Action: map[bool]string{true: "fail_closed", false: "fail_open"}[deny],
		Tenant: tenant, Path: r.URL.Path, Version: f.engine.Version(), Reason: cause.Error(),
	}
	f.emit(ev)
	if deny {
		f.blocked.Add(1)
		w.Header().Set("X-WAF-Decision", "fail_closed")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"waf engine unavailable (fail-closed)"}`))
		return
	}
	f.allowed.Add(1)
	w.Header().Set("X-WAF-Decision", "fail_open")
	f.next.ServeHTTP(w, r)
}
