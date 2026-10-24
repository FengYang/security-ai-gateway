//go:build pkcs11

package cryptopsvc

// metrics_module_live_test.go —— M5-e 端到端指标冒烟（真实 SoftHSM 后端）。
//
// 仅当 P11_LIVE=1 运行（.248 联调机）。构造真实 PKCS11Backend →
// NewModuleProviderWithBackend → NewServer(ProfileSMModule) → 命中 /v1/rand
// 触发 op 计时与观测采集 → 渲染 /metrics，断言 5 个 cryptop_module_* 序列
// 携带真实槽位 "0"（验证 M5 接线在真机链路闭合）。
//
// 环境变量同 pkcs11_live_test.go：
//
//	P11_LIVE=1
//	P11_LIVE_LIB=/usr/lib/softhsm/libsofthsm2.so
//	P11_LIVE_PIN=0000

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/cryptop"
	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

func liveEnvOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestModuleMetricsLiveEndToEnd(t *testing.T) {
	if os.Getenv("P11_LIVE") != "1" {
		t.Skip("P11_LIVE != 1，跳过真机端到端指标冒烟")
	}
	cfgM := cryptopmodule.DefaultConfig()
	cfgM.Backend = cryptopmodule.BackendPKCS11
	cfgM.LibPath = liveEnvOr("P11_LIVE_LIB", "/usr/lib/softhsm/libsofthsm2.so")
	cfgM.Slot = 0
	cfgM.PinRef = "env:P11_LIVE_PIN" // R-S3-2 载体引用，非字面值
	cfgM.MaxSessions = 4
	cfgM.SessionQueueSize = 2
	cfgM.RequiredMechanisms = []string{cryptopmodule.MechRand}

	backend, err := cryptopmodule.NewBackend(cfgM)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	defer func() { _ = backend.Close() }()

	prov, err := cryptop.NewModuleProviderWithBackend(backend, cfgM)
	if err != nil {
		t.Fatalf("NewModuleProviderWithBackend: %v", err)
	}
	s, err := NewServer(prov, Config{
		Profile:     cryptop.ProfileSMModule,
		CallTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer(sm-module live): %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// 命中一次 /v1/rand：经真实后端 C_GenerateRandom，触发 op 计时 +
	// 观测采集（setModuleObservability），并消耗会话（sessions_active 非零）。
	resp, err := ts.Client().Post(ts.URL+"/v1/rand", "application/json",
		strings.NewReader(`{"n":32}`))
	if err != nil {
		t.Fatalf("POST /v1/rand: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/rand HTTP %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	raw := renderMetrics(t, s)
	checks := []string{
		`cryptop_module_rand_health{slot="0"} 1`,                          // 真实自检通过
		`cryptop_module_health{peer="primary",slot="0"} 1`,                // 真实 token 探活
		`cryptop_module_sessions_active{slot="0"}`,                        // 真实会话池占用
		`cryptop_module_latency_seconds_count{op="rand",slot="0"} 1`,      // SetOpObserver 生效
	}
	for _, c := range checks {
		if !strings.Contains(raw, c) {
			t.Fatalf("真机 /metrics 缺序列（含真实槽位 0）: %q\n--- metrics ---\n%s", c, raw)
		}
	}
	t.Logf("真机 /metrics 通过，5 个 cryptop_module_* 序列均含真实槽位 0：\n%s",
		extractModuleMetrics(raw))
}

// extractModuleMetrics 从全量指标文本中筛出 cryptop_module_* 行（日志用）。
func extractModuleMetrics(raw string) string {
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "cryptop_module_") {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
