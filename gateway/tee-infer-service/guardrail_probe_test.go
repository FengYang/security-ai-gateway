// 侧车健康探活单测：健康端点派生、探活状态、readiness 联动。
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDeriveHealthURL 健康端点 = 分类器 URL 同目录下的 /healthz。
func TestDeriveHealthURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"根路径 /classify", "http://127.0.0.1:19091/classify", "http://127.0.0.1:19091/healthz", false},
		{"子路径 /x/classify", "http://h:1/x/classify", "http://h:1/x/healthz", false},
		{"无路径", "http://h:1", "http://h:1/healthz", false},
		{"带查询串被剥离", "http://h:1/classify?k=v", "http://h:1/healthz", false},
		{"非法 URL", "://bad", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveHealthURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("非法 URL 应报错，实际 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应报错：%v", err)
			}
			if got != tc.want {
				t.Errorf("派生结果应为 %q，实际 %q", tc.want, got)
			}
		})
	}
}

// TestGuardClassifierProbeTransitions 探活：首探前不健康 → 健康 → 故障 → 恢复。
func TestGuardClassifierProbeTransitions(t *testing.T) {
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("探活应打 /healthz，实际 %s", r.URL.Path)
		}
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := newGuardClassifierProbe(srv.URL+"/classify", nil)
	if err != nil {
		t.Fatalf("构造探活器失败：%v", err)
	}
	// 未探活过 = 不健康（避免"未确认侧车可用即接流量"）
	if p.Healthy() {
		t.Fatal("首探前应为不健康")
	}
	healthy.Store(true)
	if !p.probe() || !p.Healthy() {
		t.Fatal("侧车正常时应探活为健康")
	}
	healthy.Store(false)
	if p.probe() || p.Healthy() {
		t.Fatal("侧车 500 时应探活为不健康")
	}
	healthy.Store(true)
	if !p.probe() || !p.Healthy() {
		t.Fatal("侧车恢复后应探活为健康")
	}
}

// TestReadinessReflectsClassifierProbe 侧车不健康 → readiness 503（摘流）；
// 健康 → 200；未配置侧车（guardProbe=nil）→ 200（行为不变）。
func TestReadinessReflectsClassifierProbe(t *testing.T) {
	var healthy atomic.Bool
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()

	p, err := newGuardClassifierProbe(sidecar.URL+"/classify", nil)
	if err != nil {
		t.Fatalf("构造探活器失败：%v", err)
	}
	srv := &teeServer{guard: newGuardrail(), metrics: newMetrics(), guardProbe: p}

	// 首探前（不健康）：readiness 503
	if rec := healthzRec(srv); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("侧车未确认健康时 readiness 应 503，实际 %d", rec.Code)
	}
	// 侧车健康：readiness 200
	healthy.Store(true)
	p.probe()
	if rec := healthzRec(srv); rec.Code != http.StatusOK {
		t.Fatalf("侧车健康时 readiness 应 200，实际 %d", rec.Code)
	}
	// 侧车故障：readiness 503
	healthy.Store(false)
	p.probe()
	if rec := healthzRec(srv); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("侧车故障时 readiness 应 503，实际 %d", rec.Code)
	}
	// liveness 不受侧车状态影响
	rec := httptest.NewRecorder()
	srv.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("liveness 应 200（不联动侧车），实际 %d", rec.Code)
	}

	// 未配置侧车：readiness 200（默认行为不变）
	bare := &teeServer{guard: newGuardrail(), metrics: newMetrics()}
	if rec := healthzRec(bare); rec.Code != http.StatusOK {
		t.Fatalf("未配置侧车时 readiness 应 200，实际 %d", rec.Code)
	}
}

// healthzRec 调用 readiness 探针并返回 recorder。
func healthzRec(s *teeServer) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	return rec
}

// TestGuardProbeReportsHealthGauge 探活状态须上报 gauge（侧车故障→readiness 摘流
// 必须可被指标观测，而非只能靠日志推断）。
func TestGuardProbeReportsHealthGauge(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()

	m := newMetrics()
	p, err := newGuardClassifierProbe(sidecar.URL+"/classify", m.setGuardSidecarHealthy)
	if err != nil {
		t.Fatalf("构造探活器失败：%v", err)
	}
	// 未探活：不输出该指标（避免"未配置/未探活"被误读为不健康）
	var buf bytes.Buffer
	m.render(&buf, 0)
	if strings.Contains(buf.String(), "otpmask_guard_sidecar_healthy") {
		t.Error("未探活时不应输出侧车健康指标")
	}
	// 健康 → 1
	if !p.probe() {
		t.Fatal("侧车正常应探活为健康")
	}
	buf.Reset()
	m.render(&buf, 0)
	if !strings.Contains(buf.String(), "otpmask_guard_sidecar_healthy 1") {
		t.Errorf("健康时应输出 gauge=1，实际：\n%s", buf.String())
	}
	// 故障 → 0
	healthy.Store(false)
	if p.probe() {
		t.Fatal("侧车 503 应探活为不健康")
	}
	buf.Reset()
	m.render(&buf, 0)
	if !strings.Contains(buf.String(), "otpmask_guard_sidecar_healthy 0") {
		t.Errorf("不健康时应输出 gauge=0，实际：\n%s", buf.String())
	}
}
