// P2-4 T-3.4：core 侧心跳上报（applied_config_version 携载）单测。
package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestReporter 构造指向测试端点的上报器。
func newTestReporter(t *testing.T, endpoint, clusterID, cred string) *Reporter {
	t.Helper()
	r, err := NewReporter(Config{
		Endpoint:   endpoint,
		ClusterID:  clusterID,
		Credential: cred,
		Interval:   10 * time.Millisecond,
		Timeout:    time.Second,
		Logger:     log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("构造上报器失败: %v", err)
	}
	return r
}

// TestNewReporterValidatesConfig 配置校验：端点/集群 ID/凭证缺失即报错。
func TestNewReporterValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"缺端点", Config{ClusterID: "c1", Credential: "k"}},
		{"端点协议非法", Config{Endpoint: "ftp://x/heartbeat", ClusterID: "c1", Credential: "k"}},
		{"缺集群ID", Config{Endpoint: "http://x/hb", Credential: "k"}},
		{"缺凭证", Config{Endpoint: "http://x/hb", ClusterID: "c1"}},
	}
	for _, c := range cases {
		if _, err := NewReporter(c.cfg); err == nil {
			t.Fatalf("%s 应报错", c.name)
		}
	}
}

// TestReportOnceSendsVersionAndCredential 上报体携带 applied_config_version 与集群凭证。
func TestReportOnceSendsVersionAndCredential(t *testing.T) {
	var gotBody map[string]string
	var gotCred string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCred = r.Header.Get("X-Cluster-Credential")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestReporter(t, srv.URL, "cluster-a", "cred-123")
	if err := r.ReportOnce(context.Background(), "9"); err != nil {
		t.Fatalf("上报失败: %v", err)
	}
	if gotBody["applied_config_version"] != "9" {
		t.Fatalf("请求体版本错误: %v", gotBody)
	}
	if gotCred != "cred-123" {
		t.Fatalf("集群凭证头错误: %q", gotCred)
	}
}

// TestReportOnceEmptyVersionMeansUnknown 未上报时上报空串（管理面标记 unknown）。
func TestReportOnceEmptyVersionMeansUnknown(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestReporter(t, srv.URL, "cluster-a", "cred-123")
	if err := r.ReportOnce(context.Background(), ""); err != nil {
		t.Fatalf("上报失败: %v", err)
	}
	v, ok := gotBody["applied_config_version"]
	if !ok {
		t.Fatalf("请求体缺少 applied_config_version: %v", gotBody)
	}
	if v != "" {
		t.Fatalf("未上报时应为空串: %q", v)
	}
}

// TestReportOnceRejectedStatus 被管理面拒绝时返回错误（调用方可告警）。
func TestReportOnceRejectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	r := newTestReporter(t, srv.URL, "cluster-a", "bad-cred")
	if err := r.ReportOnce(context.Background(), "3"); err == nil {
		t.Fatalf("被拒时应返回错误")
	}
}

// TestRunReportsPeriodically 周期上报：多次触发且版本取自 provider。
func TestRunReportsPeriodically(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		seen = append(seen, body["applied_config_version"])
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestReporter(t, srv.URL, "cluster-a", "cred-123")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	go r.Run(ctx, func() string { return "42" })

	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("周期上报次数不足: %d", len(seen))
	}
	for _, v := range seen {
		if v != "42" {
			t.Fatalf("上报版本错误: %q", v)
		}
	}
}

// TestRunStopsOnContextCancel ctx 取消后停止上报（不泄漏 goroutine）。
func TestRunStopsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newTestReporter(t, srv.URL, "cluster-a", "cred-123")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, func() string { return "1" })
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("ctx 取消后 Run 未退出")
	}
}

// TestNewReporterDefaults 默认值兜底（周期/超时）。
func TestNewReporterDefaults(t *testing.T) {
	r, err := NewReporter(Config{Endpoint: "http://x/hb", ClusterID: "c", Credential: "k"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if r.Interval() != DefaultInterval {
		t.Fatalf("默认周期应为 %v: got %v", DefaultInterval, r.Interval())
	}
	if !strings.Contains(r.cfg.Endpoint, "http://") {
		t.Fatalf("端点被改写: %q", r.cfg.Endpoint)
	}
}
