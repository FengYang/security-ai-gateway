// Package mock — 离线保护 Transport 测试（T05：真·断网代码级强制，§7.9 QA-4/QA2-08~12）。
//
// 验证 OfflineTransport 的 DialContext：
//   - 拒绝一切非 loopback 地址（错误含 "offline guard"，并计入 EgressAttempts）；
//   - 0.0.0.0 不在白名单（§7.9-2）；
//   - 放行 127.0.0.0/8 与 ::1。
package mock

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOfflineTransportRejectsNonLoopback(t *testing.T) {
	ResetEgressAttempts()
	tr := NewOfflineTransport()
	req, err := http.NewRequest("GET", "http://10.0.0.1/somepath", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil {
		t.Fatal("应拒绝非 loopback 地址")
	}
	if !strings.Contains(err.Error(), "offline guard") {
		t.Fatalf("错误应来自离线保护（offline guard）：%v", err)
	}
	if EgressAttempts() == 0 {
		t.Fatal("非 loopback 尝试应计入 EgressAttempts")
	}
	ResetEgressAttempts()
}

func TestOfflineTransportRejectsZeroZeroZeroZero(t *testing.T) {
	ResetEgressAttempts()
	tr := NewOfflineTransport()
	req, err := http.NewRequest("GET", "http://0.0.0.0:8080/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "offline guard") {
		t.Fatalf("0.0.0.0 不应视作 loopback（应被拒绝）：%v", err)
	}
	ResetEgressAttempts()
}

func TestOfflineTransportAllowsLoopback(t *testing.T) {
	tr := NewOfflineTransport()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("loopback 应被离线保护放行：%v", err)
	}
	resp.Body.Close()
}
