package billing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------- 告警外部交付 sink（Webhook，§6.11） ----------

func TestNewWebhookAlertSink_EmptyURL(t *testing.T) {
	if s := NewWebhookAlertSink("", time.Second); s != nil {
		t.Error("empty url should yield nil sink（仅本地日志）")
	}
}

func TestWebhookAlertSink_Posts(t *testing.T) {
	type payload struct {
		Kind           string  `json:"kind"`
		Tenant         string  `json:"tenant"`
		RemainingRatio float64 `json:"remaining_ratio"`
		Period         string  `json:"period"`
	}
	got := make(chan payload, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}
		var p payload
		_ = json.NewDecoder(r.Body).Decode(&p)
		got <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewWebhookAlertSink(srv.URL, 2*time.Second)
	if sink == nil {
		t.Fatal("sink is nil")
	}
	sink(AlertEvent{Kind: "quota_low", Tenant: "t1", RemainingRatio: 0.08, Period: "2026-10"})

	select {
	case p := <-got:
		if p.Kind != "quota_low" || p.Tenant != "t1" || p.Period != "2026-10" || p.RemainingRatio != 0.08 {
			t.Errorf("payload = %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook not received")
	}
}

// 非 2xx / 不可达 → 仅记日志，不 panic（fire-and-forget）
func TestWebhookAlertSink_Non2xxNoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s1 := NewWebhookAlertSink(srv.URL, 2*time.Second)
	s1(AlertEvent{Kind: "quota_low", Tenant: "t1"}) // 不应 panic

	s2 := NewWebhookAlertSink("http://127.0.0.1:1/unreachable", 500*time.Millisecond)
	s2(AlertEvent{Kind: "quota_low", Tenant: "t1"})
}
