package main

// T-1 请求体上限单测：Content-Length 超限确定性 413，限额内正常透传。

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLimitBodyOversizedRejected(t *testing.T) {
	called := false
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	body := bytes.NewReader(make([]byte, maxRequestBodyBytes+1))
	req := httptest.NewRequest(http.MethodPost, "/v1/infer", body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called {
		t.Fatal("超限请求不应到达处理器")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限应返回 413，got %d", rec.Code)
	}
}

func TestLimitBodyWithinLimitPasses(t *testing.T) {
	const payload = `{"text":"hello"}`
	var got []byte
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("限额内 body 读取失败: %v", err)
		}
		got = b
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/infer", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if string(got) != payload {
		t.Fatalf("限额内 body 应透传，got %q", got)
	}
}
