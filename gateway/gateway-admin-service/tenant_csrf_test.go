package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFCheck(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	h := csrfCheck(ok)

	cases := []struct {
		name   string
		method string
		cookie string
		header string
		want   int
	}{
		{"GET 放行", "GET", "", "", 200},
		{"HEAD 放行", "HEAD", "", "", 200},
		{"POST 缺 cookie", "POST", "", "x", 403},
		{"POST 缺 header", "POST", "x", "", 403},
		{"POST 不匹配", "POST", "a", "b", 403},
		{"POST 匹配", "POST", "tok", "tok", 200},
		{"DELETE 匹配", "DELETE", "tok", "tok", 200},
		{"PUT 缺 cookie", "PUT", "", "", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: tc.cookie})
			}
			if tc.header != "" {
				req.Header.Set(csrfHeaderName, tc.header)
			}
			w := httptest.NewRecorder()
			h(w, req)
			if w.Code != tc.want {
				t.Errorf("got=%d want=%d", w.Code, tc.want)
			}
		})
	}
}

func TestIsWriteMethod(t *testing.T) {
	cases := map[string]bool{
		"POST": true, "PUT": true, "DELETE": true, "PATCH": true,
		"GET": false, "HEAD": false, "OPTIONS": false,
	}
	for m, want := range cases {
		if got := isWriteMethod(m); got != want {
			t.Errorf("isWriteMethod(%s)=%v want=%v", m, got, want)
		}
	}
}
