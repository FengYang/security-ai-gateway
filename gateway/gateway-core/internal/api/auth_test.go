// SEC-1 回归：withAuth 内网静态 token 鉴权（恒定时间比较）行为。
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler 仅在被调用时回 200，用于区分"被 withAuth 放行"与"被拦截"。
func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func TestWithAuthRejectsMissingToken(t *testing.T) {
	s := &Server{token: "secret-token"}
	h := s.withAuth(okHandler())

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 Authorization 头应 401，实际 %d", rec.Code)
	}
}

func TestWithAuthRejectsWrongToken(t *testing.T) {
	s := &Server{token: "secret-token"}
	h := s.withAuth(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误令牌应 401，实际 %d", rec.Code)
	}
}

func TestWithAuthAcceptsCorrectToken(t *testing.T) {
	s := &Server{token: "secret-token"}
	h := s.withAuth(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确令牌应放行（200），实际 %d", rec.Code)
	}
}

// TestWithAuthEmptyTokenPassthrough 验证 token 为空时 withAuth 放行（向后兼容）：
// 空令牌语义由 cmd/main.go 的 fail-closed 启动门槛收紧，withAuth 本身保持透传。
func TestWithAuthEmptyTokenPassthrough(t *testing.T) {
	s := &Server{token: ""}
	h := s.withAuth(okHandler())

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("空 token 应透传放行（向后兼容），实际 %d", rec.Code)
	}
}
