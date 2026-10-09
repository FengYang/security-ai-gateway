// Package main — CSRF 双提交 cookie 防护（C-17）。
//
// 模式（§6.1）：cookie `otpmask_csrf`（非 HttpOnly，供前端读取）与请求头
// `X-CSRF-Token` 常量时间比对；所有租户写操作（POST/PUT/DELETE/PATCH）必校，
// 缺失/不符 → 403。
//
// 会话 cookie `admext1.*` 的 SameSite=Strict/HttpOnly/Secure 属性由 Console
// 会话层负责（§6.2 会话归属），Go 侧仅校验双提交一致性。
package main

import (
	"crypto/subtle"
	"net/http"
)

const (
	csrfCookieName = "otpmask_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

// csrfCheck 双提交校验中间件（仅对写方法生效；读方法放行）。
func csrfCheck(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isWriteMethod(r.Method) {
			next(w, r)
			return
		}
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "forbidden: 缺少 CSRF cookie", http.StatusForbidden)
			return
		}
		header := r.Header.Get(csrfHeaderName)
		if header == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			http.Error(w, "forbidden: CSRF 令牌校验失败", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// isWriteMethod 判断是否写方法（需 CSRF 校验）。
func isWriteMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}
