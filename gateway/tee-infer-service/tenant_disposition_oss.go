// S4-4：租户处置状态机（OSS/私有化版本，永远为空实现）。
// 非 SaaS 构建时使用：不初始化 store、不注册端点、不拦截。
//
//go:build !saas

package main

import "net/http"

// initTenantDisposition OSS/私有化版本空实现：保持 nilDisposition 默认放行。
func initTenantDisposition(s *teeServer, mux *http.ServeMux) {
	// 空：s.disposition 默认 nilDisposition{}，永远放行
}
