// P2-4 T-3.4：core 侧 applied 配置版本链路单测。
//
// 覆盖四项验收要点：
//  1. 带版本头的拉取被缓存并可读回；
//  2. 不带版本头不影响既有行为（拉取照常、无覆盖）；
//  3. 并发拉取下版本记录单调不回退；
//  4. 非法版本头被忽略、不 fail 业务请求。
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/configversion"
)

// appliedVersionPathConst 状态查询端点路径（与装配口径一致）。
const appliedVersionPathConst = "/v1/internal/applied-config-version"

// pullRoutes 发起一次 GET /routes 拉取（带可选版本头）。
func pullRoutes(s *Server, version string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	req.Header.Set("Authorization", "Bearer tok")
	if version != "" {
		req.Header.Set(configversion.HeaderName, version)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// queryAppliedVersion 读取状态查询端点并解析响应。
func queryAppliedVersion(s *Server) map[string]any {
	req := httptest.NewRequest(http.MethodGet, appliedVersionPathConst, nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		return nil
	}
	return out
}

// TestAppliedVersionCachedAndReadable 带版本头的拉取被缓存，并可从状态端点读回。
func TestAppliedVersionCachedAndReadable(t *testing.T) {
	s := testServer()
	if rec := pullRoutes(s, "7"); rec.Code != http.StatusOK {
		t.Fatalf("拉取应 200: got %d", rec.Code)
	}
	out := queryAppliedVersion(s)
	if out == nil {
		t.Fatalf("状态端点查询失败")
	}
	if out["applied_config_version"] != "7" {
		t.Fatalf("读回版本错误: %v", out["applied_config_version"])
	}
	if out["known"] != true {
		t.Fatalf("known 应为 true: %v", out["known"])
	}
	if _, ok := out["reported_at"]; !ok {
		t.Fatalf("应含上报时间: %v", out)
	}
}

// TestAppliedVersionAbsentHeaderKeepsBehavior 不带版本头：拉取照常，且不产生记录。
func TestAppliedVersionAbsentHeaderKeepsBehavior(t *testing.T) {
	s := testServer()
	rec := pullRoutes(s, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("无版本头时拉取应照常 200: got %d", rec.Code)
	}
	// 响应体仍是路由表（既有行为未变）。
	var tbl map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatalf("拉取响应体不是路由表 JSON: %v", err)
	}
	if _, ok := tbl["version"]; !ok {
		t.Fatalf("响应体缺少 version 字段: %v", tbl)
	}
	out := queryAppliedVersion(s)
	if out == nil {
		t.Fatalf("状态端点查询失败")
	}
	if out["applied_config_version"] != "" {
		t.Fatalf("未上报时版本应为空: %v", out["applied_config_version"])
	}
	if out["known"] != false {
		t.Fatalf("未上报时 known 应为 false: %v", out["known"])
	}
}

// TestAppliedVersionAbsentHeaderDoesNotOverwrite 无版本头的后续拉取不覆盖已有记录。
func TestAppliedVersionAbsentHeaderDoesNotOverwrite(t *testing.T) {
	s := testServer()
	pullRoutes(s, "12")
	pullRoutes(s, "") // 无版本头 ⇒ unknown ⇒ 不覆盖
	out := queryAppliedVersion(s)
	if out["applied_config_version"] != "12" {
		t.Fatalf("无版本头不应覆盖既有版本: %v", out["applied_config_version"])
	}
}

// TestAppliedVersionConcurrentMonotonic 并发拉取下版本记录单调不回退。
func TestAppliedVersionConcurrentMonotonic(t *testing.T) {
	s := testServer()
	const n = 32
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			pullRoutes(s, itoa(v))
		}(i)
	}
	wg.Wait()
	out := queryAppliedVersion(s)
	if out == nil {
		t.Fatalf("状态端点查询失败")
	}
	got, _ := out["applied_config_version"].(string)
	if got != itoa(n) {
		t.Fatalf("并发上报后生效版本应为最大值 %d: got %q", n, got)
	}
	seq, _ := out["seq"].(float64)
	if int(seq) != n {
		t.Fatalf("上报计数应等于 %d（无丢失更新）: got %v", n, seq)
	}
}

// TestAppliedVersionInvalidIgnored 不合法的版本头被忽略，且不 fail 业务请求。
func TestAppliedVersionInvalidIgnored(t *testing.T) {
	s := testServer()
	// 先上报一个合法版本，确认非法头不会污染既有值。
	pullRoutes(s, "5")
	for _, bad := range []string{"bad version", "v1\nv2", strings.Repeat("x", configversion.MaxVersionLength+1)} {
		rec := pullRoutes(s, bad)
		if rec.Code != http.StatusOK {
			t.Fatalf("非法版本头不应影响业务请求（应 200）: bad=%q got=%d", bad, rec.Code)
		}
	}
	out := queryAppliedVersion(s)
	if out["applied_config_version"] != "5" {
		t.Fatalf("非法头污染了生效版本: %v", out["applied_config_version"])
	}
	rej, _ := out["rejected_invalid_count"].(float64)
	if rej < 1 {
		t.Fatalf("非法头应被计数: %v", out)
	}
}

// TestAppliedVersionStaleDoesNotRegress 陈旧版本上报不回退生效版本（单调保护）。
func TestAppliedVersionStaleDoesNotRegress(t *testing.T) {
	s := testServer()
	pullRoutes(s, "20")
	pullRoutes(s, "3")
	out := queryAppliedVersion(s)
	if out["applied_config_version"] != "20" {
		t.Fatalf("陈旧上报不应回退生效版本: %v", out["applied_config_version"])
	}
	stale, _ := out["rejected_stale_count"].(float64)
	if stale != 1 {
		t.Fatalf("陈旧上报应被计数: %v", out)
	}
}

// TestAppliedVersionStatusRequiresAuth 状态端点与控制面其余端点一致：须鉴权。
func TestAppliedVersionStatusRequiresAuth(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, appliedVersionPathConst, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未鉴权应 401: got %d", rec.Code)
	}
}

// itoa 整数转字符串（测试辅助）。
func itoa(v int) string {
	return strconv.Itoa(v)
}
