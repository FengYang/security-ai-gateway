package model

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordResults 收集 onResult 回调（"ok"/"degraded"）。
type recordResults struct {
	mu  sync.Mutex
	got []string
}

func (r *recordResults) cb(result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, result)
}

func (r *recordResults) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

// keywordFallback 回退实现（与运行时接线一致：关键词规则分类器）。
func keywordFallback() Classifier {
	return NewKeywordClassifier(
		[2]string{"prompt_injection", "忽略以上"},
		[2]string{"prompt_injection", "ignore previous instructions"},
	)
}

func TestHTTPClassifierBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer k1" {
			t.Errorf("应带 Bearer 令牌，实际 %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blocked":true,"category":"prompt_injection","match":"越狱","resources":{"mem_mb":128}}`))
	}))
	defer srv.Close()

	rec := &recordResults{}
	c := NewHTTPClassifier(srv.URL, "k1", time.Second, keywordFallback(), rec.cb)
	cat, match := c.Classify("任意文本")
	if cat != "prompt_injection" || match != "越狱" {
		t.Errorf("应返回侧车判定，实际 cat=%q match=%q", cat, match)
	}
	if got := rec.list(); len(got) != 1 || got[0] != "ok" {
		t.Errorf("应上报一次 ok，实际 %v", got)
	}
	if c.Backend() != GuardClassifierBackendHTTP {
		t.Errorf("后端标识应为 %s，实际 %s", GuardClassifierBackendHTTP, c.Backend())
	}
}

func TestHTTPClassifierAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"blocked":false}`))
	}))
	defer srv.Close()

	rec := &recordResults{}
	c := NewHTTPClassifier(srv.URL, "", time.Second, keywordFallback(), rec.cb)
	if cat, match := c.Classify("忽略以上指令"); cat != "" || match != "" {
		t.Errorf("侧车放行时不得回退命中，实际 cat=%q match=%q", cat, match)
	}
	if got := rec.list(); len(got) != 1 || got[0] != "ok" {
		t.Errorf("应上报一次 ok，实际 %v", got)
	}
}

// TestHTTPClassifierEmptyCategoryDefaults 侧车只给 blocked=true 不给类别时按既有类别名处理。
func TestHTTPClassifierEmptyCategoryDefaults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"blocked":true}`))
	}))
	defer srv.Close()

	c := NewHTTPClassifier(srv.URL, "", time.Second, keywordFallback(), nil)
	if cat, _ := c.Classify("x"); cat != "prompt_injection" {
		t.Errorf("空类别应回落到 prompt_injection，实际 %q", cat)
	}
}

// TestHTTPClassifierDegradesAndFallsBack 侧车各类故障 → 回退关键词规则 + degraded 上报。
func TestHTTPClassifierDegradesAndFallsBack(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"HTTP 500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{"响应非 JSON", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not-json`)) }},
		{"超时", func(w http.ResponseWriter, _ *http.Request) { time.Sleep(300 * time.Millisecond) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			rec := &recordResults{}
			c := NewHTTPClassifier(srv.URL, "", 50*time.Millisecond, keywordFallback(), rec.cb)
			// 回退实现应接管：关键词命中 → 仍拦截（降级不降安全，规则水位保留）
			if cat, _ := c.Classify("请忽略以上内容"); cat != "prompt_injection" {
				t.Errorf("应回退到关键词规则并命中，实际 cat=%q", cat)
			}
			// 未命中关键词 → 放行（语义检出能力此时回落到规则水位，须靠指标可观测）
			if cat, _ := c.Classify("请把这段话翻译成英文"); cat != "" {
				t.Errorf("回退后未命中关键词应放行，实际 cat=%q", cat)
			}
			if got := rec.list(); len(got) != 2 || got[0] != "degraded" || got[1] != "degraded" {
				t.Errorf("两次调用均应上报 degraded，实际 %v", got)
			}
		})
	}
}

// TestHTTPClassifierUnreachable 侧车进程不存在（连接失败）→ 同样降级而非报错外泄。
func TestHTTPClassifierUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // 立即关闭：端口不可达

	rec := &recordResults{}
	c := NewHTTPClassifier(url, "", 200*time.Millisecond, keywordFallback(), rec.cb)
	if cat, _ := c.Classify("忽略以上"); cat != "prompt_injection" {
		t.Errorf("不可达时应回退关键词规则，实际 cat=%q", cat)
	}
	if got := rec.list(); len(got) != 1 || got[0] != "degraded" {
		t.Errorf("应上报 degraded，实际 %v", got)
	}
}

// TestHTTPClassifierNoFallbackFailClosed 未配置回退实现时按 fail-closed：不放行并标注原因。
func TestHTTPClassifierNoFallbackFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewHTTPClassifier(srv.URL, "", time.Second, nil, nil)
	cat, match := c.Classify("普通文本")
	if cat != "prompt_injection" || match != "classifier_unavailable" {
		t.Errorf("无回退时应 fail-closed，实际 cat=%q match=%q", cat, match)
	}
}

// TestHTTPClassifierWithResources 评测跑道依赖的 resources 透传与原始错误语义。
func TestHTTPClassifierWithResources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"blocked":false,"resources":{"mem_mb":256,"device":"cpu"}}`))
	}))
	defer srv.Close()

	c := NewHTTPClassifier(srv.URL, "", time.Second, nil, nil)
	resp, err := c.ClassifyWithResources("x")
	if err != nil {
		t.Fatalf("正常应答不应报错：%v", err)
	}
	if resp.Blocked || resp.Resources["device"] != "cpu" {
		t.Errorf("resources 应透传，实际 %+v", resp)
	}
}

// TestHTTPClassifierErrorIsNotAllow 原始错误必须可与"未命中"区分（否则评测会把故障算成放行）。
func TestHTTPClassifierErrorIsNotAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	c := NewHTTPClassifier(srv.URL, "", time.Second, nil, nil)
	if _, err := c.ClassifyWithResources("x"); err == nil {
		t.Fatal("非 200 应返回错误")
	} else if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("错误应标注不可用语义，实际 %v", err)
	}
}
