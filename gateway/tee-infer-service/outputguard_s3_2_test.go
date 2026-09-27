// S3-2 单测：策略档位（A/B/C）派生与诚实门控、类目启停硬底、categoryGate 门控与运行时端点。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- 门控用伪分类器（命名加 s32 前缀，避免与包内其它 fake 冲突）----

type s32FakeClassifier struct{ cat string }

func (f s32FakeClassifier) Classify(string) (string, float64, string) {
	if f.cat == "" {
		return "", 0, ""
	}
	return f.cat, 1.0, "match"
}

type s32FakeEarly struct{ s32FakeClassifier }

func (f s32FakeEarly) ClassifyWithEarly(_ string, onEarly func(bool)) (string, float64, string) {
	if onEarly != nil {
		onEarly(false)
	}
	return f.Classify("")
}

// ---- 纯函数 ----

func TestS32UnitForStrategy(t *testing.T) {
	cases := map[string]string{
		outputStrategyA: unitSentence,
		outputStrategyB: unitFixedWindow,
		outputStrategyC: unitFixedWindow,
	}
	for in, want := range cases {
		if got := unitForStrategy(in); got != want {
			t.Errorf("unitForStrategy(%s)=%s，期望 %s", in, got, want)
		}
	}
}

func TestS32ValidateStrategy(t *testing.T) {
	for _, ok := range []string{"", outputStrategyA, outputStrategyB, outputStrategyC} {
		if err := validateOutputStrategy(ok); err != nil {
			t.Errorf("strategy=%q 应合法，实际 %v", ok, err)
		}
	}
	if err := validateOutputStrategy("X"); err == nil {
		t.Error("strategy=X 应非法")
	}
}

func TestS32StrategyRunnable(t *testing.T) {
	if !strategyRunnable(outputStrategyA) || !strategyRunnable(outputStrategyB) {
		t.Error("策略 A/B 应可运行")
	}
	if strategyRunnable(outputStrategyC) {
		t.Error("策略 C 前置未齐备，应不可运行（诚实门控）")
	}
}

func TestS32CategoryDisableAllowed(t *testing.T) {
	disallowed := []string{"A1-01", "A1-06", "A4-06"} // block 底线 + PII mask 底线
	for _, cat := range disallowed {
		if categoryDisableAllowed(cat) {
			t.Errorf("类目 %s 不允许停用", cat)
		}
	}
	for _, cat := range []string{"A1-07", "A2-09", "A3-05", "A5-01"} {
		if !categoryDisableAllowed(cat) {
			t.Errorf("类目 %s 应允许停用（flag/pass）", cat)
		}
	}
	if categoryDisableAllowed("NOPE") {
		t.Error("不存在的类目应不允许停用")
	}
}

// ---- categoryGate ----

func TestS32CategoryGate(t *testing.T) {
	if g := withCategoryGate(nil, map[string]bool{"A2-09": true}); g != nil {
		t.Error("inner 为 nil 应返回 nil")
	}
	inner := s32FakeClassifier{cat: "A2-09"}
	if g := withCategoryGate(inner, nil); g != inner {
		t.Error("停用集合为空时应原样返回（零包装）")
	}
	// 命中类目被停用 → 抑制。
	gated := withCategoryGate(inner, map[string]bool{"A2-09": true})
	if cat, _, _ := gated.Classify("x"); cat != "" {
		t.Errorf("停用类目应被抑制，实际命中 %s", cat)
	}
	// 命中类目未停用 → 放行。
	gated2 := withCategoryGate(inner, map[string]bool{"A2-01": true})
	if cat, _, _ := gated2.Classify("x"); cat != "A2-09" {
		t.Errorf("未停用类目应放行，实际 %q", cat)
	}
	// Early 能力保留：包装后仍实现 EarlyOutputClassifier，且终态被停用抑制。
	early := s32FakeEarly{s32FakeClassifier{cat: "A2-09"}}
	gatedEarly := withCategoryGate(early, map[string]bool{"A2-09": true})
	if _, ok := gatedEarly.(EarlyOutputClassifier); !ok {
		t.Error("包装 Early 分类器后应仍实现 EarlyOutputClassifier（保留两段式）")
	}
	if cat, _, _ := gatedEarly.(EarlyOutputClassifier).ClassifyWithEarly("x", nil); cat != "" {
		t.Errorf("ClassifyWithEarly 停用类目应被抑制，实际 %s", cat)
	}
}

// 证明策略派生的 unit 真实进入缓冲器（请求级管线，切换对新请求生效）。
func TestS32StrategyDrivesBufferUnit(t *testing.T) {
	m := newMetrics()
	a := newAuditChain()
	for _, strat := range []string{outputStrategyA, outputStrategyB} {
		want := unitForStrategy(strat)
		og, err := newOutputGuard(outputGuardConfig{
			Mode: outputGuardShadow,
			Params: outputGuardParams{Unit: want},
		}, nil, nil, m, a, "acme", "r-"+strat)
		if err != nil {
			t.Fatalf("newOutputGuard(%s): %v", strat, err)
		}
		if og.buf.unit != want {
			t.Errorf("策略 %s 缓冲 unit=%s，期望 %s", strat, og.buf.unit, want)
		}
	}
}

// ---- 端点级 ----

func newS32Server(cfgPath, token string) *teeServer {
	return &teeServer{
		audit:              newAuditChain(),
		metrics:            newMetrics(),
		adminToken:         token,
		outputGuardCfgPath: cfgPath,
	}
}

func newS32Mux(srv *teeServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/config/output-guard/strategy", srv.handleOutputGuardStrategy)
	mux.HandleFunc("/config/output-guard/categories", srv.handleOutputGuardCategories)
	return mux
}

func s32Post(mux *http.ServeMux, url, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set(adminHeader, token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestS32StrategyEndpoint(t *testing.T) {
	mux := newS32Mux(newS32Server("", "tok"))

	// 认证 / 方法。
	if rec := s32Post(mux, "/config/output-guard/strategy", `{"strategy":"A"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实际 %d", rec.Code)
	}
	// 切到 B：生效，派生 fixed-window。
	rec := s32Post(mux, "/config/output-guard/strategy", `{"strategy":"B"}`, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("切 B 应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非 JSON：%v", err)
	}
	if resp["strategy"] != "B" || resp["unit"] != unitFixedWindow || resp["status"] != "applied" {
		t.Fatalf("切 B 响应不符：%+v", resp)
	}
	// 切 C：诚实拒绝，状态保持 B。
	rec = s32Post(mux, "/config/output-guard/strategy", `{"strategy":"C"}`, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("切 C 应 400，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["reason"] != "strategy_c_unavailable" {
		t.Fatalf("C 拒绝原因应为 strategy_c_unavailable：%+v", resp)
	}
	if cur := newS32Server("", "").currentOutputGuardStrategy(); cur != defaultOutputStrategy {
		t.Fatalf("新服务缺省应为 A，实际 %s", cur)
	}
}

func TestS32StrategyEndpointPersist(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "og-config.json")
	srv := newS32Server(cfgPath, "tok")
	mux := newS32Mux(srv)
	if rec := s32Post(mux, "/config/output-guard/strategy", `{"strategy":"B"}`, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("切 B 应 200：%s", rec.Body.String())
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("持久化文件未写出：%v", err)
	}
	var saved outputGuardConfigRecord
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("持久化文件非 JSON：%v", err)
	}
	if saved.Strategy != "B" {
		t.Fatalf("持久化 strategy=%q，期望 B", saved.Strategy)
	}
}

func TestS32CategoriesEndpoint(t *testing.T) {
	mux := newS32Mux(newS32Server("", "tok"))

	if rec := s32Post(mux, "/config/output-guard/categories", `{"disable":["A2-09"]}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实际 %d", rec.Code)
	}
	// 停用合法 flag 类目。
	rec := s32Post(mux, "/config/output-guard/categories", `{"disable":["A2-09"]}`, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("停用 A2-09 应 200：%s", rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非 JSON：%v", err)
	}
	list, _ := resp["disabled_categories"].([]any)
	if len(list) != 1 || list[0] != "A2-09" {
		t.Fatalf("停用列表应为 [A2-09]，实际 %+v", resp["disabled_categories"])
	}
	// 底线类目不可停用。
	for _, bad := range []string{"A1-01", "A1-06", "A4-06"} {
		if rec := s32Post(mux, "/config/output-guard/categories", `{"disable":["`+bad+`"]}`, "tok"); rec.Code != http.StatusBadRequest {
			t.Errorf("停用 %s 应 400，实际 %d", bad, rec.Code)
		}
	}
	// 不存在类目。
	if rec := s32Post(mux, "/config/output-guard/categories", `{"disable":["NOPE"]}`, "tok"); rec.Code != http.StatusBadRequest {
		t.Errorf("停用不存在类目应 400，实际 %d", rec.Code)
	}
	// 重新启用：清空停用集合。
	rec = s32Post(mux, "/config/output-guard/categories", `{"enable":["A2-09"]}`, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("启用 A2-09 应 200：%s", rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非 JSON：%v", err)
	}
	if list, _ := resp["disabled_categories"].([]any); len(list) != 0 {
		t.Fatalf("启用后停用列表应为空，实际 %+v", list)
	}
}

func TestS32CategoriesPersistRoundTrip(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "og-config.json")
	srv := newS32Server(cfgPath, "tok")
	mux := newS32Mux(srv)
	if rec := s32Post(mux, "/config/output-guard/categories", `{"disable":["A2-09","A3-05"]}`, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("停用应 200：%s", rec.Body.String())
	}
	// 用一个新服务从持久化文件恢复，验证跨重启保持。
	restored := newS32Server(cfgPath, "tok")
	restored.loadOutputGuardOverride()
	got := disabledCategoryList(restored.currentDisabledCategories())
	if len(got) != 2 || got[0] != "A2-09" || got[1] != "A3-05" {
		t.Fatalf("恢复停用集合应为 [A2-09 A3-05]，实际 %+v", got)
	}
}
