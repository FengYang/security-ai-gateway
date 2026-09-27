package main

// S3-2 执行器端到端：提交 → 他人复核 → tee-infer 实际收到正确路径与请求体（含 actor 留痕）。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newS32ExecStub 记录任意配置端点的 path/body/actor（catch-all）。
func newS32ExecStub(t *testing.T) (*httptest.Server, func() (string, map[string]interface{}, string)) {
	t.Helper()
	var (
		gotPath  string
		gotBody  map[string]interface{}
		gotActor string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotPath = r.URL.Path
		gotActor = r.Header.Get("X-Admin-Actor")
		gotBody = map[string]interface{}{}
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"applied"}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, func() (string, map[string]interface{}, string) { return gotPath, gotBody, gotActor }
}

func TestS3_2_StrategyExecuteRoundTrip(t *testing.T) {
	cfg := testCfg()
	ts, snap := newS32ExecStub(t)
	cs, _, _ := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, ts.URL, "tok")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]interface{}{
		"action":  changeActionOutputGuardStrategy,
		"payload": map[string]string{"strategy": "B"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("发起应 201：%s", rec.Body.String())
	}
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("复核执行应 200：%s", rec.Body.String())
	}
	path, body, actor := snap()
	if path != "/config/output-guard/strategy" {
		t.Fatalf("tee 路径应为 /config/output-guard/strategy，实际 %q", path)
	}
	if body["strategy"] != "B" {
		t.Fatalf("tee 应收到 strategy=B，实际 %+v", body)
	}
	if actor != "bob" {
		t.Fatalf("执行留痕人应为 bob，实际 %q", actor)
	}
}

func TestS3_2_CategoryExecuteRoundTrip(t *testing.T) {
	cfg := testCfg()
	ts, snap := newS32ExecStub(t)
	cs, _, _ := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, ts.URL, "tok")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]interface{}{
		"action": changeActionOutputGuardCategoryToggle,
		"payload": map[string]string{
			"disable": "A2-09,A3-05",
			"enable":  "A5-01",
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("发起应 201：%s", rec.Body.String())
	}
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("复核执行应 200：%s", rec.Body.String())
	}
	path, body, _ := snap()
	if path != "/config/output-guard/categories" {
		t.Fatalf("tee 路径应为 /config/output-guard/categories，实际 %q", path)
	}
	gotDisable, _ := body["disable"].([]interface{})
	gotEnable, _ := body["enable"].([]interface{})
	if len(gotDisable) != 2 || gotDisable[0] != "A2-09" || gotDisable[1] != "A3-05" {
		t.Fatalf("disable 应为 [A2-09 A3-05]，实际 %+v", body["disable"])
	}
	if len(gotEnable) != 1 || gotEnable[0] != "A5-01" {
		t.Fatalf("enable 应为 [A5-01]，实际 %+v", body["enable"])
	}
}
