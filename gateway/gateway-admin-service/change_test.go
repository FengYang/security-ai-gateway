// Package main — M3-C 高敏变更复核单测。
//
// 覆盖：动作校验 / submitter≠reviewer 强制 / 驳回 / Guardrail 执行与落链 /
// 凭据轮换的明文隔离（暂存 + 执行后清理 + 变更单不含明文）/ 特性关闭。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newChangeTestStore 构造变更单存储（临时目录）与 broker 凭据 handler。
func newChangeTestStore(t *testing.T, bc *brokerConfig, teeURL, teeToken string) (*changeStore, *brokerSecretHandler, *adminAuditChain) {
	t.Helper()
	bs := testSettings(t)
	bh := newBrokerHandler(bc)
	sh := newBrokerSecretHandler(bs, bh, nil)
	chain := newAuditTestChain(t, false)
	path := filepath.Join(t.TempDir(), "changes.json")
	cs, err := newChangeStore(path, chain, sh, teeURL, teeToken)
	if err != nil {
		t.Fatalf("newChangeStore: %v", err)
	}
	return cs, sh, chain
}

// newChangeTestMux 组装仅含变更端点 + 凭据端点的 mux（与 main 同构）。
func newChangeTestMux(cfg *config, cs *changeStore, sh *brokerSecretHandler) *http.ServeMux {
	if sh != nil {
		mux := http.NewServeMux()
		mux.HandleFunc(changeAPIBase, authMiddleware(cfg, cs.handleList))
		mux.HandleFunc(changeAPIBase+"/", authMiddleware(cfg, cs.handleItem))
		return mux
	}
	return buildAdminMux(cfg, nil, nil, nil, nil, nil, nil, cs, nil, false)
}

// changeReq 以指定身份发起请求。
func changeReq(t *testing.T, mux *http.ServeMux, cfg *config, sub, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var r *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = strings.NewReader(string(raw))
	} else {
		r = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, cfg.jwtSecret, claims{
		Sub: sub, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// teeCall 记录假 tee-infer 收到的变更调用（模式 + 执行人留痕）。
type teeCall struct {
	mode  string
	actor string
}

// newChangeTeeStub 假 tee-infer：记录收到的 pii_mode 与 X-Admin-Actor。
func newChangeTeeStub(t *testing.T) (*httptest.Server, *teeCall) {
	t.Helper()
	call := &teeCall{}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/guardrail", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PIIMode string `json:"pii_mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		call.mode = body.PIIMode
		call.actor = r.Header.Get("X-Admin-Actor")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pii_mode":"` + body.PIIMode + `","status":"applied"}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, call
}

func TestChangeSubmitValidation(t *testing.T) {
	cfg := testCfg()
	cs, _, _ := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, "", "")
	mux := newChangeTestMux(cfg, cs, nil)

	cases := map[string]interface{}{
		"不支持的动作":        map[string]string{"action": "tee_key_rotate", "target": "x"},
		"guardrail 非法值": map[string]interface{}{"action": changeActionGuardrailPIIMode, "payload": map[string]string{"pii_mode": "off"}},
		"轮换缺新 Key":      map[string]string{"action": changeActionCredentialRotate, "target": "phala"},
		"删除缺 target":    map[string]string{"action": changeActionCredentialDelete},
	}
	for name, body := range cases {
		rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d：%s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestChangeSelfReviewForbiddenAndExecute(t *testing.T) {
	cfg := testCfg()
	ts, call := newChangeTeeStub(t)
	cs, _, chain := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, ts.URL, "tok")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]interface{}{
		"action": changeActionGuardrailPIIMode, "target": "guardrail", "diff": "pii_mode: block → mask",
		"payload": map[string]string{"pii_mode": "mask"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("发起应 201，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if c.Status != changeStatusPending || c.Submitter != "alice" {
		t.Fatalf("发起后应为 pending/alice，实际 %s/%s", c.Status, c.Submitter)
	}

	// 自审禁止（服务端强制）
	rec = changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("发起人自审应 403，实际 %d", rec.Code)
	}

	// 他人复核 → 执行生效
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("复核执行应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var done changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &done)
	if done.Status != changeStatusExecuted || done.Reviewer != "bob" {
		t.Fatalf("应为 executed/bob，实际 %s/%s", done.Status, done.Reviewer)
	}
	if call.mode != "mask" {
		t.Fatalf("tee-infer 应收到 mask，实际 %q", call.mode)
	}
	// 回归：执行留痕人必须是复核人（曾因赋值顺序在 execute 之后导致为空）。
	if call.actor != "bob" {
		t.Fatalf("执行留痕人应为复核人 bob，实际 %q", call.actor)
	}

	// 重复复核 → 409
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("重复复核应 409，实际 %d", rec.Code)
	}

	// 落链：submit + execute
	events, total := chain.list(50, 0)
	if total != 2 {
		t.Fatalf("应落 2 条审计事件，实际 %d", total)
	}
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action] = true
	}
	if !actions[auditActionChangeSubmit] || !actions[auditActionChangeExecute] {
		t.Fatalf("审计链应含 change_submit 与 change_execute，实际 %v", actions)
	}
}

func TestChangeRejectClearsAndForbidsSelf(t *testing.T) {
	cfg := testCfg()
	cs, _, _ := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, "", "")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]interface{}{
		"action": changeActionGuardrailPIIMode, "payload": map[string]string{"pii_mode": "mask"},
	})
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)

	rec = changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase+"/"+c.ID+"/reject",
		map[string]string{"reason": "自驳"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("发起人自驳应 403，实际 %d", rec.Code)
	}

	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/reject",
		map[string]string{"reason": "变更窗口未到"})
	if rec.Code != http.StatusOK {
		t.Fatalf("驳回应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var rej changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &rej)
	if rej.Status != changeStatusRejected || rej.RejectReason != "变更窗口未到" {
		t.Fatalf("应为 rejected 且带原因，实际 %s/%s", rej.Status, rej.RejectReason)
	}
}

func TestChangeCredentialRotateKeepsPlaintextIsolated(t *testing.T) {
	cfg := testCfg()
	const secret = "sk-super-secret-value-2026"
	bc := &brokerConfig{providers: map[string]*brokerProvider{"phala": testProvider(t)}}
	cs, sh, chain := newChangeTestStore(t, bc, "", "")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]interface{}{
		"action": changeActionCredentialRotate, "target": "phala",
		"diff": "rotate key for phala", "secret": secret,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("发起应 201，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if c.KeyFingerprint == "" {
		t.Fatal("变更单应记录新 Key 指纹（供确认轮换生效）")
	}

	// ① 变更单文件不得含明文
	raw, err := os.ReadFile(cs.path)
	if err != nil {
		t.Fatalf("读取变更单文件: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("凭据明文泄漏进变更单文件")
	}
	if strings.Contains(string(raw), c.KeyFingerprint) == false {
		t.Fatal("变更单应含指纹")
	}
	// ② 响应体不得回显明文
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("响应体回显了凭据明文")
	}
	// ③ 暂存文件存在且为 0600
	st, err := os.Stat(cs.pendingPath(c.ID))
	if err != nil {
		t.Fatalf("暂存文件应存在: %v", err)
	}
	// 权限位断言仅在有 Unix 权限模型的环境生效（Windows 无 Unix perm 语义；
	// 生产为 Linux 容器，文件权限由部署环境承载）。
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("暂存文件应为 0600，实际 %o", st.Mode().Perm())
	}

	// 复核 → 提升为正式凭据 + 清理暂存
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("复核应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(cs.pendingPath(c.ID)); !os.IsNotExist(err) {
		t.Fatal("执行后应删除暂存明文")
	}
	if got := sh.broker.currentRoutes()["phala"]; got == nil {
		t.Fatal("轮换后 provider 应仍在托管")
	} else if string(got.p.key) != secret {
		t.Fatal("正式凭据未更新为新 Key")
	}
	// 审计链只记指纹，不含明文
	events, _ := chain.list(50, 0)
	for _, e := range events {
		if strings.Contains(e.KeyFingerprint, "sk-") {
			t.Fatal("审计链泄漏凭据明文")
		}
	}
}

func TestChangeDisabledWhenUnconfigured(t *testing.T) {
	cs, err := newChangeStore("", nil, nil, "", "")
	if err != nil {
		t.Fatalf("未配置不应报错: %v", err)
	}
	if cs != nil {
		t.Fatal("ADMIN_CHANGES_FILE 未配置应返回 nil（端点不注册）")
	}
	// cs=nil 时路由不注册 → 404
	cfg := testCfg()
	mux := newChangeTestMux(cfg, nil, nil)
	rec := changeReq(t, mux, cfg, "alice", http.MethodGet, changeAPIBase, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("特性关闭时端点应 404，实际 %d", rec.Code)
	}
}

// outputGuardTeeCall 记录假 tee-infer 收到的输出侧调用。
type outputGuardTeeCall struct {
	mode         string
	actor        string
	reloads      int
	reloadStatus int // 0=200；非 0 时 reload 返回该 HTTP 状态（模拟 tee 侧 rolled_back 409）
}

// newOutputGuardTeeStub 假 tee-infer：输出侧模式切换 + 策略热加载两端点。
func newOutputGuardTeeStub(t *testing.T, reloadStatus int) (*httptest.Server, *outputGuardTeeCall) {
	t.Helper()
	call := &outputGuardTeeCall{reloadStatus: reloadStatus}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/output-guard", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Mode string `json:"mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		call.mode = body.Mode
		call.actor = r.Header.Get("X-Admin-Actor")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mode":"` + body.Mode + `","status":"applied"}`))
	})
	mux.HandleFunc("/config/policy/reload", func(w http.ResponseWriter, r *http.Request) {
		call.reloads++
		call.actor = r.Header.Get("X-Admin-Actor")
		if call.reloadStatus != 0 {
			http.Error(w, `{"status":"rolled_back","reason":"hash_mismatch"}`, call.reloadStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"applied","policy_version":"pv2026.09.16"}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, call
}

// TestChangeOutputGuardModeAction：OG-8 D8 扩列——输出侧模式切换走完整复核链。
func TestChangeOutputGuardModeAction(t *testing.T) {
	cfg := testCfg()
	ts, call := newOutputGuardTeeStub(t, 0)
	cs, _, chain := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, ts.URL, "tok")
	mux := newChangeTestMux(cfg, cs, nil)

	// 提交校验：enforcing 属 M4 双闸拒绝；非法值/缺 payload 一律 400。
	for name, body := range map[string]interface{}{
		"enforcing 拒绝": map[string]interface{}{"action": changeActionOutputGuardMode, "payload": map[string]string{"mode": "enforcing"}},
		"非法值":          map[string]interface{}{"action": changeActionOutputGuardMode, "payload": map[string]string{"mode": "bogus"}},
		"缺 payload":    map[string]string{"action": changeActionOutputGuardMode},
	} {
		if rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d：%s", name, rec.Code, rec.Body.String())
		}
	}

	// 合法发起 → target 固定为 output-guard，payload 记录模式。
	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]interface{}{
		"action": changeActionOutputGuardMode, "diff": "off → shadow 影子观察",
		"payload": map[string]string{"mode": "shadow"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("发起应 201，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if c.Target != "output-guard" || c.Payload["mode"] != "shadow" {
		t.Fatalf("target/payload 不符：target=%q payload=%v", c.Target, c.Payload)
	}

	// 自审禁止。
	if rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("自审应 403，实际 %d", rec.Code)
	}

	// 他人复核 → tee 执行，留痕人=复核人。
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("复核执行应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var done changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &done)
	if done.Status != changeStatusExecuted || done.Reviewer != "bob" {
		t.Fatalf("应为 executed/bob，实际 %s/%s", done.Status, done.Reviewer)
	}
	if call.mode != "shadow" || call.actor != "bob" {
		t.Fatalf("tee 应收 mode=shadow/actor=bob，实际 mode=%q actor=%q", call.mode, call.actor)
	}

	// 落链：change_submit + change_execute。
	events, total := chain.list(50, 0)
	if total != 2 {
		t.Fatalf("应落 2 条审计事件，实际 %d", total)
	}
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action] = true
	}
	if !actions[auditActionChangeSubmit] || !actions[auditActionChangeExecute] {
		t.Fatalf("审计链应含 submit/execute，实际 %v", actions)
	}
}

// TestChangeOutputGuardReloadAction：OG-9 D8 扩列——策略热加载走复核链，tee 200 即 executed。
func TestChangeOutputGuardReloadAction(t *testing.T) {
	cfg := testCfg()
	ts, call := newOutputGuardTeeStub(t, 0)
	cs, _, chain := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, ts.URL, "tok")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]string{
		"action": changeActionOutputGuardReload, "diff": "词库 pv2026.09.16 热加载",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("发起应 201，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if c.Target != "output-guard-policy" {
		t.Fatalf("reload target 应固定 output-guard-policy，实际 %q", c.Target)
	}

	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("复核执行应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if call.reloads != 1 || call.actor != "bob" {
		t.Fatalf("tee 应收到 1 次 reload/actor=bob，实际 %d/%q", call.reloads, call.actor)
	}
	events, total := chain.list(50, 0)
	if total != 2 {
		t.Fatalf("应落 2 条审计事件，实际 %d", total)
	}
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action] = true
	}
	if !actions[auditActionChangeSubmit] || !actions[auditActionChangeExecute] {
		t.Fatalf("审计链应含 submit/execute，实际 %v", actions)
	}
}

// TestChangeOutputGuardReloadRollbackMarksFailed：tee 侧热加载回退（409）→ 变更单 failed
// + change_execute_failed 落链；已决单重复复核 409（tee 不被重复调用）。
func TestChangeOutputGuardReloadRollbackMarksFailed(t *testing.T) {
	cfg := testCfg()
	ts, call := newOutputGuardTeeStub(t, http.StatusConflict)
	cs, _, chain := newChangeTestStore(t, &brokerConfig{providers: map[string]*brokerProvider{}}, ts.URL, "tok")
	mux := newChangeTestMux(cfg, cs, nil)

	rec := changeReq(t, mux, cfg, "alice", http.MethodPost, changeAPIBase, map[string]string{
		"action": changeActionOutputGuardReload,
	})
	var c changeRequest
	_ = json.Unmarshal(rec.Body.Bytes(), &c)

	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("tee 409 时复核应 500（执行失败），实际 %d：%s", rec.Code, rec.Body.String())
	}
	if call.reloads != 1 {
		t.Fatalf("tee 应仅被调用 1 次，实际 %d", call.reloads)
	}

	// 变更单状态 failed + 错误留痕（GET 列表核对持久化结果）。
	rec = changeReq(t, mux, cfg, "bob", http.MethodGet, changeAPIBase, nil)
	var list struct {
		Items []changeRequest `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("列表解析失败: %v", err)
	}
	var got *changeRequest
	for i := range list.Items {
		if list.Items[i].ID == c.ID {
			got = &list.Items[i]
		}
	}
	if got == nil || got.Status != changeStatusFailed || got.ExecError == "" {
		t.Fatalf("变更单应为 failed 且带 exec_error，实际 %+v", got)
	}

	// 已决单重复复核 → 409，tee 不重复调用。
	rec = changeReq(t, mux, cfg, "bob", http.MethodPost, changeAPIBase+"/"+c.ID+"/approve", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("已决单重复复核应 409，实际 %d", rec.Code)
	}
	if call.reloads != 1 {
		t.Fatalf("重复复核不得再调 tee，实际 %d 次", call.reloads)
	}

	events, total := chain.list(50, 0)
	if total != 2 {
		t.Fatalf("应落 submit + execute_failed 共 2 条，实际 %d", total)
	}
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action] = true
	}
	if !actions[auditActionChangeSubmit] || !actions[auditActionChangeExecuteFailed] {
		t.Fatalf("审计链应含 submit/execute_failed，实际 %v", actions)
	}
}
