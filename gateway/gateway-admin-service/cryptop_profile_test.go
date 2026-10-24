// cryptop_profile_test.go — §4.3.10 profile 切换端点单测（B5-c）。
//
// 覆盖（含附录 C T-12.6-3/4/5 的 handler 逻辑面）：
//   - 鉴权：无令牌 401、auditor 403
//   - 入参：confirm、to 枚举/sm-module 501、from stale_from 409
//   - 一致性：sidecar 基线不符 inconsistent 409、URL 未配置 503、sidecar 不可达 503
//   - mask_prg：枚举非法、R-14 组合非法、身份切换未带合法 PRG、no-op
//   - 动作：hot 跨 provider restart_required 409；restart 成功受理 + 审计四字段 + #12；
//     mask_prg-only hot（from==to）→ ok + #12{from=to}（T-12.6-5）
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"security-ai-gateway/gateway/cryptop"
)

// newMockSidecar 构造返回指定 capabilities 的 sidecar mock（status=0 视为 200）。
func newMockSidecar(t *testing.T, profile, maskPRG string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/capabilities" {
			http.NotFound(w, r)
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"profile": profile, "mask_prg": maskPRG,
		})
	}))
}

// newProfileSwitchServer 组装端点测试服务器（挂鉴权中间件，与 main 同构）。
func newProfileSwitchServer(t *testing.T, sw *cryptopProfileSwitcher) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(cryptopProfileSwitchPath, authMiddleware(testCfg(), sw.handle))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// doProfileSwitch 以指定角色发起切换请求，返回状态码与解析后响应。
// sub 固定 testAdminUser（白名单成员）；需要非白名单身份时用 doProfileSwitchAs。
func doProfileSwitch(t *testing.T, srvURL, role string, body cryptopProfileSwitchRequest) (int, cryptopProfileSwitchResponse) {
	t.Helper()
	return doProfileSwitchAs(t, srvURL, testAdminUser, role, body)
}

// doProfileSwitchAs 以指定 sub/role 发起切换请求。
func doProfileSwitchAs(t *testing.T, srvURL, sub, role string, body cryptopProfileSwitchRequest) (int, cryptopProfileSwitchResponse) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, srvURL+cryptopProfileSwitchPath, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got cryptopProfileSwitchResponse
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return resp.StatusCode, got
}

// baseReq 构造合法基础请求（调用方按用例覆写）。
func baseReq() cryptopProfileSwitchRequest {
	return cryptopProfileSwitchRequest{
		From: "intl", To: "intl", Mode: "restart", Confirm: true,
	}
}

func TestCryptopProfileSwitchAuth(t *testing.T) {
	sidecar := newMockSidecar(t, "intl", "hmac-sha256", 0)
	defer sidecar.Close()
	sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
	srv := newProfileSwitchServer(t, sw)

	t.Run("无令牌 → 401", func(t *testing.T) {
		resp, err := http.Post(srv.URL+cryptopProfileSwitchPath, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("期望 401，实际 %d", resp.StatusCode)
		}
	})

	t.Run("auditor → 403", func(t *testing.T) {
		// bob 不在 roleAdmins 白名单：JWT auditor 不被提升。
		code, got := doProfileSwitchAs(t, srv.URL, "bob", roleAuditor, baseReq())
		if code != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d %+v", code, got)
		}
	})
}

func TestCryptopProfileSwitchValidation(t *testing.T) {
	cases := []struct {
		name      string
		smCurrent bool // 当前 profile 是否为 sm-software（影响 sidecar 基线）
		mutate    func(*cryptopProfileSwitchRequest)
		wantCode  int
		wantErr   string
	}{
		{"confirm=false", false, func(r *cryptopProfileSwitchRequest) { r.Confirm = false }, 400, "bad_request"},
		{"to 非法枚举", false, func(r *cryptopProfileSwitchRequest) { r.To = "fips" }, 400, "bad_request"},
		{"from≠当前 stale_from", false, func(r *cryptopProfileSwitchRequest) { r.From = "sm-software" }, 409, "stale_from"},
		{"no-op 同档无变更", false, func(r *cryptopProfileSwitchRequest) {}, 400, "bad_request"},
		{"intl+mask_prg=sm4", false, func(r *cryptopProfileSwitchRequest) { r.MaskPRG = "sm4" }, 400, "bad_request"},
		{"intl+mask_prg=bridge", false, func(r *cryptopProfileSwitchRequest) { r.MaskPRG = "bridge" }, 400, "bad_request"},
		{"mask_prg 枚举非法", true, func(r *cryptopProfileSwitchRequest) {
			r.From, r.To = "sm-software", "sm-software"
			r.MaskPRG = "seqwr"
		}, 400, "bad_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 每用例独立装配，杜绝 sw/sidecar 状态跨用例污染。
			current := cryptop.ProfileIntl
			sidecarPRG := "hmac-sha256"
			if tc.smCurrent {
				current = cryptop.ProfileSMSW
				sidecarPRG = "bridge"
			}
			sidecar := newMockSidecar(t, string(current), sidecarPRG, 0)
			defer sidecar.Close()
			sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
			sw.currentProfile = func() cryptop.Profile { return current }
			srv := newProfileSwitchServer(t, sw)

			req := baseReq()
			tc.mutate(&req)
			code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
			if code != tc.wantCode {
				t.Fatalf("期望 %d，实际 %d body=%+v", tc.wantCode, code, got)
			}
			if got.Error == nil || got.Error.Code != tc.wantErr {
				t.Fatalf("期望错误码 %q，实际 %+v", tc.wantErr, got.Error)
			}
		})
	}
}

func TestCryptopProfileSwitchSMModuleAccepted(t *testing.T) {
	// §7.6 切换端点开闸：sm-module 切换受理（沿用 restart 语义 + sidecar 一致性校验 + 显式 mask_prg）。
	sidecar := newMockSidecar(t, "intl", "hmac-sha256", 0)
	defer sidecar.Close()
	sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
	sw.currentProfile = func() cryptop.Profile { return cryptop.ProfileIntl }
	srv := newProfileSwitchServer(t, sw)

	req := baseReq()
	req.To = "sm-module"
	req.MaskPRG = "sm4" // intl→sm-module 须显式指定合法 mask_prg（R-14/R-21）
	code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
	if code != http.StatusOK || !got.OK {
		t.Fatalf("期望 200 ok（sm-module 切换开闸），实际 %d %+v", code, got)
	}
	if got.Applied != "sm-module" || got.Mode != "restart" {
		t.Fatalf("响应字段不符：%+v", got)
	}
}

func TestCryptopProfileSwitchSMModuleRequiresExplicitPRG(t *testing.T) {
	// intl→sm-module 未显式指定 mask_prg，当前 hmac-sha256 对 sm 非法 → 400（强制 bridge/sm4 先行，§7.6）。
	sidecar := newMockSidecar(t, "intl", "hmac-sha256", 0)
	defer sidecar.Close()
	sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
	sw.currentProfile = func() cryptop.Profile { return cryptop.ProfileIntl }
	srv := newProfileSwitchServer(t, sw)

	req := baseReq()
	req.To = "sm-module" // 不带 MaskPRG
	code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
	if code != http.StatusBadRequest || got.Error == nil || got.Error.Code != "bad_request" {
		t.Fatalf("期望 400 bad_request（须显式指定 mask_prg），实际 %d %+v", code, got)
	}
}

func TestCryptopProfileSwitchInconsistent(t *testing.T) {
	// sidecar 上报 sm-software，而 admin 当前基线 intl → 半切换 → 409。
	sidecar := newMockSidecar(t, "sm-software", "bridge", 0)
	defer sidecar.Close()
	sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
	srv := newProfileSwitchServer(t, sw)

	code, got := doProfileSwitch(t, srv.URL, roleAdmin, baseReq())
	if code != http.StatusConflict || got.Error == nil || got.Error.Code != "inconsistent" {
		t.Fatalf("期望 409 inconsistent，实际 %d %+v", code, got)
	}
}

func TestCryptopProfileSwitchSidecarUnavailable(t *testing.T) {
	t.Run("URL 未配置 → 503", func(t *testing.T) {
		sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), "")
		srv := newProfileSwitchServer(t, sw)
		code, got := doProfileSwitch(t, srv.URL, roleAdmin, baseReq())
		if code != http.StatusServiceUnavailable || got.Error == nil {
			t.Fatalf("期望 503，实际 %d %+v", code, got)
		}
	})

	t.Run("sidecar 返回 500 → 503", func(t *testing.T) {
		sidecar := newMockSidecar(t, "intl", "hmac-sha256", http.StatusInternalServerError)
		defer sidecar.Close()
		sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
		srv := newProfileSwitchServer(t, sw)
		code, got := doProfileSwitch(t, srv.URL, roleAdmin, baseReq())
		if code != http.StatusServiceUnavailable || got.Error == nil {
			t.Fatalf("期望 503，实际 %d %+v", code, got)
		}
	})
}

func TestCryptopProfileSwitchRestartSuccess(t *testing.T) {
	// intl（hmac-sha256）→ sm-software，PRG=bridge（§13.2 步3.1 路径）。
	sidecar := newMockSidecar(t, "intl", "hmac-sha256", 0)
	defer sidecar.Close()
	chain := newAuditTestChain(t, false)
	sw := newCryptopProfileSwitcher(chain, sidecar.URL)
	srv := newProfileSwitchServer(t, sw)

	req := baseReq()
	req.To = "sm-software"
	req.MaskPRG = "bridge"
	code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
	if code != http.StatusOK || !got.OK {
		t.Fatalf("期望 200 ok，实际 %d %+v", code, got)
	}
	if got.Applied != "sm-software" || got.Mode != "restart" {
		t.Fatalf("响应字段不符：%+v", got)
	}
	if got.Consistency["mask_prg"] != "bridge" {
		t.Fatalf("consistency.mask_prg 期望 bridge，实际 %+v", got.Consistency)
	}

	// 审计事件含 from/to/mode/mask_prg 四字段（T-12.6-4）。
	events, n := chain.list(1, 0)
	if n == 0 {
		t.Fatal("审计链应有事件")
	}
	ev := events[0]
	if ev.Action != auditActionCryptopProfileSwitch || ev.ProfileFrom != "intl" ||
		ev.ProfileTo != "sm-software" || ev.SwitchMode != "restart" || ev.MaskPRG != "bridge" {
		t.Fatalf("审计事件字段不符：%+v", ev)
	}

	// #12 发射 {intl,sm-software} 行。
	var buf bytes.Buffer
	metrics.render(&buf)
	if !bytes.Contains(buf.Bytes(),
		[]byte(`gateway_cryptop_profile_switch_total{from="intl",to="sm-software"}`)) {
		t.Fatalf("#12 缺 {intl,sm-software} 行：\n%s", buf.String())
	}
}

func TestCryptopProfileSwitchHotCrossProviderRejected(t *testing.T) {
	sidecar := newMockSidecar(t, "intl", "hmac-sha256", 0)
	defer sidecar.Close()
	sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
	srv := newProfileSwitchServer(t, sw)

	req := baseReq()
	req.To = "sm-software"
	req.Mode = "hot"
	req.MaskPRG = "bridge"
	code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
	if code != http.StatusConflict || got.Error == nil || got.Error.Code != "restart_required" {
		t.Fatalf("期望 409 restart_required，实际 %d %+v", code, got)
	}
}

func TestCryptopProfileSwitchMaskPRGOnlyHot(t *testing.T) {
	// T-12.6-5：from==to=sm-software，bridge → sm4 收桥；hot 即时受理。
	sidecar := newMockSidecar(t, "sm-software", "bridge", 0)
	defer sidecar.Close()
	chain := newAuditTestChain(t, false)
	sw := newCryptopProfileSwitcher(chain, sidecar.URL)
	sw.currentProfile = func() cryptop.Profile { return cryptop.ProfileSMSW }
	srv := newProfileSwitchServer(t, sw)

	req := baseReq()
	req.From, req.To = "sm-software", "sm-software"
	req.Mode = "hot"
	req.MaskPRG = "sm4"
	code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
	if code != http.StatusOK || !got.OK {
		t.Fatalf("期望 200 ok，实际 %d %+v", code, got)
	}
	if got.Consistency["mask_prg"] != "sm4" {
		t.Fatalf("生效 mask_prg 期望 sm4，实际 %+v", got.Consistency)
	}

	// #12 发射 {from=to} 行（R7-1）。
	var buf bytes.Buffer
	metrics.render(&buf)
	if !bytes.Contains(buf.Bytes(),
		[]byte(`gateway_cryptop_profile_switch_total{from="sm-software",to="sm-software"}`)) {
		t.Fatalf("#12 缺 {sm-software,sm-software} 行：\n%s", buf.String())
	}

	events, _ := chain.list(1, 0)
	if events[0].MaskPRG != "sm4" || events[0].ProfileFrom != events[0].ProfileTo {
		t.Fatalf("审计事件收桥字段不符：%+v", events[0])
	}
}

func TestCryptopProfileSwitchIdentityChangeWithoutPRGRejected(t *testing.T) {
	// intl→sm 未带 PRG，当前 hmac-sha256 对 sm 非法 → 400（强制 bridge 先行）。
	sidecar := newMockSidecar(t, "intl", "hmac-sha256", 0)
	defer sidecar.Close()
	sw := newCryptopProfileSwitcher(newAuditTestChain(t, false), sidecar.URL)
	srv := newProfileSwitchServer(t, sw)

	req := baseReq()
	req.To = "sm-software"
	code, got := doProfileSwitch(t, srv.URL, roleAdmin, req)
	if code != http.StatusBadRequest || got.Error == nil || got.Error.Code != "bad_request" {
		t.Fatalf("期望 400 bad_request，实际 %d %+v", code, got)
	}
}
