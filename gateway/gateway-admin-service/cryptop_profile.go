// Package main — P0-4 §4.3.10 密码 profile 切换管理端点（B5-c）。
//
// 定位（本体 §4.3.10）：**admin 管理面，非密码原语**——不做任何密码运算，
// 仅承担「入参校验 → sidecar 基线一致性校验（§7.5）→ 写审计事件 → 发射指标 #12」。
// 故不并入 sidecar 十三端点，cryptop_ops_total（#1）不含 profile_switch。
//
// 生效语义（用户裁决 2026-10-06·编排受理）：
//   - mode=restart（默认）：切换受理后由外部滚动重启 sidecar/Go 服务生效；
//   - mode=hot：跨 provider 形态（intl↔sm）一律 409 restart_required；
//     from==to 仅切 mask_prg 为合法即时受理路径（R7-1，桥接收桥唯一工具路径）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// cryptopProfileSwitchPath 端点路径。
const cryptopProfileSwitchPath = "/v1/adminext/cryptop/profile"

// cryptopProfileSwitchTimeout 管理面调 sidecar 单次超时（本机 loopback；
// R-3 的 50ms 针对插件调用，管理面留 100ms 余量）。
const cryptopProfileSwitchTimeout = 100 * time.Millisecond

// cryptopProfileSwitchRequest 切换入参（§4.3.10）。
type cryptopProfileSwitchRequest struct {
	From    string `json:"from"`              // 须 == 当前生效 profile
	To      string `json:"to"`                // intl / sm-software / sm-module
	Mode    string `json:"mode"`              // restart（默认）/ hot
	MaskPRG string `json:"mask_prg,omitempty"` // hmac-sha256 / sm4 / bridge；缺省不动
	Confirm bool   `json:"confirm"`           // 必须 true（防误触）
}

// cryptopProfileError 错误体（§4.3.10 契约）。
type cryptopProfileError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// cryptopProfileSwitchResponse 切换出参（§4.3.10 契约）。
type cryptopProfileSwitchResponse struct {
	OK          bool              `json:"ok"`
	Applied     string            `json:"applied,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Consistency map[string]string `json:"consistency,omitempty"`
	Error       *cryptopProfileError `json:"error,omitempty"`
}

// sidecarCapabilities sidecar /v1/capabilities 中本端点消费的字段。
type sidecarCapabilities struct {
	Profile string `json:"profile"`
	MaskPRG string `json:"mask_prg"`
}

// cryptopProfileSwitcher profile 切换处理器（依赖注入，便于单测）。
type cryptopProfileSwitcher struct {
	chain          *adminAuditChain
	sidecarURL     string // 空 = 未配置 → 503 fail-closed
	httpClient     *http.Client
	currentProfile func() cryptop.Profile // 默认取 cryptoProvider.Profile()
}

// newCryptopProfileSwitcher 构造切换处理器（生产装配）。
func newCryptopProfileSwitcher(chain *adminAuditChain, sidecarURL string) *cryptopProfileSwitcher {
	return &cryptopProfileSwitcher{
		chain:          chain,
		sidecarURL:     sidecarURL,
		httpClient:     &http.Client{Timeout: cryptopProfileSwitchTimeout},
		currentProfile: func() cryptop.Profile { return cryptoProvider.Profile() },
	}
}

// writeProfileErr 按 §4.3.10 契约输出 {ok:false,error:{code,message}}。
func writeProfileErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, cryptopProfileSwitchResponse{
		OK:    false,
		Error: &cryptopProfileError{Code: code, Message: msg},
	})
}

// validMaskPRGEnum mask_prg 入参枚举校验。
func validMaskPRGEnum(prg string) bool {
	switch prg {
	case "hmac-sha256", "sm4", "bridge":
		return true
	default:
		return false
	}
}

// maskPRGAllowedForProfile R-14/R-21 合法矩阵（与 cryptopsvc.validateMaskPRG 同规则）：
// intl 仅 hmac-sha256；sm-* 为 sm4 / bridge。
func maskPRGAllowedForProfile(p cryptop.Profile, prg string) bool {
	switch p {
	case cryptop.ProfileIntl:
		return prg == "hmac-sha256"
	default: // sm-software / sm-module
		return prg == "sm4" || prg == "bridge"
	}
}

// handle POST /v1/adminext/cryptop/profile。
func (s *cryptopProfileSwitcher) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProfileErr(w, http.StatusBadRequest, "bad_request", "仅接受 POST")
		return
	}
	// 写操作：必须 admin 角色（auditor → 403）。
	if !requireRule(w, r, epCryptopProfile) {
		return
	}

	var req cryptopProfileSwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProfileErr(w, http.StatusBadRequest, "bad_request", "请求体 JSON 解析失败")
		return
	}
	if !req.Confirm {
		writeProfileErr(w, http.StatusBadRequest, "bad_request", "confirm 必须为 true（防误触硬约束）")
		return
	}

	current := s.currentProfile()

	// to 枚举校验；sm-module 未接入 → not_implemented（绝不回退 sm-software 冒充，P4）。
	to := cryptop.Profile(req.To)
	switch to {
	case cryptop.ProfileIntl, cryptop.ProfileSMSW:
	case cryptop.ProfileSMModule:
		writeProfileErr(w, http.StatusNotImplemented, "not_implemented", "sm-module 未接入")
		return
	default:
		writeProfileErr(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("未知目标 profile %q", req.To))
		return
	}

	// from 须 == 当前生效 profile（否则 stale_from）。
	if cryptop.Profile(req.From) != current {
		writeProfileErr(w, http.StatusConflict, "stale_from",
			fmt.Sprintf("from=%q 与当前生效 profile=%q 不符", req.From, current))
		return
	}

	// 切换前基线一致性校验（§7.5 半切换防护）。
	if s.sidecarURL == "" {
		writeProfileErr(w, http.StatusServiceUnavailable, "internal",
			"CRYPTOPSVC_URL 未配置，无法做切换前一致性校验（fail-closed）")
		return
	}
	caps, err := s.fetchCapabilities(r.Context())
	if err != nil {
		writeProfileErr(w, http.StatusServiceUnavailable, "internal",
			"sidecar /v1/capabilities 不可达: " + err.Error())
		return
	}
	if caps.Profile != string(current) {
		writeProfileErr(w, http.StatusConflict, "inconsistent",
			fmt.Sprintf("sidecar profile=%q 与当前基线=%q 不一致（半切换，拒绝发起下一跳）",
				caps.Profile, current))
		return
	}

	mode := req.Mode
	if mode == "" {
		mode = "restart"
	}
	if mode != "restart" && mode != "hot" {
		writeProfileErr(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("mode 仅接受 restart/hot，收到 %q", req.Mode))
		return
	}

	// mask_prg：以 sidecar 上报值为当前基线；判定是否变更、校验与目标 profile 的组合。
	currentPRG := caps.MaskPRG
	effectivePRG := currentPRG
	prgChanged := false
	if req.MaskPRG != "" {
		if !validMaskPRGEnum(req.MaskPRG) {
			writeProfileErr(w, http.StatusBadRequest, "bad_request",
				fmt.Sprintf("mask_prg 仅接受 hmac-sha256/sm4/bridge，收到 %q", req.MaskPRG))
			return
		}
		if !maskPRGAllowedForProfile(to, req.MaskPRG) {
			writeProfileErr(w, http.StatusBadRequest, "bad_request",
				fmt.Sprintf("mask_prg=%q 与目标 profile=%q 非法组合（R-14/R-21）",
					req.MaskPRG, to))
			return
		}
		effectivePRG = req.MaskPRG
		prgChanged = req.MaskPRG != currentPRG
	} else if to != current && !maskPRGAllowedForProfile(to, currentPRG) {
		// 身份切换且未显式给 PRG：当前 PRG 必须对目标 profile 合法
		// （如 intl→sm 时当前 hmac-sha256 对 sm 非法 ⇒ 强制 PRG=bridge，§13.2 步3.1）。
		writeProfileErr(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("切至 profile=%q 须显式指定合法 mask_prg（当前 %q 对目标非法，R-14）",
				to, currentPRG))
		return
	}

	// 真 no-op：from==to 且 mask_prg 未变更（§4.3.10）。
	if current == to && !prgChanged {
		writeProfileErr(w, http.StatusBadRequest, "bad_request",
			"无任何维度变更（from==to 且 mask_prg 未变）")
		return
	}

	// mode=hot 跨 provider 形态：密钥长度不可复用，不支持热切（§4.3.10）。
	if mode == "hot" && current != to {
		writeProfileErr(w, http.StatusConflict, "restart_required",
			"跨 provider 形态不支持热切，须 mode=restart 并滚动重启")
		return
	}

	// 写审计（失败 = 切换不受理，fail-closed；不发射 #12）。
	if s.chain != nil {
		if err := s.chain.append(adminAuditEvent{
			Actor:       operationSub(r),
			Action:      auditActionCryptopProfileSwitch,
			RequestID:   r.Header.Get("X-Request-ID"),
			Result:      "ok",
			ProfileFrom: string(current),
			ProfileTo:   string(to),
			SwitchMode:  mode,
			MaskPRG:     effectivePRG,
		}); err != nil {
			metrics.incBrokerAuditWriteFailed()
			writeProfileErr(w, http.StatusInternalServerError, "internal",
				"审计链写入失败（切换未受理，fail-closed）: " + err.Error())
			return
		}
	}

	// #12 唯一生产者（身份切换 from==to 的掩码档变更发射 {from=to} 行，R7-1）。
	metrics.incProfileSwitch(string(current), string(to))
	writeJSON(w, http.StatusOK, cryptopProfileSwitchResponse{
		OK:          true,
		Applied:     string(to),
		Mode:        mode,
		Consistency: map[string]string{"mask_prg": effectivePRG},
	})
}

// fetchCapabilities 调 sidecar GET /v1/capabilities。
func (s *cryptopProfileSwitcher) fetchCapabilities(ctx context.Context) (sidecarCapabilities, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.sidecarURL+"/v1/capabilities", nil)
	if err != nil {
		return sidecarCapabilities{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return sidecarCapabilities{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sidecarCapabilities{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var caps sidecarCapabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return sidecarCapabilities{}, err
	}
	return caps, nil
}
