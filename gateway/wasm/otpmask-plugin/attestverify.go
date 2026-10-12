package main

// attestverify.go —— 插件侧 attest-verify sidecar 客户端（P1-8 T1 部署接线）。
//
// 职责：封装对 attest-verify sidecar POST /verify 的 wrapper.ClusterClient 调用，
// 供 verifyPluginProof 走 sidecar 验证路径时使用。
//
// 设计（对齐 cryptoclient 范式）：
//   - 核心结构体 + 构造函数在本文件（不依赖 hostcall，可纯逻辑理解）
//   - 出站经 wrapper.FQDNCluster → 插件侧 cluster 名（如 attest-verify.static）
//   - CPS 交付：回调函数，适配 proxy-wasm 无阻塞 HTTP 语义
//
// 双路径策略（verifyPluginProof）：
//   - 配置了 attest_verify_service → 走 sidecar（完整验证链）
//   - 未配置 → 走原 CryptoClient 验签路径（行为完全不变）

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/higress-group/wasm-go/pkg/wrapper"
)

// defaultAttestVerifyPort sidecar 缺省端口（与 server.go 缺省一致）。
const defaultAttestVerifyPort int64 = 19191

// defaultAttestVerifyTimeoutMS 缺省调用超时（2000ms；quote 验证含签名链解析，比密码操作重）。
const defaultAttestVerifyTimeoutMS uint32 = 2000

// AttestVerifyResult 验证结果。
type AttestVerifyResult struct {
	OK           bool
	Measurements []string
	Error        string
}

// VerifyProof 调用 attest-verify sidecar 验证证明。
//
// quote: sidecar 期望的证明 wire（Proof 结构体 base64 口径，由 sidecarProofWire 生成）
// reportData: 绑定材料 H(nonce ‖ server_pub)（经 cryptop sidecar 求值），可 nil = 不校验绑定
// token: 共享验证令牌（X-Verify-Token，空 = 不发送）
// done: 回调；任一失败（传输/解析/验证拒绝）err 非 nil
func VerifyProof(clusterName string, port int64, timeoutMS uint32, token string,
	quote, reportData []byte, done func(result *AttestVerifyResult, err error)) {

	// 构造请求体：quote/report_data 用 base64 编码（与 server.go VerifyRequest 的 []byte 对齐）
	body := map[string]string{
		"quote":       base64.StdEncoding.EncodeToString(quote),
		"report_data": base64.StdEncoding.EncodeToString(reportData),
	}
	reqBody, _ := json.Marshal(body)

	headers := [][2]string{
		{"Content-Type", "application/json"},
	}
	if token != "" {
		headers = append(headers, [2]string{"X-Verify-Token", token})
	}

	client := wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: clusterName,
		Port: port,
	})

	err := client.Post("/verify", headers, reqBody,
		func(statusCode int, _ http.Header, body []byte) {
			if statusCode != http.StatusOK {
				// 尝试解析 error 字段（403 时也有 body）
				var resp AttestVerifyResult
				if jerr := json.Unmarshal(body, &resp); jerr == nil && resp.Error != "" {
					done(&resp, fmt.Errorf("attest-verify: 验证拒绝（%d）: %s", statusCode, resp.Error))
				} else {
					done(nil, fmt.Errorf("attest-verify: sidecar 返回 %d", statusCode))
				}
				return
			}
			var resp AttestVerifyResult
			if jerr := json.Unmarshal(body, &resp); jerr != nil {
				done(nil, fmt.Errorf("attest-verify: 解析响应失败: %w", jerr))
				return
			}
			if !resp.OK {
				done(&resp, fmt.Errorf("attest-verify: 验证拒绝: %s", resp.Error))
				return
			}
			done(&resp, nil)
		}, timeoutMS)

	if err != nil {
		done(nil, fmt.Errorf("attest-verify: 调用 sidecar 失败: %w", err))
	}
}

// effectiveAttestVerifyPort 取有效端口（0 → 缺省 19191）。
func effectiveAttestVerifyPort(p int64) int64 {
	if p == 0 {
		return defaultAttestVerifyPort
	}
	return p
}

// effectiveAttestVerifyTimeout 取有效超时（0 → 缺省 2000ms）。
func effectiveAttestVerifyTimeout(ms int64) uint32 {
	if ms <= 0 {
		return defaultAttestVerifyTimeoutMS
	}
	return uint32(ms)
}

// sidecarProofWire 将 tee-infer `/attest` 的 hex proof wire 转成 attest-verify sidecar
// `Proof` 结构体期望的 base64 wire（[]byte 字段按 Go 默认 base64 解码）。
//
// 背景：tee-infer 的 proofJSON() 将 nonce/report_data/signing_key/signature/quote
// 输出为 hex 字符串，而 sidecar 的 Proof.Nonce/ReportData/... 为 []byte（JSON 默认 base64）
// ⇒ 直接透传会报 "illegal base64 data"。此处仅做 hex→base64 编码转换（非密码操作）；
// platform / measurements 为字符串/map，原样保留。
func sidecarProofWire(proof map[string]any) ([]byte, error) {
	out := make(map[string]any, len(proof))
	for _, k := range []string{"nonce", "report_data", "signing_key", "signature", "quote"} {
		v, ok := proof[k]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("attest-verify: proof 字段 %q 非字符串", k)
		}
		if s == "" {
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("attest-verify: proof 字段 %q 非 hex: %w", k, err)
		}
		out[k] = base64.StdEncoding.EncodeToString(b)
	}
	if v, ok := proof["platform"]; ok {
		out["platform"] = v
	}
	if v, ok := proof["measurements"]; ok {
		out["measurements"] = v
	}
	return json.Marshal(out)
}
