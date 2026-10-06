// Package attestverify — 证明验证 sidecar（P3，D2 确认）。
//
// 职责：TDX quote 验证在网关域验证 sidecar 内完成（完整 Go 进程，与网关同域部署），
// wasm 插件经 localhost 调用。理由（《GA-路线1方案评审.md》D2）：
// TinyGo 环境做 ECDSA/DER 解析重且脆；sidecar 实现自由、可缓存 Intel PCS collateral、
// 边界清晰。
//
// 当前形态：
// - BuiltinVerifier 为第一个实现（自家协议：X25519 握手 + quote 验证），
//   验证逻辑与 tee-infer 侧 AttestationProof 校验对称（ECDSA P-256 验签、
//   report_data = H(nonce ‖ server_pub) 绑定、度量 allowlist 比对）。
// - mock 平台（开发/CI）验证自签证明链；tdx/sgx/nv-cc 平台留真机 quote
//   解析接缝（VerifyQuote 校验签名链与度量，Intel PCS collateral 随部署接入）。
// - 第三方（Trustee/NRAS/MAA）后续以"加一个实现文件"方式接入 AttestationVerifier。
//
// 本机验证：go test ./gateway/attest-verify/...（fixture 证明载荷）。
package attestverify

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"security-ai-gateway/gateway/cryptop"
)

// Proof 远程证明载荷（与 tee-infer AttestationProof JSON wire 兼容）。
type Proof struct {
	Nonce        []byte            `json:"nonce"`
	Platform     string            `json:"platform"`
	ReportData   []byte            `json:"report_data"`
	Quote        []byte            `json:"quote,omitempty"`
	Measurements map[string]string `json:"measurements"`
	SigningKey   []byte            `json:"signing_key"`
	Signature    []byte            `json:"signature"`
}

// AttestationVerifier 验证 quote 签名链与度量；reportData 为握手绑定材料。
// 第三方（Trustee/NRAS/MAA 等）以新实现接入，不改动调用方（D2 接口抽象）。
type AttestationVerifier interface {
	// VerifyQuote 验证 quote 签名链与度量；reportData 为握手绑定材料。
	// 返回度量列表（匹配 allowlist 的度量名）。
	VerifyQuote(quote, reportData []byte) (measurements []string, err error)
}

// ---------- BuiltinVerifier（自家协议，本发布默认） ----------

// Allowlist 度量基线：允许的 app_hash 集合（发布件，随部署指南维护）。
type Allowlist struct {
	mu      sync.RWMutex
	appHash map[string]bool // hex(app_hash) → 允许
}

// NewAllowlist 构造度量基线（空 = 拒绝一切证明，fail-closed）。
func NewAllowlist() *Allowlist {
	return &Allowlist{appHash: map[string]bool{}}
}

// Add 添加允许的 app_hash（hex）。
func (a *Allowlist) Add(appHashHex string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.appHash[appHashHex] = true
}

// Contains app_hash 是否在基线内。
func (a *Allowlist) Contains(appHashHex string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.appHash[appHashHex]
}

// BuiltinVerifier 自家协议证明验证器。
type BuiltinVerifier struct {
	allowlist *Allowlist // app_hash 度量基线
	platforms map[string]bool
}

// NewBuiltinVerifier 构造验证器；allowlist 为度量基线（nil = 仅验签不验度量）。
func NewBuiltinVerifier(allowlist *Allowlist) *BuiltinVerifier {
	return &BuiltinVerifier{
		allowlist: allowlist,
		platforms: map[string]bool{"mock": true, "tdx": true, "sgx": true, "nv-cc": true},
	}
}

// VerifyQuote 校验证明链（nonce 回显由调用方绑定、report_data 绑定、签名、度量基线）。
// 当前签名链为 ECDSA P-256（mock 自签）；真机 TDX quote 下根植 Intel CA
// （PCS collateral 随部署接入，签名链扩展点已预留）。
func (v *BuiltinVerifier) VerifyQuote(quote, reportData []byte) ([]string, error) {
	if len(quote) == 0 {
		return nil, errors.New("attestverify: 空 quote")
	}
	var p Proof
	if err := decodeProof(quote, &p); err != nil {
		return nil, err
	}
	if !v.platforms[p.Platform] {
		return nil, fmt.Errorf("attestverify: 未知平台 %q", p.Platform)
	}
	if len(p.ReportData) == 0 {
		return nil, errors.New("attestverify: 证明缺少 report_data（握手公钥绑定）")
	}
	if len(reportData) > 0 && subtle.ConstantTimeCompare(p.ReportData, reportData) != 1 {
		return nil, errors.New("attestverify: report_data 与 H(nonce‖server_pub) 不匹配（疑似握手公钥被替换）")
	}
	// 签名覆盖 (report_data ‖ signing_key)（P1b 绑定升级）
	if err := verifyProofSignature(&p); err != nil {
		return nil, err
	}
	// 度量基线比对（app_hash allowlist）
	appHash, _ := p.Measurements["app_hash"]
	if v.allowlist != nil && !v.allowlist.Contains(appHash) {
		return nil, fmt.Errorf("attestverify: app_hash %q 不在度量基线内（拒绝）", appHash)
	}
	names := make([]string, 0, len(p.Measurements))
	for k := range p.Measurements {
		names = append(names, k)
	}
	return names, nil
}

// decodeProof 解码证明 wire（支持原始 JSON 或 hex(JSON)）。
func decodeProof(raw []byte, p *Proof) error {
	data := raw
	if dec, err := hex.DecodeString(string(raw)); err == nil && len(dec) > 0 {
		data = dec
	}
	if err := jsonUnmarshal(data, p); err != nil {
		return fmt.Errorf("attestverify: 证明 JSON 无效: %w", err)
	}
	return nil
}

// jsonUnmarshal 宽松 JSON 解码（标准库封装，保持包内解耦）。
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// verifyProofSignature 校验证明签名（ECDSA P-256，SHA-256；契约见 INT-2：
// SEC1 裸点 + 裸 r‖s 64B，验签统一收敛 cryptop.VerifyP256，与 tee 侧同实现）。
func verifyProofSignature(p *Proof) error {
	toSign := append(append([]byte(nil), p.ReportData...), p.SigningKey...)
	if err := cryptop.VerifyP256(p.SigningKey, toSign, p.Signature); err != nil {
		return errors.New("attestverify: 证明签名无效")
	}
	return nil
}
