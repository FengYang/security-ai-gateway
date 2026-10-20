package a2aregistry

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2acrypto"
	sdk "github.com/a2aproject/a2a-go/v2/a2a"

	"security-ai-gateway/gateway/a2a"
	"security-ai-gateway/gateway/a2aproxy"
)

// verifyResult 是注册/更新校验与验签的结果。
type verifyResult struct {
	card        *sdk.AgentCard
	contentHash string
	rawHash     string
	sigKid      string
	sigAlg      string
	verified    bool
}

// signatureHeader 是 JWS protected 头中本控制面关心的字段。
type signatureHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Jku string `json:"jku,omitempty"`
}

// parseSignatureHeader 解析 protected 头（base64url JSON）。
func parseSignatureHeader(protected string) (*signatureHeader, error) {
	raw, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return nil, fmt.Errorf("protected 头 base64url 解码失败: %w", err)
	}
	var h signatureHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("protected 头 JSON 解析失败: %w", err)
	}
	return &h, nil
}

// validateAndVerify 执行注册/更新前的校验与验签（冻结 §3.4 / §4.1）。
//
// 流程：
//  1. AgentCard v1.0 严格解码与冻结校验（复用 gateway/a2a）；
//  2. backend_url 冻结规则校验（复用 gateway/a2aproxy 的 SSRF 守卫）;
//  3. 载入该 (tenant, provider) 的 pinned 公钥构造信任库;
//  4. 逐签名验签：**可信 kid 的签名必须全部有效**，且至少一条可信有效签名；
//     不可信 kid 忽略但计入审计；jku 非白名单直接拒绝。
func (r *Registry) validateAndVerify(ctx context.Context, tx *sql.Tx, tenant, providerID string, raw []byte, backendURL, publicURL string) (*verifyResult, *regError) {
	card, cardErr := a2a.DecodeAndValidateAgentCard(raw, a2a.CardValidationOptions{
		Tenant:    tenant,
		PublicURL: publicURL,
	})
	if cardErr != nil {
		return nil, cardErrorToRegError(cardErr)
	}
	if err := a2aproxy.CheckBackendURL(backendURL, r.cfg.DevAllowLoopback); err != nil {
		return nil, errValidation(codeValidationFailed, "backend_url 不合规: %v", err)
	}
	keys, err := r.loadTrustedKeys(tx, tenant, providerID)
	if err != nil {
		return nil, errUnavailable("载入信任库失败: %v", err)
	}
	resolver, err := a2a.NewPinnedKeyResolver(keys, r.cfg.JKUAllowlist)
	if err != nil {
		return nil, errValidation(codeUntrustedKey, "信任库无效: %v", err)
	}
	verifier := a2acrypto.NewVerifier(a2acrypto.VerifierConfig{KeyResolver: resolver})

	trusted := make(map[string]bool, len(keys))
	for _, k := range keys {
		trusted[k.Kid] = true
	}

	var (
		verifiedKid string
		verifiedAlg string
		verifiedAny bool
		seenKids    = map[string]bool{}
	)
	for i := range card.Signatures {
		h, herr := parseSignatureHeader(card.Signatures[i].Protected)
		if herr != nil {
			return nil, errValidation(codeSignatureInvalid, "签名 %d 的 protected 头非法: %v", i, herr)
		}
		if h.Kid == "" {
			return nil, errValidation(codeSignatureInvalid, "签名 %d 缺 kid", i)
		}
		if seenKids[h.Kid] {
			return nil, errValidation(codeSignatureInvalid, "重复 kid %q（重复签名拒绝）", h.Kid)
		}
		seenKids[h.Kid] = true
		if !algAllowed(h.Alg) {
			return nil, errValidation(codeSignatureInvalid, "签名 %d 的 alg %q 不在白名单内", i, h.Alg)
		}
		// jku 仅做 allowlist 校验，不作为信任来源（§4.1）；非白名单即拒绝。
		if h.Jku != "" && !r.jkuAllowed(h.Jku) {
			return nil, errValidation(codeJKUNotAllowed, "jku %q 不在租户白名单内", h.Jku)
		}
		if !trusted[h.Kid] {
			// 不可信 kid：忽略该签名（不构成信任），但若全部签名均不可信则拒绝。
			continue
		}
		if err := verifier.Verify(ctx, raw, &card.Signatures[i]); err != nil {
			// 可信 kid 的签名无效 → 拒绝（防篡改，§4.1 多签规则）。
			return nil, errValidation(codeSignatureInvalid, "kid %q 的签名验签失败: %v", h.Kid, err)
		}
		if !verifiedAny {
			verifiedAny = true
			verifiedKid = h.Kid
			verifiedAlg = h.Alg
		}
	}
	if !verifiedAny {
		return nil, errValidation(codeUntrustedKey, "无任何可信 kid 的有效签名")
	}
	ch, err := contentHash(raw)
	if err != nil {
		return nil, errValidation(codeValidationFailed, "计算 content_hash 失败: %v", err)
	}
	return &verifyResult{
		card:        card,
		contentHash: ch,
		rawHash:     rawHash(raw),
		sigKid:      verifiedKid,
		sigAlg:      verifiedAlg,
		verified:    true,
	}, nil
}

// loadTrustedKeys 载入 (tenant, provider) 的 pinned 公钥（仅 active/retired 且在有效期内）。
func (r *Registry) loadTrustedKeys(tx *sql.Tx, tenant, providerID string) ([]a2a.PinnedKey, error) {
	rows, err := r.store.ListProviderKeys(tx, tenant, providerID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]a2a.PinnedKey, 0, len(rows))
	for _, k := range rows {
		if k.Status == "revoked" {
			continue
		}
		if !keyInWindow(k, now) {
			continue
		}
		pub, err := parsePublicJWK(k.PublicJWK)
		if err != nil {
			// 坏 JWK 不应阻断其余密钥；跳过并留待运维处置。
			continue
		}
		if k.Alg != "" && !algMatchesKey(k.Alg, pub) {
			continue
		}
		out = append(out, a2a.PinnedKey{Kid: k.Kid, Alg: k.Alg, PublicKey: pub})
	}
	return out, nil
}

// keyInWindow 校验密钥时间窗（允许 ±5 分钟时钟偏差，§4.1）。
func keyInWindow(k *ProviderKey, now time.Time) bool {
	const skew = 5 * time.Minute
	if k.NotBefore != nil {
		if t, err := time.Parse(time.RFC3339, *k.NotBefore); err == nil {
			if now.Add(skew).Before(t) {
				return false
			}
		}
	}
	if k.NotAfter != nil {
		if t, err := time.Parse(time.RFC3339, *k.NotAfter); err == nil {
			if now.Add(-skew).After(t) {
				return false
			}
		}
	}
	return true
}

// jkuAllowed 判断 jku 是否在白名单内（仅 allowlist 判定，不抓取）。
func (r *Registry) jkuAllowed(jku string) bool {
	for _, allowed := range r.cfg.JKUAllowlist {
		if allowed == jku {
			return true
		}
	}
	return false
}

// cardErrorToRegError 把冻结的卡片校验原因码映射为控制面错误（§5.6）。
func cardErrorToRegError(e *a2a.CardError) *regError {
	code := codeValidationFailed
	switch e.Reason {
	case a2a.ReasonCardTooLarge:
		return errPayloadTooLarge("%s", e.Message)
	case a2a.ReasonCardInvalid:
		code = codeValidationFailed
	case a2a.ReasonUnsupportedBinding:
		code = "unsupported_binding"
	case a2a.ReasonURLNotGateway:
		code = "url_not_gateway"
	case a2a.ReasonTenantMismatch:
		code = "tenant_mismatch"
	case a2a.ReasonUnsupportedCapability:
		code = "unsupported_capability"
	case a2a.ReasonUnsupportedRequiredExtension:
		code = "unsupported_required_extension"
	case a2a.ReasonUnsupportedSecurityScheme:
		code = "unsupported_security_scheme"
	case a2a.ReasonSignatureInvalid:
		code = codeSignatureInvalid
	}
	msg := e.Message
	if e.Field != "" {
		msg = e.Field + ": " + e.Message
	}
	return errValidation(code, "%s", msg)
}

