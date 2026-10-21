package a2aregistry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2acrypto"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// --- 测试夹具 ---

// testSigner 持有一个临时 Ed25519 密钥对（测试专用，不入库）。
type testSigner struct {
	kid     string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	jwkJSON string
}

// newTestSigner 生成临时签名者与其公钥 JWK。
func newTestSigner(t *testing.T, kid string) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": kid,
		"alg": "EdDSA",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	jb, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("序列化 JWK 失败: %v", err)
	}
	return &testSigner{kid: kid, priv: priv, pub: pub, jwkJSON: string(jb)}
}

// signCard 对卡片签名（用 a2acrypto.Signer，与生产同管线）。
func (s *testSigner) signCard(t *testing.T, raw []byte) sdk.AgentCardSignature {
	t.Helper()
	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: s.priv,
		KeyID:      s.kid,
		Algorithm:  "EdDSA",
	})
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}
	sig, err := signer.Sign(context.Background(), json.RawMessage(raw))
	if err != nil {
		t.Fatalf("签名卡片失败: %v", err)
	}
	return *sig
}

// buildCard 构造一张符合冻结 v1.0 契约的卡片（未签名）。
func buildCard(publicURL, tenant, name string) []byte {
	return buildCardWithVersion(publicURL, tenant, name, "2.1.0")
}

// buildCardWithVersion 构造指定版本的卡片（未签名）。
func buildCardWithVersion(publicURL, tenant, name, version string) []byte {
	card := &sdk.AgentCard{
		Name:        "Research Agent",
		Description: "test agent for registry",
		Version:     version,
		SupportedInterfaces: []*sdk.AgentInterface{{
			URL:             publicURL,
			ProtocolBinding: sdk.TransportProtocolJSONRPC,
			ProtocolVersion: sdk.Version,
			Tenant:          tenant,
		}},
		Capabilities: sdk.AgentCapabilities{
			Streaming:         false,
			PushNotifications: false,
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills: []sdk.AgentSkill{{
			ID:          "summarize",
			Name:        "Summarize",
			Description: "summarize text",
			Tags:        []string{"text"},
		}},
	}
	raw, err := json.Marshal(card)
	if err != nil {
		panic(err)
	}
	return raw
}

// signedCard 构造带签名的卡片字节（签名在 signatures 字段）。
func (s *testSigner) signedCard(t *testing.T, publicURL, tenant, name string) []byte {
	t.Helper()
	return s.signedCardWithVersion(t, publicURL, tenant, name, "2.1.0")
}

// signedCardWithVersion 构造指定版本的带签名卡片字节。
func (s *testSigner) signedCardWithVersion(t *testing.T, publicURL, tenant, name, version string) []byte {
	t.Helper()
	raw := buildCardWithVersion(publicURL, tenant, name, version)
	sig := s.signCard(t, raw)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析卡片失败: %v", err)
	}
	m["signatures"] = []any{map[string]any{
		"protected": sig.Protected,
		"signature": sig.Signature,
	}}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("序列化签名卡片失败: %v", err)
	}
	return out
}

// signedCardWithJKU 构造带 jku 声明的签名卡片（VA-205：jku 非白名单拒绝路径取证）。
//
// jku 仅做 allowlist 校验、不作为信任来源（冻结 §4.1）：签名密钥仍是 pinned 公钥，
// 但 protected 头带上非白名单 jku 时注册必须被拒。
func (s *testSigner) signedCardWithJKU(t *testing.T, publicURL, tenant, name, jku string) []byte {
	t.Helper()
	raw := buildCard(publicURL, tenant, name)
	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: s.priv,
		KeyID:      s.kid,
		Algorithm:  "EdDSA",
		JWKSURL:    jku,
	})
	if err != nil {
		t.Fatalf("构造带 jku 的签名器失败: %v", err)
	}
	sig, err := signer.Sign(context.Background(), json.RawMessage(raw))
	if err != nil {
		t.Fatalf("签名卡片失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析卡片失败: %v", err)
	}
	m["signatures"] = []any{map[string]any{
		"protected": sig.Protected,
		"signature": sig.Signature,
	}}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("序列化签名卡片失败: %v", err)
	}
	return out
}

// newTestRegistry 构造带临时 SQLite 的 Registry（path 模式）。
//
// 默认注入内存审计链：治理拒绝事件须**同步落链**，无链时按 fail-closed 返回 503
// （冻结 §5.7），故涉及拒绝路径的用例必须具备审计链。
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	return newTestRegistryWithAudit(t, &policyaudit.Chain{})
}

// newTestRegistryWithToken 构造带静态令牌的 Registry（DevMode）。
//
// 供 HTTP 层用例使用：认证发生在请求体解析**之前**，未配静态令牌时
// 任何 Bearer 都会被拒（401），无法触达 400/413 等请求体相关分支。
func newTestRegistryWithToken(t *testing.T) *Registry {
	t.Helper()
	reg, err := New(Config{
		DSN:         "file:" + t.TempDir() + "/registry.db",
		PublicMode:  PublicModePath,
		GatewayBase: "https://gateway.example.com",
		JWTSecret:   "test-secret",
		StaticToken: "dev-token",
		DevMode:     true,
	}, nil)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

// newTestRegistryWithCfg 按给定配置构造 Registry（VA-205：需要 JKUAllowlist 的用例）。
//
// 审计链默认注入内存链：拒绝路径须**同步落链**，无链时按 fail-closed 返回 503（冻结 §5.7）。
func newTestRegistryWithCfg(t *testing.T, cfg Config) *Registry {
	t.Helper()
	reg, err := New(cfg, &policyaudit.Chain{})
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

// newTestRegistryWithAudit 构造带临时 SQLite 的 Registry（可注入审计链）。
func newTestRegistryWithAudit(t *testing.T, audit *policyaudit.Chain) *Registry {
	t.Helper()
	reg, err := New(Config{
		DSN:         "file:" + t.TempDir() + "/registry.db",
		PublicMode:  PublicModePath,
		GatewayBase: "https://gateway.example.com",
		JWTSecret:   "test-secret",
		DevMode:     true,
	}, audit)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

// importKey 导入 pinned 公钥。
func importKey(t *testing.T, reg *Registry, tenant, provider string, s *testSigner) {
	t.Helper()
	status, err := reg.ImportKey(Authn{Tenant: tenant, Role: RoleA2AAdmin}, "tester", "req-1", "trace-1", provider,
		ProviderKeyInput{Kid: s.kid, Alg: "EdDSA", PublicJWK: s.jwkJSON})
	if err != nil {
		t.Fatalf("导入密钥失败: %v (status=%d)", err, status)
	}
}

// doRequest 发起一次控制面请求。
func doRequest(t *testing.T, h http.Handler, method, path, token string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求体失败: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// errorCodeOf 从错误体解析 code。
func errorCodeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			RequestID string         `json:"request_id"`
			Details   map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析错误体失败: %v (body=%s)", err, rec.Body.String())
	}
	return body.Error.Code
}
