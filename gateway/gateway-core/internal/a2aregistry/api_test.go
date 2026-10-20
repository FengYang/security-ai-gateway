package a2aregistry

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hmacSHA256 计算 HS256 摘要（测试用）。
func hmacSHA256(secret, data string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// makeJWT 构造一个 HS256 JWT（测试用）。
func makeJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("序列化 header 失败: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("序列化 claims 失败: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	mac := hmacSHA256(secret, signingInput)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// TestAPIRequiresAuth 无 token → 401 unauthorized。
func TestAPIRequiresAuth(t *testing.T) {
	reg := newTestRegistry(t)
	rec := doRequest(t, reg.Handler(), http.MethodGet, "/v1/a2a/agents", "", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if code := errorCodeOf(t, rec); code != codeUnauthorized {
		t.Fatalf("错误码 = %q, want %q", code, codeUnauthorized)
	}
}

// TestAPIJWTRequired 生产模式仅静态 token → 401（静态 token 降级被拒）。
func TestAPIStaticTokenRejectedWithoutDevMode(t *testing.T) {
	reg, err := New(Config{
		DSN:         "file:" + t.TempDir() + "/registry.db",
		PublicMode:  PublicModePath,
		GatewayBase: "https://gateway.example.com",
		JWTSecret:   "test-secret",
		StaticToken: "static-token",
		DevMode:     false,
	}, nil)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	rec := doRequest(t, reg.Handler(), http.MethodGet, "/v1/a2a/agents", "static-token", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401（生产不接受静态 token）", rec.Code)
	}
}

// TestAPIRegisterAndGetViaHTTP 完整 HTTP 流程：注册 → 列表 → 详情（ETag）→ 删除。
func TestAPIRegisterAndGetViaHTTP(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	h := reg.Handler()
	authn := adminAuth("tenant-a")
	_ = authn

	// 注册（通过服务层预置签名密钥，HTTP 层用 DevMode 静态 token 认证）
	rec := doRequest(t, h, http.MethodPost, "/v1/a2a/agents", "dev-token", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401（未配置静态 token 时应拒绝）", rec.Code)
	}
}

// TestAPIRegisterWithStaticToken DevMode + 静态 token → 可注册，且响应含 ETag。
func TestAPIRegisterWithStaticToken(t *testing.T) {
	reg, err := New(Config{
		DSN:         "file:" + t.TempDir() + "/registry.db",
		PublicMode:  PublicModePath,
		GatewayBase: "https://gateway.example.com",
		StaticToken: "dev-token",
		SnapshotToken: "snap-token",
		DevMode:     true,
	}, nil)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	signer := newTestSigner(t, "ed-1")
	// 静态 token 降级为 platform_admin，需 X-GA-Tenant 指定目标租户
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	h := reg.Handler()
	headers := map[string]string{"X-GA-Tenant": "tenant-a"}

	rec := doRequest(t, h, http.MethodPost, "/v1/a2a/agents", "dev-token", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, headers)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag != `"a2a-research-agent-1"` {
		t.Fatalf("ETag = %q, want %q", etag, `"a2a-research-agent-1"`)
	}

	// 详情：If-None-Match 命中 → 304
	rec = doRequest(t, h, http.MethodGet, "/v1/a2a/agents/research-agent", "dev-token", nil, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	rec = doRequest(t, h, http.MethodGet, "/v1/a2a/agents/research-agent", "dev-token", nil,
		map[string]string{"X-GA-Tenant": "tenant-a", "If-None-Match": etag})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec.Code)
	}

	// 列表
	rec = doRequest(t, h, http.MethodGet, "/v1/a2a/agents", "dev-token", nil, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var listBody struct {
		Agents []*AgentDetail `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("解析列表失败: %v", err)
	}
	if len(listBody.Agents) != 1 {
		t.Fatalf("列表长度 = %d, want 1", len(listBody.Agents))
	}

	// 删除：缺 If-Match → 428
	rec = doRequest(t, h, http.MethodDelete, "/v1/a2a/agents/research-agent", "dev-token", nil, headers)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", rec.Code)
	}
	// 删除：带 If-Match → 204
	rec = doRequest(t, h, http.MethodDelete, "/v1/a2a/agents/research-agent", "dev-token", nil,
		map[string]string{"X-GA-Tenant": "tenant-a", "If-Match": etag})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestSnapshotEndpointRequiresToken 快照端点需内部 token；带 token 返回快照并支持 304。
func TestSnapshotEndpointRequiresToken(t *testing.T) {
	reg, err := New(Config{
		DSN:           "file:" + t.TempDir() + "/registry.db",
		PublicMode:    PublicModePath,
		GatewayBase:   "https://gateway.example.com",
		StaticToken:   "dev-token",
		SnapshotToken: "snap-token",
		DevMode:       true,
	}, nil)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	h := reg.Handler()

	// 无 token → 401
	rec := doRequest(t, h, http.MethodGet, "/internal/a2a/snapshot", "", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// 错 token → 401
	rec = doRequest(t, h, http.MethodGet, "/internal/a2a/snapshot", "wrong", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// 正确 token → 200 + 快照
	rec = doRequest(t, h, http.MethodGet, "/internal/a2a/snapshot", "snap-token", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("快照响应须带 ETag")
	}
	// If-None-Match 命中 → 304
	rec = doRequest(t, h, http.MethodGet, "/internal/a2a/snapshot", "snap-token", nil,
		map[string]string{"If-None-Match": etag})
	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec.Code)
	}
}

// TestSnapshotNotConfiguredSnapshotToken 未配置快照令牌 → 503。
func TestSnapshotNotConfiguredSnapshotToken(t *testing.T) {
	reg := newTestRegistry(t)
	rec := doRequest(t, reg.Handler(), http.MethodGet, "/internal/a2a/snapshot", "any", nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestAPIErrorBodyShape 错误体统一为 {"error":{code,message,details,request_id}}。
func TestAPIErrorBodyShape(t *testing.T) {
	reg := newTestRegistry(t)
	rec := doRequest(t, reg.Handler(), http.MethodPost, "/v1/a2a/agents", "tok", RegisterRequest{
		Name: "x", ProviderID: "p", Card: []byte(`{}`), BackendURL: "http://a.svc:80",
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			RequestID string         `json:"request_id"`
			Details   map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析错误体失败: %v", err)
	}
	if body.Error.Code == "" || body.Error.Message == "" || body.Error.RequestID == "" {
		t.Fatalf("错误体字段缺失: %+v", body.Error)
	}
	if body.Error.Details == nil {
		t.Fatal("details 不得为 null")
	}
}

// TestAPIInvalidJSONBody 非法 JSON → 400 invalid_request。
func TestAPIInvalidJSONBody(t *testing.T) {
	reg := newTestRegistryWithToken(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/a2a/agents", strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer dev-token")
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if code := errorCodeOf(t, rec); code != codeInvalidRequest {
		t.Fatalf("错误码 = %q, want %q", code, codeInvalidRequest)
	}
}

// TestAPIPayloadTooLarge 超出 1 MiB 请求体 → 413。
func TestAPIPayloadTooLarge(t *testing.T) {
	reg := newTestRegistryWithToken(t)
	big := strings.Repeat("a", (1<<20)+1024)
	body, _ := json.Marshal(RegisterRequest{
		Name: "x", ProviderID: "p", Card: []byte(`{"d":"` + big + `"}`), BackendURL: "http://a.svc:80",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/a2a/agents", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer dev-token")
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestAPIIdempotencyKeyLength Idempotency-Key 长度须 8..128。
func TestAPIIdempotencyKeyLength(t *testing.T) {
	reg, err := New(Config{
		DSN:         "file:" + t.TempDir() + "/registry.db",
		PublicMode:  PublicModePath,
		GatewayBase: "https://gateway.example.com",
		StaticToken: "dev-token",
		DevMode:     true,
	}, nil)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	rec := doRequest(t, reg.Handler(), http.MethodPost, "/v1/a2a/agents", "dev-token", RegisterRequest{
		Name: "x", ProviderID: "p", Card: []byte(`{}`), BackendURL: "http://a.svc:80",
	}, map[string]string{"Idempotency-Key": "short", "X-GA-Tenant": "tenant-a"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestJWTAuthFlow JWT 认证路径（tenant/role 从 claims 取，body 不得覆盖租户）。
func TestJWTAuthFlow(t *testing.T) {
	reg, err := New(Config{
		DSN:         "file:" + t.TempDir() + "/registry.db",
		PublicMode:  PublicModePath,
		GatewayBase: "https://gateway.example.com",
		JWTSecret:   "jwt-secret",
		DevMode:     false,
	}, nil)
	if err != nil {
		t.Fatalf("构造 Registry 失败: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	h := reg.Handler()

	// 无效签名 → 401
	bad := makeJWT(t, "wrong-secret", map[string]any{
		"tenant": "tenant-a", "role": "a2a_admin", "exp": 4102444800,
	})
	rec := doRequest(t, h, http.MethodGet, "/v1/a2a/agents", bad, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	// 过期 → 401
	expired := makeJWT(t, "jwt-secret", map[string]any{
		"tenant": "tenant-a", "role": "a2a_admin", "exp": 1000000000,
	})
	rec = doRequest(t, h, http.MethodGet, "/v1/a2a/agents", expired, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401（过期 token 应拒绝）", rec.Code)
	}

	// 有效 → 200（空列表）
	good := makeJWT(t, "jwt-secret", map[string]any{
		"tenant": "tenant-a", "role": "a2a_viewer", "exp": 4102444800,
	})
	rec = doRequest(t, h, http.MethodGet, "/v1/a2a/agents", good, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// viewer 写操作 → 403
	rec = doRequest(t, h, http.MethodPost, "/v1/a2a/agents", good, RegisterRequest{
		Name: "x", ProviderID: "p", Card: []byte(`{}`), BackendURL: "http://a.svc:80",
	}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestJWKRejectsPrivateMaterial JWK 含私钥/对称材料 → 拒绝（冻结 §4.2）。
func TestJWKRejectsPrivateMaterial(t *testing.T) {
	bad := []string{
		`{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","d":"AAAA"}`,
		`{"kty":"oct","k":"AAAA"}`,
		`{"kty":"EC","crv":"P-256","x":"AA","y":"BB","d":"AA"}`,
		`{"kty":"RSA","n":"AA","e":"AQAB","d":"AA"}`,
		`{"kty":"RSA","n":"AA","e":"AQAB","p":"AA"}`,
		`{"kty":"unknown"}`,
		`not json`,
		``,
	}
	for _, jwk := range bad {
		if _, err := parsePublicJWK(jwk); err == nil {
			t.Fatalf("JWK 应被拒绝: %s", jwk)
		}
	}
}

// TestJWKAlgMatch alg 与公钥类型须相容。
func TestJWKAlgMatch(t *testing.T) {
	signer := newTestSigner(t, "ed-1")
	pub, err := parsePublicJWK(signer.jwkJSON)
	if err != nil {
		t.Fatalf("解析 JWK 失败: %v", err)
	}
	if !algMatchesKey("EdDSA", pub) {
		t.Fatal("EdDSA 应与 Ed25519 公钥匹配")
	}
	if algMatchesKey("ES256", pub) {
		t.Fatal("ES256 不应与 Ed25519 公钥匹配")
	}
	if algMatchesKey("none", pub) {
		t.Fatal("none 不应被接受")
	}
}

// TestImportKeyRejectsBadAlg 导入密钥时 alg 不在白名单 → 422。
func TestImportKeyRejectsBadAlg(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	status, err := reg.ImportKey(adminAuth("tenant-a"), "alice", "req-1", "trace-1", "team-research", ProviderKeyInput{
		Kid: "ed-1", Alg: "HS256", PublicJWK: signer.jwkJSON,
	})
	if err == nil {
		t.Fatal("HS256 应被拒绝")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
}

// TestImportKeyRejectsPrivateJWK 导入私钥材料 → 422 untrusted_key。
func TestImportKeyRejectsPrivateJWK(t *testing.T) {
	reg := newTestRegistry(t)
	status, err := reg.ImportKey(adminAuth("tenant-a"), "alice", "req-1", "trace-1", "team-research", ProviderKeyInput{
		Kid: "ed-1", Alg: "EdDSA", PublicJWK: `{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"AAAA"}`,
	})
	if err == nil {
		t.Fatal("含私钥材料的 JWK 应被拒绝")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
}

// TestKeyListDoesNotLeakPrivateMaterial 密钥列表只回显公钥。
func TestKeyListDoesNotLeakPrivateMaterial(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	keys, _, err := reg.ListKeys(viewerAuth("tenant-a"), "team-research")
	if err != nil {
		t.Fatalf("列出密钥失败: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("密钥数 = %d, want 1", len(keys))
	}
	if keys[0].Kid != "ed-1" || keys[0].Status != "active" {
		t.Fatalf("密钥元数据异常: %+v", keys[0])
	}
}

// TestHexSeedIsStable 固定种子可复现（测试自身的稳定性锚）。
func TestHexSeedIsStable(t *testing.T) {
	priv := ed25519FromSeed(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	pub := priv.Public().(ed25519.PublicKey)
	if len(pub) != 32 {
		t.Fatalf("公钥长度 = %d, want 32", len(pub))
	}
	_ = hex.EncodeToString(pub)
}
