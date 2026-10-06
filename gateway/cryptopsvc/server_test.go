package cryptopsvc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/cryptop/keystore"
)

// ---- 测试夹具 ----

func newTestServer(t *testing.T, profile cryptop.Profile) (*Server, *httptest.Server, cryptop.Provider) {
	t.Helper()
	p, err := cryptop.New(profile)
	if err != nil {
		t.Fatalf("cryptop.New(%s): %v", profile, err)
	}
	cfg := Config{
		Profile: profile,
		StaticKeys: map[string][]byte{
			"static/aead": bytes.Repeat([]byte{0xAB}, p.SymmetricKeySize()), // R-16：键长匹配 profile
			"static/hmac": bytes.Repeat([]byte{0xCD}, p.SymmetricKeySize()),
		},
	}
	s, err := NewServer(p, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts, p
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func getJSON(t *testing.T, ts *httptest.Server, path string) (int, map[string]any) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func errCode(t *testing.T, out map[string]any) string {
	t.Helper()
	e, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("缺少 error 对象: %+v", out)
	}
	return e["code"].(string)
}

func b64d(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 解码: %v", err)
	}
	return b
}

// ---- 端点契约（U-8）----

func TestCapabilities(t *testing.T) {
	for _, profile := range []cryptop.Profile{cryptop.ProfileIntl, cryptop.ProfileSMSW} {
		_, ts, p := newTestServer(t, profile)
		code, out := getJSON(t, ts, "/v1/capabilities")
		if code != 200 {
			t.Fatalf("[%s] /v1/capabilities 状态 %d", profile, code)
		}
		if out["profile"] != string(profile) {
			t.Fatalf("[%s] profile=%v", profile, out["profile"])
		}
		wantSuite := float64(1)
		if profile != cryptop.ProfileIntl {
			wantSuite = 2
		}
		if out["suite"].(float64) != wantSuite {
			t.Fatalf("[%s] suite=%v 期望 %v", profile, out["suite"], wantSuite)
		}
		sizes := out["sizes"].(map[string]any)
		if int(sizes["symmetric_key"].(float64)) != p.SymmetricKeySize() {
			t.Fatalf("[%s] symmetric_key 尺寸不符", profile)
		}
		if !strings.Contains(out["compliance_note"].(string), "密评") {
			t.Fatalf("[%s] compliance_note 缺如实标注: %v", profile, out["compliance_note"])
		}
	}
}

func TestRandAndLimit(t *testing.T) {
	_, ts, _ := newTestServer(t, cryptop.ProfileIntl)
	code, out := postJSON(t, ts, "/v1/rand", map[string]any{"n": 16}, nil)
	if code != 200 || len(b64d(t, out["bytes"].(string))) != 16 {
		t.Fatalf("rand 失败: %d %+v", code, out)
	}
	code, out = postJSON(t, ts, "/v1/rand", map[string]any{"n": maxRandLen + 1}, nil)
	if code != 413 || errCode(t, out) != "limit_exceeded" {
		t.Fatalf("rand 超限应 413 limit_exceeded，得 %d %+v", code, out)
	}
}

func TestHashHMACAndUnknownKey(t *testing.T) {
	_, ts, p := newTestServer(t, cryptop.ProfileIntl)
	code, out := postJSON(t, ts, "/v1/hash", map[string]any{"data": b64([]byte("hello"))}, nil)
	if code != 200 || len(b64d(t, out["digest"].(string))) != p.HashSize() {
		t.Fatalf("hash 失败: %d %+v", code, out)
	}
	code, out = postJSON(t, ts, "/v1/hmac", map[string]any{"key_ref": "static/hmac", "data": b64([]byte("m"))}, nil)
	if code != 200 || len(b64d(t, out["mac"].(string))) != 32 {
		t.Fatalf("hmac 失败: %d %+v", code, out)
	}
	code, out = postJSON(t, ts, "/v1/hmac", map[string]any{"key_ref": "nope", "data": b64([]byte("m"))}, nil)
	if code != 404 || errCode(t, out) != "unknown_key_ref" {
		t.Fatalf("未知 KeyRef 应 404 unknown_key_ref，得 %d %+v", code, out)
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	for _, profile := range []cryptop.Profile{cryptop.ProfileIntl, cryptop.ProfileSMSW} {
		_, ts, _ := newTestServer(t, profile)
		aad := b64([]byte("aad"))
		pt := []byte("secret payload")
		code, out := postJSON(t, ts, "/v1/seal", map[string]any{
			"key_ref": "static/aead", "aad": aad, "plaintext": b64(pt),
		}, nil)
		if code != 200 {
			t.Fatalf("[%s] seal 失败: %d %+v", profile, code, out)
		}
		nonce := out["nonce"].(string)
		ct := out["ciphertext"].(string)
		code, out = postJSON(t, ts, "/v1/open", map[string]any{
			"key_ref": "static/aead", "aad": aad, "nonce": nonce, "ciphertext": ct,
		}, nil)
		if code != 200 || !bytes.Equal(b64d(t, out["plaintext"].(string)), pt) {
			t.Fatalf("[%s] open 失败/明文不符: %d %+v", profile, code, out)
		}
		// 篡改密文 → 400 decrypt（fail-closed）
		bad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xFF}, len(b64d(t, ct))))
		code, out = postJSON(t, ts, "/v1/open", map[string]any{
			"key_ref": "static/aead", "aad": aad, "nonce": nonce, "ciphertext": bad,
		}, nil)
		if code != 400 || errCode(t, out) != "decrypt" {
			t.Fatalf("[%s] 篡改密文应 400 decrypt，得 %d %+v", profile, code, out)
		}
	}
}

func TestSignVerifyAndP256(t *testing.T) {
	_, ts, _ := newTestServer(t, cryptop.ProfileIntl)
	// 空签名应验签失败（HTTP 200, ok:false），而非 HTTP 错误
	code, out := postJSON(t, ts, "/v1/verify", map[string]any{
		"key_ref": "static/hmac", "data": b64([]byte("d")), "signature": b64([]byte("short")),
	}, nil)
	if code != 200 || out["ok"] != false {
		t.Fatalf("验签失败应 200 {ok:false}，得 %d %+v", code, out)
	}
	if out["error"] != nil {
		t.Fatalf("verify 失败不应带 error 对象（§4.4：200 {ok:false}）")
	}

	// 内联公钥 P-256 验签（§5.4.2 例外，alg="p256"）
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	msg := []byte("toSign-bytes")
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("p256 sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	code, out = postJSON(t, ts, "/v1/verify", map[string]any{
		"pub_key": b64(pub), "data": b64(msg), "signature": b64(sig), "alg": "p256",
	}, nil)
	if code != 200 || out["ok"] != true {
		t.Fatalf("P-256 验签应通过，得 %d %+v", code, out)
	}
	// 篡改消息 → ok:false
	code, out = postJSON(t, ts, "/v1/verify", map[string]any{
		"pub_key": b64(pub), "data": b64([]byte("tampered")), "signature": b64(sig), "alg": "p256",
	}, nil)
	if code != 200 || out["ok"] != false {
		t.Fatalf("P-256 篡改应 ok:false，得 %d %+v", code, out)
	}
}

func TestKDFDeriveAndUse(t *testing.T) {
	_, ts, _ := newTestServer(t, cryptop.ProfileIntl)
	code, out := postJSON(t, ts, "/v1/kdf", map[string]any{
		"key_ref": "static/hmac", "out_len": 32, "alias": "derived/child",
	}, nil)
	if code != 200 {
		t.Fatalf("kdf 失败: %d %+v", code, out)
	}
	child := out["key_ref"].(string)
	if child != "derived/child" {
		t.Fatalf("别名未生效: %v", child)
	}
	// 派生子键可被消费（机制生效）
	code, out = postJSON(t, ts, "/v1/hmac", map[string]any{"key_ref": child, "data": b64([]byte("x"))}, nil)
	if code != 200 {
		t.Fatalf("派生键 hmac 失败: %d %+v", code, out)
	}
	// out_len 超限
	code, out = postJSON(t, ts, "/v1/kdf", map[string]any{"key_ref": "static/hmac", "out_len": 99999}, nil)
	if code != 413 || errCode(t, out) != "limit_exceeded" {
		t.Fatalf("kdf out_len 超限应 413，得 %d %+v", code, out)
	}
}

func TestMaskStreamDeterministic(t *testing.T) {
	_, ts, _ := newTestServer(t, cryptop.ProfileIntl)
	seed := bytes.Repeat([]byte{0x01}, 32) // v1.9：hmac 路径 seed ≥ MinSeedLen(32)，由调用方传入
	body := map[string]any{"seed": b64(seed), "domain": "otpmask/guardrail-text/v1", "count": 32, "modulus": 1 << 32}
	code, out1 := postJSON(t, ts, "/v1/mask/stream", body, nil)
	if code != 200 {
		t.Fatalf("mask 失败: %d %+v", code, out1)
	}
	v1 := out1["values"].([]any)
	if len(v1) != 32 {
		t.Fatalf("mask 元素数 %d", len(v1))
	}
	code, out2 := postJSON(t, ts, "/v1/mask/stream", body, nil)
	if code != 200 {
		t.Fatalf("mask2 失败: %d", code)
	}
	v2 := out2["values"].([]any)
	for i := range v1 {
		if v1[i] != v2[i] {
			t.Fatalf("掩码流不确定：元素 %d 不同（同 seed+domain+modulus 应逐字节一致）", i)
		}
		for _, x := range []any{v1[i]} {
			if uint64(x.(float64)) >= uint64(1)<<32 {
				t.Fatalf("掩码元素越界: %v", x)
			}
		}
	}
	// count 超限
	code, out := postJSON(t, ts, "/v1/mask/stream", map[string]any{"seed": b64(seed), "count": maxMaskCount + 1, "modulus": 4}, nil)
	if code != 413 || errCode(t, out) != "limit_exceeded" {
		t.Fatalf("mask count 超限应 413，得 %d %+v", code, out)
	}
	// modulus < 2
	code, out = postJSON(t, ts, "/v1/mask/stream", map[string]any{"seed": b64(seed), "count": 1, "modulus": 1}, nil)
	if code != 400 || errCode(t, out) != "bad_request" {
		t.Fatalf("modulus<2 应 400，得 %d %+v", code, out)
	}
	// seed 缺失/空（v1.9：seed 为必填）
	code, out = postJSON(t, ts, "/v1/mask/stream", map[string]any{"count": 1, "modulus": 4}, nil)
	if code != 400 || errCode(t, out) != "bad_request" {
		t.Fatalf("空 seed 应 400 bad_request，得 %d %+v", code, out)
	}
	// seed 长度不足（hmac 路径 < MinSeedLen）
	code, out = postJSON(t, ts, "/v1/mask/stream", map[string]any{"seed": b64(bytes.Repeat([]byte{0x02}, 16)), "count": 1, "modulus": 4}, nil)
	if code != 400 || errCode(t, out) != "key_size_mismatch" {
		t.Fatalf("短 seed 应 400 key_size_mismatch，得 %d %+v", code, out)
	}
}

// TestSessionBeginEndNetZero T-5.4-6：会话 KeyRef 净值归零（#6 不单调上升）。
func TestSessionBeginEndNetZero(t *testing.T) {
	s, ts, p := newTestServer(t, cryptop.ProfileIntl)
	_, serverPub, err := p.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("gen ecdh: %v", err)
	}
	nonce, _ := p.Rand(32)
	base := activeKeyRefs(s.m, keystore.ScopeSession)

	code, out := postJSON(t, ts, "/v1/session/begin", map[string]any{
		"server_pub": b64(serverPub), "nonce": b64(nonce), "peer_pub_alg": "x25519",
	}, nil)
	if code != 200 {
		t.Fatalf("session/begin 失败: %d %+v", code, out)
	}
	ksig := out["key_ref_sig"].(string)
	kenc := out["key_ref_enc"].(string)
	if len(b64d(t, out["client_pub"].(string))) == 0 {
		t.Fatal("client_pub 为空")
	}
	if got := activeKeyRefs(s.m, keystore.ScopeSession) - base; got != 2 {
		t.Fatalf("session/begin 应 +2 KeyRef，得 %d", got)
	}

	// 会话密钥可被消费（机制生效）：用 K_enc 做 seal
	code, out = postJSON(t, ts, "/v1/seal", map[string]any{"key_ref": kenc, "plaintext": b64([]byte("hi"))}, nil)
	if code != 200 {
		t.Fatalf("会话键 seal 失败: %d %+v", code, out)
	}

	// v1.7 §5.4.5（R8-P1-1）：信封方向子密钥经 /v1/kdf 派生，alias 取 <key_ref_enc>/<dir>
	// （会话内唯一）——插件即以此二 ref 调 /v1/seal。派生后再验 session/end 一并销毁（4-ref 净值归零）。
	for _, suf := range []string{"/c2s", "/s2c"} {
		code, out = postJSON(t, ts, "/v1/kdf", map[string]any{
			"key_ref": kenc, "info": b64([]byte("otpmask/kdf/enc/" + suf[1:] + "/v1")),
			"out_len": 32, "alias": kenc + suf,
		}, nil)
		if code != 200 || out["key_ref"] != kenc+suf {
			t.Fatalf("kdf 派生 %s 失败: %d %+v", suf, code, out)
		}
	}
	if got := activeKeyRefs(s.m, keystore.ScopeSession) - base; got != 4 {
		t.Fatalf("派生后应 +4 KeyRef（sig/enc/c2s/s2c），得 %d", got)
	}

	code, out = postJSON(t, ts, "/v1/session/end", map[string]any{"key_ref_sig": ksig, "key_ref_enc": kenc}, nil)
	if code != 200 || out["ok"] != true {
		t.Fatalf("session/end 失败: %d %+v", code, out)
	}
	if got := activeKeyRefs(s.m, keystore.ScopeSession); got != base {
		t.Fatalf("session/end 后 KeyRef 未归零：base=%d got=%d", got, base)
	}
	// 已销毁 KeyRef 再用 → 404（fail-closed）
	code, out = postJSON(t, ts, "/v1/seal", map[string]any{"key_ref": kenc, "plaintext": b64([]byte("hi"))}, nil)
	if code != 404 || errCode(t, out) != "unknown_key_ref" {
		t.Fatalf("销毁后使用应 404，得 %d %+v", code, out)
	}
	// 方向子密钥亦随会话一并销毁（R8-P1-1：4-ref 全部归零）
	code, out = postJSON(t, ts, "/v1/open", map[string]any{
		"key_ref": kenc + "/c2s", "nonce": b64(make([]byte, 12)), "ciphertext": b64([]byte("x")),
	}, nil)
	if code != 404 || errCode(t, out) != "unknown_key_ref" {
		t.Fatalf("子密钥销毁后使用应 404，得 %d %+v", code, out)
	}
}

func TestBatchPerOpIsolation(t *testing.T) {
	_, ts, _ := newTestServer(t, cryptop.ProfileIntl)
	body := map[string]any{"ops": []map[string]any{
		{"id": "1", "op": "hash", "data": b64([]byte("a"))},
		{"id": "2", "op": "hmac", "key_ref": "missing", "data": b64([]byte("b"))}, // 应失败
		{"id": "3", "op": "rand", "n": 8},
	}}
	code, out := postJSON(t, ts, "/v1/batch", body, nil)
	if code != 200 {
		t.Fatalf("batch 失败: %d %+v", code, out)
	}
	results := out["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("结果数 %d", len(results))
	}
	if results[0].(map[string]any)["id"] != "1" || results[0].(map[string]any)["digest"] == nil {
		t.Fatalf("op1 应成功: %+v", results[0])
	}
	if results[1].(map[string]any)["error"] == nil { // per-op 错误隔离（R-6）
		t.Fatalf("op2 应失败: %+v", results[1])
	}
	if results[2].(map[string]any)["bytes"] == nil {
		t.Fatalf("op3 应成功（不被 op2 污染）: %+v", results[2])
	}
	// ops 超限
	ops := make([]map[string]any, 0, maxBatchOps+1)
	for i := 0; i <= maxBatchOps; i++ {
		ops = append(ops, map[string]any{"id": "x", "op": "hash", "data": b64([]byte("z"))})
	}
	code, out = postJSON(t, ts, "/v1/batch", map[string]any{"ops": ops}, nil)
	if code != 413 || errCode(t, out) != "limit_exceeded" {
		t.Fatalf("ops 超限应 413，得 %d %+v", code, out)
	}
}

// ---- 配置校验（R-2/R-14/R-20/R-21）----

func TestNewServerConfigValidation(t *testing.T) {
	intl, _ := cryptop.New(cryptop.ProfileIntl)
	sm, _ := cryptop.New(cryptop.ProfileSMSW)

	cases := []struct {
		name string
		p    cryptop.Provider
		cfg  Config
	}{
		{"profile 不一致", intl, Config{Profile: cryptop.ProfileSMSW}},
		{"intl+sm4 非法", intl, Config{MaskPRG: "sm4"}},
		{"intl+bridge 非法", intl, Config{MaskPRG: "bridge"}},
		{"sm+hmac-sha256 非法", sm, Config{MaskPRG: "hmac-sha256"}},
		{"非 loopback 拒绝", intl, Config{ListenAddr: "0.0.0.0:8443"}},
		{"R-16 intl 短键（16≠32）", intl, Config{StaticKeys: map[string][]byte{"static/aead": bytes.Repeat([]byte{1}, 16)}}},
		{"R-16 sm 长键（32≠16）", sm, Config{StaticKeys: map[string][]byte{"static/aead": bytes.Repeat([]byte{1}, 32)}}},
	}
	for _, c := range cases {
		if _, err := NewServer(c.p, c.cfg); err == nil {
			t.Fatalf("[%s] 应报错（R-2/R-14/R-16/R-20/R-21）", c.name)
		}
	}
	// 合法：sm-software + bridge（R-21）
	if _, err := NewServer(sm, Config{MaskPRG: "bridge"}); err != nil {
		t.Fatalf("sm-software+bridge 应合法: %v", err)
	}
	// 合法：loopback
	if _, err := NewServer(intl, Config{ListenAddr: "127.0.0.1:8443"}); err != nil {
		t.Fatalf("127.0.0.1 loopback 应合法: %v", err)
	}
	// 合法：静态键长度匹配 profile（R-16 启动期通过）
	if _, err := NewServer(intl, Config{StaticKeys: map[string][]byte{
		"static/aead": bytes.Repeat([]byte{0xAB}, intl.SymmetricKeySize()),
	}}); err != nil {
		t.Fatalf("长度匹配的静态键应登记成功: %v", err)
	}
}

// TestMaskBridgeSM 桥接档（R-21）：sm profile + bridge，按 X-OTPMask-MaskVersion 选 PRG。
func TestMaskBridgeSM(t *testing.T) {
	p, _ := cryptop.New(cryptop.ProfileSMSW)
	s, err := NewServer(p, Config{
		MaskPRG: "bridge",
		StaticKeys: map[string][]byte{
			"static/aead": bytes.Repeat([]byte{0x11}, p.SymmetricKeySize()),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	// v1.9：seed 由调用方传入，长度随 PRG（hmac≥32 / sm4=秘钥长度 16）。
	bodyHMAC := map[string]any{"seed": b64(bytes.Repeat([]byte{0x22}, 32)), "domain": "d", "count": 8, "modulus": 1 << 16}
	// hmac 格（bridge + 请求头 hmac-sha256）
	code, outHMAC := postJSON(t, ts, "/v1/mask/stream", bodyHMAC, map[string]string{"X-OTPMask-MaskVersion": "hmac-sha256"})
	if code != 200 {
		t.Fatalf("bridge hmac 格失败: %d %+v", code, outHMAC)
	}
	// sm4 格（bridge + 缺省）
	bodySM4 := map[string]any{"seed": b64(bytes.Repeat([]byte{0x33}, p.SymmetricKeySize())), "domain": "d", "count": 8, "modulus": 1 << 16}
	code, outSM4 := postJSON(t, ts, "/v1/mask/stream", bodySM4, nil)
	if code != 200 {
		t.Fatalf("bridge sm4 格失败: %d %+v", code, outSM4)
	}
	// 两格流不同（T-5.3-5：SM4 与 HMAC 版 PRG 不同源，不互操作）
	if equalValues(outHMAC["values"].([]any), outSM4["values"].([]any)) {
		t.Fatal("bridge 的两 PRG 格流不应相同")
	}
	// sm4 格 seed 长度须 = SymmetricKeySize（16）；32B 传入应 key_size_mismatch
	code, outBad := postJSON(t, ts, "/v1/mask/stream", map[string]any{"seed": b64(bytes.Repeat([]byte{0x33}, 32)), "domain": "d", "count": 8, "modulus": 1 << 16}, nil)
	if code != 400 || errCode(t, outBad) != "key_size_mismatch" {
		t.Fatalf("sm4 格 32B seed 应 400 key_size_mismatch，得 %d %+v", code, outBad)
	}
	// #15 compat_mode 已置 1
	raw := renderMetrics(t, s)
	if !strings.Contains(raw, `cryptop_compat_mode{feature="mask_bridge"} 1`) {
		t.Fatalf("bridge 应置 #15=1:\n%s", raw)
	}
}

// ---- 指标（#1/#2/#3/#6/#9/#11）----

func TestMetricsProducers(t *testing.T) {
	s, ts, _ := newTestServer(t, cryptop.ProfileIntl)
	postJSON(t, ts, "/v1/hash", map[string]any{"data": b64([]byte("x"))}, nil)
	postJSON(t, ts, "/v1/hmac", map[string]any{"key_ref": "missing", "data": b64([]byte("x"))}, nil)
	postJSON(t, ts, "/v1/mask/stream", map[string]any{"seed": b64(bytes.Repeat([]byte{0x04}, 32)), "count": 5, "modulus": 1 << 8}, nil)

	raw := renderMetrics(t, s)
	for _, want := range []string{
		`cryptop_ops_total{op="hash",profile="intl"}`,
		`cryptop_ops_total{op="mask",profile="intl"}`,
		`cryptop_errors_total{op="hmac",code="unknown_key_ref"}`,
		`cryptop_op_duration_seconds_count{op="hash"}`,
		`cryptop_key_refs{scope="static"} 2`,
		`cryptop_profile_info{profile="intl"`,
		`cryptop_mask_stream_values_total 5`,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("指标缺失 %q:\n%s", want, raw)
		}
	}
}

// ---- 辅助 ----

func activeKeyRefs(m *metrics, scope keystore.KeyScope) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keyRefs[string(scope)]
}

func renderMetrics(t *testing.T, s *Server) string {
	t.Helper()
	var buf bytes.Buffer
	s.m.render(&buf)
	return buf.String()
}

func equalValues(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
