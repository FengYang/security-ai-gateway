package main

// P1b 插件侧安全测试：会话状态机 + 段① 信封密封/解密 + report_data 绑定验证链。
// 全部为纯逻辑测试（不依赖 proxywasm hostcall，可宿主执行）；
// Envoy 内 HTTP 编排（onRequestBody/onResponseBody）由部署冒烟与 P1d 跨端测试覆盖。

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"security-ai-gateway/protocol/go"
)

// newSessionForTest 建立带双密钥的测试会话（测试结束清除，串行执行下互不干扰）。
func newSessionForTest(t *testing.T) (ksig, kenc []byte) {
	t.Helper()
	ksig = bytes.Repeat([]byte{0x41}, 32)
	kenc = bytes.Repeat([]byte{0x42}, 32)
	Session.set("sess-test-00000001", ksig, kenc)
	t.Cleanup(Session.clear)
	return ksig, kenc
}

// TestPluginSessionState 会话状态机：初始无效 → set 有效 → clear 失效且密钥零化。
func TestPluginSessionState(t *testing.T) {
	if Session.valid() {
		t.Fatal("初始会话不应有效")
	}
	newSessionForTest(t)
	if !Session.valid() {
		t.Fatal("set 后会话应有效")
	}
	kencRef := Session.K_enc
	Session.clear()
	if Session.valid() || Session.SessionID != "" || Session.K_enc != nil || Session.K_sig != nil {
		t.Fatal("clear 后会话应完全失效")
	}
	for _, b := range kencRef {
		if b != 0 {
			t.Fatal("clear 未零化 K_enc")
		}
	}
	// 重新 set 后计数器与窗口重置（新会话 nonce 空间全新）
	Session.set("sess-test-00000002", bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32))
	defer Session.clear()
	if Session.sendCounter != 1 {
		t.Fatalf("新会话计数器应从 1 起: %d", Session.sendCounter)
	}
}

// TestPluginPayloadBeforeHandshake 未握手即加密/解密必须报错（fail-closed）。
func TestPluginPayloadBeforeHandshake(t *testing.T) {
	Session.clear()
	if _, err := Session.sealPayload(protocol.EndpointInfer, []byte("x")); err == nil {
		t.Fatal("未握手 sealPayload 未被拒绝")
	}
	if _, err := Session.openPayload(protocol.EndpointInfer, []byte("x")); err == nil {
		t.Fatal("未握手 openPayload 未被拒绝")
	}
}

// TestPluginSealPayloadRoundtrip c2s 密封 → 协议层解密（服务端等价）；计数器严格递增。
func TestPluginSealPayloadRoundtrip(t *testing.T) {
	_, kenc := newSessionForTest(t)

	wire, err := Session.sealPayload(protocol.EndpointInfer, []byte("hello-tensor"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if env.Counter != 1 || env.Direction != protocol.DirectionC2S {
		t.Fatalf("首信封 counter/direction 异常: counter=%d direction=%d", env.Counter, env.Direction)
	}
	pt, gotCounter, err := protocol.OpenEnvelope(kenc, Session.SessionID, protocol.EndpointInfer, protocol.DirectionC2S, wire)
	if err != nil || string(pt) != "hello-tensor" || gotCounter != 1 {
		t.Fatalf("c2s 往返失败: %v %q counter=%d", err, pt, gotCounter)
	}
	// 计数器单调递增（nonce 唯一性来源）
	wire2, _ := Session.sealPayload(protocol.EndpointKeyIssue, []byte("second"))
	env2, _ := protocol.DecodeEnvelope(wire2)
	if env2.Counter != 2 {
		t.Fatalf("计数器未递增: %d", env2.Counter)
	}
	// c2s 密文不能被当作 s2c 解开（方向子密钥）
	if _, _, err := protocol.OpenEnvelope(kenc, Session.SessionID, protocol.EndpointInfer, protocol.DirectionS2C, wire); err == nil {
		t.Fatal("c2s 信封按 s2c 解开未被拒绝")
	}
}

// TestPluginOpenPayloadReplay s2c 信封（服务端等价加密）→ openPayload 解密 + 重放/越窗拒绝。
func TestPluginOpenPayloadReplay(t *testing.T) {
	_, kenc := newSessionForTest(t)
	var wires [][]byte
	for i := uint64(1); i <= 3; i++ {
		w, err := protocol.SealEnvelope(kenc, Session.SessionID, protocol.EndpointInfer, protocol.DirectionS2C, i, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		wires = append(wires, w)
	}
	for i, w := range wires {
		pt, err := Session.openPayload(protocol.EndpointInfer, w)
		if err != nil {
			t.Fatalf("第 %d 个信封解密失败: %v", i+1, err)
		}
		if pt[0] != byte(i+1) {
			t.Fatalf("明文不符: %d", pt[0])
		}
	}
	// 重放第 2 个 → 拒绝（CounterWindow）
	if _, err := Session.openPayload(protocol.EndpointInfer, wires[1]); err == nil {
		t.Fatal("重放信封未被拒绝")
	}
	// 陈旧越窗（counter 1，已落后窗口）→ 拒绝
	if _, err := Session.openPayload(protocol.EndpointInfer, wires[0]); err == nil {
		t.Fatal("越窗陈旧信封未被拒绝")
	}
}

// TestPluginOpenPayloadEndpointBinding 跨端点信封（/key/issue 密文投给 /v1/infer）→ 拒绝。
func TestPluginOpenPayloadEndpointBinding(t *testing.T) {
	_, kenc := newSessionForTest(t)
	wire, err := protocol.SealEnvelope(kenc, Session.SessionID, protocol.EndpointKeyIssue, protocol.DirectionS2C, 1, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Session.openPayload(protocol.EndpointInfer, wire); err == nil {
		t.Fatal("跨端点信封未被拒绝")
	}
}

// TestPluginOpenPayloadTamper 篡改密文 → 拒绝。
func TestPluginOpenPayloadTamper(t *testing.T) {
	_, kenc := newSessionForTest(t)
	wire, _ := protocol.SealEnvelope(kenc, Session.SessionID, protocol.EndpointInfer, protocol.DirectionS2C, 1, []byte("secret"))
	wire[len(wire)-1] ^= 0xFF
	if _, err := Session.openPayload(protocol.EndpointInfer, wire); err == nil {
		t.Fatal("篡改信封未被拒绝")
	}
}

// ---------- verifyPluginProof 验证链 ----------

// buildPluginProof 测试用证明构造（与服务端 proofJSON 字段对齐，签名覆盖 report_data‖signing_key）。
func buildPluginProof(t *testing.T, nonce, serverPub []byte) map[string]any {
	t.Helper()
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rd := reportDataBinding(nonce, serverPub)
	signingPub := elliptic.Marshal(signKey.Curve, signKey.X, signKey.Y)
	toSign := append(append([]byte(nil), rd...), signingPub...)
	h := sha256.Sum256(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, signKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	return map[string]any{
		"nonce":        hex.EncodeToString(nonce),
		"platform":     "mock",
		"report_data":  hex.EncodeToString(rd),
		"measurements": map[string]any{"app_hash": hex.EncodeToString(bytes.Repeat([]byte{0x0A}, 32)), "runtime": "mock"},
		"signing_key":  hex.EncodeToString(signingPub),
		"signature":    hex.EncodeToString(sig),
	}
}

// TestVerifyPluginProofValid 合法证明通过（含 app_hash 期望值校验）。
func TestVerifyPluginProofValid(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 32)
	serverPub := bytes.Repeat([]byte{0x02}, 32)
	proof := buildPluginProof(t, nonce, serverPub)
	if err := verifyPluginProof(proof, nonce, serverPub, ""); err != nil {
		t.Fatalf("合法证明被拒: %v", err)
	}
	// app_hash 期望值匹配 → 通过；不匹配 → 拒绝
	want := hex.EncodeToString(bytes.Repeat([]byte{0x0A}, 32))
	if err := verifyPluginProof(proof, nonce, serverPub, want); err != nil {
		t.Fatalf("app_hash 匹配被拒: %v", err)
	}
	if err := verifyPluginProof(proof, nonce, serverPub, hex.EncodeToString(bytes.Repeat([]byte{0x0B}, 32))); err == nil {
		t.Fatal("app_hash 不匹配未被拒绝")
	}
}

// TestVerifyPluginProofBindingRejected MITM 公钥替换 / 篡改 report_data / nonce 不符 / 伪造签名 → 全部拒绝。
func TestVerifyPluginProofBindingRejected(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x01}, 32)
	serverPub := bytes.Repeat([]byte{0x02}, 32)
	proof := buildPluginProof(t, nonce, serverPub)

	// MITM 替换握手公钥：证明绑定的公钥 ≠ 客户端收到的公钥 → report_data 不匹配 → 拒绝
	mitmPub := bytes.Repeat([]byte{0x03}, 32)
	if err := verifyPluginProof(proof, nonce, mitmPub, ""); err == nil {
		t.Fatal("握手公钥替换未被拒绝")
	}
	// 篡改 report_data → 拒绝
	origRD := proof["report_data"].(string)
	proof["report_data"] = hex.EncodeToString(bytes.Repeat([]byte{0x09}, 32))
	if err := verifyPluginProof(proof, nonce, serverPub, ""); err == nil {
		t.Fatal("篡改 report_data 未被拒绝")
	}
	proof["report_data"] = origRD
	// nonce 回显不匹配 → 拒绝
	if err := verifyPluginProof(proof, bytes.Repeat([]byte{0x07}, 32), serverPub, ""); err == nil {
		t.Fatal("nonce 回显不匹配未被拒绝")
	}
	// 伪造签名 → 拒绝
	origSig := proof["signature"].(string)
	proof["signature"] = hex.EncodeToString(bytes.Repeat([]byte{0x01}, 64))
	if err := verifyPluginProof(proof, nonce, serverPub, ""); err == nil {
		t.Fatal("伪造签名未被拒绝")
	}
	proof["signature"] = origSig
	// 空证明 / 缺 report_data / 缺 nonce → 拒绝
	if err := verifyPluginProof(nil, nonce, serverPub, ""); err == nil {
		t.Fatal("空证明未被拒绝")
	}
	if err := verifyPluginProof(map[string]any{"nonce": proof["nonce"]}, nonce, serverPub, ""); err == nil {
		t.Fatal("缺 report_data 未被拒绝")
	}
	if err := verifyPluginProof(map[string]any{}, nonce, serverPub, ""); err == nil {
		t.Fatal("缺 nonce 未被拒绝")
	}
}

// ---------- 会话密钥派生一致性 ----------

// TestPluginSessionKeyAgreement 插件侧 derivePluginSessionKey 与服务端镜像
// （tee-infer-service/session.go 同款 HKDF 信息串）派生结果完全一致，防两侧 KDF 漂移。
func TestPluginSessionKeyAgreement(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x11}, 32)
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ksig, kenc, err := derivePluginSessionKey(clientPriv, serverPriv.PublicKey().Bytes(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	// 服务端镜像：ECDH + HKDF("otpmask/session/v1") + 域分离派生（与 session.go 逐字节一致）
	shared, err := serverPriv.ECDH(clientPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := serverMirrorHKDF(shared, nonce, []byte("otpmask/session/v1"), 32)
	wantSig := serverMirrorHKDF(sessionKey, nil, []byte("otpmask/kdf/sig/v1"), 32)
	wantEnc := serverMirrorHKDF(sessionKey, nil, []byte("otpmask/kdf/enc/v1"), 32)
	if !bytes.Equal(ksig, wantSig) {
		t.Fatal("K_sig 插件侧与服务端镜像不一致")
	}
	if !bytes.Equal(kenc, wantEnc) {
		t.Fatal("K_enc 插件侧与服务端镜像不一致")
	}
	if bytes.Equal(ksig, kenc) {
		t.Fatal("K_sig 与 K_enc 域分离失败")
	}
}

// serverMirrorHKDF 服务端 session.go hkdfSHA256 的镜像实现（extract+expand，RFC 5869）。
func serverMirrorHKDF(ikm, salt, info []byte, length int) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	out := make([]byte, 0, length)
	var t []byte
	counter := byte(1)
	for len(out) < length {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{counter})
		t = m.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}
