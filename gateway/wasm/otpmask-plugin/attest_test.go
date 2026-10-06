package main

// P1b 插件侧安全测试：会话状态机 + 段① 信封密封/解密 + report_data 绑定验证链。
//
// P0-4 接线后：会话只持 **KeyRef**、全部密码经 cryptop sidecar（cryptoseam_test.go 的
// in-process 接缝）。测试语义与原「插件内直算」版一一对应，仅交付方式改为 CPS + 经 sidecar。

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
	"security-ai-gateway/protocol/go"
)

// TestPluginSessionState 会话状态机：初始无效 → set 有效 → clear 失效且 KeyRef 清空。
func TestPluginSessionState(t *testing.T) {
	if Session.valid() {
		t.Fatal("初始会话不应有效")
	}
	newSessionForTest(t)
	if !Session.valid() {
		t.Fatal("set 后会话应有效")
	}
	Session.clear()
	if Session.valid() || Session.SessionID != "" || Session.SigRef != "" ||
		Session.EncRef != "" || Session.C2SRef != "" || Session.S2CRef != "" {
		t.Fatal("clear 后会话应完全失效（四 KeyRef 清空）")
	}
	// 重新 set 后计数器与窗口重置（新会话 nonce 空间全新）
	Session.set("sess-test-00000002", "r/sig", "r/enc", "r/c2s", "r/s2c")
	defer Session.clear()
	if Session.sendCounter != 1 {
		t.Fatalf("新会话计数器应从 1 起: %d", Session.sendCounter)
	}
}

// TestPluginPayloadBeforeHandshake 未握手即加密/解密必须报错（fail-closed）。
func TestPluginPayloadBeforeHandshake(t *testing.T) {
	Session.clear()
	var serr, oerr error
	Session.sealPayload(protocol.EndpointInfer, []byte("x"), func(_ []byte, err error) { serr = err })
	if serr == nil {
		t.Fatal("未握手 sealPayload 未被拒绝")
	}
	Session.openPayload(protocol.EndpointInfer, []byte("x"), func(_ []byte, err error) { oerr = err })
	if oerr == nil {
		t.Fatal("未握手 openPayload 未被拒绝")
	}
}

// TestPluginSealPayloadRoundtrip c2s 密封 → 会话 c2s 子密钥解密（服务端等价）；计数器严格递增。
func TestPluginSealPayloadRoundtrip(t *testing.T) {
	newSessionForTest(t)

	var wire []byte
	var serr error
	Session.sealPayload(protocol.EndpointInfer, []byte("hello-tensor"), func(w []byte, err error) { wire, serr = w, err })
	if serr != nil {
		t.Fatal(serr)
	}
	env, err := protocol.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if env.Counter != 1 || env.Direction != protocol.DirectionC2S {
		t.Fatalf("首信封 counter/direction 异常: counter=%d direction=%d", env.Counter, env.Direction)
	}
	// 经 sidecar 以 c2s 子密钥解回
	aad := protocol.EnvelopeAAD(Session.SessionID, protocol.DirectionC2S, env.Counter, protocol.EndpointInfer)
	pt, oerr := clientOpen(Session.C2SRef, aad, protocol.EnvelopeNonce(env.Counter), env.Ciphertext)
	if oerr != nil || string(pt) != "hello-tensor" {
		t.Fatalf("c2s 往返失败: %v %q", oerr, pt)
	}
	// 计数器单调递增（nonce 唯一性来源）
	var wire2 []byte
	Session.sealPayload(protocol.EndpointKeyIssue, []byte("second"), func(w []byte, err error) { wire2 = w })
	env2, _ := protocol.DecodeEnvelope(wire2)
	if env2.Counter != 2 {
		t.Fatalf("计数器未递增: %d", env2.Counter)
	}
	// c2s 密文不能被当作 s2c 解开（方向子密钥）
	aadS2C := protocol.EnvelopeAAD(Session.SessionID, protocol.DirectionS2C, env.Counter, protocol.EndpointInfer)
	if _, err := clientOpen(Session.S2CRef, aadS2C, protocol.EnvelopeNonce(env.Counter), env.Ciphertext); err == nil {
		t.Fatal("c2s 信封按 s2c 解开未被拒绝")
	}
}

// TestPluginOpenPayloadReplay s2c 信封（服务端等价加密）→ openPayload 解密 + 重放/越窗拒绝。
func TestPluginOpenPayloadReplay(t *testing.T) {
	newSessionForTest(t)
	var wires [][]byte
	for i := uint64(1); i <= 3; i++ {
		wires = append(wires, sealS2CForTest(t, protocol.EndpointInfer, i, []byte{byte(i)}))
	}
	for i, w := range wires {
		var pt []byte
		var oerr error
		Session.openPayload(protocol.EndpointInfer, w, func(p []byte, err error) { pt, oerr = p, err })
		if oerr != nil {
			t.Fatalf("第 %d 个信封解密失败: %v", i+1, oerr)
		}
		if pt[0] != byte(i+1) {
			t.Fatalf("明文不符: %d", pt[0])
		}
	}
	// 重放第 2 个 → 拒绝（CounterWindow）
	var rerr error
	Session.openPayload(protocol.EndpointInfer, wires[1], func(_ []byte, err error) { rerr = err })
	if rerr == nil {
		t.Fatal("重放信封未被拒绝")
	}
	// 陈旧越窗（counter 1，已落后窗口）→ 拒绝
	var serr error
	Session.openPayload(protocol.EndpointInfer, wires[0], func(_ []byte, err error) { serr = err })
	if serr == nil {
		t.Fatal("越窗陈旧信封未被拒绝")
	}
}

// TestPluginOpenPayloadEndpointBinding 跨端点信封（/key/issue 密文投给 /v1/infer）→ 拒绝。
func TestPluginOpenPayloadEndpointBinding(t *testing.T) {
	newSessionForTest(t)
	wire := sealS2CForTest(t, protocol.EndpointKeyIssue, 1, []byte("k"))
	var oerr error
	Session.openPayload(protocol.EndpointInfer, wire, func(_ []byte, err error) { oerr = err })
	if oerr == nil {
		t.Fatal("跨端点信封未被拒绝")
	}
}

// TestPluginOpenPayloadTamper 篡改密文 → 拒绝。
func TestPluginOpenPayloadTamper(t *testing.T) {
	newSessionForTest(t)
	wire := sealS2CForTest(t, protocol.EndpointInfer, 1, []byte("secret"))
	wire[len(wire)-1] ^= 0xFF
	var oerr error
	Session.openPayload(protocol.EndpointInfer, wire, func(_ []byte, err error) { oerr = err })
	if oerr == nil {
		t.Fatal("篡改信封未被拒绝")
	}
}

// ---------- verifyPluginProof 验证链 ----------

// verifyProofSync 同步驱动 verifyPluginProof（seam 同步回调）。
func verifyProofSync(proof map[string]any, challenge, serverPub []byte, appHash string) error {
	var got error
	verifyPluginProof(proof, challenge, serverPub, appHash, func(err error) { got = err })
	return got
}

// buildPluginProof 测试用证明构造（与服务端 proofJSON 字段对齐，签名覆盖 report_data‖signing_key）。
// report_data = SHA-256(nonce‖server_pub)（intl profile 的 /v1/hash），与插件 verifyPluginProof 一致。
func buildPluginProof(t *testing.T, nonce, serverPub []byte) map[string]any {
	t.Helper()
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rdInput := append(append([]byte(nil), nonce...), serverPub...)
	rdSum := sha256.Sum256(rdInput)
	rd := rdSum[:]
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
	installSeam(t)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	serverPub := bytes.Repeat([]byte{0x02}, 32)
	proof := buildPluginProof(t, nonce, serverPub)
	if err := verifyProofSync(proof, nonce, serverPub, ""); err != nil {
		t.Fatalf("合法证明被拒: %v", err)
	}
	// app_hash 期望值匹配 → 通过；不匹配 → 拒绝
	want := hex.EncodeToString(bytes.Repeat([]byte{0x0A}, 32))
	if err := verifyProofSync(proof, nonce, serverPub, want); err != nil {
		t.Fatalf("app_hash 匹配被拒: %v", err)
	}
	if err := verifyProofSync(proof, nonce, serverPub, hex.EncodeToString(bytes.Repeat([]byte{0x0B}, 32))); err == nil {
		t.Fatal("app_hash 不匹配未被拒绝")
	}
}

// TestVerifyPluginProofBindingRejected MITM 公钥替换 / 篡改 report_data / nonce 不符 / 伪造签名 → 全部拒绝。
func TestVerifyPluginProofBindingRejected(t *testing.T) {
	installSeam(t)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	serverPub := bytes.Repeat([]byte{0x02}, 32)
	proof := buildPluginProof(t, nonce, serverPub)

	// MITM 替换握手公钥：证明绑定的公钥 ≠ 客户端收到的公钥 → report_data 不匹配 → 拒绝
	mitmPub := bytes.Repeat([]byte{0x03}, 32)
	if err := verifyProofSync(proof, nonce, mitmPub, ""); err == nil {
		t.Fatal("握手公钥替换未被拒绝")
	}
	// 篡改 report_data → 拒绝
	origRD := proof["report_data"].(string)
	proof["report_data"] = hex.EncodeToString(bytes.Repeat([]byte{0x09}, 32))
	if err := verifyProofSync(proof, nonce, serverPub, ""); err == nil {
		t.Fatal("篡改 report_data 未被拒绝")
	}
	proof["report_data"] = origRD
	// nonce 回显不匹配 → 拒绝
	if err := verifyProofSync(proof, bytes.Repeat([]byte{0x07}, 32), serverPub, ""); err == nil {
		t.Fatal("nonce 回显不匹配未被拒绝")
	}
	// 伪造签名 → 拒绝
	origSig := proof["signature"].(string)
	proof["signature"] = hex.EncodeToString(bytes.Repeat([]byte{0x01}, 64))
	if err := verifyProofSync(proof, nonce, serverPub, ""); err == nil {
		t.Fatal("伪造签名未被拒绝")
	}
	proof["signature"] = origSig
	// 空证明 / 缺 report_data / 缺 nonce → 拒绝
	if err := verifyProofSync(nil, nonce, serverPub, ""); err == nil {
		t.Fatal("空证明未被拒绝")
	}
	if err := verifyProofSync(map[string]any{"nonce": proof["nonce"]}, nonce, serverPub, ""); err == nil {
		t.Fatal("缺 report_data 未被拒绝")
	}
	if err := verifyProofSync(map[string]any{}, nonce, serverPub, ""); err == nil {
		t.Fatal("缺 nonce 未被拒绝")
	}
}

// TestPluginSessionKeyRefShape 会话 KeyRef 命名契约（v1.7 §5.4.5）：SessionBegin 返回的
// key_ref_enc 派生子密钥 alias 取 `<key_ref_enc>/<dir>`，Session 持 4 个互异 KeyRef。
func TestPluginSessionKeyRefShape(t *testing.T) {
	newSessionForTest(t)
	if Session.SigRef == "" || Session.EncRef == "" || Session.C2SRef == "" || Session.S2CRef == "" {
		t.Fatal("会话应持 4 个非空 KeyRef")
	}
	want := map[cryptoclient.KeyRef]bool{
		Session.SigRef: false, Session.EncRef: false, Session.C2SRef: false, Session.S2CRef: false,
	}
	if len(want) != 4 {
		t.Fatalf("四 KeyRef 应互异: %+v", want)
	}
}
