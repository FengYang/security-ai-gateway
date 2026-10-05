package main

// P1c 会话信封通道测试：会话密钥隔离、服务端反重放、destroy 零化、
// 明文载荷 fail-closed（兼容开关仅 dev）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// setupCompletedSession 建立已完成会话并返回（会话、客户端派生 K_enc）。
func setupCompletedSession(t *testing.T) (*teeSession, []byte) {
	t.Helper()
	nonce, _ := randomNonce()
	s, err := newSession(nonce)
	if err != nil {
		t.Fatal(err)
	}
	pub := s.ServerPub() // Complete 前记录（完成后私钥销毁）
	c, err := newClientSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(c.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	_, kenc, err := deriveClientSessionKey(c, pub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.K_enc, kenc) {
		t.Fatal("服务端 K_enc 与客户端派生不一致")
	}
	return s, kenc
}

// TestSessionKeyIsolation 会话密钥隔离（P1c）：
// 不同会话派生密钥必然不同；跨会话信封（密钥或 sessionID 不符）一律拒绝。
func TestSessionKeyIsolation(t *testing.T) {
	s1, kenc1 := setupCompletedSession(t)
	s2, kenc2 := setupCompletedSession(t)
	if bytes.Equal(s1.K_enc, s2.K_enc) {
		t.Fatal("不同会话 K_enc 相同（隔离失败）")
	}
	if bytes.Equal(s1.K_sig, s2.K_sig) {
		t.Fatal("不同会话 K_sig 相同（隔离失败）")
	}
	// 会话 1 的 c2s 信封投给会话 2 的入口 → 拒绝（K_enc 不同）
	wire1, err := cryptoops.SealEnvelope(kenc1, s1.ID, protocol.EndpointInfer, protocol.DirectionC2S, 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.openPayload(protocol.EndpointInfer, wire1); err == nil {
		t.Fatal("跨会话信封未被拒绝（密钥隔离失败）")
	}
	// 会话 2 自身信封正常
	wire2, err := cryptoops.SealEnvelope(kenc2, s2.ID, protocol.EndpointInfer, protocol.DirectionC2S, 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.openPayload(protocol.EndpointInfer, wire2); err != nil {
		t.Fatalf("会话自身信封被拒: %v", err)
	}
	// sessionID 混淆：会话 2 密钥 + 会话 1 sessionID（AAD 绑定）→ 拒绝
	wire3, err := cryptoops.SealEnvelope(kenc2, s1.ID, protocol.EndpointInfer, protocol.DirectionC2S, 2, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.openPayload(protocol.EndpointInfer, wire3); err == nil {
		t.Fatal("sessionID 混淆未被拒绝")
	}
}

// TestSessionEnvelopeReplayServer 服务端入口反重放：重放/越窗信封拒绝。
func TestSessionEnvelopeReplayServer(t *testing.T) {
	s, kenc := setupCompletedSession(t)
	seal := func(counter uint64, pt string) []byte {
		w, err := cryptoops.SealEnvelope(kenc, s.ID, protocol.EndpointKeyIssue, protocol.DirectionC2S, counter, []byte(pt))
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	if _, err := s.openPayload(protocol.EndpointKeyIssue, seal(1, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.openPayload(protocol.EndpointKeyIssue, seal(2, "b")); err != nil {
		t.Fatal(err)
	}
	// 重放 counter=1 → 拒绝
	if _, err := s.openPayload(protocol.EndpointKeyIssue, seal(1, "a")); err == nil {
		t.Fatal("重放信封未被拒绝")
	}
	// 跳跃后回放远落后信封（counter=1 相对 highest=100 越窗）→ 拒绝
	if _, err := s.openPayload(protocol.EndpointKeyIssue, seal(100, "c")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.openPayload(protocol.EndpointKeyIssue, seal(1, "a")); err == nil {
		t.Fatal("越窗陈旧信封未被拒绝")
	}
	// 出口计数器单调递增（s2c）
	s1, err := s.sealPayload(protocol.EndpointInfer, []byte("r1"))
	if err != nil {
		t.Fatal(err)
	}
	s2wire, err := s.sealPayload(protocol.EndpointInfer, []byte("r2"))
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := protocol.DecodeEnvelope(s1)
	e2, _ := protocol.DecodeEnvelope(s2wire)
	if e1.Counter != 1 || e2.Counter != 2 || e1.Direction != protocol.DirectionS2C {
		t.Fatalf("s2c 计数器/方向异常: %d %d %d", e1.Counter, e2.Counter, e1.Direction)
	}
}

// TestSessionDestroyAndZeroize 会话销毁：seal/open 拒绝 + K_enc/K_sig 零化（best-effort）。
func TestSessionDestroyAndZeroize(t *testing.T) {
	s, kenc := setupCompletedSession(t)
	wire, err := cryptoops.SealEnvelope(kenc, s.ID, protocol.EndpointInfer, protocol.DirectionC2S, 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.openPayload(protocol.EndpointInfer, wire); err != nil {
		t.Fatalf("destroy 前信封应可用: %v", err)
	}
	kencRef := s.K_enc
	ksigRef := s.K_sig
	s.destroy()
	if _, err := s.sealPayload(protocol.EndpointInfer, []byte("x")); err == nil {
		t.Fatal("destroy 后 sealPayload 未被拒绝")
	}
	if _, err := s.openPayload(protocol.EndpointInfer, wire); err == nil {
		t.Fatal("destroy 后 openPayload 未被拒绝")
	}
	if s.K_enc != nil || s.K_sig != nil || s.Completed {
		t.Fatal("destroy 后会话状态未清零")
	}
	for _, b := range kencRef {
		if b != 0 {
			t.Fatal("destroy 未零化 K_enc")
		}
	}
	for _, b := range ksigRef {
		if b != 0 {
			t.Fatal("destroy 未零化 K_sig")
		}
	}
}

// TestSessionPlaintextFailClosed 明文载荷 fail-closed（P1c）：
// 有效会话下明文请求 → 400 拒绝；OTPMASK_SESSION_PLAINTEXT=dev 兼容放行（仅调试），
// 且 dev 模式响应出口仍是 s2c 信封（入口可降级调试，出口不降级）。
func TestSessionPlaintextFailClosed(t *testing.T) {
	_, ts := newM9Server(t)
	sessionID, _, kenc := setupTestSession(t, ts)

	// 明文 JSON + 有效会话 → 400（fail-closed，防降级攻击）
	plainBody, _ := json.Marshal(map[string]string{"model": "mock", "request_id": nextTestRequestID("pl")})
	req, _ := http.NewRequest("POST", ts.URL+"/key/issue", bytes.NewReader(plainBody))
	req.Header.Set("X-Session-ID", sessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("会话下明文载荷应 400（fail-closed），got %d", resp.StatusCode)
	}

	// dev 兼容开关：明文放行（仅调试，生产禁用）
	t.Setenv("OTPMASK_SESSION_PLAINTEXT", "dev")
	req2, _ := http.NewRequest("POST", ts.URL+"/key/issue", bytes.NewReader(plainBody))
	req2.Header.Set("X-Session-ID", sessionID)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("dev 模式明文入口应放行，got %d", resp2.StatusCode)
	}
	// dev 模式下响应出口仍为 s2c 信封（出口不降级）
	if _, _, err := cryptoops.OpenEnvelope(kenc, sessionID, protocol.EndpointKeyIssue, protocol.DirectionS2C, mustReadAll(t, resp2.Body)); err != nil {
		t.Fatalf("dev 模式响应应为 s2c 信封（出口不降级）: %v", err)
	}
}
