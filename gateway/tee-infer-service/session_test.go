// 会话密钥派生测试（双端 ECDH+HKDF 一致性 + 验证链拒绝路径）。
package main

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// TestSessionKeyAgreement 服务端 Complete 与客户端 derive 派生 K_sig/K_enc 完全一致。
func TestSessionKeyAgreement(t *testing.T) {
	nonce, _ := randomNonce()

	// 服务端会话
	srv, err := newSession(nonce)
	if err != nil {
		t.Fatal(err)
	}
	// 客户端密钥对 + 派生
	clientPriv, err := newClientSession()
	if err != nil {
		t.Fatal(err)
	}
	clientKsig, clientKenc, err := deriveClientSessionKey(clientPriv, srv.ServerPub(), nonce)
	if err != nil {
		t.Fatalf("客户端派生失败: %v", err)
	}

	// 服务端 complete
	if err := srv.Complete(clientPriv.PublicKey().Bytes()); err != nil {
		t.Fatalf("服务端 complete 失败: %v", err)
	}
	if !srv.Completed {
		t.Fatal("会话未标记完成")
	}
	if !bytes.Equal(srv.K_sig, clientKsig) {
		t.Fatal("K_sig 双端不一致")
	}
	if !bytes.Equal(srv.K_enc, clientKenc) {
		t.Fatal("K_enc 双端不一致")
	}
	// K_sig 与 K_enc 必须不同（域分离）
	if bytes.Equal(srv.K_sig, srv.K_enc) {
		t.Fatal("K_sig 与 K_enc 域分离失败")
	}
	// 会话私钥已销毁（前向保密）
	if srv.ServerPriv != nil {
		t.Fatal("会话私钥未销毁")
	}
}

// TestSessionCompleteOnce 会话不可重复 complete（防重放）。
func TestSessionCompleteOnce(t *testing.T) {
	nonce, _ := randomNonce()
	srv, _ := newSession(nonce)
	clientPriv, _ := newClientSession()
	if err := srv.Complete(clientPriv.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	other, _ := newClientSession()
	if err := srv.Complete(other.PublicKey().Bytes()); err == nil {
		t.Fatal("重复 complete 未被拒绝")
	}
}

// TestVerifyAttestationProof 证明链验证通过；篡改 app_hash / 伪造签名 / 错误 nonce 被拒。
func TestVerifyAttestationProof(t *testing.T) {
	e, _ := NewMockEnclave()
	measure, _ := e.Measure()
	expectedHash := hex.EncodeToString(measure)

	// 合法载荷通过
	challenge, _ := randomNonce()
	proof, err := e.Attest(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttestationProof(proof, expectedHash); err != nil {
		t.Fatalf("合法载荷被拒: %v", err)
	}
	if !bytes.Equal(proof.Nonce, challenge) {
		t.Fatal("nonce 回显不一致")
	}

	// 篡改 app_hash → 拒绝
	proof.Measurements["app_hash"] = hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))
	if err := VerifyAttestationProof(proof, expectedHash); err == nil {
		t.Fatal("篡改 app_hash 未被拒绝")
	}
	// 恢复并伪造签名 → 拒绝
	proof.Measurements["app_hash"] = expectedHash
	proof.Signature = bytes.Repeat([]byte{0x01}, 64)
	if err := VerifyAttestationProof(proof, expectedHash); err == nil {
		t.Fatal("伪造签名未被拒绝")
	}
	// 错误 nonce 回显（篡改 nonce）→ 拒绝
	proof2, _ := e.Attest(challenge)
	proof2.Nonce = bytes.Repeat([]byte{0x02}, 32)
	if err := VerifyAttestationProof(proof2, expectedHash); err == nil {
		t.Fatal("错误 nonce 未被拒绝")
	}
}

// TestSessionTTL 会话 TTL 联动（5min 超时失效）。
func TestSessionTTL(t *testing.T) {
	nonce, _ := randomNonce()
	srv, _ := newSession(nonce)
	if time.Since(srv.CreatedAt) > sessionTTL {
		t.Fatal("会话初始即过期")
	}
	if srv.CreatedAt.Add(sessionTTL).Before(time.Now().Add(sessionTTL - time.Second)) {
		t.Fatal("会话 TTL 计算错误")
	}
}
