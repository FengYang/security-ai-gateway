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

// TestVerifyAttestationProof 证明链验证通过；篡改 app_hash / 伪造签名 / report_data 绑定不匹配被拒。
// report_data = H(nonce ‖ server_pub)：客户端用自己发出的 nonce 与服务端临时公钥
// 计算期望绑定材料，防止中间人替换握手公钥（P1b / 评审 F3）。
func TestVerifyAttestationProof(t *testing.T) {
	e, _ := NewMockEnclave()
	measure, _ := e.Measure()
	expectedHash := hex.EncodeToString(measure)

	challenge, _ := randomNonce()
	serverPub := []byte("server-ephemeral-pub-raw-bytes!!!")
	expectedRD := reportDataBinding(challenge, serverPub)

	// 合法载荷通过（含 report_data 绑定强校验）
	proof, err := e.Attest(challenge, expectedRD)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttestationProof(proof, expectedHash, expectedRD); err != nil {
		t.Fatalf("合法载荷被拒: %v", err)
	}
	if !bytes.Equal(proof.Nonce, challenge) {
		t.Fatal("nonce 回显不一致")
	}
	// 不传期望绑定（宽松模式，向后兼容）也通过
	if err := VerifyAttestationProof(proof, expectedHash, nil); err != nil {
		t.Fatalf("宽松校验被拒: %v", err)
	}

	// report_data 与期望绑定不匹配（中间人替换握手公钥场景）→ 拒绝
	mitmRD := reportDataBinding(challenge, bytes.Repeat([]byte{0x33}, 32))
	if err := VerifyAttestationProof(proof, expectedHash, mitmRD); err == nil {
		t.Fatal("report_data 绑定不匹配未被拒绝")
	}

	// report_data 缺失 → 拒绝
	proofEmptyRD := *proof
	proofEmptyRD.ReportData = nil
	if err := VerifyAttestationProof(&proofEmptyRD, expectedHash, nil); err == nil {
		t.Fatal("缺少 report_data 未被拒绝")
	}

	// 篡改 report_data（签名覆盖 report_data，篡改即验签失败）→ 拒绝
	proofBadRD := *proof
	proofBadRD.ReportData = bytes.Repeat([]byte{0x44}, 32)
	if err := VerifyAttestationProof(&proofBadRD, expectedHash, nil); err == nil {
		t.Fatal("篡改 report_data 未被拒绝")
	}

	// 篡改 app_hash → 拒绝
	proofBadHash := *proof
	proofBadHash.Measurements = map[string]string{
		"app_hash": hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)),
		"runtime":  "mock",
	}
	if err := VerifyAttestationProof(&proofBadHash, expectedHash, expectedRD); err == nil {
		t.Fatal("篡改 app_hash 未被拒绝")
	}

	// 伪造签名 → 拒绝
	proofBadSig := *proof
	proofBadSig.Signature = bytes.Repeat([]byte{0x01}, 64)
	if err := VerifyAttestationProof(&proofBadSig, expectedHash, expectedRD); err == nil {
		t.Fatal("伪造签名未被拒绝")
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
