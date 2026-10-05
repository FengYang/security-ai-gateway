package cryptoops

// 协议消息 HMAC 签名单测（P0-4 §5.4.5 拆包：由 `protocol/go` 下沉）。
// 防重放（CheckReplay）为 framing 辅助，测试留 `protocol/go`。

import (
	"testing"
	"time"

	protocol "security-ai-gateway/protocol/go"
)

func TestSignVerify(t *testing.T) {
	kSig := []byte("test-k-sig-32-bytes-key-material")
	req := &protocol.InferenceRequest{
		RequestID:     "req-002",
		TimestampNS:   time.Now().UnixNano(),
		Model:         "mock",
		Nonce:         []byte("n1"),
		CipherVectors: []protocol.CipherVector{{Data: []uint64{100, 200}}},
	}
	SignRequest(kSig, req)
	if !VerifyRequest(kSig, req) {
		t.Fatal("合法签名校验失败")
	}
	// 篡改：修改向量后签名应失效
	req.CipherVectors[0].Data[0]++
	if VerifyRequest(kSig, req) {
		t.Fatal("篡改请求签名未被拒绝")
	}
	// 错误密钥
	req.CipherVectors[0].Data[0]--
	SignRequest(kSig, req)
	if VerifyRequest([]byte("wrong-key"), req) {
		t.Fatal("错误密钥校验通过")
	}
}

func TestSignVerifyResponse(t *testing.T) {
	kSig := []byte("test-k-sig-32-bytes-key-material")
	resp := &protocol.InferenceResponse{
		RequestID:       "req-002",
		TimestampNS:     time.Now().UnixNano(),
		Status:          protocol.StatusOK,
		CipherOutput:    protocol.CipherVector{Data: []uint64{1, 2, 3}},
		TokensGenerated: 3,
	}
	SignResponse(kSig, resp)
	if !VerifyResponse(kSig, resp) {
		t.Fatal("合法响应签名校验失败")
	}
	resp.TokensGenerated++
	if VerifyResponse(kSig, resp) {
		t.Fatal("篡改响应签名未被拒绝")
	}
}
