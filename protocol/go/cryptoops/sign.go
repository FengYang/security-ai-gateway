// 协议消息 HMAC 签名（P0-4 §5.4.5 拆包：由 `protocol/go` 下沉）。
//
// 签名 = HMAC-SHA256(K_sig, request_id || ts || nonce || 规范化载荷)。
// **仅 Go 服务/sidecar 可链接**；Wasm 插件改经 cryptop sidecar `/v1/hmac`、`/v1/verify`
// （§5.4.5 checklist 组④：`main.go` 的 `protocol.SignRequest`/`VerifyResponse`）。
package cryptoops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	protocol "security-ai-gateway/protocol/go"
)

// signMessage 计算 HMAC-SHA256 签名。
func signMessage(kSig []byte, reqID string, ts int64, nonce, payload []byte) []byte {
	mac := hmac.New(sha256.New, kSig)
	_, _ = mac.Write([]byte(reqID))
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))
	_, _ = mac.Write(tsb[:])
	_, _ = mac.Write(nonce)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

// SignRequest 对请求签名（覆盖 request_id || ts || nonce || 向量负载 || 密文文本 || text 载荷）。
// 返回的签名写入 req.Signature。
func SignRequest(kSig []byte, req *protocol.InferenceRequest) {
	payload := make([]byte, 0)
	payload = protocol.PutString(payload, req.Model)
	payload = protocol.PutUint64(payload, uint64(req.MaxNewTokens))
	payload = protocol.PutUint64(payload, uint64(len(req.CipherVectors)))
	for _, v := range req.CipherVectors {
		payload = append(payload, protocol.EncodeVector(v)...)
	}
	payload = protocol.PutBytes(payload, req.CipherText)  // M9-4：密文文本纳入签名
	payload = protocol.PutBytes(payload, req.TextPayload) // P2/P5：text 载荷纳入签名
	payload = protocol.PutUint64(payload, protocol.BoolWord(req.Stream))
	req.Signature = signMessage(kSig, req.RequestID, req.TimestampNS, req.Nonce, payload)
}

// VerifyRequest 校验请求签名（HMAC 常量时间比较）。
func VerifyRequest(kSig []byte, req *protocol.InferenceRequest) bool {
	got := req.Signature
	SignRequest(kSig, req)
	return hmac.Equal(got, req.Signature)
}

// SignResponse 对响应签名。
func SignResponse(kSig []byte, resp *protocol.InferenceResponse) {
	payload := make([]byte, 0)
	payload = protocol.PutUint64(payload, uint64(resp.Status))
	payload = append(payload, protocol.EncodeVector(resp.CipherOutput)...)
	payload = protocol.PutUint64(payload, uint64(resp.TokensGenerated))
	resp.Signature = signMessage(kSig, resp.RequestID, resp.TimestampNS, nil, payload)
}

// VerifyResponse 校验响应签名。
func VerifyResponse(kSig []byte, resp *protocol.InferenceResponse) bool {
	got := resp.Signature
	SignResponse(kSig, resp)
	return hmac.Equal(got, resp.Signature)
}
