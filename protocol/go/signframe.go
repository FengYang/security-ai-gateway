// 协议消息签名的 **framing / 编码部分**（P0-4 §5.4.5 拆包）。
//
// 签名消息 = `request_id || ts(8B 大端) || nonce || 规范化载荷`。
// 本文件只构造**待签名消息字节**（纯编码，无密码求值）——与 `Envelope`/`PutString` 同属
// framing，插件（Wasm，R-11 零密码）可安全链入：插件据此数组装消息后，经 cryptop sidecar
// `/v1/hmac`（签）/`/v1/verify`（验）完成求值。
//
// **求值部分**（HMAC-SHA256）在 `protocol/go/cryptoops`（`signMessage`），其载荷构造复用本文件，
// 保证插件侧与 Go 服务侧签名字节**逐字节一致**（否则跨端验签必失败）。
package protocol

import "encoding/binary"

// SignMessageInput 构造 HMAC 输入消息：request_id || ts(8B 大端) || nonce || payload。
// nonce 为 nil 时（响应签名）等价于空串拼接。
func SignMessageInput(reqID string, tsNS int64, nonce, payload []byte) []byte {
	buf := make([]byte, 0, len(reqID)+8+len(nonce)+len(payload))
	buf = append(buf, reqID...)
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(tsNS))
	buf = append(buf, tsb[:]...)
	buf = append(buf, nonce...)
	buf = append(buf, payload...)
	return buf
}

// RequestSignPayload 请求签名规范化载荷（framing-only）。
// 覆盖 model/max_new_tokens/向量/密文文本/text 载荷/stream。
func RequestSignPayload(req *InferenceRequest) []byte {
	payload := make([]byte, 0)
	payload = PutString(payload, req.Model)
	payload = PutUint64(payload, uint64(req.MaxNewTokens))
	payload = PutUint64(payload, uint64(len(req.CipherVectors)))
	for _, v := range req.CipherVectors {
		payload = append(payload, EncodeVector(v)...)
	}
	payload = PutBytes(payload, req.CipherText)  // M9-4：密文文本纳入签名
	payload = PutBytes(payload, req.TextPayload) // P2/P5：text 载荷纳入签名
	payload = PutUint64(payload, BoolWord(req.Stream))
	return payload
}

// ResponseSignPayload 响应签名规范化载荷（framing-only）。
func ResponseSignPayload(resp *InferenceResponse) []byte {
	payload := make([]byte, 0)
	payload = PutUint64(payload, uint64(resp.Status))
	payload = append(payload, EncodeVector(resp.CipherOutput)...)
	payload = PutUint64(payload, uint64(resp.TokensGenerated))
	return payload
}
