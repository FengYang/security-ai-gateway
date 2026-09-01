// Package protocol — 南向私有二进制协议（M5，技术方案）。
//
// 手写 Varint 二进制编解码（wire format 与 Protobuf 兼容），纯标准库，
// 可在 Go 原生 wasm（wasip1）中编译。权威定义见 protocol/proto/otpmask.proto。
//
// 本包同时实现签名与防重放：
// - 签名：HMAC-SHA256(K_sig, request_id || timestamp_ns || nonce || payload)
// - K_sig 与掩码密钥分离，MVP 静态注入，生产由 TEE 签发
// - 防重放：时间戳窗口 + request_id 去重（校验方维护 seen 集合）
package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Status 协议状态码（与 proto 一致）。
type Status uint32

// Version 南向协议 wire 版本。
// 插件与 TEE 服务协商此版本；不匹配时插件 fail-closed 拒绝，防止 wire 不兼容部署。
const Version = "1.0.0"

// 协议扩展：engine_type / attest_type 枚举（可选字段，追加于 wire 末尾，向后兼容）。
const (
	// EngineTypeTEEGPU 路线 1：GPU TEE 整模型（缺省）。
	EngineTypeTEEGPU = "tee_gpu"
	// EngineTypeMaskedVector 路线 2：密态向量推理。
	EngineTypeMaskedVector = "masked_vector"
	// EngineTypeCMAAS 路线 1：百炼 Confidential MaaS（P5）。
	EngineTypeCMAAS = "cmaas"
	// AttestTypeQuote TEE 证明（生产默认；挑战-响应 + Quote 验证）。
	AttestTypeQuote = "quote"
	// AttestTypeToken MVP 凭证（向后兼容；仅限测试/灰度环境）。
	AttestTypeToken = "token"
)

// DefaultEngineType 请求缺省引擎类型（未填写 = 路线 1）。
const DefaultEngineType = EngineTypeTEEGPU

// DefaultAttestType 请求缺省证明类型（未填写 = MVP 凭证，向后兼容）。
const DefaultAttestType = AttestTypeToken

const (
	StatusOK           Status = 0
	StatusError        Status = 1
	StatusRateLimited  Status = 2
	StatusModelNotFound Status = 3
)

// CipherVector 密文/明文向量。
type CipherVector struct {
	Data []uint64 `json:"data"`
}

// InferenceRequest 推理请求。
type InferenceRequest struct {
	RequestID     string
	TimestampNS   int64
	Model         string
	MaxNewTokens  uint32
	Nonce         []byte
	CipherVectors []CipherVector
	CipherText    []byte // M9-4：OTP-Mask 逐字节密文文本（guardrail 用；空 = 未启用）
	Signature     []byte
	// 协议扩展（可选，追加于 wire 末尾，向后兼容）：
	EngineType string // "tee_gpu"（缺省）| "masked_vector" | "cmaas"（P5）
	AttestType string // "quote" | "token"（缺省，MVP 兼容）
	// P2/P5（D1）：text 载荷——明文 messages JSON（OpenAI 兼容 [{"role","content"}]），
	// 仅在段① K_enc 信封通道内合法（无会话信封时服务端 fail-closed 拒绝）；
	// vectors 载荷（CipherVectors）为路线 2 保留路径，两者互斥。
	TextPayload []byte
	// Stream 流式响应（SSE 信封流；false = 单信封聚合响应）。
	Stream bool
}

// InferenceResponse 推理响应。
type InferenceResponse struct {
	RequestID      string
	TimestampNS    int64
	Status         Status
	CipherOutput   CipherVector
	TokensGenerated uint32
	Signature      []byte
}

// ---------- Varint 编解码 ----------

// maxVectorDim 单个向量最大维度（防止恶意构造的超大数组导致 OOM）。
const maxVectorDim = 1 << 20 // 1M

// maxMessageLen 消息最大字节数（防止恶意构造的超长消息导致 OOM）。
const maxMessageLen = 100 << 20 // 100MB

func putVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func putBytes(buf []byte, b []byte) []byte {
	buf = putVarint(buf, uint64(len(b)))
	return append(buf, b...)
}

func putString(buf []byte, s string) []byte {
	return putBytes(buf, []byte(s))
}

func putUint64(buf []byte, v uint64) []byte { return putVarint(buf, v) }

func readVarint(data []byte, pos int) (uint64, int, error) {
	var v uint64
	var shift uint
	for {
		if pos >= len(data) {
			return 0, pos, errors.New("protocol: varint 截断")
		}
		b := data[pos]
		pos++
		v |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return v, pos, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, pos, errors.New("protocol: varint 溢出")
		}
	}
}

func readLenBytes(data []byte, pos int) ([]byte, int, error) {
	n, pos, err := readVarint(data, pos)
	if err != nil {
		return nil, pos, err
	}
	if n > maxMessageLen {
		return nil, pos, fmt.Errorf("protocol: 长度 %d 超过最大限制 %d", n, maxMessageLen)
	}
	if uint64(len(data)-pos) < n {
		return nil, pos, errors.New("protocol: 长度字节截断")
	}
	out := make([]byte, n)
	copy(out, data[pos:pos+int(n)])
	return out, pos + int(n), nil
}

func readString(data []byte, pos int) (string, int, error) {
	b, pos, err := readLenBytes(data, pos)
	if err != nil {
		return "", pos, err
	}
	return string(b), pos, nil
}

// ---------- CipherVector ----------

// EncodeVector 编码向量：varint dim, varint n, n × varint。
func EncodeVector(v CipherVector) []byte {
	buf := putVarint(nil, uint64(len(v.Data)))
	for _, x := range v.Data {
		buf = putVarint(buf, x)
	}
	return buf
}

func decodeVector(data []byte, pos int) (CipherVector, int, error) {
	n, pos, err := readVarint(data, pos)
	if err != nil {
		return CipherVector{}, pos, err
	}
	if n > maxVectorDim {
		return CipherVector{}, pos, fmt.Errorf("protocol: 向量维度 %d 超过最大限制 %d", n, maxVectorDim)
	}
	vec := CipherVector{Data: make([]uint64, 0, n)}
	for i := uint64(0); i < n; i++ {
		x, p, err := readVarint(data, pos)
		if err != nil {
			return CipherVector{}, pos, err
		}
		pos = p
		vec.Data = append(vec.Data, x)
	}
	return vec, pos, nil
}

// ---------- 请求 ----------

// EncodeRequest 编码推理请求。
func EncodeRequest(req *InferenceRequest) ([]byte, error) {
	if req.RequestID == "" {
		return nil, errors.New("protocol: request_id 为空")
	}
	buf := putString(nil, req.RequestID)
	buf = putUint64(buf, uint64(req.TimestampNS))
	buf = putString(buf, req.Model)
	buf = putUint64(buf, uint64(req.MaxNewTokens))
	buf = putBytes(buf, req.Nonce)
	buf = putUint64(buf, uint64(len(req.CipherVectors)))
	for _, v := range req.CipherVectors {
		buf = append(buf, EncodeVector(v)...)
	}
	buf = putBytes(buf, req.CipherText) // M9-4 密文文本通道（可空）
	buf = putBytes(buf, req.Signature)
	// 协议扩展（可选字段，追加于末尾；空 engine_type 不编码，保持向后兼容）。
	// P2/P5：text 载荷请求必然声明 engine_type，故 TextPayload/Stream 随扩展段编码。
	if req.EngineType != "" {
		buf = putString(buf, req.EngineType)
		buf = putString(buf, req.AttestType)
		buf = putBytes(buf, req.TextPayload)
		buf = putUint64(buf, boolWord(req.Stream))
	}
	return buf, nil
}

// DecodeRequest 解码推理请求。
func DecodeRequest(data []byte) (*InferenceRequest, error) {
	req := &InferenceRequest{}
	pos := 0
	var err error
	if req.RequestID, pos, err = readString(data, pos); err != nil {
		return nil, err
	}
	var ts uint64
	if ts, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	req.TimestampNS = int64(ts)
	if req.Model, pos, err = readString(data, pos); err != nil {
		return nil, err
	}
	var mt uint64
	if mt, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	req.MaxNewTokens = uint32(mt)
	if req.Nonce, pos, err = readLenBytes(data, pos); err != nil {
		return nil, err
	}
	var m uint64
	if m, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	if m > maxVectorDim {
		return nil, fmt.Errorf("protocol: 向量数量 %d 超过最大限制 %d", m, maxVectorDim)
	}
	for i := uint64(0); i < m; i++ {
		v, p, err := decodeVector(data, pos)
		if err != nil {
			return nil, err
		}
		pos = p
		req.CipherVectors = append(req.CipherVectors, v)
	}
	if req.CipherText, pos, err = readLenBytes(data, pos); err != nil {
		return nil, err
	}
	if req.Signature, pos, err = readLenBytes(data, pos); err != nil {
		return nil, err
	}
	// 协议扩展（可选字段，缺省为空 = 旧格式请求，向后兼容）。
	// P2/P5：text 载荷与流式标志逐字段探测（部分存在则读，尾部缺失容忍——
	// 旧编码端只写 engine_type/attest_type 时仍可解码）。
	if pos < len(data) {
		if req.EngineType, pos, err = readString(data, pos); err != nil {
			return nil, err
		}
		if req.AttestType, pos, err = readString(data, pos); err != nil {
			return nil, err
		}
	}
	if pos < len(data) {
		if req.TextPayload, pos, err = readLenBytes(data, pos); err != nil {
			return nil, err
		}
	}
	if pos < len(data) {
		var sw uint64
		if sw, pos, err = readVarint(data, pos); err != nil {
			return nil, err
		}
		req.Stream = sw == 1
	}
	return req, nil
}

// boolWord 布尔 → wire 字（0/1）。
func boolWord(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// ---------- 响应 ----------

// EncodeResponse 编码推理响应。
func EncodeResponse(resp *InferenceResponse) ([]byte, error) {
	buf := putString(nil, resp.RequestID)
	buf = putUint64(buf, uint64(resp.TimestampNS))
	buf = putUint64(buf, uint64(resp.Status))
	buf = append(buf, EncodeVector(resp.CipherOutput)...)
	buf = putUint64(buf, uint64(resp.TokensGenerated))
	buf = putBytes(buf, resp.Signature)
	return buf, nil
}

// DecodeResponse 解码推理响应。
func DecodeResponse(data []byte) (*InferenceResponse, error) {
	resp := &InferenceResponse{}
	pos := 0
	var err error
	if resp.RequestID, pos, err = readString(data, pos); err != nil {
		return nil, err
	}
	var ts uint64
	if ts, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	resp.TimestampNS = int64(ts)
	var st uint64
	if st, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	resp.Status = Status(st)
	if resp.CipherOutput, pos, err = decodeVector(data, pos); err != nil {
		return nil, err
	}
	var tg uint64
	if tg, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	resp.TokensGenerated = uint32(tg)
	if resp.Signature, _, err = readLenBytes(data, pos); err != nil {
		return nil, err
	}
	return resp, nil
}

// ---------- 签名与防重放 ----------

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
func SignRequest(kSig []byte, req *InferenceRequest) {
	payload := make([]byte, 0)
	payload = putString(payload, req.Model)
	payload = putUint64(payload, uint64(req.MaxNewTokens))
	payload = putUint64(payload, uint64(len(req.CipherVectors)))
	for _, v := range req.CipherVectors {
		payload = append(payload, EncodeVector(v)...)
	}
	payload = putBytes(payload, req.CipherText) // M9-4：密文文本纳入签名
	payload = putBytes(payload, req.TextPayload) // P2/P5：text 载荷纳入签名
	payload = putUint64(payload, boolWord(req.Stream))
	req.Signature = signMessage(kSig, req.RequestID, req.TimestampNS, req.Nonce, payload)
}

// VerifyRequest 校验请求签名（HMAC 常量时间比较）。
func VerifyRequest(kSig []byte, req *InferenceRequest) bool {
	got := req.Signature
	SignRequest(kSig, req)
	return hmac.Equal(got, req.Signature)
}

// SignResponse 对响应签名。
func SignResponse(kSig []byte, resp *InferenceResponse) {
	payload := make([]byte, 0)
	payload = putUint64(payload, uint64(resp.Status))
	payload = append(payload, EncodeVector(resp.CipherOutput)...)
	payload = putUint64(payload, uint64(resp.TokensGenerated))
	resp.Signature = signMessage(kSig, resp.RequestID, resp.TimestampNS, nil, payload)
}

// VerifyResponse 校验响应签名。
func VerifyResponse(kSig []byte, resp *InferenceResponse) bool {
	got := resp.Signature
	SignResponse(kSig, resp)
	return hmac.Equal(got, resp.Signature)
}

// ---------- 防重放辅助 ----------

// ReplayWindow 时间戳有效窗口（纳秒）。
const ReplayWindow int64 = 30 * 1e9

// CheckReplay 校验时间戳窗口与 request_id 唯一性。
// seen 为校验方维护的已见 request_id 集合（应定期清理）。
func CheckReplay(reqID string, ts int64, nowNS int64, seen map[string]bool) error {
	if nowNS-ts > ReplayWindow || ts-nowNS > ReplayWindow {
		return fmt.Errorf("protocol: 时间戳超出窗口（%d vs now %d）", ts, nowNS)
	}
	if seen[reqID] {
		return fmt.Errorf("protocol: 重放请求 %s", reqID)
	}
	seen[reqID] = true
	return nil
}
