package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestRequestRoundtrip(t *testing.T) {
	req := &InferenceRequest{
		RequestID:    "req-001",
		TimestampNS:  time.Now().UnixNano(),
		Model:        "mock",
		MaxNewTokens: 128,
		Nonce:        []byte("nonce-16-bytes!!"),
		CipherVectors: []CipherVector{
			{Data: []uint64{1, 2, 3, 4294967295}},
			{Data: []uint64{18446744073709551615, 0, 42}},
		},
	}
	req.Signature = []byte("0123456789abcdef0123456789abcdef") // 32B 占位
	enc, err := EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.RequestID != req.RequestID || dec.Model != req.Model ||
		dec.MaxNewTokens != req.MaxNewTokens || !bytes.Equal(dec.Nonce, req.Nonce) ||
		dec.TimestampNS != req.TimestampNS {
		t.Fatalf("请求字段不一致: %+v", dec)
	}
	if len(dec.CipherVectors) != 2 {
		t.Fatalf("向量数不一致: %d", len(dec.CipherVectors))
	}
	for i := range dec.CipherVectors {
		if !bytes.Equal(uint64Bytes(dec.CipherVectors[i].Data), uint64Bytes(req.CipherVectors[i].Data)) {
			t.Fatalf("向量 %d 不一致", i)
		}
	}
}

func TestResponseRoundtrip(t *testing.T) {
	resp := &InferenceResponse{
		RequestID:       "req-001",
		TimestampNS:     time.Now().UnixNano(),
		Status:          StatusOK,
		CipherOutput:    CipherVector{Data: []uint64{9, 8, 7}},
		TokensGenerated: 5,
	}
	resp.Signature = []byte("0123456789abcdef0123456789abcdef")
	enc, err := EncodeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeResponse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.RequestID != resp.RequestID || dec.Status != resp.Status ||
		dec.TokensGenerated != resp.TokensGenerated ||
		!bytes.Equal(uint64Bytes(dec.CipherOutput.Data), uint64Bytes(resp.CipherOutput.Data)) {
		t.Fatalf("响应字段不一致: %+v", dec)
	}
}

// 签名/验签测试已下沉 `protocol/go/cryptoops`（sign_test.go）。

func TestReplayProtection(t *testing.T) {
	now := time.Now().UnixNano()
	seen := make(map[string]bool)
	req := &InferenceRequest{RequestID: "req-003", TimestampNS: now, Nonce: []byte("n")}
	if err := CheckReplay(req.RequestID, req.TimestampNS, now, seen); err != nil {
		t.Fatalf("首见请求被拒绝: %v", err)
	}
	if err := CheckReplay(req.RequestID, req.TimestampNS, now, seen); err == nil {
		t.Fatal("重放请求未被拒绝")
	}
	// 过期时间戳
	if err := CheckReplay("req-004", now-31*1e9, now, seen); err == nil {
		t.Fatal("过期时间戳未被拒绝")
	}
	// 未来时间戳
	if err := CheckReplay("req-005", now+31*1e9, now, seen); err == nil {
		t.Fatal("未来时间戳未被拒绝")
	}
}

// TestEngineTypeAttestTypeRoundtrip 协议扩展字段（engine_type/attest_type）往返一致。
func TestEngineTypeAttestTypeRoundtrip(t *testing.T) {
	req := &InferenceRequest{
		RequestID:    "req-ext-001",
		TimestampNS:  time.Now().UnixNano(),
		Model:        "qwen2.5-0.5b",
		MaxNewTokens: 32,
		Nonce:        []byte("nonce-16-bytes!!"),
		CipherVectors: []CipherVector{
			{Data: []uint64{1, 2, 3}},
		},
		EngineType: EngineTypeMaskedVector,
		AttestType: AttestTypeQuote,
	}
	req.Signature = []byte("0123456789abcdef0123456789abcdef")
	enc, err := EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.EngineType != EngineTypeMaskedVector {
		t.Fatalf("engine_type 不一致: got %q", dec.EngineType)
	}
	if dec.AttestType != AttestTypeQuote {
		t.Fatalf("attest_type 不一致: got %q", dec.AttestType)
	}
}

// TestEngineTypeBackwardCompat 旧格式请求（无扩展字段）解码兼容，缺省为空。
func TestEngineTypeBackwardCompat(t *testing.T) {
	req := &InferenceRequest{
		RequestID:     "req-old-001",
		TimestampNS:   time.Now().UnixNano(),
		Model:         "mock",
		MaxNewTokens:  8,
		Nonce:         []byte("n"),
		CipherVectors: []CipherVector{{Data: []uint64{7}}},
	}
	req.Signature = []byte("0123456789abcdef0123456789abcdef")
	enc, err := EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.EngineType != "" || dec.AttestType != "" {
		t.Fatalf("旧格式请求扩展字段应为空: engine=%q attest=%q", dec.EngineType, dec.AttestType)
	}
}

// TestDefaults 缺省值语义（未填写 = tee_gpu / token）。
func TestDefaults(t *testing.T) {
	if DefaultEngineType != EngineTypeTEEGPU {
		t.Fatalf("缺省 engine_type 应为 tee_gpu")
	}
	if DefaultAttestType != AttestTypeToken {
		t.Fatalf("缺省 attest_type 应为 token")
	}
}

func uint64Bytes(in []uint64) []byte {
	out := make([]byte, 0, len(in)*8)
	for _, v := range in {
		out = append(out, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return out
}
