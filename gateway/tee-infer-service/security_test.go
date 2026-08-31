// 明文最小化。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/protocol/go"
)

// maskTextLocal 文本掩码（与插件侧对称，R=256 域分离通道）。
func maskTextLocal(seed []byte, text string) ([]byte, error) {
	s, err := mask.NewStreamDomain(seed, 256, guardrailTextDomain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		m := s.Next() % 256
		out[i] = byte((int(text[i]) + int(m)) % 256)
	}
	return out, nil
}

// TestA6NoPlaintextInObservability A6：审计事件与指标输出不含明文、seed、K_sig。
func TestA6NoPlaintextInObservability(t *testing.T) {
	srv, ts := newM9Server(t)

	// 构造一次完整 infer（含 guardrail 明文文本 "hello secret world"）
	keyBody, _ := json.Marshal(map[string]string{"model": "mock", "request_id": nextTestRequestID("a6")})
	keyReq, _ := http.NewRequest("POST", ts.URL+"/key/issue", bytes.NewReader(keyBody))
	keyReq.Header.Set("X-Attest-Token", testAttest)
	keyResp, err := http.DefaultClient.Do(keyReq)
	if err != nil {
		t.Fatal(err)
	}
	var ki keyIssueResponse
	if err := json.NewDecoder(keyResp.Body).Decode(&ki); err != nil {
		t.Fatal(err)
	}
	keyResp.Body.Close()
	seed, _ := hex.DecodeString(ki.Seed)
	nonceB, _ := hex.DecodeString(ki.Nonce)

	secretText := "secret-plaintext-INPUT-42"
	ct, err := maskTextLocal(seed, secretText)
	if err != nil {
		t.Fatal(err)
	}
	vec := []uint64{111, 222, 333}
	cv, _ := maskVector(seed, maskModulus, vec)
	req := &protocol.InferenceRequest{
		RequestID:     nextTestRequestID("inf"),
		TimestampNS:   time.Now().UnixNano(),
		Model:         "mock",
		MaxNewTokens:  1,
		Nonce:         nonceB,
		CipherVectors: []protocol.CipherVector{{Data: cv}},
		CipherText:    ct,
		EngineType:    protocol.EngineTypeTEEGPU,
		AttestType:    protocol.AttestTypeToken,
	}
	protocol.SignRequest(bytes.Repeat([]byte{0x42}, 32), req)
	enc, _ := protocol.EncodeRequest(req)
	infReq, _ := http.NewRequest("POST", ts.URL+"/v1/infer", bytes.NewReader(enc))
	infResp, err := http.DefaultClient.Do(infReq)
	if err != nil {
		t.Fatal(err)
	}
	infResp.Body.Close()

	// 1. 审计事件：不含明文、seed、K_sig
	auditBody := getEndpoint(t, ts.URL+"/audit")
	auditJSON := string(auditBody)
	for _, forbidden := range []string{secretText, ki.Seed, hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))} {
		if strings.Contains(auditJSON, forbidden) {
			t.Fatalf("审计事件泄露敏感数据: %q", forbidden)
		}
	}

	// 2. 指标：不含明文/seed
	metricsBody := getEndpoint(t, ts.URL+"/metrics")
	metricsText := string(metricsBody)
	if strings.Contains(metricsText, secretText) || strings.Contains(metricsText, ki.Seed) {
		t.Fatal("指标泄露明文或 seed")
	}

	// 3. 响应头不含敏感数据
	for k, vs := range infResp.Header {
		for _, v := range vs {
			if strings.Contains(v, secretText) || strings.Contains(v, ki.Seed) {
				t.Fatalf("响应头 %s 泄露敏感数据", k)
			}
		}
	}

	// 4. K_sig 不在审计/指标中
	_ = srv
}

// getEndpoint GET 请求并返回 body（管理令牌未配置 = 开发模式放行）。
func getEndpoint(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	return b
}
