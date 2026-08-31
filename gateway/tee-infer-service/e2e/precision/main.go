// Package main — 精度对照实验（M7-3）：密态推理 vs 明文推理一致性。
//
// 验收标准：OTP-Mask 掩码 + TEE 解密为无损变换，密态推理输出与明文推理
// 输出必须完全一致（对应技术方案"精度损失 < 1%，演示模型下 0% 损失"）。
//
// 方法：
// 明文路径：embedding 向量 → model.Predict（直接推理，不经加密）
// 密态路径：向量 → OTP 加密 → TEE /v1/infer（解密+推理）→ 解密响应 → token
// 断言：两条路径 token ID 一致
//
// 运行：go run ./gateway/tee-infer-service/e2e/precision
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/tee-infer-service/model"
	"security-ai-gateway/protocol/go"
)

const (
	embedURL   = "http://127.0.0.1:18080/embed"
	attestURL  = "http://127.0.0.1:19090/attest"
	keyURL     = "http://127.0.0.1:19090/key/issue"
	inferURL   = "http://127.0.0.1:19090/v1/infer"
	attestTok = "3031323334353637383961626364656630313233343536373839616263646566" // 与 docker-compose -attest-token 一致
	sigKeyHex = "3031323334353637383961626364656630313233343536373839616263646566"
	R          = uint64(1) << 32
)

func main() {
	// 1. 取明文向量（embedding-service）
	eb, _ := json.Marshal(map[string]string{"text": "precision check"})
	er, _ := http.Post(embedURL, "application/json", bytes.NewReader(eb))
	var eresp struct {
		Vectors [][]uint64 `json:"vectors"`
	}
	_ = json.NewDecoder(er.Body).Decode(&eresp)
	er.Body.Close()
	plainVec := eresp.Vectors[0]
	fmt.Printf("[1] 明文向量 dim=%d 前3=%v\n", len(plainVec), plainVec[:3])

	// 2. 明文推理（直接 Predict）
	m := model.New()
	plainToken := m.Predict(toFloat(plainVec))
	fmt.Printf("[2] 明文推理 token=%d (%c)\n", plainToken, model.TokenToRune(plainToken))

	// 3. 密态路径：密钥 → 加密 → TEE 推理
	kSig, _ := hex.DecodeString(sigKeyHex)
	// 动态 requestID 避免防重放 seen 集合误杀（多次运行）
	reqID := fmt.Sprintf("precision-%d", time.Now().UnixNano())

	// attestation
	attestReq, _ := http.NewRequest("POST", attestURL, nil)
	attestReq.Header.Set("X-Attest-Token", attestTok)
	attestResp, _ := http.DefaultClient.Do(attestReq)
	attestResp.Body.Close()

	// key/issue
	kb, _ := json.Marshal(map[string]string{"model": "mock", "request_id": reqID})
	keyReq, _ := http.NewRequest("POST", keyURL, bytes.NewReader(kb))
	keyReq.Header.Set("Content-Type", "application/json")
	keyReq.Header.Set("X-Attest-Token", attestTok)
	keyResp, _ := http.DefaultClient.Do(keyReq)
	var ki struct {
		Seed  string `json:"seed"`
		Nonce string `json:"nonce"`
	}
	_ = json.NewDecoder(keyResp.Body).Decode(&ki)
	keyResp.Body.Close()
	seed, _ := hex.DecodeString(ki.Seed)
	nonce, _ := hex.DecodeString(ki.Nonce)

	// 加密
	s, err := mask.NewStream(seed, R)
	if err != nil {
		panic(fmt.Sprintf("NewStream: %v (seed len=%d)", err, len(seed)))
	}
	cipher := make([]uint64, len(plainVec))
	for i, x := range plainVec {
		cipher[i] = (x + s.Next()) % R
	}

	// 南向协议请求（签名）
	infReq := &protocol.InferenceRequest{
		RequestID: reqID, TimestampNS: time.Now().UnixNano(),
		Model: "mock", MaxNewTokens: 1, Nonce: nonce,
		CipherVectors: []protocol.CipherVector{{Data: cipher}},
	}
	protocol.SignRequest(kSig, infReq)
	enc, _ := protocol.EncodeRequest(infReq)
	infResp, err := http.Post(inferURL, "application/x-otpmask", bytes.NewReader(enc))
	if err != nil {
		panic(err)
	}
	rb, _ := io.ReadAll(infResp.Body)
	infResp.Body.Close()
	iresp, err := protocol.DecodeResponse(rb)
	if err != nil {
		panic(err)
	}
	if !protocol.VerifyResponse(kSig, iresp) {
		panic("响应签名无效")
	}

	// 解密响应 → token
	s2, err := mask.NewStream(seed, R)
	if err != nil {
		panic(err)
	}
	dec := (iresp.CipherOutput.Data[0] + R - s2.Next()%R) % R
	cipherToken := int(dec)
	fmt.Printf("[3] 密态推理 token=%d (%c)\n", cipherToken, model.TokenToRune(cipherToken))

	// 4. 断言一致性
	if plainToken == cipherToken {
		fmt.Printf("[PASS] 精度对照：密态 == 明文 token=%d (%c)，OTP-Mask 无损 ✅\n",
			plainToken, model.TokenToRune(plainToken))
	} else {
		fmt.Printf("[FAIL] 密态 %d != 明文 %d\n", cipherToken, plainToken)
	}
}

func toFloat(v []uint64) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = float64(x) / 1e6
	}
	return out
}
