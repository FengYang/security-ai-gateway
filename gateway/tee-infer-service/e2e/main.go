// Package main — tee-infer-service 端到端自检（M5-3 验收）。
//
// 流程：签发密钥 → 加密明文 → 签名请求 → /v1/infer → 验签响应 → 解密 → 断言 = 明文+7
//
// 运行：go run ./gateway/tee-infer-service/e2e
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
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

const (
	baseURL = "http://127.0.0.1:19090"
	R       = uint64(1) << 32
	delta   = 7
)

func main() {
	attestToken := "3031323334353637383961626364656630313233343536373839616263646566" // 与服务端 -attest-token 一致
	// 动态 requestID 避免防重放 seen 集合误杀（多次运行）
	requestID := fmt.Sprintf("self-check-%d", time.Now().UnixNano())

	// 1. 远程证明握手（MVP）
	attestReq, _ := http.NewRequest("POST", baseURL+"/attest", nil)
	attestReq.Header.Set("X-Attest-Token", attestToken)
	attestResp, err := http.DefaultClient.Do(attestReq)
	if err != nil {
		panic(err)
	}
	_ = attestResp.Body.Close()
	fmt.Printf("[0] attestation 握手 status=%d\n", attestResp.StatusCode)

	// 2. 签发密钥（带 attestation 令牌 + request_id）
	body := fmt.Sprintf(`{"model":"mock","request_id":%q}`, requestID)
	req, _ := http.NewRequest("POST", baseURL+"/key/issue", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Attest-Token", attestToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	var ki struct {
		Seed     string `json:"seed"`
		Nonce    string `json:"nonce"`
		MasterID uint64 `json:"master_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&ki)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("key/issue 失败: %d", resp.StatusCode))
	}
	seed, _ := hex.DecodeString(ki.Seed)
	nonce, _ := hex.DecodeString(ki.Nonce)
	fmt.Printf("[1] 密钥签发 req=%s master=%d\n", requestID, ki.MasterID)

	// 2. 加密明文（与插件同逻辑：mask.NewStream + 逐元素）
	plain := []uint64{100, 200, 300}
	s, _ := mask.NewStream(seed, R)
	cipher := make([]uint64, len(plain))
	for i, x := range plain {
		m := s.Next()
		cipher[i] = (x + m) % R
	}
	fmt.Printf("[2] 明文 %v -> 密文 %v\n", plain, cipher)

	// 3. 构造签名请求（K_sig 与服务端启动参数一致）
	kSig := []byte("0123456789abcdef0123456789abcdef")
	reqInfer := &protocol.InferenceRequest{
		RequestID:     requestID,
		TimestampNS:   time.Now().UnixNano(),
		Model:         "mock",
		MaxNewTokens:  16,
		Nonce:         nonce,
		CipherVectors: []protocol.CipherVector{{Data: cipher}},
	}
	cryptoops.SignRequest(kSig, reqInfer)
	enc, _ := protocol.EncodeRequest(reqInfer)

	// 4. 调用推理
	hr, err := http.Post(baseURL+"/v1/infer", "application/octet-stream", bytes.NewReader(enc))
	if err != nil {
		panic(err)
	}
	rb, _ := io.ReadAll(hr.Body)
	hr.Body.Close()
	if hr.StatusCode != 200 {
		fmt.Printf("[FAIL] infer 返回 %d: %s\n", hr.StatusCode, rb)
		return
	}
	iresp, err := protocol.DecodeResponse(rb)
	if err != nil {
		panic(err)
	}
	if !cryptoops.VerifyResponse(kSig, iresp) {
		fmt.Println("[FAIL] 响应签名无效")
		return
	}

	// 5. 解密断言
	s2, _ := mask.NewStream(seed, R)
	out := make([]uint64, len(iresp.CipherOutput.Data))
	for i, c := range iresp.CipherOutput.Data {
		m := s2.Next()
		out[i] = (c + R - m%R) % R
	}
	want := []uint64{107, 207, 307}
	fmt.Printf("[3] 解密输出 %v（期望 %v）\n", out, want)
	if out[0] == want[0] && out[1] == want[1] && out[2] == want[2] {
		fmt.Println("[PASS] 路径 A 端到端正确：签发→加密→签名→验签→解密推理→加密→验签→解密还原")
	} else {
		fmt.Println("[FAIL] 结果不一致")
	}
}
