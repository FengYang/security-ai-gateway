// cmd/route2-client —— 路线2（掩码像推理）端到端客户端编排器。
//
// 作用：补齐路线2 缺失的「客户端编排 + 线性层生产调用点」，让 Route 2 可在单机/云端
// 真正跑通一条完整前向：/attest → ECDH → /attest/complete → 逐层（掩码域线性 → /v1/recompute
// 非线性+重掩码）→ 末层 argmax。
//
// 关键契约（须与 gateway/tee-infer-service 逐位对齐）：
//   - 会话：ECDH(P-256) + KDF(intl=HKDF-SHA256)；K_sig/K_enc 与 session.go 对称；
//   - 掩码：seed = KDF(K_enc, nil, "otpmask/recompute-seed/v1", 32)；
//     第0层 domain = "otpmask/layer/0/v1"，r0[i] = stream.Next() % (2^64-1)；
//   - 线性：yCipher = W·V mod 2^64，W 由 route2demo 按 (layer,dim) 确定性重算（与服务端一致）；
//     优先走加速后端 AccelLinearInt128，不可用则回退 CipherLinearInt128；
//   - 补算：POST /v1/recompute（明文 JSON + HMAC(K_sig, Hash(canonical)) + X-Session-ID），
//     canonical = "req|layer|op|mask_version" + json(batch)。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/teecore/maskedinfer"
	"security-ai-gateway/gateway/teecore/route2demo"
)

const (
	route2MaskModulus uint64 = ^uint64(0) // 2^64-1（与 recompute.go route2MaskModulus 一致）
	sessionInfo              = "otpmask/session/v1"
	sigInfo                  = "otpmask/kdf/sig/v1"
	encInfo                  = "otpmask/kdf/enc/v1"
	seedInfo                 = "otpmask/recompute-seed/v1"
)

type proofWire struct {
	Nonce        string            `json:"nonce"`
	Platform     string            `json:"platform"`
	ReportData   string            `json:"report_data"`
	Measurements map[string]string `json:"measurements"`
	SigningKey   string            `json:"signing_key"`
	Signature    string            `json:"signature"`
}

type attestResp struct {
	Status    string    `json:"status"`
	Protocol  string    `json:"protocol"`
	SessionID string    `json:"session_id"`
	ServerPub string    `json:"server_pub"`
	Proof     proofWire `json:"proof"`
}

type recomputeReq struct {
	RequestID   string     `json:"request_id"`
	Layer       int        `json:"layer"`
	Op          string     `json:"op"`
	Batch       [][]uint64 `json:"batch"`
	MaskVersion int        `json:"mask_version"`
	Signature   string     `json:"signature"`
}

type recomputeResp struct {
	RequestID string     `json:"request_id"`
	Result    [][]uint64 `json:"result"`
	MaskNext  string     `json:"mask_next"`
	Signature string     `json:"signature"`
}

type client struct {
	base string
	http *http.Client
	p    cryptop.Provider
}

func main() {
	server := flag.String("server", "http://127.0.0.1:19090", "tee-infer-service 基地址")
	dim := flag.Int("dim", route2demo.DefaultDim, "向量维度（须与服务端一致，默认 32）")
	layers := flag.Int("layers", 4, "层数：前 layers-1 层 gelu，末层 argmax")
	input := flag.String("input", "", "输入向量（逗号分隔浮点）；空=确定性 ramp")
	flag.Parse()

	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		log.Fatalf("[route2-client] 初始化 cryptop(intl) 失败: %v", err)
	}
	c := &client{base: strings.TrimRight(*server, "/"), http: &http.Client{Timeout: 30 * time.Second}, p: p}

	if *dim != route2demo.DefaultDim {
		log.Printf("[route2-client] 警告：dim=%d 与服务端默认 %d 可能不一致（服务端 MaskImage 维度校验将失败）", *dim, route2demo.DefaultDim)
	}

	token, err := c.run(*dim, *layers, *input)
	if err != nil {
		log.Fatalf("[route2-client] 失败: %v", err)
	}
	fmt.Printf("[route2-client] 完成：token=%d\n", token)
}

// run 执行一条完整前向，返回末层 argmax 的 token。
func (c *client) run(dim, layers int, input string) (uint64, error) {
	if layers < 1 {
		return 0, fmt.Errorf("layers 必须 >= 1")
	}

	// 1) 挑战-响应证明 + 会话
	sessionID, serverPub, nonce, err := c.attest()
	if err != nil {
		return 0, fmt.Errorf("attest: %w", err)
	}
	clientPriv, clientPub, err := c.p.GenerateECDHKeyPair()
	if err != nil {
		return 0, fmt.Errorf("生成 ECDH 密钥: %w", err)
	}
	ksig, kenc, err := c.deriveKeys(clientPriv, serverPub, nonce)
	if err != nil {
		return 0, fmt.Errorf("派生会话密钥: %w", err)
	}
	if err := c.attestComplete(sessionID, clientPub); err != nil {
		return 0, fmt.Errorf("attest/complete: %w", err)
	}

	// 2) 掩码 seed + 第0层掩码流
	seed, err := c.p.KDF(kenc, nil, []byte(seedInfo), 32)
	if err != nil {
		return 0, fmt.Errorf("派生掩码 seed: %w", err)
	}
	stream0, err := mask.NewStreamDomain(seed, route2MaskModulus, []byte("otpmask/layer/0/v1"))
	if err != nil {
		return 0, fmt.Errorf("第0层掩码流: %w", err)
	}

	// 3) 第0层：V0 = ToMaskDomain(x0) + r0（Mod64 自然回绕）
	x0 := makeInput(dim, input)
	w0, err := route2demo.LayerWeights(0, dim)
	if err != nil {
		return 0, err
	}
	xMask := w0.ToMaskDomain(x0)
	r0 := make([]uint64, dim)
	for i := range r0 {
		r0[i] = stream0.Next() % route2MaskModulus
	}
	V := make([]uint64, dim)
	for i := range V {
		V[i] = xMask[i] + r0[i]
	}

	// 4) 逐层：线性（加速/CPU 回退）→ /v1/recompute →（非末层）用返回的掩码域结果作为下一层 V
	for L := 0; L < layers; L++ {
		w, err := route2demo.LayerWeights(L, dim)
		if err != nil {
			return 0, err
		}
		yCipher, err := c.linear(w, V)
		if err != nil {
			return 0, fmt.Errorf("layer %d 线性层: %w", L, err)
		}
		op := "gelu"
		if L == layers-1 {
			op = "argmax"
		}
		req := &recomputeReq{
			RequestID:   fmt.Sprintf("r2-%d-%d", time.Now().UnixNano(), L),
			Layer:       L,
			Op:          op,
			Batch:       [][]uint64{yCipher},
			MaskVersion: L,
		}
		resp, err := c.recompute(sessionID, ksig, req)
		if err != nil {
			return 0, fmt.Errorf("layer %d recompute: %w", L, err)
		}
		if op == "argmax" {
			if len(resp.Result) != 1 || len(resp.Result[0]) != 1 {
				return 0, fmt.Errorf("argmax 响应格式异常: %+v", resp.Result)
			}
			return resp.Result[0][0], nil
		}
		if len(resp.Result) != 1 || len(resp.Result[0]) != dim {
			return 0, fmt.Errorf("layer %d 补算结果维度异常: got %d", L, len(resp.Result[0]))
		}
		V = resp.Result[0]
	}
	return 0, fmt.Errorf("未产出 token（layers 配置异常）")
}

// attest 发起挑战并验证证明链（report_data 绑定 + ECDSA-P256 验签）。
func (c *client) attest() (sessionID string, serverPub, nonce []byte, err error) {
	nonce, err = c.p.Rand(32)
	if err != nil {
		return "", nil, nil, fmt.Errorf("生成 nonce: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"nonce": hex.EncodeToString(nonce)})
	resp, err := c.http.Post(c.base+"/attest", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, nil, fmt.Errorf("/attest 返回 %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	var ar attestResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", nil, nil, fmt.Errorf("解析 /attest: %w", err)
	}
	serverPub, err = hex.DecodeString(ar.ServerPub)
	if err != nil {
		return "", nil, nil, fmt.Errorf("server_pub 非 hex: %w", err)
	}
	if err := c.verifyProof(nonce, serverPub, &ar.Proof); err != nil {
		return "", nil, nil, err
	}
	return ar.SessionID, serverPub, nonce, nil
}

// verifyProof 校验：nonce 回显、report_data == H(nonce‖server_pub)、证明签名有效。
// app_hash 依赖具体飞地度量，demo 客户端不强制（留待生产接真实 Quote 时补）。
func (c *client) verifyProof(nonce, serverPub []byte, pw *proofWire) error {
	if pw == nil || pw.ReportData == "" || pw.SigningKey == "" || pw.Signature == "" {
		return fmt.Errorf("证明载荷不完整")
	}
	if pw.Nonce != "" && pw.Nonce != hex.EncodeToString(nonce) {
		return fmt.Errorf("证明 nonce 回显不一致")
	}
	rd, err := hex.DecodeString(pw.ReportData)
	if err != nil {
		return fmt.Errorf("report_data 非 hex: %w", err)
	}
	h := sha256.New()
	h.Write(nonce)
	h.Write(serverPub)
	if !hmac.Equal(rd, h.Sum(nil)) {
		return fmt.Errorf("report_data 与 H(nonce‖server_pub) 不匹配（疑似公钥被替换）")
	}
	sk, err := hex.DecodeString(pw.SigningKey)
	if err != nil {
		return fmt.Errorf("signing_key 非 hex: %w", err)
	}
	sig, err := hex.DecodeString(pw.Signature)
	if err != nil {
		return fmt.Errorf("signature 非 hex: %w", err)
	}
	toSign := append(append([]byte(nil), rd...), sk...)
	if err := cryptop.VerifyP256(sk, toSign, sig); err != nil {
		return fmt.Errorf("证明验签失败: %w", err)
	}
	return nil
}

func (c *client) deriveKeys(clientPriv, serverPub, nonce []byte) (ksig, kenc []byte, err error) {
	shared, err := c.p.ECDH(clientPriv, serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	sessionKey, err := c.p.KDF(shared, nonce, []byte(sessionInfo), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("会话密钥 KDF: %w", err)
	}
	ksig, err = c.p.KDF(sessionKey, nil, []byte(sigInfo), 32)
	if err != nil {
		return nil, nil, err
	}
	kenc, err = c.p.KDF(sessionKey, nil, []byte(encInfo), 32)
	if err != nil {
		return nil, nil, err
	}
	return ksig, kenc, nil
}

func (c *client) attestComplete(sessionID string, clientPub []byte) error {
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"client_pub": hex.EncodeToString(clientPub),
	})
	resp, err := c.http.Post(c.base+"/attest/complete", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/attest/complete 返回 %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	return nil
}

// linear 计算 yCipher = W·V（batch=1）。优先加速后端，不可用回退 CPU 128 位内核。
func (c *client) linear(m *maskedinfer.QuantizedMatrix, V []uint64) ([]uint64, error) {
	batch := [][]uint64{V}
	out, err := m.AccelLinearInt128(batch)
	if err == nil {
		return out[0], nil
	}
	// ErrAccelUnavailable（未配置/加载失败/调用失败）→ 回退 CPU 路径
	cpu, cerr := m.CipherLinearInt128(batch)
	if cerr != nil {
		return nil, fmt.Errorf("加速后端不可用(%v)且 CPU 回退失败: %w", err, cerr)
	}
	return cpu[0], nil
}

func (c *client) recompute(sessionID string, ksig []byte, req *recomputeReq) (*recomputeResp, error) {
	canon := c.canonical(req)
	req.Signature = hex.EncodeToString(c.p.HMAC(ksig, canon))
	body, _ := json.Marshal(req)
	hr, err := http.NewRequest(http.MethodPost, c.base+"/v1/recompute", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("X-Session-ID", sessionID)
	resp, err := c.http.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/v1/recompute 返回 %d: %s", resp.StatusCode, readBody(resp.Body))
	}
	var rr recomputeResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, fmt.Errorf("解析 /v1/recompute: %w", err)
	}
	return &rr, nil
}

// canonical 与服务端 recomputeCanonical 逐字节一致。
func (c *client) canonical(r *recomputeReq) []byte {
	buf := []byte(fmt.Sprintf("%s|%d|%s|%d", r.RequestID, r.Layer, r.Op, r.MaskVersion))
	bj, _ := json.Marshal(r.Batch)
	buf = append(buf, bj...)
	return c.p.Hash(buf)
}

func makeInput(dim int, spec string) []float64 {
	if strings.TrimSpace(spec) == "" {
		x := make([]float64, dim)
		for i := range x {
			x[i] = (float64(i) - float64(dim)/2) * 0.05
		}
		return x
	}
	parts := strings.Split(spec, ",")
	x := make([]float64, 0, len(parts))
	for _, s := range parts {
		var v float64
		fmt.Sscanf(strings.TrimSpace(s), "%f", &v)
		x = append(x, v)
	}
	return x
}

func readBody(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return string(b)
}

func init() {
	// 便于容器日志即时可见
	log.SetOutput(os.Stderr)
}
