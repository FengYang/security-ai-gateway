package main

// 插件侧远程证明会话管理（P1b 升级：会话承载 K_enc，段① 信封通道）。
//
// quote 模式（attest_mode=quote）：首次请求前发起挑战-响应握手：
// 1. POST /attest {nonce} → 证明载荷 + 服务端 ECDH 公钥
// 2. 验证证明链：nonce 回显 + report_data 绑定 H(nonce‖server_pub)（防握手公钥
//    替换/MITM，RA-TLS 标准做法）+ app_hash 比对 + 签名验证
// 3. 生成客户端 ECDH 密钥对 → POST /attest/complete
// 4. 派生会话 K_sig（协议签名）与 K_enc（段① 信封加密），后续请求：
//    - X-Session-ID 头 + 会话签名（K_sig）
//    - 请求体/响应体/SSE 分片整体入 AES-256-GCM 信封（K_enc，方向子密钥）
//
// token 模式（缺省，向后兼容）：沿用 X-Attest-Token MVP 凭证，明文南向协议（dev）。
//
// Wasm 环境限制：ECDH/X25519、ECDSA 验签与 AES-GCM 均为纯 Go 标准库（无 cgo），
// 可在 wasip1 编译。

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/higress-group/wasm-go/pkg/wrapper"
	logs "github.com/higress-group/wasm-go/pkg/log"

	"security-ai-gateway/protocol/go"
)

// attestSession 插件侧会话（进程级单例，跨请求复用）。
type attestSession struct {
	mu          sync.Mutex
	SessionID   string
	K_sig       []byte
	K_enc       []byte                     // 段① 信封加密密钥（P1b）
	sendCounter uint64                     // c2s 单调计数器（下一信封取值，从 1 起）
	recvWindow  protocol.CounterWindow     // s2c 反重放滑动窗口（key/issue 响应 + 推理响应 + SSE 分片共用）
	ExpiresAt   time.Time
}

// sessionTTL 会话有效期（与服务端 sessionTTL=5min 对齐，）。
const sessionTTL = 5 * time.Minute

// valid 会话是否有效（未过期，双密钥齐备）。
func (s *attestSession) valid() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.SessionID != "" && len(s.K_sig) == 32 && len(s.K_enc) == 32 && time.Now().Before(s.ExpiresAt)
}

// set 更新会话（重置计数器与反重放窗口——新会话 nonce 空间全新）。
func (s *attestSession) set(id string, kSig, kEnc []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SessionID = id
	s.K_sig = append([]byte(nil), kSig...)
	s.K_enc = append([]byte(nil), kEnc...)
	s.sendCounter = 1
	s.recvWindow = protocol.CounterWindow{}
	s.ExpiresAt = time.Now().Add(sessionTTL)
}

// clear 清除会话（密钥零化，best-effort：Go GC 下切片拷贝不可控，威胁模型如实声明）。
func (s *attestSession) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.K_sig {
		s.K_sig[i] = 0
	}
	for i := range s.K_enc {
		s.K_enc[i] = 0
	}
	s.SessionID = ""
	s.K_sig = nil
	s.K_enc = nil
	s.sendCounter = 0
	s.recvWindow = protocol.CounterWindow{}
}

// sealPayload 以会话 K_enc 加密 c2s 载荷（计数器单调递增保证 nonce 唯一）。
func (s *attestSession) sealPayload(endpoint string, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SessionID == "" || len(s.K_enc) != 32 {
		return nil, errors.New("envelope: 会话未建立或 K_enc 缺失")
	}
	counter := s.sendCounter
	s.sendCounter++
	return protocol.SealEnvelope(s.K_enc, s.SessionID, endpoint, protocol.DirectionC2S, counter, plaintext)
}

// openPayload 解密 s2c 信封并做反重放窗口校验（重放/越窗拒绝）。
func (s *attestSession) openPayload(endpoint string, wire []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SessionID == "" || len(s.K_enc) != 32 {
		return nil, errors.New("envelope: 会话未建立或 K_enc 缺失")
	}
	pt, counter, err := protocol.OpenEnvelope(s.K_enc, s.SessionID, endpoint, protocol.DirectionS2C, wire)
	if err != nil {
		return nil, err
	}
	if err := s.recvWindow.Check(counter); err != nil {
		return nil, err
	}
	return pt, nil
}

// Session 全局会话（进程级）。
var Session = &attestSession{}

// doAttestHandshake 挑战-响应握手（quote 模式）：
// attest → 验证链（含 report_data 绑定）→ complete → 派生会话 K_sig/K_enc。
// 完成后调用 onDone(sessionID, ksig, kenc)；任一失败调用 onFail(msg)。
func doAttestHandshake(config PluginConfig, log logs.Log, onDone func(id string, ksig, kenc []byte), onFail func(msg string)) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		onFail("生成 nonce 失败: " + err.Error())
		return
	}
	chalBody, _ := json.Marshal(map[string]string{"nonce": hex.EncodeToString(nonce)})

	client := wrapper.NewClusterClient(wrapper.FQDNCluster{
		FQDN: config.TEEService,
		Port: config.TEEPort,
	})
	err := client.Post("/attest", [][2]string{{"Content-Type", "application/json"}}, chalBody,
		func(statusCode int, _ http.Header, body []byte) {
			if statusCode != 200 {
				onFail(fmt.Sprintf("attest 返回 %d", statusCode))
				return
			}
			var ar struct {
				Status    string         `json:"status"`
				SessionID string         `json:"session_id"`
				ServerPub string         `json:"server_pub"`
				Proof     map[string]any `json:"proof"`
			}
			if err := json.Unmarshal(body, &ar); err != nil {
				onFail("解析 attest 响应失败: " + err.Error())
				return
			}
			serverPub, err := hex.DecodeString(ar.ServerPub)
			if err != nil {
				onFail("server_pub hex 解码失败")
				return
			}
			// 验证链（含 report_data = H(nonce‖server_pub) 绑定，防握手公钥替换）
			if err := verifyPluginProof(ar.Proof, nonce, serverPub, config.ExpectedAppHash); err != nil {
				onFail("证明链验证失败: " + err.Error())
				return
			}
			// 客户端 ECDH + 派生会话密钥
			clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				onFail("生成客户端密钥失败: " + err.Error())
				return
			}
			ksig, kenc, err := derivePluginSessionKey(clientPriv, serverPub, nonce)
			if err != nil {
				onFail("派生会话密钥失败: " + err.Error())
				return
			}
			// complete
			compBody, _ := json.Marshal(map[string]string{
				"session_id": ar.SessionID,
				"client_pub": hex.EncodeToString(clientPriv.PublicKey().Bytes()),
			})
			err = client.Post("/attest/complete", [][2]string{{"Content-Type", "application/json"}}, compBody,
				func(code int, _ http.Header, _ []byte) {
					if code != 200 {
						onFail(fmt.Sprintf("attest/complete 返回 %d", code))
						return
					}
					log.Infof("otpmask-plugin: 挑战-响应握手完成 session=%s（K_enc 通道就绪）", ar.SessionID[:8])
					onDone(ar.SessionID, ksig, kenc)
				}, 5000)
			if err != nil {
				onFail("调用 attest/complete 失败: " + err.Error())
			}
		}, 5000)
	if err != nil {
		onFail("调用 attest 失败: " + err.Error())
	}
}

// verifyPluginProof 插件侧证明链验证：
// 1. nonce 回显 == 客户挑战；
// 2. report_data == H(nonce ‖ server_pub)（绑定握手公钥，防 MITM 替换）；
// 3. app_hash == 期望测量值（配置时）；
// 4. 签名覆盖 (report_data ‖ signing_key)。
// 真实 TDX quote 下签名链根植 Intel CA（P3 验证 sidecar 完成）；mock 模式为开发占位。
func verifyPluginProof(proof map[string]any, challenge, serverPub []byte, expectedAppHash string) error {
	if proof == nil {
		return errors.New("attest: 空证明载荷")
	}
	nonceHex, _ := proof["nonce"].(string)
	gotNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return errors.New("attest: nonce 非 hex")
	}
	if subtle.ConstantTimeCompare(gotNonce, challenge) != 1 {
		return errors.New("attest: nonce 回显不匹配")
	}
	// report_data 绑定：H(nonce ‖ server_ephemeral_pub)
	wantReportData := reportDataBinding(challenge, serverPub)
	reportDataHex, _ := proof["report_data"].(string)
	gotReportData, err := hex.DecodeString(reportDataHex)
	if err != nil || len(gotReportData) == 0 {
		return errors.New("attest: 证明缺少 report_data")
	}
	if subtle.ConstantTimeCompare(gotReportData, wantReportData) != 1 {
		return errors.New("attest: report_data 与 H(nonce‖server_pub) 不匹配（疑似握手公钥被替换）")
	}
	measurements, _ := proof["measurements"].(map[string]any)
	if expectedAppHash != "" {
		gotHash, _ := measurements["app_hash"].(string)
		if !constTimeHexEq(gotHash, expectedAppHash) {
			return errors.New("attest: app_hash 与期望测量值不匹配")
		}
	}
	sigHex, _ := proof["signature"].(string)
	keyHex, _ := proof["signing_key"].(string)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("attest: signature 非 hex")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return errors.New("attest: signing_key 非 hex")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), key)
	if x == nil {
		return errors.New("attest: signing_key 非 P-256 公钥")
	}
	toSign := append(append([]byte(nil), gotReportData...), key...)
	h := sha256.Sum256(toSign)
	if len(sig) != 64 {
		return errors.New("attest: 签名长度须为 64")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("attest: 证明签名无效")
	}
	return nil
}

// reportDataBinding quote report_data 绑定材料：H(nonce ‖ server_pub)。
func reportDataBinding(nonce, serverPub []byte) []byte {
	h := sha256.New()
	h.Write(nonce)
	h.Write(serverPub)
	return h.Sum(nil)
}

// constTimeHexEq 常量时间 hex 比较。
func constTimeHexEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// derivePluginSessionKey 客户端派生会话密钥（与服务端对称，）。
func derivePluginSessionKey(clientPriv *ecdh.PrivateKey, serverPubBytes, nonce []byte) (ksig, kenc []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, nil, err
	}
	shared, err := clientPriv.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	sessionKey := pluginHKDF(shared, nonce, []byte("otpmask/session/v1"), 32)
	ksig = pluginKDF(sessionKey, "sig")
	kenc = pluginKDF(sessionKey, "enc")
	wipeBytes(shared)
	wipeBytes(sessionKey)
	return ksig, kenc, nil
}

// pluginKDF 从会话密钥派生用途密钥（sig/enc 域分离，）。
func pluginKDF(sessionKey []byte, purpose string) []byte {
	info := "otpmask/kdf/sig/v1"
	if purpose == "enc" {
		info = "otpmask/kdf/enc/v1"
	}
	return pluginHKDF(sessionKey, nil, []byte(info), 32)
}

// pluginHKDF HKDF-SHA256 最小实现（RFC 5869）。
func pluginHKDF(ikm, salt, info []byte, length int) []byte {
	prk := pluginHMAC(salt, ikm)
	out := make([]byte, 0, length)
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	wipeBytes(prk)
	return out[:length]
}

// pluginHMAC HMAC-SHA256。
func pluginHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// wipeBytes 清零敏感字节。
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
