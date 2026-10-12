package main

// 插件侧远程证明会话管理（P0-4 零密码改造：会话只持 **KeyRef**，密码求值全部经 cryptop sidecar）。
//
// quote 模式（attest_mode=quote）：首次请求前发起挑战-响应握手：
// 1. POST /attest {nonce} → 证明载荷 + 服务端 ECDH 公钥（nonce 由 sidecar /v1/rand 生成）
// 2. 验证证明链（全部经 sidecar）：
//      nonce 回显（本地比较，公开值）
//      report_data == /v1/hash(nonce‖server_pub)（绑定握手公钥，防 MITM 替换）
//      app_hash 比对（公开值）+ 签名验证 /v1/verify(alg="p256")（§5.4.2 例外）
// 3. 客户端 ECDH + 会话密钥派生在 **sidecar /v1/session/begin** 内完成，返回 3 个值：
//      KeyRef_sig / KeyRef_enc（**密钥字节不出 sidecar**，C-5/R-11）+ client_pub（转交 TEE）
// 4. 信封方向子密钥（K_enc → c2s/s2c）经 **/v1/kdf** 派生两个**子 KeyRef**
//      （info=otpmask/kdf/enc/{c2s,s2c}/v1，alias=<key_ref_enc>/<dir>；R8-P1-1）
// 5. 后续请求：
//      - X-Session-ID 头 + 会话签名（KeyRef_sig → /v1/hmac）
//      - 请求体/响应体/SSE 分片整体入 AEAD 信封（方向子 KeyRef → /v1/seal | /v1/open）
//
// token 模式（缺省，向后兼容）：沿用 X-Attest-Token MVP 凭证，明文南向协议（dev）。
//
// **零密码约束（C-1/C-5/R-11）**：本文件不含任何 `crypto/*` / `cryptoops` 链接；
// 所有 HMAC/AEAD/HKDF/ECDH/验签均经 `CryptoClient`（cryptop sidecar 唯一 HTTP 面，§4.7）。

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
	"security-ai-gateway/protocol/go"
)

// 会话方向子密钥 KeyRef 确定性后缀（§4.3.6；须与 sidecar `subkeySuffix*` 一致，T-5.4-6）。
const (
	subkeySuffixC2S = "/c2s"
	subkeySuffixS2C = "/s2c"
)

// fail-closed 错误（C-4：sidecar 未就绪/会话缺失一律拒绝，无本地回退）。
var (
	errCryptoUnavailable = errors.New("envelope: cryptop sidecar 未就绪（C-4/R-11）")
	errSessionMissing    = errors.New("envelope: 会话未建立（无 KeyRef）")
)

// attestSession 插件侧会话（进程级单例，跨请求复用）。
//
// 只持有 **KeyRef**（不透明句柄）与计数状态——密钥字节恒驻 sidecar（C-5）。
type attestSession struct {
	mu          sync.Mutex
	SessionID   string
	SigRef      cryptoclient.KeyRef // 协议签名密钥句柄（/v1/hmac）
	EncRef      cryptoclient.KeyRef // 原始 K_enc 句柄（方向子密钥之母，session/end 一并销毁）
	C2SRef      cryptoclient.KeyRef // c2s 方向子密钥句柄（信封加密 /v1/seal）
	S2CRef      cryptoclient.KeyRef // s2c 方向子密钥句柄（信封解密 /v1/open）
	sendCounter uint64                 // c2s 单调计数器（下一信封取值，从 1 起）
	recvWindow  protocol.CounterWindow // s2c 反重放滑动窗口（key/issue 响应 + 推理响应 + SSE 分片共用）
	ExpiresAt   time.Time
}

// sessionTTL 会话有效期（与服务端 sessionTTL=5min 对齐）。
const sessionTTL = 5 * time.Minute

// valid 会话是否有效（未过期，四 KeyRef 齐备）。
func (s *attestSession) valid() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.SessionID != "" && s.SigRef != "" && s.EncRef != "" && s.C2SRef != "" && s.S2CRef != "" &&
		time.Now().Before(s.ExpiresAt)
}

// sigRefValid 取有效会话的签名 KeyRef（无会话/过期返回空串，供签名调用点 fail-closed 判定）。
func (s *attestSession) sigRefValid() cryptoclient.KeyRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SessionID == "" || s.SigRef == "" || time.Now().After(s.ExpiresAt) {
		return ""
	}
	return s.SigRef
}

// set 更新会话（重置计数器与反重放窗口——新会话 nonce 空间全新）。
func (s *attestSession) set(id string, sigRef, encRef, c2sRef, s2cRef cryptoclient.KeyRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SessionID = id
	s.SigRef, s.EncRef, s.C2SRef, s.S2CRef = sigRef, encRef, c2sRef, s2cRef
	s.sendCounter = 1
	s.recvWindow = protocol.CounterWindow{}
	s.ExpiresAt = time.Now().Add(sessionTTL)
}

// clear 清除会话并发起 session/end（best-effort 销毁 sidecar 内 4 个 KeyRef：sig/enc + 2 方向子密钥，
// 令 §10.1 #6 会话密钥净值归零，T-5.4-6）。密钥字节已驻 sidecar，插件侧无需零化。
func (s *attestSession) clear() {
	s.mu.Lock()
	sigRef, encRef := s.SigRef, s.EncRef
	s.SessionID = ""
	s.SigRef, s.EncRef, s.C2SRef, s.S2CRef = "", "", "", ""
	s.sendCounter = 0
	s.recvWindow = protocol.CounterWindow{}
	s.mu.Unlock()
	if CryptoClient != nil && (sigRef != "" || encRef != "") {
		CryptoClient.SessionEnd(sigRef, encRef, func(error) {}) // #8（best-effort）
	}
}

// sealPayload 以会话 c2s 方向子密钥加密载荷（计数器单调递增保证 nonce 唯一）。
// CPS 交付（proxy-wasm 无阻塞 HTTP，§4.7）：cb(wire, err)。
func (s *attestSession) sealPayload(endpoint string, plaintext []byte, cb func(wire []byte, err error)) {
	if !cryptoUsable() {
		cb(nil, errCryptoUnavailable)
		return
	}
	s.mu.Lock()
	if s.SessionID == "" || s.C2SRef == "" {
		s.mu.Unlock()
		cb(nil, errSessionMissing)
		return
	}
	counter := s.sendCounter
	s.sendCounter++
	sid, ref := s.SessionID, s.C2SRef
	s.mu.Unlock()
	aad := protocol.EnvelopeAAD(sid, protocol.DirectionC2S, counter, endpoint)
	nonce := protocol.EnvelopeNonce(counter)
	CryptoClient.Seal(ref, aad, nonce, plaintext, func(_, ct []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		wire, e := protocol.EncodeEnvelope(&protocol.Envelope{
			Version:    protocol.EnvelopeVersion,
			Suite:      cryptoSuite,
			Direction:  protocol.DirectionC2S,
			Counter:    counter,
			Ciphertext: ct,
		})
		if e != nil {
			cb(nil, e)
			return
		}
		cb(wire, nil)
	})
}

// openPayload 解密 s2c 信封并做反重放窗口校验（重放/越窗拒绝）。
// CPS 交付：cb(pt, err)。顺序与既有同步实现一致：先 AEAD 解封，成功后再 Check 窗口。
func (s *attestSession) openPayload(endpoint string, wire []byte, cb func(pt []byte, err error)) {
	if !cryptoUsable() {
		cb(nil, errCryptoUnavailable)
		return
	}
	// 信封 framing 校验（插件侧显式，DecodeEnvelope 为纯 framing 不做版本/方向/suite 校验）
	env, err := protocol.DecodeEnvelope(wire)
	if err != nil {
		cb(nil, err)
		return
	}
	if env.Version != protocol.EnvelopeVersion {
		cb(nil, fmt.Errorf("envelope: 版本不符（got=%d want=%d）", env.Version, protocol.EnvelopeVersion))
		return
	}
	if env.Direction != protocol.DirectionS2C {
		cb(nil, fmt.Errorf("envelope: 方向不符（期望 s2c，got=%d）", byte(env.Direction)))
		return
	}
	if env.Suite != cryptoSuite {
		cb(nil, fmt.Errorf("envelope: suite 不符（got=%d want=%d）", env.Suite, cryptoSuite))
		return
	}
	s.mu.Lock()
	if s.SessionID == "" || s.S2CRef == "" {
		s.mu.Unlock()
		cb(nil, errSessionMissing)
		return
	}
	sid, ref := s.SessionID, s.S2CRef
	s.mu.Unlock()
	aad := protocol.EnvelopeAAD(sid, protocol.DirectionS2C, env.Counter, endpoint)
	nonce := protocol.EnvelopeNonce(env.Counter)
	CryptoClient.Open(ref, aad, nonce, env.Ciphertext, func(pt []byte, oerr error) {
		if oerr != nil {
			cb(nil, oerr)
			return
		}
		s.mu.Lock()
		werr := s.recvWindow.Check(env.Counter)
		s.mu.Unlock()
		if werr != nil {
			cb(nil, werr)
			return
		}
		cb(pt, nil)
	})
}

// batchOpenPayloads 批量解密 s2c 信封（一次 /v1/batch 解多帧），顺序做反重放窗口校验。
//
// 安全语义与 openPayload 等价：任一帧解密失败 / 版本/方向/suite 不符 / 反重放窗口拒绝
// → 该帧索引的 err 非 nil；调用方负责 fail-closed（整批中任一失败则整流拒绝）。
// 窗口校验按 wires 原始顺序依次执行（与逐帧模式顺序一致，保证窗口状态机等价）。
//
// CPS 交付：cb(results, overallErr)。overallErr 非 nil = 批整体失败（熔断/传输/解码）；
// results 与 wires 等长，逐帧给出 pt/err。
func (s *attestSession) batchOpenPayloads(endpoint string, wires [][]byte, cb func(results []batchOpenResult, overallErr error)) {
	if !cryptoUsable() {
		cb(nil, errCryptoUnavailable)
		return
	}
	n := len(wires)
	if n == 0 {
		cb(nil, nil)
		return
	}

	// 第一步：每帧做 framing/version/direction/suite 预校验，构造 batch ops
	type validatedFrame struct {
		env       *protocol.Envelope
		aad       []byte
		nonce     []byte
		ciphertext []byte
	}
	validated := make([]validatedFrame, n)
	for i, wire := range wires {
		env, err := protocol.DecodeEnvelope(wire)
		if err != nil {
			cb(nil, fmt.Errorf("envelope[%d]: framing 失败: %w", i, err))
			return
		}
		if env.Version != protocol.EnvelopeVersion {
			cb(nil, fmt.Errorf("envelope[%d]: 版本不符（got=%d want=%d）", i, env.Version, protocol.EnvelopeVersion))
			return
		}
		if env.Direction != protocol.DirectionS2C {
			cb(nil, fmt.Errorf("envelope[%d]: 方向不符（期望 s2c，got=%d）", i, byte(env.Direction)))
			return
		}
		if env.Suite != cryptoSuite {
			cb(nil, fmt.Errorf("envelope[%d]: suite 不符（got=%d want=%d）", i, env.Suite, cryptoSuite))
			return
		}
		validated[i] = validatedFrame{env: env, ciphertext: env.Ciphertext}
	}

	s.mu.Lock()
	if s.SessionID == "" || s.S2CRef == "" {
		s.mu.Unlock()
		cb(nil, errSessionMissing)
		return
	}
	sid, ref := s.SessionID, s.S2CRef
	s.mu.Unlock()

	// 构造 batch ops（每帧 aad/nonce 派生）
	ops := make([]cryptoclient.Op, n)
	for i := 0; i < n; i++ {
		v := &validated[i]
		v.aad = protocol.EnvelopeAAD(sid, protocol.DirectionS2C, v.env.Counter, endpoint)
		v.nonce = protocol.EnvelopeNonce(v.env.Counter)
		ops[i] = cryptoclient.Op{
			ID: strconv.Itoa(i),
			Op: cryptoclient.OpOpen,
			Payload: map[string]any{
				"key_ref":    string(ref),
				"aad":        b64str(v.aad),
				"nonce":      b64str(v.nonce),
				"ciphertext": b64str(v.ciphertext),
			},
		}
	}

	// 调一次 /v1/batch
	CryptoClient.Batch(ops, func(bresults []cryptoclient.OpResult, berr error) {
		if berr != nil {
			cb(nil, fmt.Errorf("envelope batch: %w", berr))
			return
		}
		// 按 id 重排为原始顺序
		sorted := make([]cryptoclient.OpResult, n)
		seen := 0
		for _, r := range bresults {
			idx, cerr := strconv.Atoi(r.ID)
			if cerr != nil || idx < 0 || idx >= n {
				continue
			}
			sorted[idx] = r
			seen++
		}
		if seen != n {
			cb(nil, fmt.Errorf("envelope batch: 结果数量不匹配（got %d want %d）", seen, n))
			return
		}

		// 顺序交付：先做窗口校验（与逐帧模式状态机等价），再组装结果
		results := make([]batchOpenResult, n)
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := 0; i < n; i++ {
			r := sorted[i]
			if r.Error != nil {
				results[i] = batchOpenResult{Err: r.Error}
				continue
			}
			ptStr, ok := r.Fields["plaintext"].(string)
			if !ok {
				results[i] = batchOpenResult{Err: fmt.Errorf("envelope batch[%d]: 响应缺 plaintext", i)}
				continue
			}
			pt, derr := unb64(ptStr)
			if derr != nil {
				results[i] = batchOpenResult{Err: fmt.Errorf("envelope batch[%d]: plaintext base64 失败: %w", i, derr)}
				continue
			}
			// 反重放窗口校验（顺序执行，与逐帧模式一致）
			if werr := s.recvWindow.Check(validated[i].env.Counter); werr != nil {
				results[i] = batchOpenResult{Err: werr}
				continue
			}
			results[i] = batchOpenResult{Pt: pt}
		}
		cb(results, nil)
	})
}

// batchOpenResult 单帧批量解密结果。
type batchOpenResult struct {
	Pt  []byte // 明文（成功时）
	Err error  // 该帧错误（失败时）
}

// b64str base64 编码（attest 内辅助）。
func b64str(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// unb64 base64 解码（attest 内辅助）。
func unb64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// Session 全局会话（进程级）。
var Session = &attestSession{}

// peerPubAlg 会话 ECDH 对端公钥算法（§4.3.8：intl→x25519，sm→sm2）。
func peerPubAlg() string {
	if cryptoProfile == "intl" {
		return "x25519"
	}
	return "sm2"
}

// doAttestHandshake 挑战-响应握手（quote 模式）：
// attest → 验证链（经 sidecar）→ session/begin → 方向子密钥派生 → complete。
// 完成后调用 onDone(sessionID, sigRef, encRef, c2sRef, s2cRef)；任一失败调用 onFail(msg)。
func doAttestHandshake(config PluginConfig, log logs.Log,
	onDone func(id string, sigRef, encRef, c2sRef, s2cRef cryptoclient.KeyRef),
	onFail func(msg string)) {
	if !cryptoUsable() {
		onFail("cryptop sidecar 未就绪（C-4/R-11）")
		return
	}
	CryptoClient.Rand(32, func(nonce []byte, err error) {
		if err != nil {
			onFail("生成 nonce 失败: " + err.Error())
			return
		}
		chalBody, _ := json.Marshal(map[string]string{"nonce": hex.EncodeToString(nonce)})
		client := wrapper.NewClusterClient(wrapper.FQDNCluster{
			FQDN: config.TEEService,
			Port: config.TEEPort,
		})
		err = client.Post("/attest", [][2]string{{"Content-Type", "application/json"}}, chalBody,
			func(statusCode int, _ http.Header, body []byte) {
				if statusCode != 200 {
					onFail(fmt.Sprintf("attest 返回 %d", statusCode))
					return
				}
				var ar attestResponse
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
				// 双路径：配置了 attest_verify_service → 走 sidecar（完整验证链）；
				//        未配置 → 走原 CryptoClient 验签路径（行为与改造前完全一致）。
				if config.AttestVerifyService != "" {
					verifyPluginProofViaSidecar(config, ar.Proof, nonce, serverPub, func(verr error) {
						if verr != nil {
							onFail("证明链验证失败（sidecar）: " + verr.Error())
							return
						}
						continueHandshake(config, log, ar, nonce, serverPub, client, onDone, onFail)
					})
				} else {
					verifyPluginProof(ar.Proof, nonce, serverPub, config.ExpectedAppHash, func(verr error) {
						if verr != nil {
							onFail("证明链验证失败: " + verr.Error())
							return
						}
						continueHandshake(config, log, ar, nonce, serverPub, client, onDone, onFail)
					})
				}
			}, 5000)
		if err != nil {
			onFail("调用 attest 失败: " + err.Error())
		}
	})
}

// deriveDirSubkeys 从原始 K_enc KeyRef 派生 c2s/s2c 方向子密钥 KeyRef（R8-P1-1 / §4.3.6）。
// alias 取 `<key_ref_enc>/<dir>`——与 sidecar `session/end` 的销毁前缀一致（T-5.4-6）。
func deriveDirSubkeys(encRef cryptoclient.KeyRef, cb func(c2s, s2c cryptoclient.KeyRef, err error)) {
	CryptoClient.KDF(encRef, nil, protocol.EnvelopeSubkeyInfo(protocol.DirectionC2S), 32,
		string(encRef)+subkeySuffixC2S, func(c2s cryptoclient.KeyRef, err error) {
			if err != nil {
				cb("", "", err)
				return
			}
			CryptoClient.KDF(encRef, nil, protocol.EnvelopeSubkeyInfo(protocol.DirectionS2C), 32,
				string(encRef)+subkeySuffixS2C, func(s2c cryptoclient.KeyRef, err error) {
					if err != nil {
						cb("", "", err)
						return
					}
					cb(c2s, s2c, nil)
				})
		})
}

// verifyPluginProof 插件侧证明链验证（全部经 sidecar，CPS）：
//  1. nonce 回显 == 客户挑战（公开值，本地 bytes.Equal）；
//  2. report_data == /v1/hash(nonce ‖ server_pub)（绑定握手公钥，防 MITM 替换）；
//  3. app_hash == 期望测量值（配置时；公开值比较）；
//  4. 签名覆盖 (report_data ‖ signing_key)（/v1/verify alg="p256"，§5.4.2 例外：TDX quote 恒 P-256）。
//
// 真实 TDX quote 下签名链根植 Intel CA（P3 验证 sidecar 完成）；mock 模式为开发占位。
func verifyPluginProof(proof map[string]any, challenge, serverPub []byte, expectedAppHash string, done func(err error)) {
	if proof == nil {
		done(errors.New("attest: 空证明载荷"))
		return
	}
	nonceHex, _ := proof["nonce"].(string)
	gotNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		done(errors.New("attest: nonce 非 hex"))
		return
	}
	if !bytes.Equal(gotNonce, challenge) {
		done(errors.New("attest: nonce 回显不匹配"))
		return
	}
	// report_data 绑定：H(nonce ‖ server_ephemeral_pub)（经 /v1/hash，插件不持哈希原语）
	rdInput := make([]byte, 0, len(challenge)+len(serverPub))
	rdInput = append(rdInput, challenge...)
	rdInput = append(rdInput, serverPub...)
	CryptoClient.Hash(rdInput, func(wantReportData []byte, herr error) {
		if herr != nil {
			done(herr)
			return
		}
		reportDataHex, _ := proof["report_data"].(string)
		gotReportData, err := hex.DecodeString(reportDataHex)
		if err != nil || len(gotReportData) == 0 {
			done(errors.New("attest: 证明缺少 report_data"))
			return
		}
		if !bytes.Equal(gotReportData, wantReportData) {
			done(errors.New("attest: report_data 与 H(nonce‖server_pub) 不匹配（疑似握手公钥被替换）"))
			return
		}
		measurements, _ := proof["measurements"].(map[string]any)
		if expectedAppHash != "" {
			gotHash, _ := measurements["app_hash"].(string)
			if !hexEq(gotHash, expectedAppHash) {
				done(errors.New("attest: app_hash 与期望测量值不匹配"))
				return
			}
		}
		sigHex, _ := proof["signature"].(string)
		keyHex, _ := proof["signing_key"].(string)
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			done(errors.New("attest: signature 非 hex"))
			return
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			done(errors.New("attest: signing_key 非 hex"))
			return
		}
		toSign := make([]byte, 0, len(gotReportData)+len(key))
		toSign = append(toSign, gotReportData...)
		toSign = append(toSign, key...)
		CryptoClient.Verify(nil, key, toSign, sig, "p256", func(ok bool, verr error) {
			if verr != nil {
				done(verr)
				return
			}
			if !ok {
				done(errors.New("attest: 证明签名无效"))
				return
			}
			done(nil)
		})
	})
}

// hexEq 常量无关的 hex 比较（公开测量值；长度不符或非法 hex 返回 false）。
func hexEq(a, b string) bool {
	if a == "" || len(a) != len(b) {
		return false
	}
	ab, err1 := hex.DecodeString(a)
	bb, err2 := hex.DecodeString(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// shortID 日志安全截断（会话 ID 可能短于 8）。
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// ---------- P1-8 T1：attest-verify sidecar 路径 ----------

// attestResponse /attest 响应结构（与 doAttestHandshake 内联结构对齐，抽为命名类型供复用）。
type attestResponse struct {
	Status    string         `json:"status"`
	SessionID string         `json:"session_id"`
	ServerPub string         `json:"server_pub"`
	Proof     map[string]any `json:"proof"`
}

// verifyPluginProofViaSidecar 走 attest-verify sidecar 做完整证明验证：
//  1. nonce 回显 == 客户挑战（公开值，本地 bytes.Equal）——sidecar 不感知 nonce，插件侧自检；
//  2. 其余（report_data 绑定、签名链、度量基线）全部经 sidecar /verify。
//
// fail-closed：sidecar 调用失败 / 验证拒绝 → done(err)，无本地回退。
func verifyPluginProofViaSidecar(config PluginConfig, proof map[string]any,
	challenge, serverPub []byte, done func(err error)) {

	if proof == nil {
		done(errors.New("attest: 空证明载荷"))
		return
	}

	// 1. nonce 回显校验（公开值，本地比较）
	nonceHex, _ := proof["nonce"].(string)
	gotNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		done(errors.New("attest: nonce 非 hex"))
		return
	}
	if !bytes.Equal(gotNonce, challenge) {
		done(errors.New("attest: nonce 回显不匹配"))
		return
	}

	// 2. 组装 sidecar 期望的 proof wire：tee-infer 输出 hex 字段，而 sidecar 的
	//    Proof 结构体 []byte 字段按 Go 默认 base64 解码 ⇒ 此处 hex→base64 转码（非密码操作）。
	wire, werr := sidecarProofWire(proof)
	if werr != nil {
		done(werr)
		return
	}

	// 3. report_data = H(nonce ‖ server_pub)（防握手公钥替换）。
	//    ⚠️ sidecar 侧做的是**直接比较**（不自行哈希），故此处须经 cryptop sidecar 求值后传入，
	//    与本地路径 verifyPluginProof 一致。
	reportDataInput := make([]byte, 0, len(challenge)+len(serverPub))
	reportDataInput = append(reportDataInput, challenge...)
	reportDataInput = append(reportDataInput, serverPub...)
	CryptoClient.Hash(reportDataInput, func(wantReportData []byte, herr error) {
		if herr != nil {
			done(herr)
			return
		}
		// 4. 调用 sidecar /verify
		port := effectiveAttestVerifyPort(config.AttestVerifyPort)
		timeout := effectiveAttestVerifyTimeout(config.AttestVerifyTimeoutMS)
		VerifyProof(config.AttestVerifyService, port, timeout, config.AttestVerifyToken,
			wire, wantReportData, func(result *AttestVerifyResult, verr error) {
				if verr != nil {
					done(verr)
					return
				}
				_ = result // 验证通过即 ok；measurements 可用于日志，当前省略
				done(nil)
			})
	})
}

// continueHandshake 验证通过后的握手继续：session/begin → 方向子密钥 → attest/complete。
// 从 doAttestHandshake 中抽离，供两条验证路径复用，避免代码重复。
func continueHandshake(config PluginConfig, log logs.Log,
	ar attestResponse,
	nonce, serverPub []byte,
	client wrapper.HttpClient,
	onDone func(id string, sigRef, encRef, c2sRef, s2cRef cryptoclient.KeyRef),
	onFail func(msg string)) {

	// 客户端 ECDH + 会话密钥派生在 sidecar 内完成（密钥字节不出 sidecar，C-5）
	CryptoClient.SessionBegin(serverPub, nonce, peerPubAlg(),
		func(sigRef, encRef cryptoclient.KeyRef, clientPub []byte, serr error) {
			if serr != nil {
				onFail("session/begin 失败: " + serr.Error())
				return
			}
			deriveDirSubkeys(encRef, func(c2sRef, s2cRef cryptoclient.KeyRef, derr error) {
				if derr != nil {
					onFail("方向子密钥派生失败: " + derr.Error())
					return
				}
				compBody, _ := json.Marshal(map[string]string{
					"session_id": ar.SessionID,
					"client_pub": hex.EncodeToString(clientPub),
				})
				cerr := client.Post("/attest/complete", [][2]string{{"Content-Type", "application/json"}}, compBody,
					func(code int, _ http.Header, _ []byte) {
						if code != 200 {
							onFail(fmt.Sprintf("attest/complete 返回 %d", code))
							return
						}
						log.Infof("otpmask-plugin: 挑战-响应握手完成 session=%s（4 KeyRef 就绪）", shortID(ar.SessionID))
						onDone(ar.SessionID, sigRef, encRef, c2sRef, s2cRef)
					}, 5000)
				if cerr != nil {
					onFail("调用 attest/complete 失败: " + cerr.Error())
				}
			})
		})
}
