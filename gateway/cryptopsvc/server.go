// Package cryptopsvc —— cryptop sidecar 服务端（P0-4 §4.3/§4.7，子任务 6）。
//
// 定位与约束：
//   - **只服务 Wasm 插件**（Go 服务经 in-process `cryptop`，不得经 sidecar；B-4.6-1/R-7）；
//   - 插件侧严格零密码（C-5/R-11）：密钥字节只存于本进程的 `KeyStore`，插件只持 `KeyRef`；
//   - **fail-closed 无回退**（C-4/R-5）：错误即拒绝，绝不回退到插件内运算；
//   - 提供 §4.3 十三端点（密码原语契约）+ `/metrics`（§10.1）。**不含** §4.3.10 admin 管理面端点。
//
// 一致性关键（§4.3.8/§5.3.2）：`session/begin` 的 KDF 链与 tee-infer `session.go` **逐字节一致**：
//
//	sessionKey = HKDF(shared, nonce, "otpmask/session/v1", 32)
//	K_sig      = HKDF(sessionKey, nil, "otpmask/kdf/sig/v1", 32)
//	K_enc      = HKDF(sessionKey, nil, "otpmask/kdf/enc/v1", 32)
package cryptopsvc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"security-ai-gateway/cipher/mask"
	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/cryptop/keystore"
)

// ---- 配置（§12.3）----

// Config sidecar 启动配置。
type Config struct {
	// Profile 须与 p.Profile() 一致（R-2 启动拒）；空则取 p.Profile()。
	Profile cryptop.Profile
	// MaskPRG ∈ {hmac-sha256, sm4, bridge}（R-14/R-21）；空则随 profile（intl→hmac-sha256，sm→sm4）。
	MaskPRG string
	// StaticKeys KeyRef→密钥字节（§12.3 crypto_static_keys；R-16 键长须匹配 profile）。
	StaticKeys map[string][]byte
	// CallTimeout 单次调用超时（R-3；默认 50ms；≤0 取默认）。
	CallTimeout time.Duration
	// ListenAddr crypto_listen（R-20：非空时须 loopback，否则启动拒）。
	ListenAddr string
}

const (
	defaultCallTimeoutMS = 50
	// 会话 KDF info（§4.3.8；与 tee-infer session.go 一致）。
	sessionInfo = "otpmask/session/v1"
	kdfInfoSig  = "otpmask/kdf/sig/v1"
	kdfInfoEnc  = "otpmask/kdf/enc/v1"
	sessionTTL  = 5 * time.Minute

	// 会话方向子密钥 KeyRef 确定性后缀（v1.7 §5.4.5 / §4.3.6）：插件在 `SessionBegin` 后以
	// `/v1/kdf` 派生 `otpmask/kdf/enc/{c2s,s2c}/v1` 子密钥，**alias 须取 `<key_ref_enc>/<dir>`**
	// （会话内唯一，避跨会话 Register 覆盖致 #6 净值不归零）。`session/end` 据此前缀一并销毁（T-5.4-6）。
	subkeySuffixC2S = "/c2s"
	subkeySuffixS2C = "/s2c"

	// R-8 上限。
	maxRandLen   = 4096
	maxMaskCount = 65536
	maxBatchOps  = 64
	maxKDFOutLen = 4096
)

// ---- 服务 ----

// Server cryptop sidecar 服务端（§4.7 符号清单）。
type Server struct {
	p    cryptop.Provider
	keys keystore.KeyStore
	km   *keystore.KeyManager
	cfg  Config
	m    *metrics
}

// NewServer 构造 sidecar 服务端；p 为 nil / profile 不一致 / mask_prg 非法组合 → 报错（R-1/R-2/R-14/R-21/R-20）。
func NewServer(p cryptop.Provider, cfg Config) (*Server, error) {
	if p == nil {
		return nil, errors.New("cryptopsvc: provider 为 nil")
	}
	if cfg.Profile == "" {
		cfg.Profile = p.Profile()
	}
	if cfg.Profile != p.Profile() { // R-2
		return nil, fmt.Errorf("cryptopsvc: profile 不一致：配置 %q vs provider %q（R-2）", cfg.Profile, p.Profile())
	}
	if cfg.MaskPRG == "" {
		if p.Profile() == cryptop.ProfileIntl {
			cfg.MaskPRG = "hmac-sha256"
		} else {
			cfg.MaskPRG = "sm4"
		}
	}
	if err := validateMaskPRG(p.Profile(), cfg.MaskPRG); err != nil { // R-14/R-21
		return nil, err
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = defaultCallTimeoutMS * time.Millisecond
	}
	if cfg.ListenAddr != "" { // R-20
		if err := checkLoopback(cfg.ListenAddr); err != nil {
			return nil, err
		}
	}

	m := newMetrics()
	// 密钥目录选型（P1-5 M4/B-6.1-5）：sm-module 档走 moduleStore（密钥入模块、
	// 只持 token）；intl/sm-software 档走 memStore（既有路径零改动）。
	var store keystore.KeyStore
	if mbp, ok := p.(cryptop.ModuleBackendProvider); ok {
		store = keystore.NewModuleStore(mbp.ModuleBackend(), m)
	} else {
		store = keystore.NewMemStore(p, m)
	}
	s := &Server{
		p:    p,
		keys: store,
		km:   keystore.NewKeyManager(store, p, "keystore/root", m),
		cfg:  cfg,
		m:    m,
	}
	// 登记静态密钥（§12.3）；R-16：AEAD 对称键长度启动期即拒，不留待首次使用。
	for ref, key := range cfg.StaticKeys {
		if len(key) != p.SymmetricKeySize() { // R-16
			return nil, fmt.Errorf("cryptopsvc: 静态密钥 %q 长度 %d != profile=%s 对称键长 %d（R-16，启动拒）",
				ref, len(key), p.Profile(), p.SymmetricKeySize())
		}
		if err := store.Register(keystore.KeyRef(ref), key, keystore.KeyMeta{
			Scope:     keystore.ScopeStatic,
			Profile:   p.Profile(),
			CreatedAt: time.Now(),
		}); err != nil {
			return nil, fmt.Errorf("cryptopsvc: 登记静态密钥 %q 失败: %w", ref, err)
		}
	}
	m.setProfileInfo(p)                                     // #9
	m.setCompatMode("mask_bridge", cfg.MaskPRG == "bridge") // #15（R-21）
	return s, nil
}

// Handler 注册 §4.3 全部端点 + /metrics（**不含 §4.3.10 管理面端点**）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/capabilities", s.handleCapabilities) // GET
	mux.HandleFunc("/v1/rand", s.op("rand"))
	mux.HandleFunc("/v1/hash", s.op("hash"))
	mux.HandleFunc("/v1/hmac", s.op("hmac"))
	mux.HandleFunc("/v1/seal", s.op("seal"))
	mux.HandleFunc("/v1/open", s.op("open"))
	mux.HandleFunc("/v1/sign", s.op("sign"))
	mux.HandleFunc("/v1/verify", s.op("verify"))
	mux.HandleFunc("/v1/kdf", s.op("kdf"))
	mux.HandleFunc("/v1/mask/stream", s.op("mask"))
	mux.HandleFunc("/v1/session/begin", s.op("session_begin"))
	mux.HandleFunc("/v1/session/end", s.op("session_end"))
	mux.HandleFunc("/v1/batch", s.handleBatch)
	mux.HandleFunc("/metrics", s.handleMetrics)
	return s.withTimeout(mux)
}

// ---- HTTP 传输层 ----

// op 构造单端点 handler：读体 → dispatch → 写 JSON。
func (s *Server) op(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			s.writeErr(w, name, &apiError{http.StatusMethodNotAllowed, "bad_request", "仅接受 POST"})
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			s.writeErr(w, name, &apiError{http.StatusBadRequest, "bad_request", "读取请求体失败"})
			return
		}
		res, aerr := s.dispatch(name, raw, r.Header)
		if aerr != nil {
			s.writeErr(w, name, aerr)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErr(w, "capabilities", &apiError{http.StatusMethodNotAllowed, "bad_request", "仅接受 GET"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":         string(s.p.Profile()),
		"suite":           suiteFor(s.p.Profile()),
		"algorithms":      algorithmsFor(s.p.Profile()),
		"sizes":           map[string]int{"symmetric_key": s.p.SymmetricKeySize(), "nonce": s.p.NonceSize(), "hash": s.p.HashSize()},
		"mask_prg":        s.cfg.MaskPRG,
		"compliance_note": s.p.ComplianceNote(),
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.m.render(w)
}

// dispatch 统一入口：发射 #1（op 计数）、#2（延迟）、#3（错误码）。
// hdr 供 /v1/mask/stream 读取 X-OTPMask-MaskVersion（B-5.3-1）；批量时透传外层请求头。
func (s *Server) dispatch(op string, raw []byte, hdr http.Header) (map[string]any, *apiError) {
	start := time.Now()
	s.m.incOp(op, string(s.p.Profile()))                              // #1
	defer func() { s.m.observeOp(op, time.Since(start).Seconds()) }() // #2

	res, aerr := s.runOp(op, raw, hdr)
	if aerr != nil {
		s.m.incError(op, aerr.code) // #3
	}
	return res, aerr
}

// runOp 执行单个原语（单端点与 /v1/batch 共用）。
func (s *Server) runOp(op string, raw []byte, hdr http.Header) (map[string]any, *apiError) {
	switch op {
	case "rand":
		var req struct {
			N int `json:"n"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		if req.N < 0 || req.N > maxRandLen {
			return nil, limitErr("n 超出范围 [0,%d]", maxRandLen)
		}
		b, err := s.p.Rand(req.N)
		if err != nil {
			return nil, toAPIError(err)
		}
		return map[string]any{"bytes": b64(b)}, nil

	case "hash":
		var req struct {
			Data string `json:"data"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		data, aerr := decB64(req.Data)
		if aerr != nil {
			return nil, aerr
		}
		return map[string]any{"digest": b64(s.p.Hash(data))}, nil

	case "hmac":
		var req struct {
			KeyRef string `json:"key_ref"`
			Data   string `json:"data"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		key, meta, err := s.keys.Lookup(keystore.KeyRef(req.KeyRef))
		if err != nil {
			return nil, toAPIError(err)
		}
		_ = meta
		data, aerr := decB64(req.Data)
		if aerr != nil {
			return nil, aerr
		}
		return map[string]any{"mac": b64(s.p.HMAC(key, data))}, nil

	case "seal":
		var req struct {
			KeyRef    string `json:"key_ref"`
			AAD       string `json:"aad"`
			Plaintext string `json:"plaintext"`
			Nonce     string `json:"nonce"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		key, err := s.lookupKey(req.KeyRef)
		if err != nil {
			return nil, toAPIError(err)
		}
		aad, aerr := decB64(req.AAD)
		if aerr != nil {
			return nil, aerr
		}
		pt, aerr := decB64(req.Plaintext)
		if aerr != nil {
			return nil, aerr
		}
		if req.Nonce == "" {
			nonce, ct, err := s.p.SealWithNonce(key, pt, aad)
			if err != nil {
				return nil, toAPIError(err)
			}
			return map[string]any{"nonce": b64(nonce), "ciphertext": b64(ct)}, nil
		}
		nonce, aerr := decB64(req.Nonce)
		if aerr != nil {
			return nil, aerr
		}
		ct, err := s.p.Seal(key, nonce, pt, aad)
		if err != nil {
			return nil, toAPIError(err)
		}
		return map[string]any{"nonce": b64(nonce), "ciphertext": b64(ct)}, nil

	case "open":
		var req struct {
			KeyRef     string `json:"key_ref"`
			AAD        string `json:"aad"`
			Nonce      string `json:"nonce"`
			Ciphertext string `json:"ciphertext"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		key, err := s.lookupKey(req.KeyRef)
		if err != nil {
			return nil, toAPIError(err)
		}
		aad, aerr := decB64(req.AAD)
		if aerr != nil {
			return nil, aerr
		}
		nonce, aerr := decB64(req.Nonce)
		if aerr != nil {
			return nil, aerr
		}
		ct, aerr := decB64(req.Ciphertext)
		if aerr != nil {
			return nil, aerr
		}
		pt, err := s.p.Open(key, nonce, ct, aad)
		if err != nil {
			return nil, toAPIError(err)
		}
		return map[string]any{"plaintext": b64(pt)}, nil

	case "sign":
		var req struct {
			KeyRef string `json:"key_ref"`
			Data   string `json:"data"`
			Alg    string `json:"alg"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		key, err := s.lookupKey(req.KeyRef)
		if err != nil {
			return nil, toAPIError(err)
		}
		data, aerr := decB64(req.Data)
		if aerr != nil {
			return nil, aerr
		}
		sig, err := s.p.Sign(key, data)
		if err != nil {
			return nil, toAPIError(err)
		}
		return map[string]any{"signature": b64(sig)}, nil

	case "verify":
		return s.runVerify(raw)

	case "kdf":
		var req struct {
			KeyRef string `json:"key_ref"`
			Salt   string `json:"salt"`
			Info   string `json:"info"`
			OutLen int    `json:"out_len"`
			Alias  string `json:"alias"`
		}
		if aerr := unmarshal(raw, &req); aerr != nil {
			return nil, aerr
		}
		if req.OutLen <= 0 || req.OutLen > maxKDFOutLen {
			return nil, limitErr("out_len 超出范围 [1,%d]", maxKDFOutLen)
		}
		salt, aerr := decB64(req.Salt)
		if aerr != nil {
			return nil, aerr
		}
		info, aerr := decB64(req.Info)
		if aerr != nil {
			return nil, aerr
		}
		ref, err := s.keys.Derive(keystore.KeyRef(req.KeyRef), salt, info, req.OutLen, req.Alias)
		if err != nil {
			return nil, toAPIError(err)
		}
		return map[string]any{"key_ref": string(ref)}, nil

	case "mask":
		return s.runMask(raw, hdr)

	case "session_begin":
		return s.runSessionBegin(raw)

	case "session_end":
		return s.runSessionEnd(raw)

	default:
		return nil, &apiError{http.StatusBadRequest, "bad_request", "未知 op: " + op}
	}
}

// runVerify 验签（默认 profile 算法；alg="p256" 走 §5.4.2 例外）。
// 验签不通过 = HTTP 200 {"ok":false}（verify_failed，非 HTTP 错误）。
func (s *Server) runVerify(raw []byte) (map[string]any, *apiError) {
	var req struct {
		KeyRef    string `json:"key_ref"`
		PubKey    string `json:"pub_key"`
		Data      string `json:"data"`
		Signature string `json:"signature"`
		Alg       string `json:"alg"`
	}
	if aerr := unmarshal(raw, &req); aerr != nil {
		return nil, aerr
	}
	var pub []byte
	switch {
	case req.PubKey != "":
		b, aerr := decB64(req.PubKey)
		if aerr != nil {
			return nil, aerr
		}
		pub = b
	case req.KeyRef != "":
		b, err := s.lookupKey(req.KeyRef)
		if err != nil {
			return nil, toAPIError(err)
		}
		pub = b
	default:
		return nil, &apiError{http.StatusBadRequest, "bad_request", "须提供 key_ref 或 pub_key"}
	}
	data, aerr := decB64(req.Data)
	if aerr != nil {
		return nil, aerr
	}
	sig, aerr := decB64(req.Signature)
	if aerr != nil {
		return nil, aerr
	}
	var verr error
	if req.Alg == "p256" {
		verr = cryptop.VerifyP256(pub, data, sig) // §5.4.2 例外（恒国际算法）
	} else {
		verr = s.p.Verify(pub, data, sig)
	}
	if verr != nil {
		s.m.incError("verify", "verify_failed") // §4.4（HTTP 200，非 HTTP 错误）
		return map[string]any{"ok": false}, nil
	}
	return map[string]any{"ok": true}, nil
}

// runMask /v1/mask/stream（§4.3.7/§5.3.2）：PRG 由 mask_prg + X-OTPMask-MaskVersion 选择。
//
// v1.9（R4·方案 A）：入参由 `key_ref` 改为 `seed`（base64）——掩码 seed 须与 tee-infer **逐请求一致**
// （tee-infer `recompute.go` 亦按同值产流），不可能是一枚长期 KeyRef；故由调用方（插件）传入本次
// 掩码流的 seed 字节，sidecar 仅做 PRG 求值（插件仍零密码、不做 PRG），模算术留在插件（§5.4.5）。
func (s *Server) runMask(raw []byte, hdr http.Header) (map[string]any, *apiError) {
	var req struct {
		Seed    string `json:"seed"`
		Domain  string `json:"domain"`
		Count   int    `json:"count"`
		Modulus uint64 `json:"modulus"`
	}
	if aerr := unmarshal(raw, &req); aerr != nil {
		return nil, aerr
	}
	if req.Count < 0 || req.Count > maxMaskCount {
		return nil, limitErr("count 超出范围 [0,%d]", maxMaskCount)
	}
	if req.Modulus < 2 {
		return nil, &apiError{http.StatusBadRequest, "bad_request", "modulus 须 ≥ 2"}
	}
	seed, aerr := decB64(req.Seed)
	if aerr != nil {
		return nil, aerr
	}
	if len(seed) == 0 {
		return nil, &apiError{http.StatusBadRequest, "bad_request", "seed 须非空（base64）"}
	}
	domain := []byte(req.Domain)

	// §5.3.2 PRG 选择：bridge 时按请求头选 hmac/sm4；其余单值。
	version := ""
	if hdr != nil {
		version = hdr.Get("X-OTPMask-MaskVersion")
	}
	useHMAC := s.cfg.MaskPRG == "hmac-sha256" || (s.cfg.MaskPRG == "bridge" && version == "hmac-sha256")

	// seed 长度随 PRG 而非 profile：hmac 路径 ≥ MinSeedLen(32)；sm4 路径须 = SymmetricKeySize。
	if useHMAC {
		if len(seed) < mask.MinSeedLen {
			return nil, &apiError{http.StatusBadRequest, "key_size_mismatch",
				fmt.Sprintf("seed 长度 %d 小于最小值 %d", len(seed), mask.MinSeedLen)}
		}
	} else if len(seed) != s.p.SymmetricKeySize() {
		return nil, &apiError{http.StatusBadRequest, "key_size_mismatch",
			fmt.Sprintf("seed 长度 %d != SymmetricKeySize %d", len(seed), s.p.SymmetricKeySize())}
	}

	var st *mask.Stream
	var err error
	if useHMAC {
		st, err = mask.NewStreamDomain(seed, req.Modulus, domain)
	} else {
		st, err = mask.NewStreamWithProvider(s.p, seed, domain, req.Modulus)
	}
	if err != nil {
		return nil, toAPIError(err)
	}
	defer st.Zeroize() // B-5.3-2：掩码值/种子用完即弃，不跨请求复用

	vals := make([]uint64, req.Count)
	if err := st.Fill(vals); err != nil {
		return nil, toAPIError(err)
	}
	s.m.addMaskValues(req.Count) // #11
	return map[string]any{"values": vals}, nil
}

// runSessionBegin /v1/session/begin（§4.3.8）：ECDH → KDF 链 → 注册 2 个会话 KeyRef。
func (s *Server) runSessionBegin(raw []byte) (map[string]any, *apiError) {
	var req struct {
		ServerPub  string `json:"server_pub"`
		Nonce      string `json:"nonce"`
		PeerPubAlg string `json:"peer_pub_alg"`
	}
	if aerr := unmarshal(raw, &req); aerr != nil {
		return nil, aerr
	}
	// peer_pub_alg 须与本 profile 的 ECDH 算法一致（intl=x25519 / sm=sm2）。
	want := "x25519"
	if s.p.Profile() != cryptop.ProfileIntl {
		want = "sm2"
	}
	if req.PeerPubAlg != "" && req.PeerPubAlg != want {
		return nil, &apiError{http.StatusBadRequest, "bad_request",
			fmt.Sprintf("peer_pub_alg=%q 与本 profile 的 ECDH 算法 %q 不符", req.PeerPubAlg, want)}
	}
	serverPub, aerr := decB64(req.ServerPub)
	if aerr != nil {
		return nil, aerr
	}
	nonce, aerr := decB64(req.Nonce)
	if aerr != nil {
		return nil, aerr
	}

	priv, pub, err := s.p.GenerateECDHKeyPair()
	if err != nil {
		return nil, toAPIError(err)
	}
	shared, err := s.p.ECDH(priv, serverPub)
	if err != nil {
		return nil, toAPIError(err)
	}
	sessionKey, err := s.p.KDF(shared, nonce, []byte(sessionInfo), 32)
	if err != nil {
		return nil, toAPIError(err)
	}
	ksig, err := s.p.KDF(sessionKey, nil, []byte(kdfInfoSig), 32)
	if err != nil {
		return nil, toAPIError(err)
	}
	kenc, err := s.p.KDF(sessionKey, nil, []byte(kdfInfoEnc), 32)
	if err != nil {
		return nil, toAPIError(err)
	}

	idRaw, err := s.p.Rand(16)
	if err != nil {
		return nil, toAPIError(err)
	}
	sessID := hex.EncodeToString(idRaw)
	ksigRef := keystore.KeyRef("session/" + sessID + "/sig")
	kencRef := keystore.KeyRef("session/" + sessID + "/enc")
	meta := keystore.KeyMeta{Scope: keystore.ScopeSession, Profile: s.p.Profile(), CreatedAt: time.Now(), TTL: sessionTTL}
	if err := s.keys.Register(ksigRef, ksig, meta); err != nil {
		return nil, toAPIError(err)
	}
	if err := s.keys.Register(kencRef, kenc, meta); err != nil {
		return nil, toAPIError(err)
	}
	return map[string]any{
		"key_ref_sig": string(ksigRef),
		"key_ref_enc": string(kencRef),
		"client_pub":  b64(pub),
	}, nil
}

// runSessionEnd /v1/session/end（§4.3.8）：零化会话全部 KeyRef（发 #8），令 #6 净值归零（T-5.4-6）。
//
// v1.7 §5.4.5（R8-P1-1）：每会话实为 **4 个 KeyRef**（sig / enc / enc+c2s / enc+s2c）——两个方向子密钥
// 由插件在 `SessionBegin` 后经 `/v1/kdf`（alias = `<key_ref_enc>/<dir>`，见 subkeySuffix*）派生。
// 故本端点除 `key_ref_sig`/`key_ref_enc` 外，还按确定性后缀销毁两个子密钥 KeyRef，否则其只增不减。
func (s *Server) runSessionEnd(raw []byte) (map[string]any, *apiError) {
	var req struct {
		KeyRefSig string `json:"key_ref_sig"`
		KeyRefEnc string `json:"key_ref_enc"`
	}
	if aerr := unmarshal(raw, &req); aerr != nil {
		return nil, aerr
	}
	// sig/enc 为会话注册的必备 ref，缺失即协议错（fail-closed）。
	for _, ref := range []string{req.KeyRefSig, req.KeyRefEnc} {
		if ref == "" {
			continue
		}
		if err := s.km.Destroy(keystore.KeyRef(ref)); err != nil {
			return nil, toAPIError(err)
		}
	}
	// 方向子密钥为**可选**（会话未被使用时插件未派生）：best-effort 销毁，未注册则跳过（不报错）。
	if req.KeyRefEnc != "" {
		for _, suf := range []string{subkeySuffixC2S, subkeySuffixS2C} {
			if err := s.km.Destroy(keystore.KeyRef(req.KeyRefEnc + suf)); err != nil && !errors.Is(err, keystore.ErrUnknownKeyRef) {
				return nil, toAPIError(err)
			}
		}
	}
	return map[string]any{"ok": true}, nil
}

// handleBatch /v1/batch（§4.3.9）：多 op 合并 + per-op 错误隔离（R-6）。
func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeErr(w, "batch", &apiError{http.StatusMethodNotAllowed, "bad_request", "仅接受 POST"})
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeErr(w, "batch", &apiError{http.StatusBadRequest, "bad_request", "读取请求体失败"})
		return
	}
	var body struct {
		Ops []json.RawMessage `json:"ops"`
	}
	if aerr := unmarshal(raw, &body); aerr != nil {
		s.writeErr(w, "batch", aerr)
		return
	}
	if len(body.Ops) > maxBatchOps {
		s.writeErr(w, "batch", limitErr("ops 数量 %d 超出上限 %d", len(body.Ops), maxBatchOps))
		return
	}
	results := make([]map[string]any, 0, len(body.Ops))
	for _, opRaw := range body.Ops {
		var head struct {
			ID string `json:"id"`
			Op string `json:"op"`
		}
		if aerr := unmarshal(opRaw, &head); aerr != nil {
			results = append(results, map[string]any{"error": aerr.errObj()}) // R-6：per-op 错误隔离
			continue
		}
		res, aerr := s.dispatch(head.Op, opRaw, r.Header)
		if aerr != nil {
			results = append(results, map[string]any{"id": head.ID, "error": aerr.errObj()})
			continue
		}
		res["id"] = head.ID
		results = append(results, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// ---- 超时中间件（R-3）：缓冲响应，超预算即 fail-closed（不落半响应） ----

func (s *Server) withTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		bw := &bufWriter{}
		next.ServeHTTP(bw, r)
		if time.Since(start) > s.cfg.CallTimeout {
			s.m.incTimeout() // #4
			writeJSON(w, http.StatusInternalServerError, errBody("internal", "调用超时（R-3）"))
			return
		}
		for k, v := range bw.hdr {
			w.Header()[k] = v
		}
		if bw.status == 0 {
			bw.status = http.StatusOK
		}
		w.WriteHeader(bw.status)
		_, _ = w.Write(bw.buf.Bytes())
	})
}

// bufWriter 缓冲 ResponseWriter（供超时中间件判定后再落盘）。
type bufWriter struct {
	hdr    http.Header
	buf    bytes.Buffer
	status int
}

func (b *bufWriter) Header() http.Header {
	if b.hdr == nil {
		b.hdr = http.Header{}
	}
	return b.hdr
}

func (b *bufWriter) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *bufWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.buf.Write(p)
}

// ---- 错误映射（§4.4 稳定契约）----

// apiError 稳定错误契约（HTTP 状态 + code）。
type apiError struct {
	status int
	code   string
	msg    string
}

func (e *apiError) Error() string { return e.code + ": " + e.msg }

func (e *apiError) body() map[string]any {
	return errBody(e.code, e.msg)
}

// errObj batch 结果元素内的错误对象（§4.3.9：{"error":{"code","message"}}）。
func (e *apiError) errObj() map[string]string {
	return map[string]string{"code": e.code, "message": e.msg}
}

func errBody(code, msg string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": msg}}
}

func limitErr(format string, args ...any) *apiError {
	return &apiError{http.StatusRequestEntityTooLarge, "limit_exceeded", fmt.Sprintf(format, args...)}
}

// toAPIError 把 cryptop/keystore 错误映射到 §4.4 错误码。
func toAPIError(err error) *apiError {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, cryptop.ErrInvalidKeySize):
		return &apiError{http.StatusBadRequest, "key_size_mismatch", err.Error()}
	case errors.Is(err, cryptop.ErrDecrypt):
		return &apiError{http.StatusBadRequest, "decrypt", err.Error()}
	case errors.Is(err, keystore.ErrUnknownKeyRef):
		return &apiError{http.StatusNotFound, "unknown_key_ref", err.Error()}
	case errors.Is(err, cryptop.ErrNotImplemented):
		return &apiError{http.StatusNotImplemented, "not_implemented", err.Error()}
	default:
		return &apiError{http.StatusInternalServerError, "internal", err.Error()}
	}
}

func (s *Server) writeErr(w http.ResponseWriter, op string, aerr *apiError) {
	if op != "" {
		s.m.incError(op, aerr.code) // #3（GET/方法错误等非 dispatch 路径）
	}
	writeJSON(w, aerr.status, aerr.body())
}

// ---- 小工具 ----

func (s *Server) lookupKey(ref string) ([]byte, error) {
	key, _, err := s.keys.Lookup(keystore.KeyRef(ref))
	return key, err
}

func unmarshal(raw []byte, v any) *apiError {
	if err := json.Unmarshal(raw, v); err != nil {
		return &apiError{http.StatusBadRequest, "bad_request", "JSON 解析失败: " + err.Error()}
	}
	return nil
}

func decB64(s string) ([]byte, *apiError) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &apiError{http.StatusBadRequest, "bad_request", "base64 解码失败"}
	}
	return b, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// suiteFor wire suite 字节（1=AES-GCM，2=SM4-GCM；§4.3.1）。
func suiteFor(p cryptop.Profile) int {
	if p == cryptop.ProfileIntl {
		return 1
	}
	return 2
}

// algorithmsFor §4.3.1 算法清单。
func algorithmsFor(p cryptop.Profile) map[string]string {
	if p == cryptop.ProfileIntl {
		return map[string]string{
			"aead": "AES-256-GCM", "hash": "SHA-256", "hmac": "HMAC-SHA256",
			"kdf": "HKDF-SHA256", "ecdh": "X25519", "sign": "Ed25519",
		}
	}
	return map[string]string{
		"aead": "SM4-GCM", "hash": "SM3", "hmac": "HMAC-SM3",
		"kdf": "SM3-KDF", "ecdh": "SM2", "sign": "SM2",
	}
}

// validateMaskPRG R-14/R-21：mask_prg × profile 兼容矩阵。
// 允许组合：intl+hmac-sha256；sm-*+sm4；sm-*+bridge。其余（intl+sm4 / intl+bridge / sm-*+hmac-sha256）启动拒。
func validateMaskPRG(p cryptop.Profile, prg string) error {
	allowed := false
	switch p {
	case cryptop.ProfileIntl:
		allowed = prg == "hmac-sha256"
	default: // sm-software / sm-module
		allowed = prg == "sm4" || prg == "bridge"
	}
	if !allowed {
		return fmt.Errorf("cryptopsvc: mask_prg=%q 与 profile=%q 非法组合（R-14/R-21）", prg, p)
	}
	return nil
}

// checkLoopback R-20：crypto_listen 必须 loopback。
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 兼容 ":port" 形式：host 空 = 未指定 → 视作非 loopback（要求显式 127.0.0.1/::1）。
		return fmt.Errorf("cryptopsvc: crypto_listen=%q 格式非法或主机缺失（R-20 须显式 loopback）", addr)
	}
	host = strings.TrimSpace(host)
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("cryptopsvc: crypto_listen=%q 非 loopback（R-20）", addr)
	}
	return nil
}

// BridgeWarning 供 main 在启用 mask_prg=bridge 时记录启动告警（R-21②）。
func (c Config) BridgeWarning() string {
	if c.MaskPRG == "bridge" {
		return "WARN: mask_prg=bridge 已启用（兼容/桥接模式，R-21）——滚动升级期临时态，收桥后应置 mask_prg=sm4"
	}
	return ""
}
