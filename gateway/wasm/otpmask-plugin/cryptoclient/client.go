// client.go —— cryptop sidecar 客户端（P0-4 §4.3/§4.4/§4.7）。
//
// 为何是**回调式（CPS）**：proxy-wasm 是单线程事件循环，`proxywasm.DispatchHttpCall`
// 异步，无法阻塞等待响应。故 §4.7 的同步记法
// `Seal(ref,aad,pt) (nonce,ct,err)` 在此实现为等价的回调式
// `Seal(ref,aad,pt, func(nonce,ct,err))`——语义一一对应，仅交付方式为 CPS。
//
// 每个方法统一经 `call`：熔断检查（R-4）→ #13 计入 → POST → 状态码/JSON 解码 →
// 错误码映射（§4.4）→ #4/#14/#5。**所有失败分支一律 fail-closed（C-4）**，
// 无任何 `if err != nil { 本地运算 }` 回退。

package cryptoclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ---- wire 契约（与 gateway/cryptopsvc 端点逐字段对齐）----

// 端点路径。
const (
	pathCapabilities = "/v1/capabilities"
	pathRand         = "/v1/rand"
	pathHash         = "/v1/hash"
	pathHMAC         = "/v1/hmac"
	pathSeal         = "/v1/seal"
	pathOpen         = "/v1/open"
	pathSign         = "/v1/sign"
	pathVerify       = "/v1/verify"
	pathKDF          = "/v1/kdf"
	pathMaskStream   = "/v1/mask/stream"
	pathSessionBegin = "/v1/session/begin"
	pathSessionEnd   = "/v1/session/end"
	pathBatch        = "/v1/batch"
)

// op 名（#13/#14 的标签值；对齐 sidecar 的 op 命名）。
const (
	OpRand         = "rand"
	OpHash         = "hash"
	OpHMAC         = "hmac"
	OpSeal         = "seal"
	OpOpen         = "open"
	OpSign         = "sign"
	OpVerify       = "verify"
	OpKDF          = "kdf"
	OpMask         = "mask"
	OpSessionBegin = "session_begin"
	OpSessionEnd   = "session_end"
	OpBatch        = "batch"
)

// HeaderMaskVersion 掩码版本请求头（§5.3.2 / B-5.3-1；仅 /v1/mask/stream 消费）。
const HeaderMaskVersion = "X-OTPMask-MaskVersion"

// 掩码算法标识（客户端声明；§5.3.2 单键三值）。
const (
	MaskPRGHMAC = "hmac-sha256"
	MaskPRGSM4  = "sm4"
	MaskPRGBridge = "bridge"
)

// §4.4 错误码。
const (
	CodeBadRequest     = "bad_request"
	CodeUnknownKeyRef  = "unknown_key_ref"
	CodeKeySizeMismatch = "key_size_mismatch"
	CodeDecrypt        = "decrypt"
	CodeVerifyFailed   = "verify_failed"
	CodeNotImplemented = "not_implemented"
	CodeLimitExceeded  = "limit_exceeded"
	CodeInternal       = "internal"
)

// KeyRef 不透明密钥句柄（C-5：插件只见句柄，不见字节）。
type KeyRef string

// Capabilities /v1/capabilities 响应（§4.3.1）。
type Capabilities struct {
	Profile        string            `json:"profile"`
	Suite          int               `json:"suite"`
	Algorithms     map[string]string `json:"algorithms"`
	Sizes          map[string]int    `json:"sizes"`
	MaskPRG        string            `json:"mask_prg"`
	ComplianceNote string            `json:"compliance_note"`
}

// Error sidecar 返回的结构化错误（§4.4）。status = HTTP 状态码，code = 上层错误码。
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("cryptop sidecar: %s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// 客户端本地错误（非 sidecar 返回）。
var (
	// ErrCircuitOpen 熔断开启，未发起调用（R-4）。
	ErrCircuitOpen = errors.New("cryptoclient: 熔断开启，fail-closed")
	// ErrMalformed sidecar 响应无法解析（按 fail-closed 处理）。
	ErrMalformed = errors.New("cryptoclient: sidecar 响应格式非法")
	// ErrTransport 出站派发失败（sidecar 不可达/超时）。
	ErrTransport = errors.New("cryptoclient: sidecar 不可达")
)

// VerifyFailed sidecar 返回的 `verify_failed`（HTTP 200 `{ok:false}`）——按 §4.4 **非错误**。
var ErrVerifyFailed = errors.New("cryptoclient: 验签不通过")

// ResponseCallback sidecar 响应回调（与 wrapper.ResponseCallback 同型）。
type ResponseCallback func(statusCode int, hdr http.Header, body []byte)

// Transport 出站派发抽象：插件侧由 wrapper.ClusterClient 实现；单测用同步 mock。
type Transport interface {
	Post(path string, headers [][2]string, body []byte, cb ResponseCallback, timeoutMs uint32) error
	Get(path string, headers [][2]string, cb ResponseCallback, timeoutMs uint32) error
}

// Metrics 插件侧指标接收器（nil-safe）。对应 §10.1 #13/#14/#5。
type Metrics interface {
	Call(op string)          // #13 otpmask_crypto_call_total{op}
	FailClosed(op string)    // #14 otpmask_crypto_failclosed_total{op}
	CircuitOpen(open bool)   // #5 cryptop_circuit_open（0/1）
}

// Config 客户端构造参数。
type Config struct {
	TimeoutMS   uint32 // 单次调用超时（R-3：50ms）；0 取 50
	MaskVersion string // → X-OTPMask-MaskVersion（仅掩码流；空则不发送）
}

// DefaultTimeoutMS R-3 单次调用超时。
const DefaultTimeoutMS uint32 = 50

// Client cryptop sidecar 客户端（唯一 HTTP 面，§4.7）。
type Client struct {
	tr      Transport
	br      *Breaker
	m       Metrics
	timeout uint32
	maskVer string

	caps Capabilities
}

// New 构造客户端；br 可为 nil（不熔断），m 可为 nil（不埋点）。
func New(tr Transport, br *Breaker, m Metrics, cfg Config) *Client {
	to := cfg.TimeoutMS
	if to == 0 {
		to = DefaultTimeoutMS
	}
	c := &Client{tr: tr, br: br, m: m, timeout: to, maskVer: cfg.MaskVersion}
	if br != nil && m != nil {
		br.OnStateChange(m.CircuitOpen) // #5 唯一生产者
	}
	return c
}

// Capabilities 返回上次 LoadCapabilities 的结果。
func (c *Client) Capabilities() Capabilities { return c.caps }

// ---- 低层：统一调用入口 ----

// call 统一入口：熔断 → #13 → POST → 状态码/解码 → 错误码映射 → #4(隐含)/#14/#5。
// cb 交付裸响应体与错误；**任一错误路径 = fail-closed**。
func (c *Client) call(op, path string, hdrs [][2]string, req any, cb func(body []byte, err error)) {
	if c.m != nil {
		c.m.Call(op) // #13
	}
	if c.br != nil && !c.br.Allow() {
		c.fail(op)
		cb(nil, ErrCircuitOpen)
		return
	}
	var body []byte
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			c.result(op, false)
			cb(nil, err)
			return
		}
		body = b
	}
	derr := c.tr.Post(path, append([][2]string{{"Content-Type", "application/json"}}, hdrs...), body,
		func(status int, _ http.Header, resp []byte) {
			if status < 200 || status >= 300 {
				c.result(op, false)
				cb(nil, decodeError(status, resp))
				return
			}
			c.result(op, true)
			cb(resp, nil)
		}, c.timeout)
	if derr != nil {
		c.result(op, false)
		cb(nil, fmt.Errorf("%w: %v", ErrTransport, derr))
	}
}

// callGet 与 call 同，但用 GET（仅 /v1/capabilities）。
func (c *Client) callGet(op, path string, cb func(body []byte, err error)) {
	if c.m != nil {
		c.m.Call(op)
	}
	if c.br != nil && !c.br.Allow() {
		c.fail(op)
		cb(nil, ErrCircuitOpen)
		return
	}
	derr := c.tr.Get(path, nil, func(status int, _ http.Header, resp []byte) {
		if status < 200 || status >= 300 {
			c.result(op, false)
			cb(nil, decodeError(status, resp))
			return
		}
		c.result(op, true)
		cb(resp, nil)
	}, c.timeout)
	if derr != nil {
		c.result(op, false)
		cb(nil, fmt.Errorf("%w: %v", ErrTransport, derr))
	}
}

// result 上报熔断结果，并在失败时计 #14（fail-closed）。
func (c *Client) result(op string, ok bool) {
	if c.br != nil {
		c.br.OnResult(ok)
	}
	if !ok {
		c.fail(op)
	}
}

// fail 计 #14（仅计数，不含熔断上报）。
func (c *Client) fail(op string) {
	if c.m != nil {
		c.m.FailClosed(op) // #14
	}
}

// decode 反序列化响应体；失败按 fail-closed 计 #14。
func (c *Client) decode(op string, body []byte, dst any) error {
	if err := json.Unmarshal(body, dst); err != nil {
		c.fail(op)
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}

// ---- 高层类型化方法（§4.7 契约，回调式交付）----

// Rand /v1/rand。
func (c *Client) Rand(n int, cb func(b []byte, err error)) {
	c.call(OpRand, pathRand, nil, map[string]any{"n": n}, func(body []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		var r struct{ Bytes string `json:"bytes"` }
		if e := c.decode(OpRand, body, &r); e != nil {
			cb(nil, e)
			return
		}
		b, e := unb64(r.Bytes)
		if e != nil {
			c.fail(OpRand)
			cb(nil, ErrMalformed)
			return
		}
		cb(b, nil)
	})
}

// Hash /v1/hash。
func (c *Client) Hash(data []byte, cb func(digest []byte, err error)) {
	c.call(OpHash, pathHash, nil, map[string]any{"data": b64(data)}, func(body []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		var r struct{ Digest string `json:"digest"` }
		if e := c.decode(OpHash, body, &r); e != nil {
			cb(nil, e)
			return
		}
		d, e := unb64(r.Digest)
		if e != nil {
			c.fail(OpHash)
			cb(nil, ErrMalformed)
			return
		}
		cb(d, nil)
	})
}

// HMAC /v1/hmac（= §4.7 的 Sign 侧；对应现役 SignRequest）。
func (c *Client) HMAC(ref KeyRef, data []byte, cb func(mac []byte, err error)) {
	c.call(OpHMAC, pathHMAC, nil, map[string]any{"key_ref": string(ref), "data": b64(data)}, func(body []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		var r struct{ MAC string `json:"mac"` }
		if e := c.decode(OpHMAC, body, &r); e != nil {
			cb(nil, e)
			return
		}
		m, e := unb64(r.MAC)
		if e != nil {
			c.fail(OpHMAC)
			cb(nil, ErrMalformed)
			return
		}
		cb(m, nil)
	})
}

// Seal /v1/seal：AEAD 封装。nonce 为空时由 sidecar 生成（返回生成的 nonce）。
func (c *Client) Seal(ref KeyRef, aad, pt []byte, cb func(nonce, ct []byte, err error)) {
	req := map[string]any{"key_ref": string(ref), "aad": b64(aad), "plaintext": b64(pt)}
	c.call(OpSeal, pathSeal, nil, req, func(body []byte, err error) {
		if err != nil {
			cb(nil, nil, err)
			return
		}
		var r struct {
			Nonce      string `json:"nonce"`
			Ciphertext string `json:"ciphertext"`
		}
		if e := c.decode(OpSeal, body, &r); e != nil {
			cb(nil, nil, e)
			return
		}
		nonce, e1 := unb64(r.Nonce)
		ct, e2 := unb64(r.Ciphertext)
		if e1 != nil || e2 != nil {
			c.fail(OpSeal)
			cb(nil, nil, ErrMalformed)
			return
		}
		cb(nonce, ct, nil)
	})
}

// Open /v1/open：AEAD 解封；失败 → `decrypt`（fail-closed）。
func (c *Client) Open(ref KeyRef, aad, nonce, ct []byte, cb func(pt []byte, err error)) {
	req := map[string]any{"key_ref": string(ref), "aad": b64(aad), "nonce": b64(nonce), "ciphertext": b64(ct)}
	c.call(OpOpen, pathOpen, nil, req, func(body []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		var r struct{ Plaintext string `json:"plaintext"` }
		if e := c.decode(OpOpen, body, &r); e != nil {
			cb(nil, e)
			return
		}
		pt, e := unb64(r.Plaintext)
		if e != nil {
			c.fail(OpOpen)
			cb(nil, ErrMalformed)
			return
		}
		cb(pt, nil)
	})
}

// Verify /v1/verify：ref 与 pub 二选一（ref≠nil 用对称密钥验 MAC；否则内联公钥）。
// alg=="p256" 走 §5.4.2 例外（恒国际算法，不随 profile）。**验签不通过不是错误**——
// 返回 (false, nil)（§4.4 verify_failed=200 {ok:false}）。
func (c *Client) Verify(ref *KeyRef, pub, data, sig []byte, alg string, cb func(ok bool, err error)) {
	req := map[string]any{"data": b64(data), "signature": b64(sig), "alg": alg}
	if ref != nil {
		req["key_ref"] = string(*ref)
	} else {
		req["pub_key"] = b64(pub)
	}
	c.call(OpVerify, pathVerify, nil, req, func(body []byte, err error) {
		if err != nil {
			cb(false, err)
			return
		}
		var r struct{ OK bool `json:"ok"` }
		if e := c.decode(OpVerify, body, &r); e != nil {
			cb(false, e)
			return
		}
		cb(r.OK, nil)
	})
}

// MaskStream /v1/mask/stream（§4.3.7）：取 count 个 [0,modulus) 掩码元素。
// 掩码版本由构造期 Config.MaskVersion 经 X-OTPMask-MaskVersion 头下发（B-5.3-1）。
func (c *Client) MaskStream(ref KeyRef, domain []byte, count int, modulus uint64, cb func(vals []uint64, err error)) {
	req := map[string]any{"key_ref": string(ref), "domain": string(domain), "count": count, "modulus": modulus}
	var hdrs [][2]string
	if c.maskVer != "" {
		hdrs = [][2]string{{HeaderMaskVersion, c.maskVer}}
	}
	c.call(OpMask, pathMaskStream, hdrs, req, func(body []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		var r struct {
			Values []uint64 `json:"values"`
		}
		if e := c.decode(OpMask, body, &r); e != nil {
			cb(nil, e)
			return
		}
		cb(r.Values, nil)
	})
}

// SessionBegin /v1/session/begin（§4.3.8）：ECDH+KDF 链在 sidecar 内完成，返回两个 KeyRef
// 与 client_pub（供转发给 TEE 服务）；**密钥字节不出 sidecar**（C-5）。
func (c *Client) SessionBegin(serverPub, nonce []byte, peerAlg string, cb func(ksig, kenc KeyRef, clientPub []byte, err error)) {
	req := map[string]any{"server_pub": b64(serverPub), "nonce": b64(nonce), "peer_pub_alg": peerAlg}
	c.call(OpSessionBegin, pathSessionBegin, nil, req, func(body []byte, err error) {
		if err != nil {
			cb("", "", nil, err)
			return
		}
		var r struct {
			KeyRefSig string `json:"key_ref_sig"`
			KeyRefEnc string `json:"key_ref_enc"`
			ClientPub string `json:"client_pub"`
		}
		if e := c.decode(OpSessionBegin, body, &r); e != nil {
			cb("", "", nil, e)
			return
		}
		cp, e := unb64(r.ClientPub)
		if e != nil {
			c.fail(OpSessionBegin)
			cb("", "", nil, ErrMalformed)
			return
		}
		cb(KeyRef(r.KeyRefSig), KeyRef(r.KeyRefEnc), cp, nil)
	})
}

// SessionEnd /v1/session/end（§4.3.8）：零化两个会话 KeyRef（发 #8），令 #6 净值归零（T-5.4-6）。
func (c *Client) SessionEnd(ksig, kenc KeyRef, cb func(err error)) {
	req := map[string]any{"key_ref_sig": string(ksig), "key_ref_enc": string(kenc)}
	c.call(OpSessionEnd, pathSessionEnd, nil, req, func(_ []byte, err error) {
		cb(err)
	})
}

// Op 批处理单元（§4.3.9）；Payload 为各 op 端点的请求体字段（原样序列化）。
type Op struct {
	ID      string
	Op      string
	Payload map[string]any
}

// OpResult 批处理单条结果；Error 非空表示该 op 失败（R-6 per-op 隔离）。
type OpResult struct {
	ID      string
	Fields  map[string]any
	Error   *Error
}

// Batch /v1/batch（§4.3.9）：多 op 合并；**per-op 错误隔离**（R-6）——单 op 失败不影响其它。
// 批整体失败（传输/熔断/解码）→ cb(nil, err)；任一 op 的 R-6 错误在 OpResult.Error 中逐条给出。
func (c *Client) Batch(ops []Op, cb func(results []OpResult, err error)) {
	raws := make([]map[string]any, 0, len(ops))
	for _, o := range ops {
		m := map[string]any{"id": o.ID, "op": o.Op}
		for k, v := range o.Payload {
			m[k] = v
		}
		raws = append(raws, m)
	}
	c.call(OpBatch, pathBatch, nil, map[string]any{"ops": raws}, func(body []byte, err error) {
		if err != nil {
			cb(nil, err)
			return
		}
		var r struct {
			Results []map[string]any `json:"results"`
		}
		if e := c.decode(OpBatch, body, &r); e != nil {
			cb(nil, e)
			return
		}
		out := make([]OpResult, 0, len(r.Results))
		for _, item := range r.Results {
			res := OpResult{Fields: item}
			if id, ok := item["id"].(string); ok {
				res.ID = id
			}
			if eo, ok := item["error"].(map[string]any); ok {
				res.Error = &Error{Code: str(eo["code"]), Message: str(eo["message"])}
			}
			out = append(out, res)
		}
		cb(out, nil)
	})
}

// LoadCapabilities GET /v1/capabilities（§4.3.1）：启动期载入 profile/suite/mask_prg。
func (c *Client) LoadCapabilities(cb func(caps Capabilities, err error)) {
	c.callGet(OpRand, pathCapabilities, func(body []byte, err error) {
		if err != nil {
			cb(Capabilities{}, err)
			return
		}
		var caps Capabilities
		if e := c.decode("capabilities", body, &caps); e != nil {
			cb(Capabilities{}, e)
			return
		}
		c.caps = caps
		cb(caps, nil)
	})
}

// ---- wire 辅助 ----

// decodeError 解析 sidecar 错误体 `{"error":{"code","message"}}`（§4.4）。
func decodeError(status int, body []byte) *Error {
	e := &Error{Status: status, Code: CodeInternal}
	var w struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &w) == nil && w.Error.Code != "" {
		e.Code = w.Error.Code
		e.Message = w.Error.Message
	}
	return e
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
