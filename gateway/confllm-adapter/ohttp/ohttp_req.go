// ohttp_req.go — RFC 9458 Oblivious HTTP 请求/响应封装（M8-1，技术方案 §5.5）。
//
// 依据 RFC 9458 §4.3/§4.4（封装算法逐字对齐）：
//
//	请求：hdr = key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)（网络字节序）
//	      info = "message/bhttp request" || 0x00 || hdr
//	      enc, sctxt = SetupBaseS(pkR, info)；ct = sctxt.Seal("", bhttp_request)
//	      enc_request = hdr || enc || ct
//	响应：secret = context.Export("message/bhttp response", max(Nn, Nk))
//	      response_nonce = random(max(Nn, Nk))；salt = enc || response_nonce
//	      prk = Extract(salt, secret)；aead_key = Expand(prk, "key", Nk)；
//	      aead_nonce = Expand(prk, "nonce", Nn)；ct = Seal(aead_key, aead_nonce, "", bhttp_response)
//	      enc_response = response_nonce || ct
//
// hpkeInfo 方向化约定（M8-2 / 技术方案 §5.5 判据 2）：请求侧 "message/bhttp request"、
// 响应侧 "message/bhttp response"；安装期参数 OHTTP_INFO_REQ / OHTTP_INFO_RES 可覆写
// （默认 RFC 值；Azure 机密推理侧对齐点——未确认前默认 RFC 值并在集成文档标注）。
//
// 算法栈（与 ohttp.go HPKE 核心一致）：DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM。
package ohttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"

	"crypto/hpke"
)

// info 前缀（RFC 9458 §4.3/§4.4；OHTTP_INFO_REQ/OHTTP_INFO_RES 可覆写）。
func ohttpInfoReq() string {
	if v := os.Getenv("OHTTP_INFO_REQ"); v != "" {
		return v
	}
	return "message/bhttp request"
}

func ohttpInfoRes() string {
	if v := os.Getenv("OHTTP_INFO_RES"); v != "" {
		return v
	}
	return "message/bhttp response"
}

// HPKE 算法 ID（RFC 9180 §7.1；标准库无导出常量，按 NewKEM/NewKDF/NewAEAD 契约登记）。
const (
	kemIDX25519HKDFSHA256 = 0x0020
	kdfIDHKDFSHA256       = 0x0001
	kdfIDHKDFSHA384       = 0x0002
	kdfIDHKDFSHA512       = 0x0003
	aeadIDAES128GCM       = 0x0001
	aeadIDAES256GCM       = 0x0002
	aeadIDChaCha20        = 0x0003
)

// KeyConfig OHTTP 密钥配置（RFC 9458 §3；技术方案 §5.5 判据 3 结构定版）。
type KeyConfig struct {
	KeyID     byte
	KEM       uint16 // HPKE KEM ID
	KDF       uint16 // HPKE KDF ID
	AEAD      uint16 // HPKE AEAD ID
	PublicKey []byte // 接收方 HPKE 公钥（SerializePublicKey 输出）
}

// Encode 序列化：key_id(1) | kem_id(2) | kdf_id(2) | aead_id(2) | public key。
func (kc KeyConfig) Encode() []byte {
	out := make([]byte, 0, 7+len(kc.PublicKey))
	out = append(out, kc.KeyID)
	out = binary.BigEndian.AppendUint16(out, kc.KEM)
	out = binary.BigEndian.AppendUint16(out, kc.KDF)
	out = binary.BigEndian.AppendUint16(out, kc.AEAD)
	return append(out, kc.PublicKey...)
}

// ParseKeyConfig 解析 Encode 输出（往返互逆）。
func ParseKeyConfig(b []byte) (KeyConfig, error) {
	if len(b) < 7 {
		return KeyConfig{}, errors.New("ohttp: key config 截断（<7 字节头）")
	}
	kc := KeyConfig{
		KeyID: b[0],
		KEM:   binary.BigEndian.Uint16(b[1:3]),
		KDF:   binary.BigEndian.Uint16(b[3:5]),
		AEAD:  binary.BigEndian.Uint16(b[5:7]),
	}
	kc.PublicKey = append([]byte(nil), b[7:]...)
	return kc, nil
}

// DefaultKeyConfig 当前栈的缺省 key config（X25519 + HKDF-SHA256 + AES-128-GCM）。
func DefaultKeyConfig(keyID byte, publicKey []byte) KeyConfig {
	return KeyConfig{KeyID: keyID, KEM: kemIDX25519HKDFSHA256, KDF: kdfIDHKDFSHA256, AEAD: aeadIDAES128GCM, PublicKey: publicKey}
}

// aeadParams AEAD 参数（Nk 密钥长 / Nn nonce 长）。
func aeadParams(id uint16) (nk, nn int, err error) {
	switch id {
	case aeadIDAES128GCM:
		return 16, 12, nil
	case aeadIDAES256GCM:
		return 32, 12, nil
	case aeadIDChaCha20:
		return 32, 12, nil
	default:
		return 0, 0, fmt.Errorf("ohttp: 不支持的 AEAD ID 0x%04x", id)
	}
}

// kemNenc KEM 封装密钥长度（解析 enc_request 时定位 enc 边界）。
func kemNenc(id uint16) (int, error) {
	switch id {
	case kemIDX25519HKDFSHA256:
		return 32, nil
	default:
		return 0, fmt.Errorf("ohttp: 不支持的 KEM ID 0x%04x（当前栈：X25519）", id)
	}
}

// kdfHash KDF ID → hash 构造器（响应派生的 Extract/Expand 用）。
func kdfHash(id uint16) (func() hash.Hash, error) {
	switch id {
	case kdfIDHKDFSHA256:
		return sha256.New, nil
	case kdfIDHKDFSHA384:
		return sha512.New384, nil
	case kdfIDHKDFSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("ohttp: 不支持的 KDF ID 0x%04x", id)
	}
}

// hkdfExtractRFC / hkdfExpandRFC：RFC 5869 标准 HKDF（OHTTP 响应派生用**普通** Extract/Expand，
// 非 RFC 9180 内部 labeled 变体——RFC 9458 §4.4 明确使用 KDF 自身的 Extract/Expand 函数）。
func hkdfExtractRFC(h func() hash.Hash, salt, ikm []byte) []byte {
	m := hmac.New(h, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpandRFC(h func() hash.Hash, prk, info []byte, length int) ([]byte, error) {
	outLen := h().Size()
	if length > 255*outLen {
		return nil, errors.New("ohttp: HKDF-Expand 长度超限")
	}
	var t, out []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(h, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length], nil
}

// buildInfo 组装 HPKE info：前缀 || 0x00 || hdr（RFC 9458 §4.3 步骤 2）。
func buildInfo(prefix string, hdr []byte) []byte {
	info := make([]byte, 0, len(prefix)+1+len(hdr))
	info = append(info, prefix...)
	info = append(info, 0x00)
	return append(info, hdr...)
}

// buildHdr 组装 hdr（key_id + kem_id + kdf_id + aead_id，网络字节序）。
func buildHdr(kc KeyConfig) []byte {
	hdr := make([]byte, 0, 7)
	hdr = append(hdr, kc.KeyID)
	hdr = binary.BigEndian.AppendUint16(hdr, kc.KEM)
	hdr = binary.BigEndian.AppendUint16(hdr, kc.KDF)
	hdr = binary.BigEndian.AppendUint16(hdr, kc.AEAD)
	return hdr
}

// ---------- 客户端（client → gateway/target 方向） ----------

// SealedRequest 已封装请求的客户端侧上下文（复用 sctxt 解密响应，RFC 9458 §4.4）。
type SealedRequest struct {
	enc    []byte
	sender *hpke.Sender
	kdfID  uint16
	aeadID uint16
}

// SealRequest 单次调用便捷封装（技术方案 §5.5 接口冻结基线签名）。
// 返回 enc_request = hdr || enc || ct（媒体类型 message/ohttp-req）。
func SealRequest(cfg KeyConfig, inner []byte) (msg []byte, err error) {
	_, msg, err = SealRequestWithState(cfg, inner)
	return msg, err
}

// SealRequestWithState 封装请求并保留客户端上下文（用于响应解密）。
func SealRequestWithState(cfg KeyConfig, inner []byte) (*SealedRequest, []byte, error) {
	kem, err := hpke.NewKEM(cfg.KEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: KEM 0x%04x 不可用: %w", cfg.KEM, err)
	}
	kdf, err := hpke.NewKDF(cfg.KDF)
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: KDF 0x%04x 不可用: %w", cfg.KDF, err)
	}
	aead, err := hpke.NewAEAD(cfg.AEAD)
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: AEAD 0x%04x 不可用: %w", cfg.AEAD, err)
	}
	pk, err := kem.NewPublicKey(cfg.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: 解析接收方公钥失败: %w", err)
	}
	hdr := buildHdr(cfg)
	info := buildInfo(ohttpInfoReq(), hdr)
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: HPKE SetupBaseS 失败: %w", err)
	}
	ct, err := sender.Seal(nil, inner) // aad = ""（RFC 9458 §4.3 步骤 4）
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: HPKE seal 失败: %w", err)
	}
	msg := make([]byte, 0, len(hdr)+len(enc)+len(ct))
	msg = append(msg, hdr...)
	msg = append(msg, enc...)
	msg = append(msg, ct...)
	return &SealedRequest{enc: enc, sender: sender, kdfID: cfg.KDF, aeadID: cfg.AEAD}, msg, nil
}

// OpenResponse 解密 enc_response（RFC 9458 §4.4 客户端方向：复用发送上下文派生）。
func (sr *SealedRequest) OpenResponse(encResp []byte) ([]byte, error) {
	if sr == nil || sr.sender == nil {
		return nil, errors.New("ohttp: 无发送上下文")
	}
	nk, nn, err := aeadParams(sr.aeadID)
	if err != nil {
		return nil, err
	}
	nLen := nk
	if nn > nLen {
		nLen = nn
	}
	if len(encResp) < nLen {
		return nil, errors.New("ohttp: 响应截断（nonce 段）")
	}
	responseNonce := encResp[:nLen]
	ct := encResp[nLen:]
	key, nonce, err := deriveResponseKeys(sr.sender, sr.enc, responseNonce, sr.kdfID, nLen, nk, nn)
	if err != nil {
		return nil, err
	}
	return aeadOpen(key, nonce, ct, sr.aeadID)
}

// deriveResponseKeys RFC 9458 §4.4 派生（context 为发送或接收 HPKE 上下文，双侧共用）。
// exportLen = max(Nn, Nk)（export 秘密长度）；nk/nn 为 AEAD 密钥/nonce 长度。
func deriveResponseKeys(ctx interface {
	Export(exporterContext string, length int) ([]byte, error)
}, enc, responseNonce []byte, kdfID uint16, exportLen, nk, nn int) (key, nonce []byte, err error) {
	h, err := kdfHash(kdfID)
	if err != nil {
		return nil, nil, err
	}
	secret, err := ctx.Export(ohttpInfoRes(), exportLen)
	if err != nil {
		return nil, nil, fmt.Errorf("ohttp: HPKE export 失败: %w", err)
	}
	salt := make([]byte, 0, len(enc)+len(responseNonce))
	salt = append(salt, enc...)
	salt = append(salt, responseNonce...)
	prk := hkdfExtractRFC(h, salt, secret)
	key, err = hkdfExpandRFC(h, prk, []byte("key"), nk)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = hkdfExpandRFC(h, prk, []byte("nonce"), nn)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// aeadOpen 以显式 key/nonce 打开 AEAD 密文。
func aeadOpen(key, nonce, ct []byte, aeadID uint16) ([]byte, error) {
	switch aeadID {
	case aeadIDAES128GCM, aeadIDAES256GCM:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		return g.Open(nil, nonce, ct, nil)
	case aeadIDChaCha20:
		return nil, errors.New("ohttp: ChaCha20Poly1305 响应方向暂未接线（当前栈 AES-GCM）")
	default:
		return nil, fmt.Errorf("ohttp: 未知 AEAD ID 0x%04x", aeadID)
	}
}

// ---------- 接收方（gateway/target 方向） ----------

// ResponseSealer 接收方上下文（复用 rctxt 加密响应，RFC 9458 §4.4）。
type ResponseSealer struct {
	enc    []byte
	rctx   *hpke.Recipient
	kdfID  uint16
	aeadID uint16
}

// OpenRequest 解封 enc_request（技术方案 §5.5 接口冻结基线签名）。
func OpenRequest(priv hpke.PrivateKey, msg []byte) (keyID byte, inner []byte, err error) {
	keyID, inner, _, err = OpenRequestResponder(priv, msg)
	return keyID, inner, err
}

// OpenRequestResponder 解封 enc_request 并保留接收方上下文（用于加密响应）。
func OpenRequestResponder(priv hpke.PrivateKey, msg []byte) (keyID byte, inner []byte, resp *ResponseSealer, err error) {
	if len(msg) < 7 {
		return 0, nil, nil, errors.New("ohttp: enc_request 截断（<7 字节头）")
	}
	keyID = msg[0]
	kemID := binary.BigEndian.Uint16(msg[1:3])
	kdfID := binary.BigEndian.Uint16(msg[3:5])
	aeadID := binary.BigEndian.Uint16(msg[5:7])
	nenc, err := kemNenc(kemID)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(msg) < 7+nenc {
		return 0, nil, nil, errors.New("ohttp: enc_request 截断（enc 段）")
	}
	enc := msg[7 : 7+nenc]
	ct := msg[7+nenc:]

	kdf, err := hpke.NewKDF(kdfID)
	if err != nil {
		return 0, nil, nil, err
	}
	aead, err := hpke.NewAEAD(aeadID)
	if err != nil {
		return 0, nil, nil, err
	}
	hdr := msg[:7]
	info := buildInfo(ohttpInfoReq(), hdr)
	rctx, err := hpke.NewRecipient(enc, priv, kdf, aead, info)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("ohttp: HPKE SetupBaseR 失败: %w", err)
	}
	inner, err = rctx.Open(nil, ct)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("ohttp: HPKE open 失败: %w", err)
	}
	return keyID, inner, &ResponseSealer{enc: enc, rctx: rctx, kdfID: kdfID, aeadID: aeadID}, nil
}

// SealResponse 加密响应（RFC 9458 §4.4 gateway 方向），返回 enc_response = response_nonce || ct。
func (rs *ResponseSealer) SealResponse(inner []byte) ([]byte, error) {
	if rs == nil || rs.rctx == nil {
		return nil, errors.New("ohttp: 无接收上下文")
	}
	nk, nn, err := aeadParams(rs.aeadID)
	if err != nil {
		return nil, err
	}
	nLen := nk
	if nn > nLen {
		nLen = nn
	}
	// response_nonce 参与派生（salt = enc || response_nonce），先取随机值再派生。
	responseNonce := make([]byte, nLen)
	if _, err := rand.Read(responseNonce); err != nil {
		return nil, fmt.Errorf("ohttp: 生成 response_nonce 失败: %w", err)
	}
	key, nonce, err := deriveResponseKeys(rs.rctx, rs.enc, responseNonce, rs.kdfID, nLen, nk, nn)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, inner, nil)
	out := make([]byte, 0, nLen+len(ct))
	out = append(out, responseNonce...)
	return append(out, ct...), nil
}
