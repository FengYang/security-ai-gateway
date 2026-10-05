package cryptop

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/emmansun/gmsm/kdf"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// sm-software 档实现：SM4-GCM / SM3 / HMAC-SM3 / SM3-KDF / SM2（协商与签名）。
//
// **合规状态（务必如实标注）**：本档为**国密算法的软件实现**，依密评 FAQ（中国密码学会密评联委会）
// "自研软件实现密码运算且无法提供安全性证明 → 判定不符合；使用长期无安全问题的第三方开源密码库
// 且正确使用 → 可酌情判定部分符合"，本档**不得用于政企合规声明**，仅限功能验证与过渡
// （见 Profile.ComplianceNote）。政企交付须使用 sm-module（认证密码模块/密码服务）。
//
// 实现依赖：github.com/emmansun/gmsm（MIT，纯 Go；固定 v0.44.1）。
// 构造说明（须写入《密码应用方案》供评估）：
//   - 载荷加密 = SM4-GCM（AEAD，12 字节 nonce；随机 nonce 由 SealWithNonce 生成）；
//   - 密钥派生 = GB/T 32918.4 KDF（以 SM3 为哈希），Z 由「共享秘密 + salt + info」以**长度前缀拼接**
//     构成，以保留与 intl 档（HKDF-SHA256）等价的密钥域分离能力；
//   - 密钥协商 = SM2 曲线的 ECDH（经 crypto/ecdh 桥接）输出的原始共享秘密，
//     **非** GB/T 32918.3 完整密钥交换流程（如后续需要该流程，须在方案中另行设计）；
//   - 签名 = SM2（GB/T 32918.2），默认用户标识 UID = "1234567812345678"，签名输出 ASN.1 DER。

const (
	smSymmetricKeySize = 16 // SM4 分组 128 位
	smBlockSize        = 16 // SM4 分组长度（CTR keystream 每块字节数）
	smNonceSize        = 12 // GCM 标准 nonce
	smHashSize         = sm3.Size
	smPrivKeySize      = 32 // SM2 私钥标量长度
	smPubKeySize       = 65 // SM2 公钥非压缩点：0x04 || X(32) || Y(32)
)

// sm2DefaultUID GB/T 32918.2 默认用户标识（签名与验签必须一致；变更须同步密码应用方案）。
var sm2DefaultUID = []byte("1234567812345678")

type smProvider struct{}

func newSMProvider() *smProvider { return &smProvider{} }

func (p *smProvider) Profile() Profile       { return ProfileSMSW }
func (p *smProvider) ComplianceNote() string { return ProfileSMSW.ComplianceNote() }
func (p *smProvider) SymmetricKeySize() int  { return smSymmetricKeySize }
func (p *smProvider) NonceSize() int         { return smNonceSize }
func (p *smProvider) HashSize() int          { return smHashSize }

func (p *smProvider) Rand(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("cryptop: Rand 长度非法")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// aead 构造 SM4-GCM。
func (p *smProvider) aead(key []byte) (cipher.AEAD, error) {
	if len(key) != smSymmetricKeySize {
		return nil, ErrInvalidKeySize
	}
	blk, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (p *smProvider) Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != smNonceSize {
		return nil, errors.New("cryptop: nonce 长度非法")
	}
	a, err := p.aead(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

func (p *smProvider) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != smNonceSize {
		return nil, errors.New("cryptop: nonce 长度非法")
	}
	a, err := p.aead(key)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func (p *smProvider) SealWithNonce(key, plaintext, aad []byte) ([]byte, []byte, error) {
	nonce, err := p.Rand(smNonceSize)
	if err != nil {
		return nil, nil, err
	}
	ct, err := p.Seal(key, nonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func (p *smProvider) Hash(data []byte) []byte {
	sum := sm3.Sum(data)
	return sum[:]
}

func (p *smProvider) HMAC(key, data []byte) []byte {
	m := hmac.New(sm3.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// KDF 以 GB/T 32918.4 KDF（SM3）为内核；Z 采用长度前缀拼接以保留密钥域分离。
func (p *smProvider) KDF(secret, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("cryptop: KDF 输出长度非法")
	}
	z := make([]byte, 0, len(secret)+8+len(salt)+len(info))
	z = append(z, secret...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(salt)))
	z = append(z, l[:]...)
	z = append(z, salt...)
	binary.BigEndian.PutUint32(l[:], uint32(len(info)))
	z = append(z, l[:]...)
	z = append(z, info...)
	return kdf.Kdf(sm3.New, z, outLen), nil
}

// Keystream sm 档：**SM4-CTR keystream**（只取流，不做认证）。
//
// 计数器块 = Hash(domain) 前 8 字节（域分离，防跨用途碰撞）‖ BE64(counter)；
// 逐块 SM4 加密计数器块取 16 字节流，counter 递增。key 长度须 = SM4 分组密钥 16B。
func (p *smProvider) Keystream(key, domain []byte, counter uint64, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("cryptop: Keystream 长度非法")
	}
	if n == 0 {
		return []byte{}, nil
	}
	if len(key) != smSymmetricKeySize {
		return nil, ErrInvalidKeySize
	}
	blk, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dh := p.Hash(domain) // SM3(domain)
	out := make([]byte, 0, n+smBlockSize)
	var ctrBlk [16]byte
	for len(out) < n {
		copy(ctrBlk[:8], dh[:8])
		binary.BigEndian.PutUint64(ctrBlk[8:], counter)
		var ks [16]byte
		blk.Encrypt(ks[:], ctrBlk[:])
		out = append(out, ks[:]...)
		counter++
	}
	return out[:n], nil
}

// pad32 左侧补零至 SM2 私钥标量长度（D.Bytes() 可能省略前导零）。
func pad32(in []byte) []byte {
	if len(in) >= smPrivKeySize {
		return in[len(in)-smPrivKeySize:]
	}
	out := make([]byte, smPrivKeySize)
	copy(out[smPrivKeySize-len(in):], in)
	return out
}

// marshalPub 将 ecdsa 公钥编码为非压缩点（0x04 || X || Y）。
func marshalPub(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func (p *smProvider) GenerateECDHKeyPair() ([]byte, []byte, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pad32(priv.D.Bytes()), marshalPub(&priv.PublicKey), nil
}

func (p *smProvider) ECDH(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != smPrivKeySize {
		return nil, errors.New("cryptop: SM2 私钥长度非法")
	}
	k, err := sm2.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	pub, err := sm2.ParseUncompressedPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	ecdhPub, err := sm2.PublicKeyToECDH(pub)
	if err != nil {
		return nil, err
	}
	// 说明：gmsm 的 ECDH 走其自带 ecdh 实现（内部映射到 P-256 曲线参数，与 SM2 曲线同参数），
	// 双方密钥类型一致，故此处无需再做曲线比对。
	return ecdhPriv.ECDH(ecdhPub)
}

func (p *smProvider) GenerateSignKeyPair() ([]byte, []byte, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pad32(priv.D.Bytes()), marshalPub(&priv.PublicKey), nil
}

func (p *smProvider) Sign(priv, msg []byte) ([]byte, error) {
	if len(priv) != smPrivKeySize {
		return nil, errors.New("cryptop: SM2 私钥长度非法")
	}
	k, err := sm2.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.SignWithSM2(rand.Reader, sm2DefaultUID, msg)
}

func (p *smProvider) Verify(pub, msg, sig []byte) error {
	k, err := sm2.ParseUncompressedPublicKey(pub)
	if err != nil {
		return err
	}
	if !sm2.VerifyASN1WithSM2(k, sm2DefaultUID, msg, sig) {
		return errors.New("cryptop: 验签失败")
	}
	return nil
}

// WrapKey 用 KEK 封装 DEK：nonce 前缀 + SM4-GCM 密文，AAD 绑定用途标签（与 intl 档同构）。
func (p *smProvider) WrapKey(kek, dek []byte) ([]byte, error) {
	nonce, ct, err := p.SealWithNonce(kek, dek, []byte("cryptop/keywrap/v1"))
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func (p *smProvider) UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) <= smNonceSize {
		return nil, ErrDecrypt
	}
	return p.Open(kek, wrapped[:smNonceSize], wrapped[smNonceSize:], []byte("cryptop/keywrap/v1"))
}
