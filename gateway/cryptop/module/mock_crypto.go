package cryptopmodule

// mock_crypto.go —— MockBackend 的软件国密原语（gmsm 委托）。
//
// **合规声明**：本文件为 mock（功能验证）后端提供软件密码运算，**不满足密评**
// （自研/软件实现无法提供安全性证明）；生产路径的运算必须在认证模块内执行（C-4）。
// 与 sm-software 档（gateway/cryptop/sm.go）保持算法参数一致（KDF 的 Z 拼接、
// SM2 默认 UID、WrapKey 的 AAD 域标签），使适配层 KAT 可与软件档交叉验签（V-4）。

import (
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/kdf"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

const (
	mockSymKeySize = 16 // SM4 128 位
	mockNonceSize  = 12 // GCM nonce
	mockPrivSize   = 32 // SM2 私钥标量
	// mockSM2UID 默认用户标识（与 sm.go:45 / §6.4 module_sm2_uid 缺省一致）。
	mockSM2UID = "1234567812345678"
	// mockWrapAAD WrapKey/UnwrapKey 的用途绑定标签（与 sm.go 一致）。
	mockWrapAAD = "cryptop/keywrap/v1"
)

var errMockKeySize = errors.New("mock: 密钥长度非法")

func mockSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	a, err := mockAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != mockNonceSize {
		return nil, errors.New("mock: nonce 长度非法")
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

func mockOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	a, err := mockAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != mockNonceSize {
		return nil, errors.New("mock: nonce 长度非法")
	}
	pt, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("mock: 解密失败（认证标签不符）")
	}
	return pt, nil
}

func mockAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != mockSymKeySize {
		return nil, errMockKeySize
	}
	blk, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func mockHash(data []byte) ([]byte, error) {
	sum := sm3.Sum(data)
	return sum[:], nil
}

func mockHMAC(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errMockKeySize
	}
	m := hmac.New(sm3.New, key)
	m.Write(data)
	return m.Sum(nil), nil
}

// mockKDF 与 sm.go 相同的 Z 构造（长度前缀拼接）——保跨档一致。
func mockKDF(secret, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("mock: KDF 输出长度非法")
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

func mockRand(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("mock: Rand 长度非法")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// mockPad32 左侧补零至 SM2 私钥标量长度。
func mockPad32(in []byte) []byte {
	if len(in) >= mockPrivSize {
		return in[len(in)-mockPrivSize:]
	}
	out := make([]byte, mockPrivSize)
	copy(out[mockPrivSize-len(in):], in)
	return out
}

func mockGenerateKeyPair() (priv, pub []byte, err error) {
	k, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return mockPad32(k.D.Bytes()), elliptic.Marshal(k.Curve, k.X, k.Y), nil
}

func mockSign(priv, msg []byte, uid string) ([]byte, error) {
	if len(priv) != mockPrivSize {
		return nil, errors.New("mock: SM2 私钥长度非法")
	}
	if uid == "" {
		uid = mockSM2UID
	}
	k, err := sm2.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.SignWithSM2(rand.Reader, []byte(uid), msg)
}

func mockVerify(pub, msg, sig []byte, uid string) error {
	if uid == "" {
		uid = mockSM2UID
	}
	k, err := sm2.ParseUncompressedPublicKey(pub)
	if err != nil {
		return err
	}
	if !sm2.VerifyASN1WithSM2(k, []byte(uid), msg, sig) {
		return errors.New("mock: 验签失败")
	}
	return nil
}

// mockECDH 与 sm.go 的 ECDH 同构（gmsm ecdh 桥接；SM2 与所用曲线同参数）。
func mockECDH(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != mockPrivSize {
		return nil, errors.New("mock: SM2 私钥长度非法")
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
	return ecdhPriv.ECDH(ecdhPub)
}
