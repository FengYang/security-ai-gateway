// Package cryptop —— P-256 验签例外（P0-4 §5.4.2 组 ⑦）。
//
// 为什么在 Provider 之外单列本函数（**不复用 Provider.Verify**）：
//   - TDX quote 由 Intel 以 **ECDSA-P256** 签名（平台可信根，不可国密化）——§5.4.2；
//   - `Provider` 的签名算法**随 profile 变**（intl=Ed25519 / sm=SM2），**无法表达"恒 P-256"**；
//   - 若把 `alg` 塞进 `Provider.Verify`，会使"算法身份随 profile"这一不变量被例外污染。
//
// 故本函数为**包级例外原语**（Provider 20 方法保持不变），语义与现役实现逐字节等价：
//   - 插件 `attest.go` / 服务 `session.go` 的 `verifyP256Sig`（`sha256(toSign)` → `ecdsa.Verify`）。
//
// ⚠️ 该例外**如实标注**（§5.4.2）：传输/应用层密码国密化，**证明链用国际算法**；密评披露边界。
package cryptop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
)

// ErrP256Verify P-256 验签失败（签名无效或公钥/签名格式不符）。
var ErrP256Verify = errors.New("cryptop: P-256 验签失败")

// VerifyP256 以 ECDSA-P256 验签（组 ⑦ 例外原语，**不随 profile 变**）。
//
// 参数：
//   - pub：SEC1 未压缩公钥（`0x04‖X(32)‖Y(32)`，65B）；
//   - msg：**原始消息**——内部以 SHA-256 摘要后验签（与现役 `sha256(toSign)`→`ecdsa.Verify` 等价）；
//   - sig：**裸签名** `r‖s`（各 32B，共 64B；非 ASN.1/DER）。
//
// 验签通过返回 nil；否则返回 ErrP256Verify。
func VerifyP256(pub, msg, sig []byte) error {
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	if x == nil {
		return ErrP256Verify
	}
	if len(sig) != 64 {
		return ErrP256Verify
	}
	h := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], r, s) {
		return ErrP256Verify
	}
	return nil
}
