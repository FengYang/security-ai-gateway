// Package shares 提供素数域上的 Shamir (t,n) 阈值秘密共享。
//
// 域 F = Z_p，p 为 256 位素数（2^256 - 2^32 - 977，secp256k1 群阶素数）。
// 域大小满足 Bonawitz CCS 2017 要求（|F| > 2^k，k 为安全参数），
// 可直接承载 256 位密钥/种子份额。
package shares

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// fieldPrime 为份额域模数 p = 2^256 - 2^32 - 977。
var fieldPrime = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 256)
	p.Sub(p, new(big.Int).Lsh(big.NewInt(1), 32))
	p.Sub(p, big.NewInt(977))
	return p
}()

// Part 为单个份额：(x, f(x))，x 为参与方索引（1..n）。
type Part struct {
	X *big.Int
	Y *big.Int
}

// MinSecretLen 秘密最小长度（字节）。
const MinSecretLen = 1

// Split 将 secret 拆为 n 份（阈值为 t）。
// secret 以 big-endian 字节表示，须小于域模数 p。
func Split(secret []byte, t, n int) ([]*Part, error) {
	if len(secret) < MinSecretLen {
		return nil, errors.New("shares: 秘密为空")
	}
	if t < 1 || n < t {
		return nil, fmt.Errorf("shares: 非法阈值参数 t=%d n=%d", t, n)
	}

	s := new(big.Int).SetBytes(secret)
	if s.Cmp(fieldPrime) >= 0 {
		return nil, errors.New("shares: 秘密超出域模数")
	}

	// 随机多项式系数 a_1..a_{t-1}
	coeffs := make([]*big.Int, t)
	coeffs[0] = s
	for i := 1; i < t; i++ {
		a, err := rand.Int(rand.Reader, fieldPrime)
		if err != nil {
			return nil, fmt.Errorf("shares: 采样系数失败: %w", err)
		}
		coeffs[i] = a
	}

	// 计算 f(x_i), x_i = i（1..n）
	parts := make([]*Part, n)
	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		y := evalPoly(coeffs, x)
		parts[i-1] = &Part{X: x, Y: y}
	}
	return parts, nil
}

// Reconstruct 由至少 t 份份额重构秘密（拉格朗日插值求 f(0)）。
func Reconstruct(parts []*Part, t int) ([]byte, error) {
	if len(parts) < t {
		return nil, fmt.Errorf("shares: 份额数 %d 少于阈值 %d", len(parts), t)
	}
	if t < 1 {
		return nil, errors.New("shares: 阈值 t 必须 ≥ 1")
	}

	// 去重 x 坐标并取前 t 份
	seen := make(map[string]bool, len(parts))
	unique := make([]*Part, 0, t)
	for _, p := range parts {
		if p == nil || p.X == nil || p.Y == nil {
			return nil, errors.New("shares: 份额字段缺失")
		}
		if p.X.Sign() <= 0 {
			return nil, errors.New("shares: 份额 x 坐标必须为正")
		}
		key := p.X.String()
		if seen[key] {
			return nil, fmt.Errorf("shares: 重复 x 坐标 %s", key)
		}
		seen[key] = true
		unique = append(unique, p)
		if len(unique) == t {
			break
		}
	}
	if len(unique) < t {
		return nil, fmt.Errorf("shares: 有效份额数 %d 少于阈值 %d", len(unique), t)
	}

	// f(0) = Σ y_i · Π_{j≠i} x_j / (x_j - x_i)
	result := new(big.Int)
	for i := 0; i < t; i++ {
		xi := unique[i].X
		yi := unique[i].Y

		num := new(big.Int).Set(yi)
		den := big.NewInt(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			xj := unique[j].X
			num.Mul(num, xj)
			num.Mod(num, fieldPrime)
			diff := new(big.Int).Sub(xj, xi)
			den.Mul(den, diff)
			den.Mod(den, fieldPrime)
		}
		denInv := new(big.Int).ModInverse(den, fieldPrime)
		if denInv == nil {
			return nil, errors.New("shares: 拉格朗日分母不可逆")
		}
		term := new(big.Int).Mul(num, denInv)
		term.Mod(term, fieldPrime)
		result.Add(result, term)
		result.Mod(result, fieldPrime)
	}

	// 输出定长 32 字节（big-endian），高位补零
	out := make([]byte, 32)
	resBytes := result.Bytes()
	copy(out[32-len(resBytes):], resBytes)
	return out, nil
}

// evalPoly 计算 f(x) = Σ coeffs[i]·x^i mod p。
func evalPoly(coeffs []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coeffs[i])
		result.Mod(result, fieldPrime)
	}
	return result
}

// FieldPrime 返回份额域模数（供测试与文档）。
func FieldPrime() *big.Int { return new(big.Int).Set(fieldPrime) }
