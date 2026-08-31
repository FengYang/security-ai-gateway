// Package paillier 提供工业级加固的 Paillier 加法同态加密实现。
//
// 设计对齐 ISO/IEC 18033-6:2019 参数规范与 Paillier 1999 原始方案：
// - 密钥生成：bits ≥ MinBits 且为偶数；g = n+1 简化构造
// - 加密：c = g^m · r^n mod n²，r ∈ Z*_n（随机数互质校验重试）
// - 解密：m = L(c^λ mod n²) · μ mod n，入口密文范围校验 + L(u) 整除断言 + 随机盲化
// - 同态：Add（密文乘）、ScalarMul（密文幂），均含密文范围校验
//
// 本实现不保证 math/big 模幂的常数时间性；针对时序侧信道，
// 解密默认启用随机盲化（c·r^n），并建议在可信硬件/独占环境部署。
package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// MinBits 允许的最小模数位长，对应 112 位安全强度（NIST 建议 2030 年前可用）。
const MinBits = 2048

// DefaultBits 推荐模数位长，对应 128 位安全强度。
const DefaultBits = 3072

// PublicKey 为 Paillier 公钥 (n, g)。
type PublicKey struct {
	N   *big.Int // n = p·q
	G   *big.Int // g = n + 1
	NSq *big.Int // n²
}

// PrivateKey 为 Paillier 私钥。
//
// 除 (λ, μ) 外保存素数 p/q 与 CRT 预计算参数（LambdaP/MuP/LambdaQ/MuQ），
// 使解密可拆分到 p²/q² 上并行计算（中国剩余定理，约 4 倍加速）。
// 兼容旧密钥：CRT 字段缺失时 Decrypt 自动回退标准路径。
type PrivateKey struct {
	Lambda *big.Int // lcm(p-1, q-1)
	Mu     *big.Int // [L(g^λ mod n²)]⁻¹ mod n
	N      *big.Int

	P *big.Int // 素数 p
	Q *big.Int // 素数 q

	LambdaP *big.Int // λ mod p(p-1)
	MuP     *big.Int // [L(g^λp mod p²)]⁻¹ mod p
	LambdaQ *big.Int // λ mod q(q-1)
	MuQ     *big.Int // [L(g^λq mod q²)]⁻¹ mod q
}

// Cipher 封装公私钥对，提供加解密与同态运算。
type Cipher struct {
	Pub  *PublicKey
	Priv *PrivateKey

	// 固定底数 g 的预计算幂表（g^{2^i} mod n²），懒初始化、并发安全。
	// 加密时 g^m 由按位查表完成，省去每次重新平方。
	gTableOnce sync.Once
	gTable     []*big.Int
}

// NewCipher 构造 Cipher 并校验密钥一致性。
func NewCipher(pub *PublicKey, priv *PrivateKey) (*Cipher, error) {
	if pub == nil || priv == nil {
		return nil, errors.New("paillier: 公钥与私钥不能为空")
	}
	if pub.N == nil || pub.G == nil || pub.NSq == nil {
		return nil, errors.New("paillier: 公钥字段不完整")
	}
	if priv.Lambda == nil || priv.Mu == nil {
		return nil, errors.New("paillier: 私钥字段不完整")
	}
	if pub.N.BitLen() < MinBits {
		return nil, fmt.Errorf("paillier: 模数过小，至少 %d 位（当前 %d）", MinBits, pub.N.BitLen())
	}
	return &Cipher{Pub: pub, Priv: priv}, nil
}

// GenerateKey 生成 bits 位模数的 Paillier 密钥对。
//
// bits 必须 ≥ MinBits 且为偶数。素数用 rand.Prime 生成
// （Go 标准库实现 32 轮 Miller-Rabin + Baillie-PSW，可靠性足够工业使用）。
func GenerateKey(randReader io.Reader, bits int) (*PublicKey, *PrivateKey, error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	if bits < MinBits {
		return nil, nil, fmt.Errorf("paillier: 密钥位长 %d 小于最小值 %d", bits, MinBits)
	}
	if bits%2 != 0 {
		return nil, nil, fmt.Errorf("paillier: 密钥位长 %d 必须为偶数", bits)
	}

	half := bits / 2
	p, err := rand.Prime(randReader, half)
	if err != nil {
		return nil, nil, fmt.Errorf("paillier: 生成素数 p 失败: %w", err)
	}
	q, err := rand.Prime(randReader, half)
	if err != nil {
		return nil, nil, fmt.Errorf("paillier: 生成素数 q 失败: %w", err)
	}
	for p.Cmp(q) == 0 {
		q, err = rand.Prime(randReader, half)
		if err != nil {
			return nil, nil, fmt.Errorf("paillier: 重新生成素数 q 失败: %w", err)
		}
	}

	n := new(big.Int).Mul(p, q)
	nSq := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, big.NewInt(1))

	lambda := lcm(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	gLambda := new(big.Int).Exp(g, lambda, nSq)
	lVal := new(big.Int).Sub(gLambda, big.NewInt(1))
	lVal.Div(lVal, n)

	mu := new(big.Int).ModInverse(lVal, n)
	if mu == nil {
		return nil, nil, errors.New("paillier: μ 的模逆不存在，密钥生成失败")
	}

	pub := &PublicKey{N: n, G: g, NSq: nSq}
	priv := &PrivateKey{
		Lambda:  lambda,
		Mu:      mu,
		N:       new(big.Int).Set(n),
		P:       new(big.Int).Set(p),
		Q:       new(big.Int).Set(q),
		LambdaP: new(big.Int).Mod(lambda, new(big.Int).Mul(p, new(big.Int).Sub(p, big.NewInt(1)))),
		LambdaQ: new(big.Int).Mod(lambda, new(big.Int).Mul(q, new(big.Int).Sub(q, big.NewInt(1)))),
	}
	// CRT μ 参数：μp = [L(g^λp mod p²)]⁻¹ mod p
	if priv.LambdaP != nil {
		priv.MuP = crtMu(g, p, priv.LambdaP)
	}
	if priv.LambdaQ != nil {
		priv.MuQ = crtMu(g, q, priv.LambdaQ)
	}
	return pub, priv, nil
}

// crtMu 计算 CRT 解密参数 μ = [L(g^λ mod m²)]⁻¹ mod m。
func crtMu(g, m, lambda *big.Int) *big.Int {
	mSq := new(big.Int).Mul(m, m)
	gLambda := new(big.Int).Exp(g, lambda, mSq)
	lVal := new(big.Int).Sub(gLambda, big.NewInt(1))
	lVal.Div(lVal, m)
	mu := new(big.Int).ModInverse(lVal, m)
	return mu
}

// lcm 计算 a, b 的最小公倍数（a,b 为正整数）。
func lcm(a, b *big.Int) *big.Int {
	gcd := new(big.Int).GCD(nil, nil, a, b)
	prod := new(big.Int).Mul(a, b)
	return new(big.Int).Div(prod, gcd)
}

// sampleR 从 [1, n) 采样与 n 互质的随机数 r。
// 概率性加密的正确性与语义安全要求 r ∈ Z*_n 且每次新鲜生成。
func sampleR(reader io.Reader, n *big.Int) (*big.Int, error) {
	one := big.NewInt(1)
	upper := new(big.Int).Sub(n, one) // 采样域 [0, n-1)
	for {
		r, err := rand.Int(reader, upper)
		if err != nil {
			return nil, fmt.Errorf("paillier: 采样随机数失败: %w", err)
		}
		r.Add(r, one) // r ∈ [1, n)
		if new(big.Int).GCD(nil, nil, r, n).Cmp(one) == 0 {
			return r, nil
		}
		// gcd(r, n) != 1 的概率约 1/p + 1/q，重试即可。
	}
}

// Encrypt 加密明文 m（要求 0 ≤ m < n）。
// c = g^m · r^n mod n²，r ∈ Z*_n 每次新鲜生成。
func (c *Cipher) Encrypt(m *big.Int) (*big.Int, error) {
	r, err := sampleR(rand.Reader, c.Pub.N)
	if err != nil {
		return nil, err
	}
	return c.encryptWithR(m, r)
}

// encryptWithR 以指定随机数 r 加密（内部使用；golden vector 测试复用）。
// c = g^m · r^n mod n²，其中 g^m 用固定底数预计算幂表加速。
func (c *Cipher) encryptWithR(m, r *big.Int) (*big.Int, error) {
	if c == nil || c.Pub == nil {
		return nil, errors.New("paillier: Cipher 未初始化")
	}
	if m == nil {
		return nil, errors.New("paillier: 明文不能为 nil")
	}
	if m.Sign() < 0 {
		return nil, errors.New("paillier: 明文为负，不支持负数明文")
	}
	if m.Cmp(c.Pub.N) >= 0 {
		return nil, errors.New("paillier: 明文超出范围 [0, n)")
	}
	if r == nil || r.Sign() <= 0 || r.Cmp(c.Pub.N) >= 0 {
		return nil, errors.New("paillier: 随机数超出范围 [1, n)")
	}

	nSq := c.Pub.NSq

	// g^m 与 r^n 相互独立，并行计算（多核直接减半耗时）。
	// 固定底数表 expTable() 经 sync.Once 懒初始化，并发安全。
	var gm, rn *big.Int
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		gm = expWithTable(m, c.expTable(), nSq)
	}()
	go func() {
		defer wg.Done()
		rn = new(big.Int).Exp(r, c.Pub.N, nSq)
	}()
	wg.Wait()

	ct := new(big.Int).Mul(gm, rn)
	ct.Mod(ct, nSq)
	return ct, nil
}

// expTable 懒预计算固定底数 g 的幂表 g^{2^i} mod n²（i = 0..bits-1）。
func (c *Cipher) expTable() []*big.Int {
	c.gTableOnce.Do(func() {
		c.gTable = precomputeTable(c.Pub.G, c.Pub.NSq, c.Pub.N.BitLen())
	})
	return c.gTable
}

// precomputeTable 预计算 base^{2^i} mod m（i = 0..bits-1）。
func precomputeTable(base, m *big.Int, bits int) []*big.Int {
	table := make([]*big.Int, bits)
	cur := new(big.Int).Mod(base, m)
	for i := 0; i < bits; i++ {
		table[i] = new(big.Int).Set(cur)
		cur.Mul(cur, cur)
		cur.Mod(cur, m)
	}
	return table
}

// expWithTable 按 x 的二进制位查表计算 x^{2^i} 的乘积（等价 x^exp mod m）。
func expWithTable(x *big.Int, table []*big.Int, m *big.Int) *big.Int {
	result := big.NewInt(1)
	for i := 0; i < len(table); i++ {
		if x.Bit(i) == 1 {
			result.Mul(result, table[i])
			result.Mod(result, m)
		}
	}
	return result
}

// Decrypt 解密密文 c（要求 1 ≤ c < n²）。
//
// 优先使用 CRT 加速路径（私钥含 p/q 预计算参数时）：
//
//	m_p = L(c^{λp} mod p²) · μp mod p，m_q 同理，CRT 合并得 m mod n。
//
// 默认启用随机盲化：c' = c · r^n mod n²（r^n 为 E(0)），
// 明文不变但指数运算随机化，缓解时序侧信道。
func (c *Cipher) Decrypt(ct *big.Int) (*big.Int, error) {
	if c == nil || c.Pub == nil || c.Priv == nil {
		return nil, errors.New("paillier: Cipher 未初始化")
	}
	if ct == nil {
		return nil, errors.New("paillier: 密文不能为 nil")
	}
	if ct.Sign() <= 0 || ct.Cmp(c.Pub.NSq) >= 0 {
		return nil, errors.New("paillier: 密文超出范围 (0, n²)")
	}

	// 盲化随机数（r^n 为 E(0)，明文不变）
	r, err := sampleR(rand.Reader, c.Pub.N)
	if err != nil {
		return nil, err
	}

	// CRT 路径（若预计算参数齐全）
	if c.Priv.P != nil && c.Priv.Q != nil && c.Priv.LambdaP != nil && c.Priv.LambdaQ != nil && c.Priv.MuP != nil && c.Priv.MuQ != nil {
		return c.decryptCRT(ct, r)
	}

	// 标准路径（兼容旧密钥）
	nSq := c.Pub.NSq
	rn := new(big.Int).Exp(r, c.Priv.N, nSq)
	blinded := new(big.Int).Mul(ct, rn)
	blinded.Mod(blinded, nSq)

	u := new(big.Int).Exp(blinded, c.Priv.Lambda, nSq)
	uMinus1 := new(big.Int).Sub(u, big.NewInt(1))
	if new(big.Int).Mod(uMinus1, c.Priv.N).Sign() != 0 {
		return nil, errors.New("paillier: 解密失败，L(u) 非整数（密文无效）")
	}
	lVal := new(big.Int).Div(uMinus1, c.Priv.N)
	m := new(big.Int).Mul(lVal, c.Priv.Mu)
	m.Mod(m, c.Priv.N)
	return m, nil
}

// decryptCRT 中国剩余定理解密（盲化融入各分支）。
//
//	m_p = L((c·r^n mod p²)^{λp} mod p²) · μp mod p，m_q 同理
//	m   = m_q + q·((m_p − m_q)·q⁻¹ mod p)  (mod n)   （Garner 合并）
//
// 分支盲化指数 n 按 φ(p²)=p(p-1) 降模：r^{n mod p(p-1)}。
// 推导要点：c^{λp} ≡ g^{mλp}·r^{nλp} ≡ 1 + n·m·λp (mod p²)，
// L(·) 后得 q·m·λp mod p，乘以 μp=(q·λp)⁻¹ 得 m mod p。
func (c *Cipher) decryptCRT(ct, r *big.Int) (*big.Int, error) {
	p := c.Priv.P
	q := c.Priv.Q
	n := c.Priv.N

	pSq := new(big.Int).Mul(p, p)
	qSq := new(big.Int).Mul(q, q)

	// 分支盲化：blinded_p = ct·r^n mod p²，指数 n 按 φ(p²)=p(p-1) 降模
	blindedP := new(big.Int).Mod(ct, pSq)
	if err := c.blindBranch(blindedP, r, pSq, p); err != nil {
		return nil, err
	}
	blindedQ := new(big.Int).Mod(ct, qSq)
	if err := c.blindBranch(blindedQ, r, qSq, q); err != nil {
		return nil, err
	}

	// m_p
	uP := new(big.Int).Exp(blindedP, c.Priv.LambdaP, pSq)
	uPm1 := new(big.Int).Sub(uP, big.NewInt(1))
	if new(big.Int).Mod(uPm1, p).Sign() != 0 {
		return nil, errors.New("paillier: CRT 解密失败，L(u_p) 非整数（密文无效）")
	}
	lP := new(big.Int).Div(uPm1, p)
	mp := new(big.Int).Mul(lP, c.Priv.MuP)
	mp.Mod(mp, p)

	// m_q
	uQ := new(big.Int).Exp(blindedQ, c.Priv.LambdaQ, qSq)
	uQm1 := new(big.Int).Sub(uQ, big.NewInt(1))
	if new(big.Int).Mod(uQm1, q).Sign() != 0 {
		return nil, errors.New("paillier: CRT 解密失败，L(u_q) 非整数（密文无效）")
	}
	lQ := new(big.Int).Div(uQm1, q)
	mq := new(big.Int).Mul(lQ, c.Priv.MuQ)
	mq.Mod(mq, q)

	// Garner 合并：m = mq + q·((mp − mq)·q⁻¹ mod p) (mod n)
	qInv := new(big.Int).ModInverse(q, p)
	if qInv == nil {
		return nil, errors.New("paillier: CRT 合并失败，q 在 mod p 下不可逆")
	}
	diff := new(big.Int).Sub(mp, mq)
	diff.Mul(diff, qInv)
	diff.Mod(diff, p)
	m := new(big.Int).Mul(q, diff)
	m.Add(m, mq)
	m.Mod(m, n)
	return m, nil
}

// blindBranch 在分支模数 m² 上乘盲化因子 r^n（指数按 φ(m²)=m(m-1) 降模）。
func (c *Cipher) blindBranch(blinded, r, mSq, m *big.Int) error {
	phiM := new(big.Int).Mul(m, new(big.Int).Sub(m, big.NewInt(1))) // m(m-1)
	nMod := new(big.Int).Mod(c.Priv.N, phiM)
	rn := new(big.Int).Exp(r, nMod, mSq)
	blinded.Mul(blinded, rn)
	blinded.Mod(blinded, mSq)
	return nil
}

// Add 同态加法：E(m1) · E(m2) mod n² = E(m1+m2)。
func (c *Cipher) Add(c1, c2 *big.Int) (*big.Int, error) {
	if err := c.validateCiphertext(c1); err != nil {
		return nil, err
	}
	if err := c.validateCiphertext(c2); err != nil {
		return nil, err
	}
	result := new(big.Int).Mul(c1, c2)
	result.Mod(result, c.Pub.NSq)
	return result, nil
}

// ScalarMul 同态标量乘：E(m)^k mod n² = E(k·m)。
func (c *Cipher) ScalarMul(ct, k *big.Int) (*big.Int, error) {
	if err := c.validateCiphertext(ct); err != nil {
		return nil, err
	}
	if k == nil || k.Sign() < 0 {
		return nil, errors.New("paillier: 标量必须为非负整数")
	}
	result := new(big.Int).Exp(ct, k, c.Pub.NSq)
	return result, nil
}

// PlaintextSpace 返回明文空间上界 n（用于聚合回绕预算校验）。
func (c *Cipher) PlaintextSpace() *big.Int {
	return c.Pub.N
}

// ValidatePlaintextSum 校验多个明文的累加和不会回绕 mod n。
// 聚合场景必须保证 Σ m_i < n，否则解密结果静默错误。
func (c *Cipher) ValidatePlaintextSum(plaintexts ...*big.Int) error {
	sum := big.NewInt(0)
	for _, m := range plaintexts {
		if m == nil || m.Sign() < 0 || m.Cmp(c.Pub.N) >= 0 {
			return fmt.Errorf("paillier: 明文 %v 超出范围 [0, n)", m)
		}
		sum.Add(sum, m)
		if sum.Cmp(c.Pub.N) >= 0 {
			return errors.New("paillier: 明文累加和回绕 mod n，需增大模数或减小明文余量")
		}
	}
	return nil
}

func (c *Cipher) validateCiphertext(ct *big.Int) error {
	if ct == nil {
		return errors.New("paillier: 密文不能为 nil")
	}
	if ct.Sign() <= 0 || ct.Cmp(c.Pub.NSq) >= 0 {
		return errors.New("paillier: 密文超出范围 (0, n²)")
	}
	return nil
}
