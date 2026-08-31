package paillier

import (
	"crypto/rand"
	"math/big"
	"sync"
	"testing"
)

// testKeys 缓存一次生成的 2048 位密钥（测试提速）。
var (
	testKeysOnce sync.Once
	testPub      *PublicKey
	testPriv     *PrivateKey
	testCipher   *Cipher
)

func setupTestKeys(t *testing.T) *Cipher {
	t.Helper()
	testKeysOnce.Do(func() {
		pub, priv, err := GenerateKey(rand.Reader, MinBits)
		if err != nil {
			t.Fatalf("测试密钥生成失败: %v", err)
		}
		c, err := NewCipher(pub, priv)
		if err != nil {
			t.Fatalf("NewCipher 失败: %v", err)
		}
		testPub, testPriv, testCipher = pub, priv, c
	})
	if testCipher == nil {
		t.Fatal("测试密钥未初始化")
	}
	return testCipher
}

func mustBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("解析大整数失败: %s", s)
	}
	return v
}

// P-01 密钥生成合法参数。
func TestGenerateKeyValid(t *testing.T) {
	for _, bits := range []int{MinBits, 3072} {
		pub, priv, err := GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("KeySize=%d 生成失败: %v", bits, err)
		}
		if pub.N.BitLen() < bits-1 {
			t.Fatalf("n 位宽 %d 不符合预期 %d", pub.N.BitLen(), bits)
		}
		if priv.Lambda == nil || priv.Mu == nil {
			t.Fatal("λ/μ 缺失")
		}
		expectedG := new(big.Int).Add(pub.N, big.NewInt(1))
		if pub.G.Cmp(expectedG) != 0 {
			t.Fatal("g 应为 n+1")
		}
	}
}

// P-02 密钥生成非法参数。
func TestGenerateKeyInvalid(t *testing.T) {
	for _, bits := range []int{0, 1, 1024, 2047, 2049, -1, -2048} {
		if _, _, err := GenerateKey(rand.Reader, bits); err == nil {
			t.Fatalf("KeySize=%d 应返回错误", bits)
		}
	}
}

// P-03 加密边界。
func TestEncryptBoundaries(t *testing.T) {
	c := setupTestKeys(t)

	m0 := big.NewInt(0)
	if _, err := c.Encrypt(m0); err != nil {
		t.Fatalf("m=0 应可加密: %v", err)
	}
	mNMinus1 := new(big.Int).Sub(c.Pub.N, big.NewInt(1))
	if _, err := c.Encrypt(mNMinus1); err != nil {
		t.Fatalf("m=n-1 应可加密: %v", err)
	}
	for _, bad := range []*big.Int{c.Pub.N, new(big.Int).Add(c.Pub.N, big.NewInt(1)), big.NewInt(-1), big.NewInt(-100)} {
		if _, err := c.Encrypt(bad); err == nil {
			t.Fatalf("明文 %v 应报错", bad)
		}
	}
}

// P-04 加密概率性。
func TestEncryptProbabilistic(t *testing.T) {
	c := setupTestKeys(t)
	m := big.NewInt(42)
	ct1, err := c.Encrypt(m)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := c.Encrypt(m)
	if err != nil {
		t.Fatal(err)
	}
	if ct1.Cmp(ct2) == 0 {
		t.Fatal("同一明文两次加密密文相同，违背概率性")
	}
}

// P-05 随机数互质校验。
func TestSampleRCoprime(t *testing.T) {
	c := setupTestKeys(t)
	for i := 0; i < 50; i++ {
		r, err := sampleR(rand.Reader, c.Pub.N)
		if err != nil {
			t.Fatal(err)
		}
		if r.Sign() <= 0 {
			t.Fatal("r 必须为正")
		}
		if r.Cmp(c.Pub.N) >= 0 {
			t.Fatal("r 必须 < n")
		}
		if new(big.Int).GCD(nil, nil, r, c.Pub.N).Cmp(big.NewInt(1)) != 0 {
			t.Fatal("r 必须与 n 互质")
		}
	}
}

// P-06 解密往返。
func TestDecryptRoundTrip(t *testing.T) {
	c := setupTestKeys(t)
	for i := 0; i < 100; i++ {
		m, err := rand.Int(rand.Reader, c.Pub.N)
		if err != nil {
			t.Fatal(err)
		}
		ct, err := c.Encrypt(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Decrypt(ct)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
		if got.Cmp(m) != 0 {
			t.Fatalf("往返不一致: got=%v want=%v", got, m)
		}
	}
}

// P-07 非法密文。
func TestDecryptInvalidCiphertext(t *testing.T) {
	c := setupTestKeys(t)
	nSq := c.Pub.NSq

	invalid := []*big.Int{
		big.NewInt(0),
		new(big.Int).Set(nSq),
		new(big.Int).Add(nSq, big.NewInt(1)),
		new(big.Int).Mul(nSq, big.NewInt(2)),
	}
	for i, ct := range invalid {
		if _, err := c.Decrypt(ct); err == nil {
			t.Fatalf("密文 #%d (%v) 应报错", i, ct)
		}
	}
	if _, err := c.Decrypt(nil); err == nil {
		t.Fatal("nil 密文应报错")
	}
}

// P-08 同态加法。
func TestHomomorphicAdd(t *testing.T) {
	c := setupTestKeys(t)
	a := big.NewInt(100)
	b := big.NewInt(200)
	ca, _ := c.Encrypt(a)
	cb, _ := c.Encrypt(b)
	csum, err := c.Add(ca, cb)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(csum)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("同态加结果错误: %v", got)
	}

	// 同态加法符合 mod n 数学性质：a+b >= n 时取模
	bigA := new(big.Int).Sub(c.Pub.N, big.NewInt(5))
	bigB := big.NewInt(10)
	cA, _ := c.Encrypt(bigA)
	cB, _ := c.Encrypt(bigB)
	cSum2, _ := c.Add(cA, cB)
	got2, _ := c.Decrypt(cSum2)
	want := new(big.Int).Mod(new(big.Int).Add(bigA, bigB), c.Pub.N)
	if got2.Cmp(want) != 0 {
		t.Fatalf("回绕取模结果错误: got=%v want=%v", got2, want)
	}
}

// P-09 同态标量乘。
func TestHomomorphicScalarMul(t *testing.T) {
	c := setupTestKeys(t)
	m := big.NewInt(7)
	cm, _ := c.Encrypt(m)

	for _, k := range []int64{0, 1, 2, 10} {
		ck, err := c.ScalarMul(cm, big.NewInt(k))
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Decrypt(ck)
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Mul(m, big.NewInt(k))
		want.Mod(want, c.Pub.N)
		if got.Cmp(want) != 0 {
			t.Fatalf("k=%d 标量乘错误: got=%v want=%v", k, got, want)
		}
	}

	if _, err := c.ScalarMul(cm, big.NewInt(-1)); err == nil {
		t.Fatal("负标量应报错")
	}
}

// P-10 解密盲化正确性（盲化开启时结果一致）。
func TestDecryptBlinding(t *testing.T) {
	c := setupTestKeys(t)
	m := mustBigInt(t, "123456789012345678901234567890")
	ct, err := c.Encrypt(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(m) != 0 {
		t.Fatalf("盲化解密结果错误: got=%v want=%v", got, m)
	}
}

// P-11 聚合回绕检测。
func TestValidatePlaintextSum(t *testing.T) {
	c := setupTestKeys(t)

	if err := c.ValidatePlaintextSum(big.NewInt(10), big.NewInt(20), big.NewInt(30)); err != nil {
		t.Fatalf("小和不应报错: %v", err)
	}

	// 构造回绕：m1 = n-1, m2 = 2 → 和 = n+1 ≥ n
	m1 := new(big.Int).Sub(c.Pub.N, big.NewInt(1))
	if err := c.ValidatePlaintextSum(m1, big.NewInt(2)); err == nil {
		t.Fatal("回绕场景应报错")
	}

	// 非法明文（负数）
	if err := c.ValidatePlaintextSum(big.NewInt(-1)); err == nil {
		t.Fatal("负明文应报错")
	}
}

// P-10b 密文范围校验在 Add/ScalarMul 中生效。
func TestHomomorphicRangeCheck(t *testing.T) {
	c := setupTestKeys(t)
	if _, err := c.Add(big.NewInt(0), big.NewInt(1)); err == nil {
		t.Fatal("c=0 密文应被 Add 拒绝")
	}
	if _, err := c.Add(big.NewInt(1), big.NewInt(0)); err == nil {
		t.Fatal("c=0 密文应被 Add 拒绝")
	}
	if _, err := c.ScalarMul(big.NewInt(0), big.NewInt(1)); err == nil {
		t.Fatal("c=0 密文应被 ScalarMul 拒绝")
	}
}

// CRT 与标准解密路径一致性（构造无 CRT 字段的兼容密钥对照）。
func TestDecryptCRTMatchesStandard(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader, MinBits)
	if err != nil {
		t.Fatal(err)
	}
	// 构造标准路径密钥（剥离 CRT 字段）
	stdPriv := &PrivateKey{Lambda: priv.Lambda, Mu: priv.Mu, N: priv.N}
	cStd, err := NewCipher(pub, stdPriv)
	if err != nil {
		t.Fatal(err)
	}
	cCRT, err := NewCipher(pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		m, _ := rand.Int(rand.Reader, pub.N)
		ct, err := cCRT.Encrypt(m)
		if err != nil {
			t.Fatal(err)
		}
		gotCRT, err := cCRT.Decrypt(ct)
		if err != nil {
			t.Fatalf("CRT 解密失败: %v", err)
		}
		gotStd, err := cStd.Decrypt(ct)
		if err != nil {
			t.Fatalf("标准解密失败: %v", err)
		}
		if gotCRT.Cmp(gotStd) != 0 {
			t.Fatalf("CRT 与标准结果不一致: crt=%v std=%v m=%v", gotCRT, gotStd, m)
		}
		if gotCRT.Cmp(m) != 0 {
			t.Fatalf("CRT 结果错误: got=%v want=%v", gotCRT, m)
		}
	}
}

// expWithTable 与 big.Int.Exp 结果一致性（固定底数表路径正确性）。
func TestExpWithTableMatches(t *testing.T) {
	c := setupTestKeys(t)
	table := c.expTable()
	for i := 0; i < 20; i++ {
		x, _ := rand.Int(rand.Reader, c.Pub.N)
		want := new(big.Int).Exp(c.Pub.G, x, c.Pub.NSq)
		got := expWithTable(x, table, c.Pub.NSq)
		if got.Cmp(want) != 0 {
			t.Fatalf("expWithTable 与 Exp 不一致: x=%v", x)
		}
	}
}

// 固定底数表并发安全（多 goroutine 懒初始化）。
func TestExpTableConcurrentInit(t *testing.T) {
	c := setupTestKeys(t)
	done := make(chan struct{}, 16)
	for i := 0; i < 16; i++ {
		go func() {
			table := c.expTable()
			if len(table) != c.Pub.N.BitLen() {
				t.Errorf("表长度 %d != %d", len(table), c.Pub.N.BitLen())
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 16; i++ {
		<-done
	}
}
