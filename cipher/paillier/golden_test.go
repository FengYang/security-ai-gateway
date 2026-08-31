package paillier

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// goldenVector 黄金向量：固定密钥 + 固定随机数 r + 固定明文 → 黄金密文。
//
// 密钥在首次运行时随机生成并固化到 testdata；跨版本回归比对黄金密文，
// 任何加密/解密/密钥推导路径的漂移都会导致不匹配。
type goldenVector struct {
	Bits       int    `json:"bits"`
	N          string `json:"n"`
	G          string `json:"g"`
	Lambda     string `json:"lambda"`
	Mu         string `json:"mu"`
	P          string `json:"p"`
	Q          string `json:"q"`
	LambdaP    string `json:"lambdap"`
	MuP        string `json:"mup"`
	LambdaQ    string `json:"lambdaq"`
	MuQ        string `json:"muq"`
	R          string `json:"r"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

// goldenPath testdata 目录下的 golden 文件路径。
func goldenPath() string {
	return filepath.Join("testdata", "golden_paillier.json")
}

func bigFromHex(t *testing.T, s string) *big.Int {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex 解码失败: %v", err)
	}
	return new(big.Int).SetBytes(b)
}

// TestGoldenVector 黄金向量回归（跨版本检测密码实现漂移）。
func TestGoldenVector(t *testing.T) {
	path := goldenPath()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		// 首次运行：生成并固化基线
		pub, priv, err := GenerateKey(rand.Reader, MinBits)
		if err != nil {
			t.Fatal(err)
		}
		m := big.NewInt(987654321987654321)
		r, err := sampleR(rand.Reader, pub.N)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewCipher(pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		ct, err := c.encryptWithR(m, r)
		if err != nil {
			t.Fatal(err)
		}
		g := goldenVector{
			Bits: MinBits,
			N:    hex.EncodeToString(pub.N.Bytes()), G: hex.EncodeToString(pub.G.Bytes()),
			Lambda: hex.EncodeToString(priv.Lambda.Bytes()), Mu: hex.EncodeToString(priv.Mu.Bytes()),
			P: hex.EncodeToString(priv.P.Bytes()), Q: hex.EncodeToString(priv.Q.Bytes()),
			LambdaP: hex.EncodeToString(priv.LambdaP.Bytes()), MuP: hex.EncodeToString(priv.MuP.Bytes()),
			LambdaQ: hex.EncodeToString(priv.LambdaQ.Bytes()), MuQ: hex.EncodeToString(priv.MuQ.Bytes()),
			R: hex.EncodeToString(r.Bytes()), Plaintext: m.String(),
			Ciphertext: hex.EncodeToString(ct.Bytes()),
		}
		data, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("golden 基线已生成: %s", path)
		return
	}

	// 加载并比对
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var g goldenVector
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}

	pub := &PublicKey{N: bigFromHex(t, g.N), G: bigFromHex(t, g.G)}
	pub.NSq = new(big.Int).Mul(pub.N, pub.N)
	priv := &PrivateKey{
		Lambda: bigFromHex(t, g.Lambda), Mu: bigFromHex(t, g.Mu), N: pub.N,
		P: bigFromHex(t, g.P), Q: bigFromHex(t, g.Q),
		LambdaP: bigFromHex(t, g.LambdaP), MuP: bigFromHex(t, g.MuP),
		LambdaQ: bigFromHex(t, g.LambdaQ), MuQ: bigFromHex(t, g.MuQ),
	}
	c, err := NewCipher(pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	// 黄金密文回归
	m, ok := new(big.Int).SetString(g.Plaintext, 10)
	if !ok {
		t.Fatal("golden plaintext 解析失败")
	}
	r := bigFromHex(t, g.R)
	ct, err := c.encryptWithR(m, r)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ct.Bytes()) != g.Ciphertext {
		t.Fatal("golden 密文不匹配：加密路径发生漂移")
	}

	// 黄金密文解密回归（覆盖 CRT 路径）
	dec, err := c.Decrypt(bigFromHex(t, g.Ciphertext))
	if err != nil {
		t.Fatalf("golden 密文解密失败: %v", err)
	}
	if dec.Cmp(m) != 0 {
		t.Fatalf("golden 解密结果漂移: got=%v want=%v", dec, m)
	}
}
