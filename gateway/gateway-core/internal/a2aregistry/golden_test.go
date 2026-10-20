package a2aregistry

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenVector 是官方跨 SDK 固定向量（a2acrypto/testdata/golden.json 结构）。
type goldenVector struct {
	Kid          string          `json:"kid"`
	SeedHex      string          `json:"ed25519_seed_hex"`
	CardJSON     json.RawMessage `json:"card_json_unsigned"`
	ProtectedB64 string          `json:"protected_b64"`
	SignatureB64 string          `json:"signature_b64"`
}

// loadGolden 读取官方跨 SDK 固定向量；模块缓存不可用时返回 ok=false（调用方跳过）。
//
// ⚠️ 定位方式：GOMODCACHE（环境变量或 $HOME/go/pkg/mod 默认布局）→
// github.com/a2aproject/a2a-go/v2@v2.6.0/a2acrypto/testdata/golden.json。
func loadGolden(t *testing.T) (goldenVector, bool) {
	t.Helper()
	for _, dir := range candidateGoldenDirs() {
		raw, err := os.ReadFile(filepath.Join(dir, "golden.json"))
		if err != nil {
			continue
		}
		var g goldenVector
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatalf("解析 golden.json 失败: %v", err)
		}
		return g, true
	}
	return goldenVector{}, false
}

// candidateGoldenDirs 枚举 a2acrypto/testdata 的可能位置。
func candidateGoldenDirs() []string {
	var out []string
	if mc := os.Getenv("GOMODCACHE"); mc != "" {
		out = append(out, filepath.Join(mc, "github.com", "a2aproject", "a2a-go", "v2@v2.6.0", "a2acrypto", "testdata"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, "go", "pkg", "mod", "github.com", "a2aproject", "a2a-go", "v2@v2.6.0", "a2acrypto", "testdata"))
	}
	return out
}

// ed25519FromSeed 由种子构造 Ed25519 私钥。
func ed25519FromSeed(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("解析 seed 失败: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed 长度非法: %d", len(seed))
	}
	return ed25519.NewKeyFromSeed(seed)
}
