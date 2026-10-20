package a2aregistry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2acrypto"
)

// TestJCSMatchesA2ACrypto 断言本仓库的 JCS 实现与 a2acrypto.canonicalizeJSON
// **逐字节一致**（冻结 §3.5）。
//
// 验证方法（不依赖上游未导出函数）：
//  1. 用 a2acrypto.Signer 对固定卡向量签名——其 payload 来自 canonicalizeJSON；
//  2. 用本仓库的 canonicalJSON 独立生成 payload；
//  3. 拼装 JWS signing input 后用 Ed25519 公钥直接验签——
//     验签通过 ⟺ 两边 payload 字节完全相同（任一字节不同即验签失败）。
func TestJCSMatchesA2ACrypto(t *testing.T) {
	g, ok := loadGolden(t)
	if !ok {
		t.Skip("a2acrypto 官方固定向量不可用（模块缓存缺失），跳过")
	}
	priv := ed25519FromSeed(t, g.SeedHex)

	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: priv,
		KeyID:      g.Kid,
		Algorithm:  "EdDSA",
	})
	if err != nil {
		t.Fatalf("构造 a2acrypto.Signer 失败: %v", err)
	}
	sig, err := signer.Sign(context.Background(), g.CardJSON)
	if err != nil {
		t.Fatalf("a2acrypto 签名失败: %v", err)
	}
	if sig.Protected != g.ProtectedB64 {
		t.Fatalf("protected 与官方向量不一致：got %s want %s", sig.Protected, g.ProtectedB64)
	}
	if sig.Signature != g.SignatureB64 {
		t.Fatalf("signature 与官方向量不一致：got %s want %s", sig.Signature, g.SignatureB64)
	}

	// 本仓库独立计算 payload（去顶层 signatures + RFC 8785）。
	payload, err := canonicalJSON(g.CardJSON)
	if err != nil {
		t.Fatalf("canonicalJSON 失败: %v", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(g.SignatureB64)
	if err != nil {
		t.Fatalf("解码官方签名失败: %v", err)
	}
	signingInput := g.ProtectedB64 + "." + base64.RawURLEncoding.EncodeToString(payload)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(signingInput), sigBytes) {
		t.Fatal("本仓库 JCS payload 与 a2acrypto 不一致（用本仓库 payload 复算的签名验签失败）")
	}
}

// TestJCSBoundaryVectors 覆盖冻结 §3.5 要求的 JCS 边界向量：
// 空对象 / 嵌套 / 转义 / Unicode / 数字格式。
func TestJCSBoundaryVectors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空对象", `{}`, `{}`},
		{"空数组", `[]`, `[]`},
		{"键按 UTF-16 码元序排序", `{"b":1,"a":2,"A":3}`, `{"A":3,"a":2,"b":1}`},
		{"嵌套对象", `{"o":{"z":1,"a":{"y":2,"b":3}}}`, `{"o":{"a":{"b":3,"y":2},"z":1}}`},
		{"数组保序", `{"a":[3,1,2]}`, `{"a":[3,1,2]}`},
		{"转义引号与反斜杠", `{"a":"x\"y\\z"}`, `{"a":"x\"y\\z"}`},
		{"控制字符转义", `{"a":"\u0000\u001f"}`, `{"a":"\u0000\u001f"}`},
		{"换行制表回车短形式", `{"a":"\n\t\r\b\f"}`, `{"a":"\n\t\r\b\f"}`},
		// 输入用 JSON 转义形式；输出必须是**字面量**（RFC 8785 §3.2.2.2）。
		{"U+2028/29 保持字面量", "{\"a\":\"\\u2028\\u2029\"}", "{\"a\":\"\u2028\u2029\"}"},
		{"非 ASCII 保持字面量", "{\"a\":\"中文\"}", "{\"a\":\"中文\"}"},
		{"整数", `{"a":42}`, `{"a":42}`},
		{"浮点去尾零", `{"a":1.0}`, `{"a":1}`},
		{"小数", `{"a":3.14}`, `{"a":3.14}`},
		{"科学计数进阈值内展开", `{"a":1e2}`, `{"a":100}`},
		{"极小指数用指数形式", `{"a":1e-7}`, `{"a":1e-7}`},
		{"极大数用指数形式", `{"a":1e21}`, `{"a":1e+21}`},
		{"负零归零", `{"a":-0}`, `{"a":0}`},
		{"布尔与 null", `{"a":true,"b":null}`, `{"a":true,"b":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalJSON([]byte(tc.in))
			if err != nil {
				t.Fatalf("canonicalJSON 失败: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("canonicalJSON(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestJCSUTF16KeyOrder 专项：含非 BMP 字符的键按 UTF-16 码元序（非 UTF-8 字节序）排序。
//
// RFC 8785 §3.2.3：代理项（U+D800–U+DFFF）排在 U+E000 之前。
// 键 "a\ufffd"（UTF-16 码元: 0x61 0xFFFD）与键 "a\U0001F600"（UTF-16 码元: 0x61 0xD83D 0xDE00）：
// UTF-16 序 0xD83D < 0xFFFD ⇒ emoji 键在前；而 UTF-8 字节序恰好相反（0xF0.. > 0xEF..）。
func TestJCSUTF16KeyOrder(t *testing.T) {
	in := "{\"a\\ufffd\":1,\"a\\ud83d\\ude00\":2}"
	want := "{\"a\U0001F600\":2,\"a\ufffd\":1}"
	got, err := canonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("canonicalJSON 失败: %v", err)
	}
	if string(got) != want {
		t.Fatalf("UTF-16 键序错误：got %s want %s", got, want)
	}
}

// TestContentHashExcludesSignatures 断言 content_hash 的输入去掉了顶层 signatures，
// 且与 raw_hash 区分（冻结 §3.5）。
func TestContentHashExcludesSignatures(t *testing.T) {
	card := `{"name":"A","skills":[{"id":"s1","name":"S","description":"d","tags":[]}],"version":"1.0.0"}`
	withSig := `{"name":"A","skills":[{"id":"s1","name":"S","description":"d","tags":[]}],"version":"1.0.0",` +
		`"signatures":[{"protected":"eyJhbGciOiJFZERTQSJ9","signature":"dGVzdA"}]}`

	h1, err := contentHash([]byte(card))
	if err != nil {
		t.Fatalf("contentHash 失败: %v", err)
	}
	h2, err := contentHash([]byte(withSig))
	if err != nil {
		t.Fatalf("contentHash 失败: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("content_hash 必须忽略顶层 signatures：%s != %s", h1, h2)
	}
	if rawHash([]byte(card)) == rawHash([]byte(withSig)) {
		t.Fatal("raw_hash 必须反映原始字节（不应与 content_hash 同源）")
	}
	if len(h1) != len("sha256:")+64 {
		t.Fatalf("content_hash 格式非法: %s", h1)
	}
}

// TestRawHashIsSHA256OfRawBytes 断言 raw_hash = SHA-256(原始卡字节)。
func TestRawHashIsSHA256OfRawBytes(t *testing.T) {
	raw := []byte(`{"a":1}`)
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got := rawHash(raw); got != want {
		t.Fatalf("rawHash = %s, want %s", got, want)
	}
}

// TestContentHashMatchesSDKPayload 断言 content_hash 的输入字节与 a2acrypto 的
// 签名 payload 同源（冻结 §3.5「签名 payload 与 content_hash 输入同源」）：
// 用 SDK 签名 → 用 contentHash 覆盖的字节复算签名输入 → 验签通过。
func TestContentHashMatchesSDKPayload(t *testing.T) {
	priv := ed25519FromSeed(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	raw := []byte(`{"name":"A","skills":[{"description":"d","id":"s1","name":"S","tags":["x"]}],"version":"1.0.0"}`)
	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: priv, KeyID: "k1", Algorithm: "EdDSA",
	})
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}
	sig, err := signer.Sign(context.Background(), json.RawMessage(raw))
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	payload, err := canonicalJSON(raw)
	if err != nil {
		t.Fatalf("canonicalJSON 失败: %v", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig.Signature)
	if err != nil {
		t.Fatalf("解码签名失败: %v", err)
	}
	signingInput := sig.Protected + "." + base64.RawURLEncoding.EncodeToString(payload)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(signingInput), sigBytes) {
		t.Fatal("content_hash 输入与 SDK 签名 payload 不同源")
	}
}
