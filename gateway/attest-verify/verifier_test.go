package attestverify

// sidecar fixture 测试（P3，D2）：本机构造 mock 证明载荷，验证：
// - 合法证明（度量在基线内）→ 通过，返回度量列表
// - 篡改 report_data / 签名 → 拒绝
// - app_hash 不在基线 → 拒绝（fail-closed）
// - HTTP /verify 接口与 VerifyViaHTTP 客户端

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signProof 构造并签名证明（P-256，签名覆盖 report_data ‖ signing_key）。
func signProof(t *testing.T, platform string, reportData []byte, appHash string) *Proof {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := &Proof{
		Nonce:      []byte("fixture-nonce-32bytes........................"),
		Platform:   platform,
		ReportData: reportData,
		Measurements: map[string]string{
			"app_hash": appHash,
		},
		SigningKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y),
	}
	toSign := append(append([]byte(nil), proof.ReportData...), proof.SigningKey...)
	h := sha256.Sum256(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	proof.Signature = append(r.Bytes(), s.Bytes()...)
	return proof
}

func TestBuiltinVerifierHappyPath(t *testing.T) {
	al := NewAllowlist()
	al.Add("aabbcc")
	v := NewBuiltinVerifier(al)
	reportData := []byte("H(nonce||server_pub)")
	proof := signProof(t, "mock", reportData, "aabbcc")
	wire, _ := json.Marshal(proof)
	measurements, err := v.VerifyQuote(wire, reportData)
	if err != nil {
		t.Fatalf("合法证明应通过: %v", err)
	}
	found := false
	for _, m := range measurements {
		if m == "app_hash" {
			found = true
		}
	}
	if !found {
		t.Fatalf("度量列表缺 app_hash: %v", measurements)
	}
}

func TestBuiltinVerifierRejects(t *testing.T) {
	al := NewAllowlist()
	al.Add("aabbcc")
	v := NewBuiltinVerifier(al)
	reportData := []byte("H(nonce||server_pub)")
	proof := signProof(t, "mock", reportData, "aabbcc")

	// 篡改 report_data → 拒绝（握手公钥绑定防替换）
	tampered := *proof
	tampered.ReportData = []byte("evil")
	wire, _ := json.Marshal(&tampered)
	if _, err := v.VerifyQuote(wire, reportData); err == nil {
		t.Fatal("篡改 report_data 应拒绝")
	}

	// 篡改签名 → 拒绝
	tampered2 := *proof
	tampered2.Signature = append([]byte(nil), proof.Signature...)
	tampered2.Signature[0] ^= 0xFF
	wire2, _ := json.Marshal(&tampered2)
	if _, err := v.VerifyQuote(wire2, reportData); err == nil {
		t.Fatal("篡改签名应拒绝")
	}

	// app_hash 不在基线 → 拒绝（fail-closed）
	bad := signProof(t, "mock", reportData, "deadbeef")
	wire3, _ := json.Marshal(bad)
	if _, err := v.VerifyQuote(wire3, reportData); err == nil {
		t.Fatal("app_hash 不在基线应拒绝")
	}

	// 空 quote → 拒绝
	if _, err := v.VerifyQuote(nil, reportData); err == nil {
		t.Fatal("空 quote 应拒绝")
	}
}

func TestVerifyViaHTTP(t *testing.T) {
	al := NewAllowlist()
	al.Add("aabbcc")
	srv := NewServer(NewBuiltinVerifier(al), "tok123", "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	reportData := []byte("H(nonce||server_pub)")
	proof := signProof(t, "mock", reportData, "aabbcc")
	wire, _ := json.Marshal(proof)
	addr := ts.URL[len("http://"):]

	// 带令牌 + 合法证明 → OK
	vr, err := VerifyViaHTTP(addr, "tok123", wire, reportData, 5*time.Second)
	if err != nil {
		t.Fatalf("VerifyViaHTTP 失败: %v", err)
	}
	if !vr.OK {
		t.Fatalf("应验证通过: %+v", vr)
	}

	// 非法证明 → 拒绝
	bad := signProof(t, "mock", reportData, "deadbeef")
	badWire, _ := json.Marshal(bad)
	if _, err := VerifyViaHTTP(addr, "tok123", badWire, reportData, 5*time.Second); err == nil {
		t.Fatal("非法证明应拒绝")
	}
}

// TestVerifyHTTPAuth 无令牌 → 401。
func TestVerifyHTTPAuth(t *testing.T) {
	al := NewAllowlist()
	al.Add("aabbcc")
	srv := NewServer(NewBuiltinVerifier(al), "tok123", "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/verify", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，got %d", resp.StatusCode)
	}
}
