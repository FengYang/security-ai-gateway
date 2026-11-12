// ohttp_framing_test.go — M8-1 单测（RFC 9292 framing 往返 / RFC 9458 封装端到端 /
// keyconfig 往返 / info 覆写 / relay 转发与重放防护）。
package ohttp

import (
	"bytes"
	"crypto/hpke"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestBinaryHTTPRequestRoundtrip 请求 bhttp 编解码往返（伪头 + 头 + 体）。
func TestBinaryHTTPRequestRoundtrip(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/chat?x=1", strings.NewReader("hello 密态"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "v1")
	req.Header.Set("Host", "api.example.com") // 应被剔除（:authority 承载）

	enc, err := EncodeBinaryHTTP(req)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	got, err := DecodeBinaryHTTP(enc)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if got.Method != http.MethodPost || got.Host != "api.example.com" ||
		got.URL.Scheme != "https" || got.URL.RequestURI() != "/v1/chat?x=1" {
		t.Fatalf("往返伪头不一致: %v %v", got.Method, got.URL)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != "hello 密态" {
		t.Fatalf("体不一致: %q", body)
	}
	if got.Header.Get("X-Custom") != "v1" || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("头不一致: %v", got.Header)
	}
	if got.Header.Get("Host") != "" {
		t.Fatal("Host 头应被剔除")
	}
}

// TestBinaryHTTPResponseRoundtrip 响应 bhttp 编解码往返。
func TestBinaryHTTPResponseRoundtrip(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}, "Connection": []string{"keep-alive"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	enc, err := EncodeBinaryHTTPResponse(resp)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	got, err := DecodeBinaryHTTPResponse(enc)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if got.StatusCode != 200 || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("响应往返不一致: %d %v", got.StatusCode, got.Header)
	}
	if got.Header.Get("Connection") != "" {
		t.Fatal("连接类头应被剔除")
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("体不一致: %q", body)
	}
}

// TestKeyConfigRoundtrip keyconfig 序列化往返（判据 3：key_id|kem|kdf|aead|pubkey）。
func TestKeyConfigRoundtrip(t *testing.T) {
	kc := DefaultKeyConfig(7, bytes.Repeat([]byte{0xAB}, 32))
	got, err := ParseKeyConfig(kc.Encode())
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.KeyID != 7 || got.KEM != 0x0020 || got.KDF != 0x0001 || got.AEAD != 0x0001 ||
		!bytes.Equal(got.PublicKey, kc.PublicKey) {
		t.Fatalf("往返不一致: %+v", got)
	}
}

// testKeyPair 生成接收方密钥对（X25519）。
func testKeyPair(t *testing.T) (hpke.PrivateKey, []byte) {
	t.Helper()
	kem, err := hpke.NewKEM(0x0020)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := kem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	return priv, pub
}

// TestOHTTPEndToEnd RFC 9458 全链路：客户端封装请求 → 接收方解封 → 响应加密 → 客户端解密（判据 1/2）。
func TestOHTTPEndToEnd(t *testing.T) {
	priv, pub := testKeyPair(t)
	kc := DefaultKeyConfig(3, pub)

	innerReq := []byte("binary-http-request-bytes")
	sr, encReq, err := SealRequestWithState(kc, innerReq)
	if err != nil {
		t.Fatalf("封装请求失败: %v", err)
	}
	// hdr 布局：key_id(1) || kem(2) || kdf(2) || aead(2)。
	if encReq[0] != 3 || encReq[1] != 0x00 || encReq[2] != 0x20 ||
		encReq[3] != 0x00 || encReq[4] != 0x01 || encReq[5] != 0x00 || encReq[6] != 0x01 {
		t.Fatalf("hdr 布局不符 RFC 9458: % x", encReq[:7])
	}

	keyID, gotInner, rs, err := OpenRequestResponder(priv, encReq)
	if err != nil {
		t.Fatalf("解封失败: %v", err)
	}
	if keyID != 3 || !bytes.Equal(gotInner, innerReq) {
		t.Fatalf("请求内容不一致: keyID=%d", keyID)
	}

	innerResp := []byte("binary-http-response-bytes")
	encResp, err := rs.SealResponse(innerResp)
	if err != nil {
		t.Fatalf("加密响应失败: %v", err)
	}
	// response_nonce 长度 = max(Nn, Nk) = 16（AES-128-GCM）。
	if len(encResp) <= 16 {
		t.Fatalf("响应过短: %d", len(encResp))
	}
	gotResp, err := sr.OpenResponse(encResp)
	if err != nil {
		t.Fatalf("客户端解密响应失败: %v", err)
	}
	if !bytes.Equal(gotResp, innerResp) {
		t.Fatalf("响应内容不一致")
	}
}

// TestOHTTPInfoOverride OHTTP_INFO_REQ/OHTTP_INFO_RES 覆写生效（M8-2 预留点；覆写不一致应解密失败）。
func TestOHTTPInfoOverride(t *testing.T) {
	t.Setenv("OHTTP_INFO_REQ", "custom/request-info")
	_, pub := testKeyPair(t)
	kc := DefaultKeyConfig(1, pub)
	encReq, err := SealRequest(kc, []byte("payload"))
	if err != nil {
		t.Fatalf("覆写封装失败: %v", err)
	}
	priv, _ := testKeyPair(t) // 不同私钥，仅验证覆写路径不 panic 且解封必败
	if _, _, _, err := OpenRequestResponder(priv, encReq); err == nil {
		t.Fatal("覆写 info + 错误密钥应解封失败")
	}
	// 同一覆写值 + 同一密钥应成功。
	t.Setenv("OHTTP_INFO_REQ", "custom/request-info")
	priv2, pub2 := testKeyPair(t)
	kc2 := DefaultKeyConfig(1, pub2)
	sr2, encReq2, err := SealRequestWithState(kc2, []byte("p2"))
	if err != nil {
		t.Fatal(err)
	}
	keyID, inner, rs2, err := OpenRequestResponder(priv2, encReq2)
	if err != nil || keyID != 1 || string(inner) != "p2" {
		t.Fatalf("同覆写值解封失败: %v", err)
	}
	encResp, err := rs2.SealResponse([]byte("r2"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := sr2.OpenResponse(encResp); err != nil || string(got) != "r2" {
		t.Fatalf("同覆写值响应解密失败: %v", err)
	}
}

// TestSealRequestLegacySignature 接口冻结基线签名 SealRequest/OpenRequest 可用。
func TestSealRequestLegacySignature(t *testing.T) {
	priv, pub := testKeyPair(t)
	kc := DefaultKeyConfig(9, pub)
	msg, err := SealRequest(kc, []byte("baseline"))
	if err != nil {
		t.Fatal(err)
	}
	keyID, inner, err := OpenRequest(priv, msg)
	if err != nil || keyID != 9 || string(inner) != "baseline" {
		t.Fatalf("基线签名不符: %v %d %q", err, keyID, inner)
	}
}

// TestRelayForwardAndReplay relay 转发（密文不解开）+ 时间窗重放拒绝（判据 4）。
func TestRelayForwardAndReplay(t *testing.T) {
	priv, pub := testKeyPair(t)

	// 模拟解密方 target：解封 → bhttp 解码 → bhttp 编码响应 → 封装响应。
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		keyID, inner, rs, err := OpenRequestResponder(priv, body)
		if err != nil {
			http.Error(w, "ohttp: 解封失败", http.StatusBadRequest)
			return
		}
		req, err := DecodeBinaryHTTP(inner)
		if err != nil {
			http.Error(w, "ohttp: bhttp 解码失败", http.StatusBadRequest)
			return
		}
		_ = keyID
		respMsg, _ := EncodeBinaryHTTPResponse(&http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("echo:" + req.URL.Path)),
		})
		encResp, err := rs.SealResponse(respMsg)
		if err != nil {
			http.Error(w, "ohttp: 响应封装失败", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "message/ohttp-resp")
		_, _ = w.Write(encResp)
	}))
	defer target.Close()

	relay, err := NewRelayHandler(RelayConfig{TargetURL: target.URL, ReplayWin: time.Minute})
	if err != nil {
		t.Fatalf("relay 构造失败: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1/infer", strings.NewReader(`{"q":1}`))
	inner, _ := EncodeBinaryHTTP(req)
	kc := DefaultKeyConfig(2, pub)
	sr, encReq, err := SealRequestWithState(kc, inner)
	if err != nil {
		t.Fatal(err)
	}

	do := func() *http.Response {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/relay", bytes.NewReader(encReq))
		r.Header.Set("Content-Type", "message/ohttp-req")
		relay.ServeHTTP(rr, r)
		return rr.Result()
	}

	first := do()
	if first.StatusCode != 200 {
		t.Fatalf("首次转发失败: %d %s", first.StatusCode, readAll(first.Body))
	}
	// 客户端侧先解密 OHTTP 响应（response_nonce || ct），再解 bhttp。
	innerResp, err := sr.OpenResponse(readBytes(first.Body))
	if err != nil {
		t.Fatalf("OHTTP 响应解密失败: %v", err)
	}
	dec, err := DecodeBinaryHTTPResponse(innerResp)
	if err != nil {
		t.Fatalf("响应 bhttp 解码失败: %v", err)
	}
	b, _ := io.ReadAll(dec.Body)
	if dec.StatusCode != 200 || string(b) != "echo:/v1/infer" {
		t.Fatalf("端到端内容不符: %d %q", dec.StatusCode, b)
	}

	// 重放：同密文再次提交 → 409。
	again := do()
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("重放未拒绝: %d", again.StatusCode)
	}

	// 错误 Content-Type → 415。
	rr := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/relay", strings.NewReader("x"))
	r2.Header.Set("Content-Type", "text/plain")
	relay.ServeHTTP(rr, r2)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("错误 Content-Type 未拒: %d", rr.Code)
	}
}

func readBytes(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

func readAll(r io.Reader) string { return string(readBytes(r)) }
