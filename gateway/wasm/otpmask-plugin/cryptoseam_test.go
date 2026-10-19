package main

// cryptoseam_test.go —— 插件单测用的 **in-process cryptop sidecar 接缝**（P0-4 §5.4.5 接线）。
//
// 为何需要：业务调用点全部改经 `CryptoClient`（cryptop sidecar HTTP，R-11 零密码）后，
// 原「插件内直算密码」的单测被迫改写。本文件以**同步 Transport**把 `cryptoclient.Client`
// 接到**同进程内**的 `cryptopsvc` HTTP handler（`httptest.NewRecorder`），令：
//   - 密码运算真实发生在 sidecar（`cryptop.Provider` intl 档），插件侧仍只见 `KeyRef`；
//   - seam Transport 同步回调 ⇒ 测试可把 CPS 调用当同步用（`done` 立即置位），
//     与 proxy-wasm 异步回调的**语义**一致（仅交付方式不同，§4.7）。
//
// 说明：`_test.go` 不在 R-11 静态扫描范围（子任务 11 门禁只扫非测试源），故本文件可 import
// `cryptopsvc`/`cryptop`/stdlib `crypto/*`（**生产代码不得如此**）。

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/cryptopsvc"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
	"security-ai-gateway/protocol/go"
)

// seamTransport 同步 Transport：直接 ServeHTTP 到 in-process handler，立即回调。
type seamTransport struct {
	h http.Handler
}

func (s *seamTransport) do(method, path string, hdr [][2]string, body []byte) (int, []byte) {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for _, kv := range hdr {
		req.Header.Set(kv[0], kv[1])
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (s *seamTransport) Post(path string, hdr [][2]string, body []byte, cb cryptoclient.ResponseCallback, _ uint32) error {
	code, resp := s.do(http.MethodPost, path, hdr, body)
	cb(code, http.Header{}, resp)
	return nil
}

func (s *seamTransport) Get(path string, hdr [][2]string, cb cryptoclient.ResponseCallback, _ uint32) error {
	code, resp := s.do(http.MethodGet, path, hdr, nil)
	cb(code, http.Header{}, resp)
	return nil
}

// installSeam 安装 in-process sidecar 接缝并把插件全局密码面指向它（intl profile）。
// 同步 Transport ⇒ LoadCapabilities 返回后 cryptoReady 已就绪。
func installSeam(t *testing.T) {
	t.Helper()
	p, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		t.Fatalf("cryptop.New(intl): %v", err)
	}
	srv, err := cryptopsvc.NewServer(p, cryptopsvc.Config{
		// §12.3 crypto_static_keys：登记插件静态 MAC 密钥句柄（JWT HS256 密钥 +
		// 审计上报签名 P1-7 D-13；密钥值 = 令牌 UTF-8 字节）。
		StaticKeys: map[string][]byte{keyRefJWT: testSecret, keyRefAuditReport: testSecret},
	})
	if err != nil {
		t.Fatalf("cryptopsvc.NewServer: %v", err)
	}
	c := cryptoclient.New(&seamTransport{h: srv.Handler()}, nil, nil, cryptoclient.Config{})
	c.LoadCapabilities(func(caps cryptoclient.Capabilities, cerr error) {
		if cerr != nil {
			t.Fatalf("LoadCapabilities: %v", cerr)
		}
	})
	CryptoClient = c
	cryptoReady = true
	cryptoSuite = protocol.SuiteAESGCM
	cryptoProfile = "intl"
}

// newSessionForTest 经 sidecar 建立**真实会话**（SessionBegin → 方向子密钥派生 → Session.set），
// 测试结束清除。测试由此获得真实 KeyRef（会话密钥字节恒驻 sidecar，C-5）。
func newSessionForTest(t *testing.T) {
	t.Helper()
	installSeam(t)
	// 对端（TEE）ECDH 公钥：任意合法 X25519 公钥（sidecar 侧 ECDH(priv, serverPub)）。
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成对端密钥: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x11}, 32)
	var serr error
	ok := false
	CryptoClient.SessionBegin(serverPriv.PublicKey().Bytes(), nonce, peerPubAlg(),
		func(sigRef, encRef cryptoclient.KeyRef, _ []byte, berr error) {
			if berr != nil {
				serr = berr
				return
			}
			deriveDirSubkeys(encRef, func(c2s, s2c cryptoclient.KeyRef, derr error) {
				if derr != nil {
					serr = derr
					return
				}
				Session.set("sess-test-00000001", sigRef, encRef, c2s, s2c)
				ok = true
			})
		})
	if !ok {
		t.Fatalf("建立测试会话失败: %v", serr)
	}
	t.Cleanup(Session.clear)
}

// sealS2CForTest 以会话 **s2c 方向子密钥**构造 s2c 信封（服务端等价），counter 由调用方指定。
func sealS2CForTest(t *testing.T, endpoint string, counter uint64, plain []byte) []byte {
	t.Helper()
	aad := protocol.EnvelopeAAD(Session.SessionID, protocol.DirectionS2C, counter, endpoint)
	nonce := protocol.EnvelopeNonce(counter)
	var wire []byte
	var serr error
	CryptoClient.Seal(Session.S2CRef, aad, nonce, plain, func(_, ct []byte, err error) {
		if err != nil {
			serr = err
			return
		}
		wire, serr = protocol.EncodeEnvelope(&protocol.Envelope{
			Version:    protocol.EnvelopeVersion,
			Suite:      cryptoSuite,
			Direction:  protocol.DirectionS2C,
			Counter:    counter,
			Ciphertext: ct,
		})
	})
	if serr != nil {
		t.Fatal(serr)
	}
	return wire
}

// clientSeal 同步调用 CryptoClient.Seal（seam 同步回调）。
func clientSeal(ref cryptoclient.KeyRef, aad, nonce, pt []byte) ([]byte, error) {
	var ct []byte
	var serr error
	CryptoClient.Seal(ref, aad, nonce, pt, func(_, c []byte, err error) { ct, serr = c, err })
	return ct, serr
}

// clientOpen 同步调用 CryptoClient.Open（seam 同步回调）。
func clientOpen(ref cryptoclient.KeyRef, aad, nonce, ct []byte) ([]byte, error) {
	var pt []byte
	var oerr error
	CryptoClient.Open(ref, aad, nonce, ct, func(p []byte, err error) { pt, oerr = p, err })
	return pt, oerr
}
