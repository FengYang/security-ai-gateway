//go:build pkcs11

package cryptopmodule

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestPKCS11SymFailClosedNoProfile M4-4b 六方法在未配置 profile 的后端上
// 一律 fail-closed（机制无 CKM 登记 → ErrNotImplemented；不回退软件实现）。
func TestPKCS11SymFailClosedNoProfile(t *testing.T) {
	b := &PKCS11Backend{}
	ref := mustEnc(t, 0, "", 1)
	nonce := make([]byte, symNonceSize)

	cases := []struct {
		name string
		err  error
	}{
		{"Seal", errOf(b.Seal(ref, nonce, []byte("x"), nil))},
		{"Open", errOf2(b.Open(ref, nonce, make([]byte, symTagSize+1), nil))},
		{"HMAC", errOf(b.HMAC(ref, []byte("x")))},
		{"WrapKey", errOf(b.WrapKey(ref, make([]byte, 16)))},
		{"UnwrapKey", errOf2(b.UnwrapKey(ref, make([]byte, 2*symWrapTagSize)))},
		{"KDF", errOf(b.KDF(ref, nil, nil, 32, ""))},
	}
	for _, c := range cases {
		if c.err == nil {
			t.Fatalf("%s 未配置 profile 应 fail-closed", c.name)
		}
		if !errors.Is(c.err, ErrNotImplemented) {
			t.Fatalf("%s 应 ErrNotImplemented（机制未登记），实得: %v", c.name, c.err)
		}
	}
}

// TestPKCS11SymParamChecksBeforeMechanism 参数校验先于机制查询：
// nonce 长度/输入截断/KDF outLen 在无 profile 时即报参数错（不经机制层）。
func TestPKCS11SymParamChecksBeforeMechanism(t *testing.T) {
	b := &PKCS11Backend{}
	ref := mustEnc(t, 0, "", 1)
	good := make([]byte, symNonceSize)

	if _, err := b.Seal(ref, good[:8], []byte("x"), nil); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("Seal 坏 nonce 应报 nonce 错: %v", err)
	}
	if _, err := b.Open(ref, good, make([]byte, 4), nil); err == nil || !strings.Contains(err.Error(), "截断") {
		t.Fatalf("Open 短输入应报截断错: %v", err)
	}
	if _, err := b.KDF(ref, nil, nil, 0, ""); err == nil || !strings.Contains(err.Error(), "outLen") {
		t.Fatalf("KDF outLen=0 应报 outLen 错: %v", err)
	}
	if _, err := b.KDF(ref, nil, nil, maxKDFOutLen+1, ""); err == nil || !strings.Contains(err.Error(), "outLen") {
		t.Fatalf("KDF 超限 outLen 应报 outLen 错: %v", err)
	}
	if _, err := b.WrapKey(ref, nil); err == nil || !strings.Contains(err.Error(), "DEK 为空") {
		t.Fatalf("WrapKey 空 DEK 应拒绝: %v", err)
	}
	if _, err := b.UnwrapKey(ref, make([]byte, 4)); err == nil || !strings.Contains(err.Error(), "非法") {
		t.Fatalf("UnwrapKey 短输入应拒绝: %v", err)
	}
}

// TestPKCS11SymBadKeyRef 坏 KeyRef 一律 ErrKeyNotFound（先于机制查询）。
func TestPKCS11SymBadKeyRef(t *testing.T) {
	b := &PKCS11Backend{}
	nonce := make([]byte, symNonceSize)
	if _, err := b.Seal(KeyRef("mock:x"), nonce, []byte("x"), nil); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Seal mock ref 应 ErrKeyNotFound: %v", err)
	}
	if _, err := b.HMAC(KeyRef("mock:x"), []byte("x")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("HMAC mock ref 应 ErrKeyNotFound: %v", err)
	}
}

// TestIsGCMAuthFailure GCM 认证失败 CKR 集合（SoftHSM v2.6 用
// CKR_GENERAL_ERROR；真机实测）；无关错误码不得误判为认证失败——那会掩盖
// 真实故障。
func TestIsGCMAuthFailure(t *testing.T) {
	yes := []uint{
		pkcs11.CKR_ENCRYPTED_DATA_INVALID, pkcs11.CKR_DATA_INVALID,
		pkcs11.CKR_SIGNATURE_INVALID, pkcs11.CKR_GENERAL_ERROR,
	}
	for _, v := range yes {
		if !isGCMAuthFailure(pkcs11.Error(v)) {
			t.Fatalf("0x%x 应判为认证失败", v)
		}
	}
	no := []uint{
		pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_KEY_HANDLE_INVALID,
		pkcs11.CKR_MECHANISM_INVALID, pkcs11.CKR_FUNCTION_FAILED,
		pkcs11.CKR_KEY_TYPE_INCONSISTENT,
	}
	for _, v := range no {
		if isGCMAuthFailure(pkcs11.Error(v)) {
			t.Fatalf("0x%x 不应判为认证失败", v)
		}
	}
}

// TestWithAttr withAttr 覆盖/追加语义（WrapKey 瞬态对象覆盖 CKA_TOKEN）。
func TestWithAttr(t *testing.T) {
	attrs := secretKeyTemplate("l", 32, false, usageEnc)
	attrs = withAttr(attrs, pkcs11.CKA_TOKEN, false)
	var found bool
	for _, a := range attrs {
		if a.Type == pkcs11.CKA_TOKEN {
			found = true
			if len(a.Value) != 1 || a.Value[0] != 0 {
				t.Fatalf("CKA_TOKEN 应被覆盖为 false: %v", a.Value)
			}
		}
	}
	if !found {
		t.Fatal("CKA_TOKEN 丢失")
	}
	// 不存在的类型走追加。
	before := len(attrs)
	attrs = withAttr(attrs, pkcs11.CKA_VALUE, []byte{1, 2, 3})
	if len(attrs) != before+1 {
		t.Fatalf("追加路径: got %d want %d", len(attrs), before+1)
	}
	for _, a := range attrs {
		if a.Type == pkcs11.CKA_VALUE && string(a.Value) != string([]byte{1, 2, 3}) {
			t.Fatalf("CKA_VALUE 值不符: %v", a.Value)
		}
	}
}

func errOf(_ []byte, err error) error  { return err }
func errOf2(_ []byte, err error) error { return err }
