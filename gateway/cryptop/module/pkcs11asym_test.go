//go:build pkcs11

package cryptopmodule

import (
	"bytes"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

// ---------------------------------------------------------------------------
// EC 点 DER 包裹/解包
// ---------------------------------------------------------------------------

// sampleECPoint 构造 65B 原始非压缩点（0x04||X32||Y32；X/Y 用可辨模式）。
func sampleECPoint() []byte {
	p := make([]byte, ecPointLen)
	p[0] = 0x04
	for i := 1; i < ecPointLen; i++ {
		p[i] = byte(i)
	}
	return p
}

func TestWrapUnwrapECPoint(t *testing.T) {
	raw := sampleECPoint()
	der, err := wrapECPoint(raw)
	if err != nil {
		t.Fatalf("wrapECPoint: %v", err)
	}
	// DER OCTET STRING：04 41 <65B>（短形式长度）。
	if len(der) != 2+len(raw) || der[0] != 0x04 || der[1] != byte(len(raw)) {
		t.Fatalf("DER 头异常: %x", der[:2])
	}
	got, err := unwrapECPoint(der)
	if err != nil {
		t.Fatalf("unwrapECPoint: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("往返后原始点不符")
	}
}

func TestUnwrapECPointErrors(t *testing.T) {
	cases := map[string][]byte{
		"空":          {},
		"单字节":        {0x04},
		"标签非OCTET":   {0x30, 0x41, 0x04},
		"长度截断(0x81)": {0x04, 0x81},
		"长度截断(0x82)": {0x04, 0x82, 0x00},
		"长度形式不支持":    {0x04, 0x83, 0x00, 0x01, 0x02},
		"内容非点":       {0x04, 0x02, 0x01, 0x02}, // 长度够但内容长度 2 ≠ 65
	}
	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := unwrapECPoint(der); err == nil {
				t.Fatalf("DER %x 应报错", der)
			}
		})
	}
	// 长形式长度（0x81）合法路径：内容 65B。
	raw := sampleECPoint()
	long := append([]byte{0x04, 0x81, byte(len(raw))}, raw...)
	got, err := unwrapECPoint(long)
	if err != nil {
		t.Fatalf("长形式 DER 应可解包: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("长形式往返不符")
	}
}

func TestValidateRawECPoint(t *testing.T) {
	if err := validateRawECPoint(sampleECPoint()); err != nil {
		t.Fatalf("合法点应通过: %v", err)
	}
	bad := sampleECPoint()
	bad[0] = 0x02 // 压缩点标记（本档不支持）
	if err := validateRawECPoint(bad); err == nil {
		t.Fatal("压缩点标记应拒绝")
	}
	if err := validateRawECPoint(bad[:64]); err == nil {
		t.Fatal("64B 应拒绝")
	}
}

// ---------------------------------------------------------------------------
// 属性模板
// ---------------------------------------------------------------------------

// attrMap 模板 → 类型索引（miekg/pkcs11 把值转 C 布局字节：bool 单字节，
// uint 平台字节序，[]byte 原样——故 uint 只断言存在与非空，数值语义由
// 真机属性回读验证，pkcs11_live_test.go）。
func attrMap(tmpl []*pkcs11.Attribute) map[uint]*pkcs11.Attribute {
	m := map[uint]*pkcs11.Attribute{}
	for _, a := range tmpl {
		m[a.Type] = a
	}
	return m
}

func boolAttr(t *testing.T, m map[uint]*pkcs11.Attribute, k uint) bool {
	t.Helper()
	a, ok := m[k]
	if !ok {
		t.Fatalf("缺属性 CKA 0x%x", k)
	}
	if len(a.Value) != 1 {
		t.Fatalf("CKA 0x%x 布尔值应单字节: %v", k, a.Value)
	}
	return a.Value[0] == 1
}

func presentNonEmpty(t *testing.T, m map[uint]*pkcs11.Attribute, k uint) {
	t.Helper()
	a, ok := m[k]
	if !ok {
		t.Fatalf("缺属性 CKA 0x%x", k)
	}
	if len(a.Value) == 0 {
		t.Fatalf("CKA 0x%x 值不应为空", k)
	}
}

func TestECTemplates(t *testing.T) {
	t.Run("公钥-签名用途", func(t *testing.T) {
		m := attrMap(ecPublicTemplate(false))
		presentNonEmpty(t, m, pkcs11.CKA_CLASS)
		presentNonEmpty(t, m, pkcs11.CKA_KEY_TYPE)
		if !bytes.Equal(m[pkcs11.CKA_EC_PARAMS].Value, ecCurveOIDP256) {
			t.Fatalf("CKA_EC_PARAMS 应为 P-256 OID: %x", m[pkcs11.CKA_EC_PARAMS].Value)
		}
		if !boolAttr(t, m, pkcs11.CKA_VERIFY) {
			t.Fatal("签名用途公钥应开 CKA_VERIFY")
		}
		if boolAttr(t, m, pkcs11.CKA_TOKEN) {
			t.Fatal("公钥对象应瞬态（CKA_TOKEN=false）")
		}
		if boolAttr(t, m, pkcs11.CKA_PRIVATE) {
			t.Fatal("公钥 CKA_PRIVATE 应 false")
		}
	})
	t.Run("公钥-协商用途", func(t *testing.T) {
		m := attrMap(ecPublicTemplate(true))
		if boolAttr(t, m, pkcs11.CKA_VERIFY) {
			t.Fatal("协商用途公钥不应开 CKA_VERIFY（最小权限）")
		}
	})
	t.Run("私钥-签名用途", func(t *testing.T) {
		m := attrMap(ecPrivateTemplate(false))
		presentNonEmpty(t, m, pkcs11.CKA_CLASS)
		presentNonEmpty(t, m, pkcs11.CKA_KEY_TYPE)
		if !boolAttr(t, m, pkcs11.CKA_TOKEN) {
			t.Fatal("私钥应落 token（模块内持久）")
		}
		if !boolAttr(t, m, pkcs11.CKA_PRIVATE) {
			t.Fatal("私钥 CKA_PRIVATE 应 true")
		}
		if !boolAttr(t, m, pkcs11.CKA_SENSITIVE) {
			t.Fatal("私钥 CKA_SENSITIVE 应 true（R-S3-4）")
		}
		if boolAttr(t, m, pkcs11.CKA_EXTRACTABLE) {
			t.Fatal("私钥 CKA_EXTRACTABLE 应 false（R-S3-4）")
		}
		if !boolAttr(t, m, pkcs11.CKA_SIGN) {
			t.Fatal("签名用途私钥应开 CKA_SIGN")
		}
		if boolAttr(t, m, pkcs11.CKA_DERIVE) {
			t.Fatal("签名用途私钥应显式关 CKA_DERIVE（最小权限；SoftHSM 默认 true）")
		}
	})
	t.Run("私钥-协商用途", func(t *testing.T) {
		m := attrMap(ecPrivateTemplate(true))
		if !boolAttr(t, m, pkcs11.CKA_DERIVE) {
			t.Fatal("协商用途私钥应开 CKA_DERIVE")
		}
		if boolAttr(t, m, pkcs11.CKA_SIGN) {
			t.Fatal("协商用途私钥应显式关 CKA_SIGN（最小权限；SoftHSM 默认 true）")
		}
	})
	t.Run("验签瞬态公钥", func(t *testing.T) {
		raw := sampleECPoint()
		der, err := wrapECPoint(raw)
		if err != nil {
			t.Fatalf("wrapECPoint: %v", err)
		}
		m := attrMap(verifyPubTemplate(der))
		if !bytes.Equal(m[pkcs11.CKA_EC_POINT].Value, der) {
			t.Fatal("CKA_EC_POINT 应为包裹后的 DER")
		}
		if boolAttr(t, m, pkcs11.CKA_TOKEN) {
			t.Fatal("验签公钥应瞬态（不落 token）")
		}
		if !boolAttr(t, m, pkcs11.CKA_VERIFY) {
			t.Fatal("验签公钥应开 CKA_VERIFY")
		}
	})
	t.Run("ECDH派生秘密", func(t *testing.T) {
		m := attrMap(ecdhDerivedTemplate())
		presentNonEmpty(t, m, pkcs11.CKA_CLASS)
		presentNonEmpty(t, m, pkcs11.CKA_KEY_TYPE)
		presentNonEmpty(t, m, pkcs11.CKA_VALUE_LEN)
		if boolAttr(t, m, pkcs11.CKA_TOKEN) {
			t.Fatal("派生秘密应瞬态（会话级，读出即毁）")
		}
		if boolAttr(t, m, pkcs11.CKA_SENSITIVE) {
			t.Fatal("派生秘密 CKA_SENSITIVE 应 false（须可读出，B-6.1-9）")
		}
		if !boolAttr(t, m, pkcs11.CKA_EXTRACTABLE) {
			t.Fatal("派生秘密 CKA_EXTRACTABLE 应 true（须可读出）")
		}
	})
}

// ---------------------------------------------------------------------------
// parseRotateSpec
// ---------------------------------------------------------------------------

func TestParseRotateSpec(t *testing.T) {
	cases := []struct {
		spec    string
		kind    rotateKind
		usage   string
		wantErr bool
		notImpl bool // SM 档：应包装 ErrNotImplemented
	}{
		{"ec-sign", rotatePair, UsageSign, false, false},
		{"ec-ecdh", rotatePair, UsageECDH, false, false},
		{"aes-128", rotateSym, "", false, false},
		{"aes-256", rotateSym, "", false, false},
		{"", rotateSym, "", false, false},
		{"sm2-sign", 0, "", true, true},
		{"sm2-ecdh", 0, "", true, true},
		{"sm4-128", 0, "", true, true},
		{"bogus", 0, "", true, false},
	}
	for _, c := range cases {
		t.Run("spec="+c.spec, func(t *testing.T) {
			kind, usage, err := parseRotateSpec(c.spec)
			if c.wantErr {
				if err == nil {
					t.Fatalf("spec=%q 应报错", c.spec)
				}
				if c.notImpl && !errors.Is(err, ErrNotImplemented) {
					t.Fatalf("spec=%q SM 档应包装 ErrNotImplemented: %v", c.spec, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("spec=%q: %v", c.spec, err)
			}
			if kind != c.kind || usage != c.usage {
				t.Fatalf("spec=%q: got (%v,%q) want (%v,%q)", c.spec, kind, usage, c.kind, c.usage)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 错误码判别
// ---------------------------------------------------------------------------

func TestAsymErrClassifiers(t *testing.T) {
	if !isKeyFunctionNotPermitted(pkcs11.Error(pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED)) {
		t.Fatal("0x68 应判为用途不允许")
	}
	if isKeyFunctionNotPermitted(pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)) {
		t.Fatal("0x60 不应判为用途不允许")
	}
	if !isVerifyFailure(pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID)) {
		t.Fatal("0xC0 应判为验签失败")
	}
	if isVerifyFailure(pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)) {
		t.Fatal("0x06 不应判为验签失败")
	}
}

// ---------------------------------------------------------------------------
// ECDSA 签名线格式归一（裸 r||s ↔ DER）
// ---------------------------------------------------------------------------

func TestECDSASigRawDERRoundtrip(t *testing.T) {
	raw := make([]byte, 2*ecSharedSecretLen)
	for i := range raw {
		raw[i] = byte(i + 1) // 避开前导 0，r/s 均为合法标量
	}
	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatalf("ecdsaRawToDER: %v", err)
	}
	// DER SEQUENCE 头 30 <len>。
	if len(der) < 2 || der[0] != 0x30 {
		t.Fatalf("DER 头异常: %x", der[:2])
	}
	back, err := ecdsaDERToRaw(der)
	if err != nil {
		t.Fatalf("ecdsaDERToRaw: %v", err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatal("raw→DER→raw 往返不符")
	}
	// 前导零分量（r 小数值）：DER→raw 须左侧补零还原。
	small := make([]byte, 2*ecSharedSecretLen)
	small[31] = 0x01 // r = 1
	small[63] = 0x02 // s = 2
	der2, err := ecdsaRawToDER(small)
	if err != nil {
		t.Fatalf("ecdsaRawToDER(小分量): %v", err)
	}
	back2, err := ecdsaDERToRaw(der2)
	if err != nil {
		t.Fatalf("ecdsaDERToRaw(小分量): %v", err)
	}
	if !bytes.Equal(back2, small) {
		t.Fatal("小分量往返不符（补零错误）")
	}
}

func TestECDSASigConvErrors(t *testing.T) {
	good := make([]byte, 2*ecSharedSecretLen)
	for i := range good {
		good[i] = byte(i + 1)
	}
	der, err := ecdsaRawToDER(good)
	if err != nil {
		t.Fatalf("ecdsaRawToDER: %v", err)
	}
	t.Run("裸长度错", func(t *testing.T) {
		if _, err := ecdsaRawToDER(good[:63]); err == nil {
			t.Fatal("63B 应拒绝")
		}
	})
	t.Run("裸分量为0", func(t *testing.T) {
		z := make([]byte, 2*ecSharedSecretLen)
		z[31] = 1
		if _, err := ecdsaRawToDER(z); err == nil { // s 全 0
			t.Fatal("s=0 应拒绝")
		}
	})
	t.Run("裸分量超界", func(t *testing.T) {
		over := make([]byte, 2*ecSharedSecretLen)
		for i := range over {
			over[i] = 0xff // ≥ N
		}
		if _, err := ecdsaRawToDER(over); err == nil {
			t.Fatal("r ≥ N 应拒绝")
		}
	})
	t.Run("DER非SEQUENCE", func(t *testing.T) {
		if _, err := ecdsaDERToRaw([]byte{0x02, 0x01, 0x01}); err == nil {
			t.Fatal("非 SEQUENCE 应拒绝")
		}
	})
	t.Run("DER尾随数据", func(t *testing.T) {
		if _, err := ecdsaDERToRaw(append(append([]byte(nil), der...), 0x00)); err == nil {
			t.Fatal("尾随数据应拒绝")
		}
	})
}

// ---------------------------------------------------------------------------
// 参数优先（未初始化后端不得 panic；参数错误先于设备状态错误）
// ---------------------------------------------------------------------------

// TestPKCS11AsymParamFirst 验证 M4-4a 裁定的校验顺序：纯参数校验（usage/
// 公钥点/KeyRef 归属/spec）先于 ctx==nil 设备检查——错误语义可判别、
// 且 &PKCS11Backend{}（cfg=nil）不得 panic。
func TestPKCS11AsymParamFirst(t *testing.T) {
	b := &PKCS11Backend{}
	validRef, err := encodeKeyRef(0, "", 7)
	if err != nil {
		t.Fatalf("encodeKeyRef: %v", err)
	}

	t.Run("GenerateKeyPair未知usage", func(t *testing.T) {
		_, _, err := b.GenerateKeyPair("bogus")
		if err == nil || errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应报参数错误（非模块不可用）: %v", err)
		}
	})
	t.Run("GenerateKeyPair合法usage未初始化", func(t *testing.T) {
		_, _, err := b.GenerateKeyPair(UsageSign)
		if !errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应 ErrModuleUnavailable: %v", err)
		}
	})
	t.Run("Sign跨后端ref", func(t *testing.T) {
		_, err := b.Sign(KeyRef("mock:whatever"), []byte("m"), "")
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("应 ErrKeyNotFound: %v", err)
		}
	})
	t.Run("Sign合法ref未初始化", func(t *testing.T) {
		_, err := b.Sign(validRef, []byte("m"), "")
		if !errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应 ErrModuleUnavailable: %v", err)
		}
	})
	t.Run("Verify坏公钥", func(t *testing.T) {
		err := b.Verify(make([]byte, 64), []byte("m"), []byte("sig"), "")
		if err == nil || errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应报参数错误（非模块不可用）: %v", err)
		}
	})
	t.Run("Verify空签名", func(t *testing.T) {
		err := b.Verify(sampleECPoint(), []byte("m"), nil, "")
		if err == nil {
			t.Fatal("空签名应拒绝")
		}
	})
	t.Run("Verify合法参数未初始化", func(t *testing.T) {
		err := b.Verify(sampleECPoint(), []byte("m"), []byte("sig"), "")
		if !errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应 ErrModuleUnavailable: %v", err)
		}
	})
	t.Run("ECDH跨后端ref", func(t *testing.T) {
		_, err := b.ECDH(KeyRef("mock:whatever"), sampleECPoint())
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("应 ErrKeyNotFound: %v", err)
		}
	})
	t.Run("ECDH坏对端公钥", func(t *testing.T) {
		_, err := b.ECDH(validRef, make([]byte, 10))
		if err == nil || errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应报参数错误（非模块不可用）: %v", err)
		}
	})
	t.Run("RotateKey坏spec", func(t *testing.T) {
		_, err := b.RotateKey(validRef, "bogus")
		if err == nil || errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应报参数错误: %v", err)
		}
	})
	t.Run("RotateKey跨后端旧ref", func(t *testing.T) {
		_, err := b.RotateKey(KeyRef("mock:whatever"), "ec-sign")
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("应 ErrKeyNotFound: %v", err)
		}
	})
	t.Run("RotateKey合法参数未初始化", func(t *testing.T) {
		_, err := b.RotateKey(validRef, "aes-256")
		if !errors.Is(err, ErrModuleUnavailable) {
			t.Fatalf("应 ErrModuleUnavailable: %v", err)
		}
	})
}
