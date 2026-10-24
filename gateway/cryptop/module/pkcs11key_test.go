//go:build pkcs11

package cryptopmodule

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestParseSymSpec spec 解析表（M4-4a 档：aes-*；SM 档明确拒绝）。
func TestParseSymSpec(t *testing.T) {
	cases := []struct {
		spec    string
		want    symSpec
		wantErr bool
	}{
		{"", symSpec{MechAESKeyGen, 16}, false},
		{"aes", symSpec{MechAESKeyGen, 16}, false},
		{"aes-128", symSpec{MechAESKeyGen, 16}, false},
		{"aes-256", symSpec{MechAESKeyGen, 32}, false},
		// SM 档：fail-closed 拒绝（不得映射到 AES 冒充合规，C-3）。
		{"sm4", symSpec{}, true},
		{"sm4-128", symSpec{}, true},
		{"sm4-256", symSpec{}, true},
		{"unknown", symSpec{}, true},
	}
	for _, c := range cases {
		t.Run("spec="+c.spec, func(t *testing.T) {
			got, err := parseSymSpec(c.spec)
			if c.wantErr {
				if err == nil {
					t.Fatalf("spec=%q 应报错", c.spec)
				}
				// SM 档拒绝须包装 ErrNotImplemented（明确"未实现"语义，
				// 区别于"未知 spec"的参数错误）。
				if strings.HasPrefix(c.spec, "sm4") && !errors.Is(err, ErrNotImplemented) {
					t.Fatalf("SM 档拒绝应包装 ErrNotImplemented: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("spec=%q: %v", c.spec, err)
			}
			if got != c.want {
				t.Fatalf("spec=%q: got %+v want %+v", c.spec, got, c.want)
			}
		})
	}
}

// TestSymSpecSMMessage SM 拒绝消息须点名 C-3 合规语义（防"静默映射"）。
func TestSymSpecSMMessage(t *testing.T) {
	_, err := parseSymSpec("sm4-128")
	if err == nil {
		t.Fatal("应报错")
	}
	if !strings.Contains(err.Error(), "C-3") || !strings.Contains(err.Error(), "S3-a") {
		t.Fatalf("SM 拒绝消息应含合规语义与选型指引: %v", err)
	}
}

// TestSecretKeyTemplate 属性模板的安全默认全集。
// 注意：miekg/pkcs11 的 NewAttribute 把值转成 C 内存布局字节（uint 为大端/
// 小端平台相关），故 uint 属性只断言存在与非空，具体数值语义由真机回读
// 属性验证（pkcs11_live_test.go）。
func TestSecretKeyTemplate(t *testing.T) {
	tmpl := secretKeyTemplate("pfx-alias", 32, false)
	byType := map[uint]*pkcs11.Attribute{}
	for _, a := range tmpl {
		byType[a.Type] = a
	}
	boolTrue := []uint{
		pkcs11.CKA_TOKEN, pkcs11.CKA_PRIVATE, pkcs11.CKA_SENSITIVE,
		pkcs11.CKA_ENCRYPT, pkcs11.CKA_DECRYPT,
	}
	for _, k := range boolTrue {
		a, ok := byType[k]
		if !ok {
			t.Fatalf("缺属性 CKA 0x%x", k)
		}
		if len(a.Value) != 1 || a.Value[0] != 1 {
			t.Fatalf("CKA 0x%x 应为 true: got %v", k, a.Value)
		}
	}
	if a, ok := byType[pkcs11.CKA_EXTRACTABLE]; !ok || len(a.Value) != 1 || a.Value[0] != 0 {
		t.Fatalf("CKA_EXTRACTABLE 应为 false（默认不可导出，R-S3-4）: %+v", a)
	}
	for _, k := range []uint{pkcs11.CKA_CLASS, pkcs11.CKA_KEY_TYPE, pkcs11.CKA_VALUE_LEN} {
		a, ok := byType[k]
		if !ok {
			t.Fatalf("缺属性 CKA 0x%x", k)
		}
		if len(a.Value) == 0 {
			t.Fatalf("CKA 0x%x 值不应为空", k)
		}
	}
	if a, ok := byType[pkcs11.CKA_LABEL]; !ok || string(a.Value) != "pfx-alias" {
		t.Fatalf("CKA_LABEL: got %+v", a)
	}
	if _, ok := byType[pkcs11.CKA_VALUE]; ok {
		t.Fatal("模板不应含 CKA_VALUE（导入路径单独追加）")
	}
	// valueLen<=0：导入路径省略 CKA_VALUE_LEN（C_CreateObject 上为只读
	// 属性，真机实测 CKR_ATTRIBUTE_READ_ONLY）。
	tmplImp := secretKeyTemplate("pfx-alias", 0, false)
	for _, a := range tmplImp {
		if a.Type == pkcs11.CKA_VALUE_LEN {
			t.Fatal("valueLen=0 模板不应含 CKA_VALUE_LEN")
		}
	}
	// extractable=true 变体（M4-4b wrap 路径预留）：该属性须可放宽。
	tmpl2 := secretKeyTemplate("pfx-alias", 32, true)
	for _, a := range tmpl2 {
		if a.Type == pkcs11.CKA_EXTRACTABLE && (len(a.Value) != 1 || a.Value[0] != 1) {
			t.Fatalf("extractable=true 变体应放开: got %v", a.Value)
		}
	}
}

// TestPKCS11BackendNotInitializedFailClosed 未 Init 的后端调用三个方法
// 一律 ErrModuleUnavailable（不回退、不 panic）。
func TestPKCS11BackendNotInitializedFailClosed(t *testing.T) {
	b := &PKCS11Backend{}
	if _, err := b.GenerateKey("aes-128", "k"); !errors.Is(err, ErrModuleUnavailable) {
		t.Fatalf("GenerateKey: got %v", err)
	}
	if _, err := b.ImportKey("aes-128", make([]byte, 16), "k"); !errors.Is(err, ErrModuleUnavailable) {
		t.Fatalf("ImportKey: got %v", err)
	}
	if err := b.DestroyKey(mustEnc(t, 0, "", 1)); !errors.Is(err, ErrModuleUnavailable) {
		t.Fatalf("DestroyKey: got %v", err)
	}
}

// TestPKCS11GenerateKeySMRejectedBeforeInit SM spec 在机制查询前即被拒
// （不依赖 ctx；错误语义为 ErrNotImplemented 而非 ModuleUnavailable）。
func TestPKCS11GenerateKeySMRejectedBeforeInit(t *testing.T) {
	b := &PKCS11Backend{}
	_, err := b.GenerateKey("sm4-128", "k")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("SM spec 应 ErrNotImplemented: %v", err)
	}
}
