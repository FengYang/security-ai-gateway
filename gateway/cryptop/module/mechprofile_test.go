// mechprofile_test.go —— M4-3 厂商机制 profile（B-6.1-2）无 tag 单测。
//
// 覆盖：profile 加载/校验（fail-closed 各分支）、CKM 解析、机制表查询、
// 配置项接线。真机探测路径见 pkcs11_live_test.go（-tags pkcs11）。
package cryptopmodule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// softhsmProfilePath 随源码发布的 SoftHSM 功能验证档 profile。
func softhsmProfilePath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("profiles", "softhsm-generic.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("profile 文件应随源码发布: %s: %v", p, err)
	}
	return p
}

// TestLoadMechProfileSofthsmGeneric 随源码发布的 functional profile 必须
// 加载通过且条目完备（CKM 值以 pkcs11t.h 标准头登记，非臆测）。
func TestLoadMechProfileSofthsmGeneric(t *testing.T) {
	p, err := LoadMechProfile(softhsmProfilePath(t))
	if err != nil {
		t.Fatalf("LoadMechProfile(softhsm-generic): %v", err)
	}
	if p.ProfileID != "softhsm-generic" {
		t.Fatalf("ProfileID=%q", p.ProfileID)
	}
	if p.Interface != mechInterfacePKCS11 {
		t.Fatalf("Interface=%q", p.Interface)
	}
	tbl := p.Table()
	if tbl.Len() != 10 {
		t.Fatalf("登记条数=%d want 10（%v）", tbl.Len(), tbl.Names())
	}
	// 抽查三条关键映射（值来自 .248 实测 zconst.go，2026-10-24）。
	e, ok := tbl.Lookup(MechAESGCM)
	if !ok || e.CKM != "0x00001087" {
		t.Fatalf("aes-gcm 条目=%+v ok=%v", e, ok)
	}
	if n, ok := tbl.NameByCKM(0x1087); !ok || n != MechAESGCM {
		t.Fatalf("NameByCKM(0x1087)=%q ok=%v", n, ok)
	}
	if e, ok := tbl.Lookup(MechAESKeyWrap); !ok || e.CKM != "0x00002109" {
		t.Fatalf("aes-key-wrap 条目=%+v ok=%v（CKM_AES_KEY_WRAP 标准值为 0x2109，勿凭记忆写 0x1090）", e, ok)
	}
	// 功能验证档不得含任何 SM 机制（S3-a 基线 §5.1：不得映射成 SM 名冒充合规）。
	for _, m := range []string{MechSM4GCM, MechSM3, MechHMACSM3, MechSM2Sign, MechSM2ECDH} {
		if _, ok := tbl.Lookup(m); ok {
			t.Fatalf("softhsm-generic 不得登记 SM 机制 %q", m)
		}
	}
	// Names 升序。
	names := tbl.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names 非升序: %v", names)
		}
	}
}

// TestLoadMechProfileTemplateVendorSM 厂商模板（CKM 未填）必须 fail-closed，
// 且错误信息指明待填机制与原因。
func TestLoadMechProfileTemplateVendorSM(t *testing.T) {
	_, err := LoadMechProfile(filepath.Join("profiles", "template-vendor-sm.json"))
	if err == nil {
		t.Fatal("厂商模板（CKM 留空）应加载失败（fail-closed）")
	}
	msg := err.Error()
	for _, want := range []string{"sm4-gcm", "CKM"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息应含 %q，实得: %s", want, msg)
		}
	}
}

// TestParseCKM CKM 解析：0x 十六进制 / 十进制 / 非法值 / 空值。
func TestParseCKM(t *testing.T) {
	cases := []struct {
		in     string
		want   uint
		errSub string
	}{
		{"0x00001087", 0x1087, ""},
		{"0X1087", 0x1087, ""},
		{"4223", 4223, ""},
		{"0x80050001", 0x80050001, ""},
		{"", 0, "未登记"},
		{"0x", 0, "非法十六进制"},
		{"0xZZ", 0, "非法十六进制"},
		{"abc", 0, "非法"},
		{"-1", 0, "非法"},
	}
	for _, c := range cases {
		got, err := parseCKM(c.in)
		if c.errSub != "" {
			if err == nil {
				t.Fatalf("parseCKM(%q) 应报错", c.in)
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("parseCKM(%q) 错误应含 %q，实得: %v", c.in, c.errSub, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseCKM(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseCKM(%q)=%#x want %#x", c.in, got, c.want)
		}
	}
}

// TestMechProfileValidationFailClosed 各违规分支必须 fail-closed 且错误明确。
func TestMechProfileValidationFailClosed(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("写临时 profile: %v", err)
		}
		return p
	}
	cases := []struct {
		name   string
		body   string
		errSub string
	}{
		{
			"未知机制名",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"sm9-foo","ckm":"0x1","source":"vendor-doc:x"}]}`,
			"未知机制名",
		},
		{
			"机制名重复",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x1","source":"standard-header:h"},{"name":"aes-gcm","ckm":"0x2","source":"standard-header:h"}]}`,
			"重复登记",
		},
		{
			"CKM 冲突（两名一值）",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x1","source":"standard-header:h"},{"name":"aes-cbc","ckm":"0x1","source":"standard-header:h"}]}`,
			"冲突",
		},
		{
			"SM 机制 source 无 vendor 标注",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"sm3","ckm":"0x80050001","sm":true,"source":"standard-header:h"}]}`,
			"vendor",
		},
		{
			"source 为空",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x1","source":""}]}`,
			"source 为空",
		},
		{
			"mechanisms 为空",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[]}`,
			"mechanisms 为空",
		},
		{
			"interface 非 pkcs11",
			`{"profile_id":"x","vendor":"x","interface":"sdf","mechanisms":[{"name":"sm3","ckm":"0x1","sm":true,"source":"vendor-doc:x"}]}`,
			"interface",
		},
		{
			"min>max",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x1","min_key_bits":256,"max_key_bits":128,"source":"standard-header:h"}]}`,
			"min_key_bits",
		},
		{
			"profile_id 为空",
			`{"profile_id":"","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x1","source":"standard-header:h"}]}`,
			"profile_id 为空",
		},
		{
			"vendor 为空",
			`{"profile_id":"x","vendor":"","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x1","source":"standard-header:h"}]}`,
			"vendor 为空",
		},
		{
			"CKM 为 0",
			`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[{"name":"aes-gcm","ckm":"0x0","source":"standard-header:h"}]}`,
			"CKM 为 0",
		},
		{
			"非 JSON",
			`not-json`,
			"解析失败",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadMechProfile(write(t, c.body))
			if err == nil {
				t.Fatalf("应 fail-closed 报错")
			}
			if !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("错误应含 %q，实得: %v", c.errSub, err)
			}
		})
	}
}

// TestLoadMechProfileUnreadable 文件不存在必须明确报错（不静默放行）。
func TestLoadMechProfileUnreadable(t *testing.T) {
	if _, err := LoadMechProfile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("不存在的 profile 应报错")
	}
	if _, err := LoadMechProfile("  "); err == nil {
		t.Fatal("空路径应报错")
	}
}

// TestMechTableEmpty 空表语义（未配置 profile：仅 rand 恒登记）。
func TestMechTableEmpty(t *testing.T) {
	tbl := EmptyMechTable()
	if !tbl.IsEmpty() || tbl.Len() != 0 || len(tbl.Names()) != 0 {
		t.Fatalf("空表异常: len=%d names=%v", tbl.Len(), tbl.Names())
	}
	if _, ok := tbl.Lookup(MechAESGCM); ok {
		t.Fatal("空表不应命中")
	}
	if _, ok := tbl.NameByCKM(0x1087); ok {
		t.Fatal("空表不应命中")
	}
	var nilTbl *MechTable
	if _, ok := nilTbl.Lookup(MechAESGCM); ok {
		t.Fatal("nil 表不应命中")
	}
	if nilTbl.Len() != 0 || !nilTbl.IsEmpty() {
		t.Fatal("nil 表 Len/IsEmpty 异常")
	}
}

// TestConfigValidateMechProfile 配置项接线：坏 profile 在 Validate 即拒绝
// （Init 接触设备前 fail-closed）；好 profile 通过。
func TestConfigValidateMechProfile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"profile_id":"x","vendor":"x","interface":"pkcs11","mechanisms":[]}`), 0o600); err != nil {
		t.Fatalf("写临时文件: %v", err)
	}
	cfg := DefaultConfig()
	cfg.MechanismProfile = bad
	if err := cfg.Validate(); err == nil {
		t.Fatal("坏 profile 应被 Validate 拒绝")
	} else if !strings.Contains(err.Error(), "mechanisms 为空") {
		t.Fatalf("错误应定位到 profile 校验，实得: %v", err)
	}

	// 好 profile：mock 后端跳过厂商项校验（lib_path 等），单独验证 profile 链路。
	cfg = DefaultConfig()
	cfg.Backend = BackendMock
	cfg.MechanismProfile = softhsmProfilePath(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("好 profile 应通过 Validate: %v", err)
	}

	// 未配置 profile 的缺省态不受影响。
	cfg.MechanismProfile = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("未配置 profile 应通过 Validate: %v", err)
	}
}

// TestEnvMechProfileLoading env 载体接线（MODULE_MECHANISM_PROFILE，
// 经 LoadConfig 生效）。
func TestEnvMechProfileLoading(t *testing.T) {
	t.Setenv(EnvMechProfile, "/etc/cryptop/vendor-x-pkcs11.json")
	cfg := LoadConfig()
	if cfg.MechanismProfile != "/etc/cryptop/vendor-x-pkcs11.json" {
		t.Fatalf("env 未生效: %q", cfg.MechanismProfile)
	}
}
