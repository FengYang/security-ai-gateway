//go:build pkcs11

// pkcs11_live_test.go —— PKCS#11 后端真机用例（M4-1）。
//
// 运行前提（.248 联调机）：SoftHSMv2 token（libsofthsm2.so）+ 环境变量：
//
//	P11_LIVE=1                    启用（未设置则 Skip，不以 mock 冒充真机）
//	P11_LIVE_LIB=/usr/lib/softhsm/libsofthsm2.so
//	P11_LIVE_PIN=0000             口令（测试内以 env: 载体传入，验证 R-S3-2 链路）
//
// SoftHSM 实测（2026-10-24）无 SM 机制，故：
//   - 生命周期用例把 RequiredMechanisms 收窄为 ["rand"]（验证探测→校验正路径）；
//   - 缺省六机制必然启动拒（验证 R-S3-11 fail-closed 负路径）。
package cryptopmodule

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

func p11LiveConfig(t *testing.T, required []string) *Config {
	t.Helper()
	if os.Getenv("P11_LIVE") != "1" {
		t.Skip("P11_LIVE != 1，跳过真机用例（不以 mock 冒充真机）")
	}
	cfg := DefaultConfig()
	cfg.Backend = BackendPKCS11
	cfg.LibPath = envOr("P11_LIVE_LIB", "/usr/lib/softhsm/libsofthsm2.so")
	cfg.Slot = 0                    // GetSlotList 下标语义（SoftHSM 单 token）
	cfg.PinRef = "env:P11_LIVE_PIN" // 载体引用（R-S3-2），非字面值
	cfg.MaxSessions = 4
	cfg.SessionQueueSize = 2
	cfg.RequiredMechanisms = required
	return cfg
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// profilePath 随源码发布的 profile 文件（go test 工作目录即包目录）。
func profilePath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("profiles", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("profile 文件缺失: %s: %v", p, err)
	}
	return p
}

// TestPKCS11LiveLifecycleRand M4-1 主链路：Init→Capabilities→Rand→会话池→
// Health→Close（§7.4 验证项"真机跑通 OpenDevice+GenerateRandom"的 PKCS#11 等价物）。
func TestPKCS11LiveLifecycleRand(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()
	if caps.Backend != BackendPKCS11 {
		t.Fatalf("caps.Backend=%q want pkcs11", caps.Backend)
	}
	if !caps.HasMechanism(MechRand) {
		t.Fatalf("caps 应含 rand（C_GenerateRandom 通用），实得 %v", caps.Mechanisms)
	}
	t.Logf("探测到能力: vendor=%q model=%q mechanisms=%v", caps.Vendor, caps.Model, caps.Mechanisms)

	r1, err := backend.Rand(32)
	if err != nil {
		t.Fatalf("Rand(32): %v", err)
	}
	if len(r1) != 32 {
		t.Fatalf("Rand(32) 长度=%d", len(r1))
	}
	r2, err := backend.Rand(32)
	if err != nil {
		t.Fatalf("Rand(32) 第二次: %v", err)
	}
	if string(r1) == string(r2) {
		t.Fatal("两次 Rand(32) 相同——CSPRNG 异常")
	}

	s, err := backend.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	if err := backend.ReleaseSession(s); err != nil {
		t.Fatalf("ReleaseSession: %v", err)
	}

	if h := backend.Health(); h != HealthOK {
		t.Fatalf("Health=%v want ok", h)
	}

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if h := backend.Health(); h != HealthDown {
		t.Fatalf("Close 后 Health=%v want down", h)
	}
	if _, err := backend.Rand(16); err == nil {
		t.Fatal("Close 后 Rand 应失败（fail-closed）")
	}
}

// TestPKCS11LiveDefaultMechanismsFailClosed R-S3-11：SoftHSM 无 SM 机制，
// 缺省六机制必须启动拒并列出缺失清单（fail-closed，不冒充合规）。
func TestPKCS11LiveDefaultMechanismsFailClosed(t *testing.T) {
	cfg := p11LiveConfig(t, DefaultRequiredMechanisms())
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("SoftHSM 无 SM 机制，缺省六机制应启动拒（R-S3-11）")
	}
	if !errors.Is(err, ErrMechanismMissing) {
		t.Fatalf("应返回 ErrMechanismMissing，实得: %v", err)
	}
	msg := err.Error()
	for _, m := range []string{MechSM4GCM, MechSM3, MechHMACSM3, MechSM2Sign, MechSM2ECDH} {
		if !strings.Contains(msg, m) {
			t.Fatalf("缺失清单应含 %s，实得: %s", m, msg)
		}
	}
	t.Logf("R-S3-11 fail-closed 如实触发: %v", err)
}

// TestPKCS11LiveLiteralPINRejected R-S3-2：PinRef 字面值（无 file:/env: 载体）
// 必须在 Init 期拒绝。
func TestPKCS11LiveLiteralPINRejected(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	cfg.PinRef = "0000" // 字面值：违规
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("PinRef 字面值应被拒绝（R-S3-2）")
	}
	t.Logf("R-S3-2 如实触发: %v", err)
}

// TestPKCS11LiveMechProfileFunctional M4-3/B-6.1-2：generic profile 登记的
// 标准机制（SoftHSM 实测有）→ Init 成功，Capabilities 只含探测命中项，
// Profile 字段溯源 profile_id。
func TestPKCS11LiveMechProfileFunctional(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand, MechAESGCM, MechAESKeyWrap, MechSHA256})
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11, generic profile): %v", err)
	}
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()
	if caps.Profile != "softhsm-generic" {
		t.Fatalf("caps.Profile=%q want softhsm-generic（B-6.1-2 溯源）", caps.Profile)
	}
	for _, m := range []string{MechRand, MechAESGCM, MechAESKeyWrap, MechSHA256} {
		if !caps.HasMechanism(m) {
			t.Fatalf("caps 应含 %s，实得 %v", m, caps.Mechanisms)
		}
	}
	// 功能验证档不得冒充合规档：任何 SM 机制都不得出现。
	for _, m := range []string{MechSM4GCM, MechSM3, MechHMACSM3, MechSM2Sign, MechSM2ECDH} {
		if caps.HasMechanism(m) {
			t.Fatalf("generic profile 不得登记 SM 机制 %q（不得冒充合规），实得 %v", m, caps.Mechanisms)
		}
	}
	t.Logf("generic profile 探测命中: mechanisms=%v", caps.Mechanisms)
}

// TestPKCS11LiveGenericProfileNoSM R-S3-11：即使配置了 generic profile，
// 缺省六 SM 机制仍必须启动拒（证明功能验证档不冒充合规档）。
func TestPKCS11LiveGenericProfileNoSM(t *testing.T) {
	cfg := p11LiveConfig(t, DefaultRequiredMechanisms())
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("generic profile 无 SM 机制，缺省六机制应启动拒（R-S3-11）")
	}
	if !errors.Is(err, ErrMechanismMissing) {
		t.Fatalf("应返回 ErrMechanismMissing，实得: %v", err)
	}
	t.Logf("generic profile + SM 缺省六机制 fail-closed 如实触发: %v", err)
}

// TestPKCS11LiveMechProfileTemplateRejected B-6.1-2：厂商模板（CKM 未填）
// 必须在 Init 期 fail-closed，且错误信息指明待填机制。
func TestPKCS11LiveMechProfileTemplateRejected(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	cfg.MechanismProfile = profilePath(t, "template-vendor-sm.json")
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("厂商模板（CKM 未填）应启动拒（fail-closed，禁止臆测标准值）")
	}
	msg := err.Error()
	for _, want := range []string{"sm4-gcm", "CKM"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息应含 %q，实得: %s", want, msg)
		}
	}
	t.Logf("厂商模板 fail-closed 如实触发: %v", err)
}

// TestPKCS11LiveKeyObjects M4-4a 真机：GenerateKey/ImportKey/DestroyKey
// 全链路 + KeyRef 归属校验 + 对象属性回读（C_FindObjects 按 label 检索，
// C_GetAttributeValue 回读 CKA_TOKEN/CKA_CLASS/CKA_VALUE_LEN；敏感对象
// 读 CKA_VALUE 必须被拒，证明"默认不可读出"）。
//
// alias 带纳秒时间戳：token 对象持久化（CKA_TOKEN=true），唯一 alias 避免
// 与既往运行残留互撞（FindObjects 按 label 精确匹配）。
func TestPKCS11LiveKeyObjects(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand, MechAESKeyGen})
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11, generic profile): %v", err)
	}
	defer func() { _ = backend.Close() }()
	pb, ok := backend.(*PKCS11Backend)
	if !ok {
		t.Fatalf("后端类型=%T want *PKCS11Backend", backend)
	}

	alias := "m44a-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	label := pb.keyLabel(alias)

	// ---- GenerateKey（C_GenerateKey）----
	ref, err := backend.GenerateKey("aes-256", alias)
	if err != nil {
		t.Fatalf("GenerateKey(aes-256): %v", err)
	}
	if !strings.HasPrefix(string(ref), "pk11:v1:") {
		t.Fatalf("KeyRef 前缀异常: %q", ref)
	}
	t.Logf("GenerateKey → ref=%s label=%q", ref, label)

	// ---- 属性回读：对象应持久化于 token 且为 SECRET_KEY/AES-256 ----
	obj := findObjectByLabel(t, pb, label)
	if obj == 0 {
		t.Fatal("按 label 未找到生成的对象（CKA_TOKEN 持久化失败？）")
	}
	assertAttrBool(t, pb, obj, pkcs11.CKA_TOKEN, true)
	assertAttrBool(t, pb, obj, pkcs11.CKA_PRIVATE, true)
	assertAttrBool(t, pb, obj, pkcs11.CKA_SENSITIVE, true)
	assertAttrBool(t, pb, obj, pkcs11.CKA_EXTRACTABLE, false)
	assertAttrUintLE(t, pb, obj, pkcs11.CKA_VALUE_LEN, 32)
	assertAttrUintLE(t, pb, obj, pkcs11.CKA_CLASS, uint(pkcs11.CKO_SECRET_KEY))
	assertAttrUintLE(t, pb, obj, pkcs11.CKA_KEY_TYPE, uint(pkcs11.CKK_AES))
	// 敏感对象读 CKA_VALUE 必须被拒（CKR_ATTRIBUTE_SENSITIVE）——"默认
	// 不可读出"的真机证明（R-S3-4）。
	assertAttrSensitiveRejected(t, pb, obj)

	// ---- ImportKey（C_CreateObject）+ 长度校验 ----
	if _, err := backend.ImportKey("aes-128", make([]byte, 16), alias+"-imp"); err != nil {
		t.Fatalf("ImportKey(aes-128, 16B): %v", err)
	}
	if _, err := backend.ImportKey("aes-128", make([]byte, 15), alias+"-bad"); err == nil {
		t.Fatal("ImportKey 长度不符应拒绝")
	}
	if _, err := backend.ImportKey("sm4-128", make([]byte, 16), alias+"-sm"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("ImportKey(sm4-128) 应 ErrNotImplemented（SM 档待 S3-a），实得: %v", err)
	}

	// ---- DestroyKey + 幂等 ----
	if err := backend.DestroyKey(ref); err != nil {
		t.Fatalf("DestroyKey: %v", err)
	}
	if obj := findObjectByLabel(t, pb, label); obj != 0 {
		t.Fatal("DestroyKey 后对象仍存在（C_DestroyObject 未生效）")
	}
	if err := backend.DestroyKey(ref); err != nil {
		t.Fatalf("DestroyKey 重复删除应幂等成功，实得: %v", err)
	}

	// ---- KeyRef 归属校验：mock ref / 跨分区误用即拒 ----
	if err := backend.DestroyKey(KeyRef("mock:whatever")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("mock ref 应 ErrKeyNotFound，实得: %v", err)
	}

	// 清理导入的对象（幂等销毁，失败仅告警不掩蔽主断言）。
	impRef, err := backend.ImportKey("aes-128", make([]byte, 16), alias+"-imp2")
	if err != nil {
		t.Logf("清理用 ImportKey 失败（仅告警）: %v", err)
	} else {
		if err := backend.DestroyKey(impRef); err != nil {
			t.Logf("清理 DestroyKey 失败（仅告警）: %v", err)
		}
	}
	t.Logf("M4-4a 真机链路 PASS: generate→属性回读→敏感读拒→import→destroy→幂等→归属校验")
}

// findObjectByLabel C_FindObjects 按 CKA_LABEL 精确检索（返回首个句柄；
// 无匹配返回 0）。会话走 Acquire/Release。
func findObjectByLabel(t *testing.T, pb *PKCS11Backend, label string) uint {
	t.Helper()
	s, err := pb.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	defer func() { _ = pb.ReleaseSession(s) }()
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	if err := pb.ctx.FindObjectsInit(pkcs11.SessionHandle(s), tmpl); err != nil {
		t.Fatalf("C_FindObjectsInit: %v", err)
	}
	objs, _, err := pb.ctx.FindObjects(pkcs11.SessionHandle(s), 8)
	if err != nil {
		_ = pb.ctx.FindObjectsFinal(pkcs11.SessionHandle(s))
		t.Fatalf("C_FindObjects: %v", err)
	}
	if err := pb.ctx.FindObjectsFinal(pkcs11.SessionHandle(s)); err != nil {
		t.Fatalf("C_FindObjectsFinal: %v", err)
	}
	if len(objs) == 0 {
		return 0
	}
	return uint(objs[0])
}

// getAttr C_GetAttributeValue 回读单属性（请求列表仅含类型，回读填 Value）。
func getAttr(t *testing.T, pb *PKCS11Backend, obj uint, attrType uint) []byte {
	t.Helper()
	s, err := pb.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	defer func() { _ = pb.ReleaseSession(s) }()
	tmpl := []*pkcs11.Attribute{{Type: attrType}}
	out, err := pb.ctx.GetAttributeValue(pkcs11.SessionHandle(s), pkcs11.ObjectHandle(obj), tmpl)
	if err != nil {
		t.Fatalf("C_GetAttributeValue(0x%x): %v", attrType, err)
	}
	if len(out) == 0 {
		t.Fatalf("C_GetAttributeValue(0x%x) 返回空", attrType)
	}
	return out[0].Value
}

func assertAttrBool(t *testing.T, pb *PKCS11Backend, obj uint, attrType uint, want bool) {
	t.Helper()
	v := getAttr(t, pb, obj, attrType)
	got := len(v) == 1 && v[0] == 1
	if got != want {
		t.Fatalf("CKA 0x%x: got %v want %v (raw %v)", attrType, got, want, v)
	}
}

// assertAttrUintLE 回读 uint 属性（C 内存布局；小端平台取首字节低 8 位，
// x86_64/arm64 Linux 均小端；精确宽度解析留给厂商库直连验证）。
func assertAttrUintLE(t *testing.T, pb *PKCS11Backend, obj uint, attrType uint, want uint) {
	t.Helper()
	v := getAttr(t, pb, obj, attrType)
	if len(v) == 0 || uint(v[0]) != want&0xff {
		t.Fatalf("CKA 0x%x 低字节: got %v want %d (raw %v)", attrType, v, want&0xff, v)
	}
}

// assertAttrSensitiveRejected 敏感对象的 CKA_VALUE 回读必须被拒
// （CKR_ATTRIBUTE_SENSITIVE；R-S3-4 不可读出的真机证明）。
func assertAttrSensitiveRejected(t *testing.T, pb *PKCS11Backend, obj uint) {
	t.Helper()
	s, err := pb.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	defer func() { _ = pb.ReleaseSession(s) }()
	tmpl := []*pkcs11.Attribute{{Type: pkcs11.CKA_VALUE}}
	if _, err := pb.ctx.GetAttributeValue(pkcs11.SessionHandle(s), pkcs11.ObjectHandle(obj), tmpl); err == nil {
		t.Fatal("敏感对象回读 CKA_VALUE 应被拒（CKA_SENSITIVE=true；R-S3-4）")
	} else {
		var p11err pkcs11.Error
		if !errors.As(err, &p11err) || p11err != pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE) {
			t.Fatalf("应返回 CKR_ATTRIBUTE_SENSITIVE，实得: %v", err)
		}
	}
}
