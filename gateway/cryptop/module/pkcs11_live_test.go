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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
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

// TestPKCS11LiveSymmetricOps M4-4b 真机：Seal/Open/HMAC/WrapKey/UnwrapKey/
// KDF 全链路 + 与 Go 标准库（crypto/aes GCM / crypto/hmac）交叉验证。
//
// 判据强度：导入**已知固定密钥**（pkcs11 生成的密钥 SENSITIVE 不可读，无法
// 喂 Go 库），使模块输出与 Go 库输出可逐字节比对——证明适配层编码/参数传递
// 正确，而非"能跑通而已"。unwrap 等价性用"原对象 Seal → 解开对象 Open"判定
// （同 nonce 下等价 ⟺ 同密钥）。
func TestPKCS11LiveSymmetricOps(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand, MechAESGCM, MechSHA256HMAC, MechAESKeyWrap})
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11, generic profile): %v", err)
	}
	defer func() { _ = backend.Close() }()
	pb, ok := backend.(*PKCS11Backend)
	if !ok {
		t.Fatalf("后端类型=%T", backend)
	}

	uniq := strconv.FormatInt(time.Now().UnixNano(), 10)
	encKey := repeatByte(0x11, 32)
	macKey := repeatByte(0x22, 32)
	kekKey := repeatByte(0x33, 32)
	dekKey := repeatByte(0x44, 32)

	// 清理台账（测试末统一销毁；幂等）。
	var cleanup []KeyRef
	destroy := func(r KeyRef) {
		if err := backend.DestroyKey(r); err != nil {
			t.Logf("清理 DestroyKey 失败（仅告警）: %v", err)
		}
	}
	defer func() {
		for _, r := range cleanup {
			destroy(r)
		}
	}()

	encRef, err := backend.ImportKey("aes-256", encKey, "m44b-enc-"+uniq)
	if err != nil {
		t.Fatalf("ImportKey(enc): %v", err)
	}
	cleanup = append(cleanup, encRef)
	macRef, err := backend.ImportKey("aes-256-mac", macKey, "m44b-mac-"+uniq)
	if err != nil {
		t.Fatalf("ImportKey(mac): %v", err)
	}
	cleanup = append(cleanup, macRef)
	kekRef, err := backend.ImportKey("aes-256-kek", kekKey, "m44b-kek-"+uniq)
	if err != nil {
		t.Fatalf("ImportKey(kek): %v", err)
	}
	cleanup = append(cleanup, kekRef)
	dekRef, err := backend.ImportKey("aes-256-dek", dekKey, "m44b-dek-"+uniq)
	if err != nil {
		t.Fatalf("ImportKey(dek): %v", err)
	}
	cleanup = append(cleanup, dekRef)

	// ---- Seal/Open 往返 + Go 交叉 ----
	nonce := repeatByte(0xA5, symNonceSize)
	pt := []byte("M4-4b 对称运算真机交叉验证负载")
	aad := []byte("cryptop/seal/v1")
	ct, err := backend.Seal(encRef, nonce, pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ct) != len(pt)+symTagSize {
		t.Fatalf("Seal 输出长度 %d != %d（ct||tag 布局）", len(ct), len(pt)+symTagSize)
	}
	wantCT := goGCMSeal(t, encKey, nonce, pt, aad)
	if string(ct) != string(wantCT) {
		t.Fatal("Seal 输出与 Go crypto/aes GCM 不一致（适配层编码错误）")
	}
	got, err := backend.Open(encRef, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatal("Open 往返明文不符")
	}
	// 篡改 tag → 认证失败（明确错误语义）。
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 0x01
	if _, err := backend.Open(encRef, nonce, bad, aad); err == nil {
		t.Fatal("篡改 tag 的 Open 应失败（GCM 认证）")
	} else {
		t.Logf("篡改 tag 拒绝: %v", err)
	}
	// 错 aad → 认证失败。
	if _, err := backend.Open(encRef, nonce, ct, []byte("wrong")); err == nil {
		t.Fatal("错 aad 的 Open 应失败")
	}

	// ---- HMAC + Go 交叉 ----
	data := []byte("hmac 交叉验证数据")
	mac, err := backend.HMAC(macRef, data)
	if err != nil {
		t.Fatalf("HMAC: %v", err)
	}
	if string(mac) != string(goHMACSHA256(macKey, data)) {
		t.Fatal("HMAC 输出与 Go crypto/hmac 不一致")
	}
	// 用途最小权限：enc 对象做 HMAC 必须被模块拒绝（真机证明）。
	if _, err := backend.HMAC(encRef, data); err == nil {
		t.Fatal("enc 对象做 HMAC 应被模块拒绝（用途最小权限）")
	} else {
		t.Logf("enc 对象 HMAC 拒绝: %v", err)
	}

	// ---- Wrap/Unwrap 往返 + 字节级等价 ----
	wrapped, err := backend.WrapKey(kekRef, dekKey)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if len(wrapped) != len(dekKey)+symWrapTagSize {
		t.Fatalf("wrapped 长度 %d != %d（RFC 3394: key + 8B AIV）", len(wrapped), len(dekKey)+symWrapTagSize)
	}
	unwrapped, err := backend.UnwrapKey(kekRef, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	// 等价性：解开的字节须与原始 DEK 逐字节一致（RFC 3394 往返保真）。
	if string(unwrapped) != string(dekKey) {
		t.Fatal("unwrap 字节与原 DEK 不一致")
	}
	// 解开结果可作 enc 密钥使用（端到端可用性）。
	unwrappedEncRef, err := backend.ImportKey("aes-256", unwrapped, "m44b-unwrappedenc-"+uniq)
	if err != nil {
		t.Fatalf("ImportKey(unwrapped→enc): %v", err)
	}
	cleanup = append(cleanup, unwrappedEncRef)
	// 篡改 wrapped → 解开失败。
	badW := append([]byte(nil), wrapped...)
	badW[len(badW)-1] ^= 0x01
	if _, err := backend.UnwrapKey(kekRef, badW); err == nil {
		t.Fatal("篡改 wrapped 的 UnwrapKey 应失败")
	}

	// ---- KDF + Go 交叉（跨块 outLen=40）----
	salt := []byte("kdf-salt")
	info := []byte("kdf-info")
	out40, err := backend.KDF(dekRef, salt, info, 40, "")
	if err != nil {
		t.Fatalf("KDF(40): %v", err)
	}
	if string(out40) != string(goKDFHMAC(dekKey, salt, info, 40)) {
		t.Fatal("KDF 输出与 Go HMAC 迭代不一致")
	}
	// 单块 outLen=32 与 40 字节前缀一致（计数器结构）。
	out32, err := backend.KDF(dekRef, salt, info, 32, "")
	if err != nil {
		t.Fatalf("KDF(32): %v", err)
	}
	if string(out40[:32]) != string(out32) {
		t.Fatal("KDF 跨块前缀不一致（计数器结构错误）")
	}
	// alias 登记：派生结果应成为模块内对象（D-4 模块内执行位置）。
	if _, err := backend.KDF(dekRef, salt, info, 32, "m44b-kdfobj-"+uniq); err != nil {
		t.Fatalf("KDF(alias): %v", err)
	}
	if obj := findObjectByLabel(t, pb, pb.keyLabel("m44b-kdfobj-"+uniq)); obj == 0 {
		t.Fatal("KDF alias 登记对象未找到（D-4 模块内登记失败）")
	} else {
		cleanup = append(cleanup, mustEnc(t, 0, cfg.Partition, obj))
	}
	t.Logf("M4-4b 真机链路 PASS: seal/open(+Go 交叉) → 篡改拒 → hmac(+Go 交叉) → 用途最小权限 → wrap/unwrap 等价 → KDF(+Go 交叉/跨块/登记)")
}

// repeatByte n 字节重复模式（固定已知密钥，供 Go 交叉验证）。
func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// goGCMSeal Go crypto/aes GCM 参考实现（Seal 输出 ct||tag 与模块一致）。
func goGCMSeal(t *testing.T, key, nonce, pt, aad []byte) []byte {
	t.Helper()
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatalf("NewGCM: %v", err)
	}
	return g.Seal(nil, nonce, pt, aad)
}

func goHMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// goKDFHMAC Go 侧复现 M4-4b 的 HMAC 迭代计数器 KDF（Z 构造同 pkcs11sym.go）。
func goKDFHMAC(key, salt, info []byte, outLen int) []byte {
	z := make([]byte, 0, 8+len(salt)+len(info))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(salt)))
	z = append(z, l[:]...)
	z = append(z, salt...)
	binary.BigEndian.PutUint32(l[:], uint32(len(info)))
	z = append(z, l[:]...)
	z = append(z, info...)
	out := make([]byte, 0, outLen+32)
	for ctr := uint32(1); len(out) < outLen; ctr++ {
		m := hmac.New(sha256.New, key)
		m.Write(z)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		m.Write(c[:])
		out = append(out, m.Sum(nil)...)
	}
	return out[:outLen]
}

// TestPKCS11LiveAsymmetricOps M4-4c 真机：Hash/GenerateKeyPair/Sign/Verify/
// ECDH/RotateKey 全链路 + 与 Go 标准库（crypto/ecdsa、crypto/ecdh、
// crypto/sha256）双向交叉验证。
//
// 判据强度（双向）：
//   - 模块私钥签名 → Go 库验签通过（证明模块产出的签名对模块公钥有效）；
//   - Go 库私钥签名 → 模块验签通过（证明模块 Verify 链路正确，非自签自验）；
//   - 模块协商私钥 + Go 协商公钥 ⟺ Go 协商私钥 + 模块公钥，两路共享秘密
//     逐字节一致（证明模块 ECDH 派生与私钥/公钥对应关系正确）；
//   - 用途最小权限：sign 密钥不能协商、ecdh 密钥不能签名（真机证明）。
func TestPKCS11LiveAsymmetricOps(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand, MechECKeyGen, MechECDSA, MechECDH1Derive, MechSHA256})
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11, generic profile): %v", err)
	}
	defer func() { _ = backend.Close() }()

	msg := []byte("M4-4c 非对称运算真机交叉验证消息")
	digest := sha256.Sum256(msg)

	// ---- Hash + Go 交叉 ----
	sum, err := backend.Hash(msg)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if string(sum) != string(digest[:]) {
		t.Fatal("Hash 输出与 Go crypto/sha256 不一致")
	}

	// 清理台账（幂等销毁）。
	var cleanup []KeyRef
	destroy := func(r KeyRef) {
		if err := backend.DestroyKey(r); err != nil {
			t.Logf("清理 DestroyKey 失败（仅告警）: %v", err)
		}
	}
	defer func() {
		for _, r := range cleanup {
			destroy(r)
		}
	}()

	// ---- GenerateKeyPair(签名用途) ----
	signRef, signPub, err := backend.GenerateKeyPair(UsageSign)
	if err != nil {
		t.Fatalf("GenerateKeyPair(sign): %v", err)
	}
	cleanup = append(cleanup, signRef)
	if len(signPub) != ecPointLen || signPub[0] != 0x04 {
		t.Fatalf("公钥应为 65B 非压缩点: len=%d head=0x%x", len(signPub), signPub[0])
	}
	goSignPub := goECDSAPub(t, signPub)

	// ---- Sign → Go 验签（模块产签名，Go 库验）----
	sig, err := backend.Sign(signRef, msg, "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(goSignPub, digest[:], sig) {
		t.Fatal("模块签名未通过 Go crypto/ecdsa 验签")
	}
	// uid 非空（ECDSA 档忽略，SM2 档才消费）——行为不因 uid 改变。
	sigUID, err := backend.Sign(signRef, msg, "1234567812345678")
	if err != nil {
		t.Fatalf("Sign(uid): %v", err)
	}
	if !ecdsa.VerifyASN1(goSignPub, digest[:], sigUID) {
		t.Fatal("带 uid 的模块签名未通过 Go 验签")
	}

	// ---- 模块往返 Verify + 篡改拒 ----
	if err := backend.Verify(signPub, msg, sig, ""); err != nil {
		t.Fatalf("Verify(模块往返): %v", err)
	}
	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)-1] ^= 0x01
	if err := backend.Verify(signPub, msg, badSig, ""); err == nil {
		t.Fatal("篡改签名的 Verify 应失败")
	} else {
		t.Logf("篡改签名拒绝: %v", err)
	}

	// ---- Go 签名 → 模块验签（独立密钥对，非自签自验）----
	goKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	goSig, err := ecdsa.SignASN1(rand.Reader, goKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	if err := backend.Verify(goECDSARawPub(&goKey.PublicKey), msg, goSig, ""); err != nil {
		t.Fatalf("模块验签 Go 侧签名失败: %v", err)
	}

	// ---- GenerateKeyPair(协商用途) + ECDH 双向交叉 ----
	ecdhRef, ecdhPub, err := backend.GenerateKeyPair(UsageECDH)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ecdh): %v", err)
	}
	cleanup = append(cleanup, ecdhRef)
	goECDHKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey: %v", err)
	}
	// 模块私钥 + Go 公钥。
	modSecret, err := backend.ECDH(ecdhRef, goECDHKey.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("ECDH(模块私钥, Go 公钥): %v", err)
	}
	if len(modSecret) != ecSharedSecretLen {
		t.Fatalf("共享秘密长度 %d != %d", len(modSecret), ecSharedSecretLen)
	}
	// Go 私钥 + 模块公钥。
	goPeerPub, err := ecdh.P256().NewPublicKey(ecdhPub)
	if err != nil {
		t.Fatalf("ecdh.NewPublicKey(模块公钥): %v", err)
	}
	goSecret, err := goECDHKey.ECDH(goPeerPub)
	if err != nil {
		t.Fatalf("Go ECDH: %v", err)
	}
	if string(modSecret) != string(goSecret) {
		t.Fatal("两路 ECDH 共享秘密不一致（模块派生或密钥对应关系错误）")
	}

	// ---- 用途最小权限（真机证明）----
	if _, err := backend.ECDH(signRef, goECDHKey.PublicKey().Bytes()); err == nil {
		t.Fatal("sign 密钥做 ECDH 应被模块拒绝（CKA_DERIVE=false）")
	} else {
		t.Logf("sign 密钥 ECDH 拒绝: %v", err)
	}
	if _, err := backend.Sign(ecdhRef, msg, ""); err == nil {
		t.Fatal("ecdh 密钥做 Sign 应被模块拒绝（CKA_SIGN=false）")
	} else {
		t.Logf("ecdh 密钥 Sign 拒绝: %v", err)
	}

	// ---- RotateKey ----
	// 非对称轮换：新句柄可用，旧句柄按规约**不销毁**（仍可签名）。
	newSignRef, err := backend.RotateKey(signRef, "ec-sign")
	if err != nil {
		t.Fatalf("RotateKey(ec-sign): %v", err)
	}
	cleanup = append(cleanup, newSignRef)
	if string(newSignRef) == string(signRef) {
		t.Fatal("轮换后句柄应不同")
	}
	if _, err := backend.Sign(newSignRef, msg, ""); err != nil {
		t.Fatalf("轮换后新句柄签名失败: %v", err)
	}
	if _, err := backend.Sign(signRef, msg, ""); err != nil {
		t.Fatalf("旧句柄应仍可用（规约：调用方策略归档，模块不销毁）: %v", err)
	}
	// 对称轮换。
	symRef, err := backend.GenerateKey("aes-256", "")
	if err != nil {
		t.Fatalf("GenerateKey(aes-256): %v", err)
	}
	cleanup = append(cleanup, symRef)
	newSymRef, err := backend.RotateKey(symRef, "aes-256")
	if err != nil {
		t.Fatalf("RotateKey(aes-256): %v", err)
	}
	cleanup = append(cleanup, newSymRef)
	// SM 档轮换：fail-closed 拒绝（不映射到 EC 冒充合规，C-3）。
	if _, err := backend.RotateKey(signRef, "sm2-sign"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RotateKey(sm2-sign) 应 ErrNotImplemented: %v", err)
	}

	t.Logf("M4-4c 真机链路 PASS: hash(+Go) → genpair → sign(Go验) → verify(往返+篡改拒+Go签名) → ecdh(双向一致) → 用途最小权限 → rotate(新旧均可用+SM拒)")
}

// goECDSAPub 原始非压缩点 → *ecdsa.PublicKey（P-256）。
func goECDSAPub(t *testing.T, raw []byte) *ecdsa.PublicKey {
	t.Helper()
	byteLen := 32
	if len(raw) != 1+2*byteLen || raw[0] != 0x04 {
		t.Fatalf("公钥点非法: len=%d", len(raw))
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1 : 1+byteLen]),
		Y:     new(big.Int).SetBytes(raw[1+byteLen:]),
	}
}

// goECDSARawPub *ecdsa.PublicKey → 原始非压缩点字节（0x04||X||Y）。
func goECDSARawPub(pub *ecdsa.PublicKey) []byte {
	byteLen := 32
	out := make([]byte, 1+2*byteLen)
	out[0] = 0x04
	pub.X.FillBytes(out[1 : 1+byteLen])
	pub.Y.FillBytes(out[1+byteLen:])
	return out
}
