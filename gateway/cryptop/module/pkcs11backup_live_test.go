//go:build pkcs11

// pkcs11backup_live_test.go —— KeyBackupBackend 的 PKCS#11 真机用例（§6.2.5 / D-9）。
//
// 运行前提（.248 联调机，与 pkcs11_live_test.go 同套环境变量）：
//
//	P11_LIVE=1                    启用（未设置则 Skip，不以 mock 冒充真机）
//	P11_LIVE_LIB=/usr/lib/softhsm/libsofthsm2.so
//	P11_LIVE_PIN=0000
//
// 覆盖（G-4 / V-4 的适配层部分）：
//
//	① wrap → unwrap 往返：导出的 blob 在模块内重建对象后，与原对象是**同一密钥**
//	   （互相加解密验证，而非比较明文——明文根本不经过应用层）；
//	② 属性核验：重建对象必须 CKA_SENSITIVE=true 且 CKA_EXTRACTABLE=false（V-4）；
//	③ 明文不出模块：ImportWrapped 返回的是 KeyRef（句柄），结构上不产出明文；
//	④ DestroyWrapped 幂等（对象不存在即成功）；
//	⑤ 缺 KEK / 空 blob / 空 alias 等入参 fail-closed。
//
// 注意：全部 live 用例合并在一个函数内——PKCS#11 的 C_Initialize 在同一进程内
// 重复调用会返回 CKR_CRYPTOKI_ALREADY_INITIALIZED（R-S3-1），故后端只构造一次。
package cryptopmodule

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

// newLiveP11Backup 连上 SoftHSM 并返回可断言为 KeyBackupBackend 的后端。
func newLiveP11Backup(t *testing.T) (ModuleBackend, KeyBackupBackend) {
	t.Helper()
	cfg := p11LiveConfig(t, []string{MechRand})
	// 机制 profile 驱动 CKM 翻译（B-6.1-2：未登记一律 fail-closed，禁止臆测标准值）。
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")

	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	kb, ok := backend.(KeyBackupBackend)
	if !ok {
		t.Fatalf("PKCS#11 后端未实现 KeyBackupBackend（shared 组将无法启动）")
	}
	t.Cleanup(func() { _ = backend.Close() })
	return backend, kb
}

// p11ObjectAttrs 读取模块内对象的属性（核验不可导出/敏感）。
func p11ObjectAttrs(t *testing.T, b ModuleBackend, ref KeyRef) (sensitive, extractable bool) {
	t.Helper()
	pb, ok := b.(*PKCS11Backend)
	if !ok {
		t.Fatalf("后端类型异常: %T", b)
	}
	h, err := decodeKeyRef(ref, pb.slotIndex, pb.partition())
	if err != nil {
		t.Fatalf("decodeKeyRef: %v", err)
	}
	s, err := pb.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	defer func() { _ = pb.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	attrs, err := pb.ctx.GetAttributeValue(sh, pkcs11.ObjectHandle(h),
		[]*pkcs11.Attribute{{Type: pkcs11.CKA_SENSITIVE}, {Type: pkcs11.CKA_EXTRACTABLE}})
	if err != nil {
		t.Fatalf("C_GetAttributeValue: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("属性返回数异常: %d", len(attrs))
	}
	return len(attrs[0].Value) > 0 && attrs[0].Value[0] != 0,
		len(attrs[1].Value) > 0 && attrs[1].Value[0] != 0
}

// createExtractableTestKey 在模块内直接建一个**可导出**的测试密钥（绕过 GenerateKey
// 的不可导出属性策略），用于验证 wrap/unwrap 适配层逻辑。
//
// 为何需要它：PKCS#11 规范规定 **CKA_EXTRACTABLE=false 的密钥不能被 C_WrapKey**
// （SoftHSM 实测返回 CKR_KEY_UNEXTRACTABLE）——这是"不可导出"的安全保证本身。
// 而生产密钥按 R-2 一律不可导出，故标准 C_WrapKey 路径备份不了它；真实备份必须走
// 厂商专有机制（D-2「优先厂商原生机制」：wrap 备份/克隆/备份库/m-of-n）。
// 本测试因此分两步：可导出密钥验证适配层往返 + 不可导出密钥验证 fail-closed。
func createExtractableTestKey(t *testing.T, b ModuleBackend, alias string, valueLen int) KeyRef {
	t.Helper()
	pb, ok := b.(*PKCS11Backend)
	if !ok {
		t.Fatalf("后端类型异常: %T", b)
	}
	val := make([]byte, valueLen)
	for i := range val {
		val[i] = byte(i + 1)
	}
	tmpl := secretKeyTemplate(pb.keyLabel(alias), 0, true /* extractable */, usageEnc)
	tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_VALUE, val))

	s, err := pb.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	defer func() { _ = pb.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	oh, err := pb.ctx.CreateObject(sh, tmpl)
	if err != nil {
		t.Fatalf("C_CreateObject(可导出测试密钥): %v", err)
	}
	ref, err := encodeKeyRef(pb.slotIndex, pb.partition(), uint(oh))
	if err != nil {
		t.Fatalf("encodeKeyRef: %v", err)
	}
	return ref
}

// TestP11KeyBackupLive 覆盖 ①②④⑤（后端只构造一次，见文件头说明）。
func TestP11KeyBackupLive(t *testing.T) {
	b, kb := newLiveP11Backup(t)

	// SoftHSM 是**持久 token**：重复运行会累积同名对象，导致 label 歧义
	// （产品侧遇歧义会 fail-closed 拒绝，这是正确行为）。故每次运行用唯一 alias。
	uniq := fmt.Sprintf("-%d", time.Now().UnixNano())
	const kekAlias = "kek-backup-test"
	const restoredAlias = "dek-backup-restored"

	// 组内独立备份 KEK（D-9：不得复用数据 KEK；usage=kek 才具备 CKA_WRAP）。
	if _, err := b.GenerateKey("aes-256-kek", kekAlias+uniq); err != nil {
		t.Fatalf("GenerateKey(KEK): %v", err)
	}

	// 生产形态：GenerateKey 生成的密钥一律不可导出（R-2）。
	prodRef, err := b.GenerateKey("aes-256-enc", "dek-prod-ne"+uniq)
	if err != nil {
		t.Fatalf("GenerateKey(DEK): %v", err)
	}
	// ⑤a 不可导出密钥的导出必须 fail-closed（PKCS#11 规范 + R-2 双重约束）。
	if _, err := kb.ExportWrapped(prodRef, kekAlias+uniq); err == nil {
		t.Fatal("不可导出密钥的 ExportWrapped 应被拒（CKA_EXTRACTABLE=false 不得 wrap；真实备份须走厂商机制）")
	} else {
		t.Logf("不可导出密钥导出被拒（符合预期）: %v", err)
	}

	// 适配层往返：用可导出测试密钥验证 C_WrapKey / C_UnwrapKey 链路本身。
	dekRef := createExtractableTestKey(t, b, "dek-bk"+uniq, 32)

	// ① 导出（可导出测试密钥）：模块内对象 → C_WrapKey（不读出明文）。
	w, err := kb.ExportWrapped(dekRef, kekAlias+uniq)
	if err != nil {
		t.Fatalf("ExportWrapped: %v", err)
	}
	if len(w.Blob) == 0 || len(w.Checksum) == 0 {
		t.Fatalf("ExportWrapped 产物不完整：blob=%d checksum=%d", len(w.Blob), len(w.Checksum))
	}
	if w.Mechanism == "" || w.Vendor == "" {
		t.Fatalf("交叉校验字段缺失：mechanism=%q vendor=%q", w.Mechanism, w.Vendor)
	}
	t.Logf("导出成功：wrapped_size=%d mechanism=%s vendor=%s/%s",
		w.WrappedSize, w.Mechanism, w.Vendor, w.Model)

	// ③ 导入：C_UnwrapKey 在模块内直接建持久对象（不产出明文）。
	restored, err := kb.ImportWrapped(w, kekAlias+uniq, restoredAlias+uniq)
	if err != nil {
		t.Fatalf("ImportWrapped: %v", err)
	}
	if restored == nil {
		t.Fatal("ImportWrapped 返回空 KeyRef")
	}

	// 往返一致性：用重建对象加密、原对象解密（明文不经过应用层）。
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	const plaintext = "p2-3 key-backup round-trip"
	ct, err := b.Seal(restored, nonce, []byte(plaintext), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal(restored): %v", err)
	}
	pt, err := b.Open(dekRef, nonce, ct, []byte("aad"))
	if err != nil {
		t.Fatalf("Open(original): %v", err)
	}
	if string(pt) != plaintext {
		t.Fatalf("往返不一致：重建对象与原对象不是同一密钥（got %q）", pt)
	}

	// ② 属性核验（V-4）：重建对象必须不可导出且敏感。
	sensitive, extractable := p11ObjectAttrs(t, b, restored)
	if !sensitive {
		t.Error("重建对象 CKA_SENSITIVE 应为 true（V-4 全属性核验）")
	}
	if extractable {
		t.Error("重建对象 CKA_EXTRACTABLE 应为 false（不可导出，R-2）")
	}

	// ④ DestroyWrapped 幂等：对象不存在即成功（备份库 blob 由 KeyBackupStore 删除）。
	if err := kb.DestroyWrapped("no-such-backup-id"); err != nil {
		t.Fatalf("DestroyWrapped 对不存在的 backup_id 应幂等成功，实际 %v", err)
	}
	if err := kb.DestroyWrapped(""); err == nil {
		t.Fatal("空 backup_id 应被拒")
	}

	// ⑤ 入参 fail-closed：缺 kekID / 空 blob / 空 alias。
	if _, err := kb.ExportWrapped(dekRef, ""); err == nil {
		t.Fatal("ExportWrapped 缺 kek_id 应被拒（D-9）")
	}
	if _, err := kb.ImportWrapped(WrappedKey{}, "", "x"); err == nil {
		t.Fatal("ImportWrapped 缺 kek_id 应被拒")
	}
	if _, err := kb.ImportWrapped(WrappedKey{KEKID: "k"}, "k", ""); err == nil {
		t.Fatal("ImportWrapped 缺 alias 应被拒")
	}
}

// TestP11KeyBackupNoPlaintextInSignature ③ 结构性保证：ImportWrapped 只返回 KeyRef，
// 接口上不存在 []byte 明文出口（编译期即成立，无需连真机）。
func TestP11KeyBackupNoPlaintextInSignature(t *testing.T) {
	// 编译期契约：导入接口的返回类型是 KeyRef（句柄），不接受也不返回明文。
	var _ KeyBackupBackend = (*PKCS11Backend)(nil)
	if _, err := (*PKCS11Backend)(nil).ImportWrapped(WrappedKey{}, "k", "a"); err == nil {
		t.Fatal("未初始化后端的 ImportWrapped 应 fail-closed")
	}
}
