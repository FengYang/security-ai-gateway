package poc

// V-3：SoftHSM / 厂商 wrap POC（本体 §7.3.1 测试矩阵·安全层 / §6.2.5 / D-9）。
//
// 验收判据（对齐证据包 README）：
//   - wrap 出的 blob 可由持有同一 KEK 的模块侧直接 C_UnwrapKey 建对象；
//   - 目标对象 CKA_SENSITIVE=true、CKA_EXTRACTABLE=false；
//   - C_GetAttributeValue(CKA_VALUE) 对目标对象失败（CKR_ATTRIBUTE_SENSITIVE）；
//   - 备份库 Put/Get 往返一致，backup_id 分配/唯一性/绑定/幂等语义成立；
//   - 全过程无明文出模块（以"加解密结果一致"间接证明密钥材料被完整保留）。
//
// 范围声明（如实登记）：
//   - SoftHSM 无 SM2/SM3/SM4 机制，本用例以 AES 验证**机制级**契约；
//   - SoftHSM 单 token 无法克隆，wrap/unwrap 在同一 token 上完成——跨成员 KEK
//     分发正是 D-20 的开放问题，本用例另附 CKA_TRUSTED 能力探测结果供决策。

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

const (
	v3KEKID  = "p2-3-poc-kek-v1"
	v3DataID = "p2-3-poc-data-1"
	v3KeyID  = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

	// v3Plaintext AES-CBC 测试向量（必须为 16 字节倍数；32 字节）。
	v3Plaintext = "p2-3-poc-wrap-equivalence-vector"
)

// isKeyUnextractable 判断错误链中是否含 CKR_KEY_UNEXTRACTABLE（0x6A）。
func isKeyUnextractable(err error) bool {
	var pe pkcs11.Error
	return errors.As(err, &pe) && pe == pkcs11.CKR_KEY_UNEXTRACTABLE
}

func openV3Module(t *testing.T) *P11Module {
	t.Helper()
	module, pin, label := p11Config(t)
	p, err := OpenP11(module, label, pin)
	if err != nil {
		t.Fatalf("打开 PKCS#11 模块失败: %v", err)
	}
	t.Cleanup(p.Close)
	// 清理历史对象，保证可重复执行。
	if err := p.CleanupIDs(v3KEKID, v3DataID, v3DataID+"-restored"); err != nil {
		t.Fatalf("清理 P11 对象失败: %v", err)
	}
	return p
}

// TestV3WrapUnwrapAttributesAndEquivalence wrap→ unwrap 全链路 + 属性强制 + 等价性。
//
// 重要范围说明（如实登记）：SoftHSM 上 CKA_EXTRACTABLE=false 的密钥**不可 wrap**
// （CKR_KEY_UNEXTRACTABLE，见 TestV3NonExtractableKeyWrapRejected）。因此本用例的
// 数据密钥使用 sensitive=true + extractable=true，仅验证**机制级**契约；
// 生产要求「非导出 + wrap 备份」必须由 D-20 ①（CKA_TRUSTED 可信包装）或
// ②（厂商克隆）满足，SoftHSM 两者皆不支持（见 TestV3TrustedCapabilityProbe）。
func TestV3WrapUnwrapAttributesAndEquivalence(t *testing.T) {
	p := openV3Module(t)

	// 1) 生成备份 KEK（可 wrap/unwrap，敏感，不可导出）与数据密钥（可导出以便 wrap）。
	kek, err := p.GenerateSecret(v3KEKID, v3KEKID, 32, true, false, true, true, false, false)
	if err != nil {
		t.Fatalf("生成 KEK 失败: %v", err)
	}
	data, err := p.GenerateSecret(v3DataID, v3DataID, 32, true, true, false, false, true, true)
	if err != nil {
		t.Fatalf("生成数据密钥失败: %v", err)
	}

	// 2) 数据密钥属性：SENSITIVE=true、可 wrap；敏感密钥即使可导出也读不到 CKA_VALUE。
	for _, tc := range []struct {
		attr uint
		want bool
		name string
	}{
		{pkcs11.CKA_SENSITIVE, true, "CKA_SENSITIVE"},
		{pkcs11.CKA_EXTRACTABLE, true, "CKA_EXTRACTABLE"},
		{pkcs11.CKA_TOKEN, true, "CKA_TOKEN"},
	} {
		got, ok, err := p.GetBoolAttr(data, tc.attr)
		if err != nil || !ok {
			t.Fatalf("读取 %s 失败: ok=%v err=%v", tc.name, ok, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %v，期望 %v", tc.name, got, tc.want)
		}
	}
	if _, err := p.ReadValueAttr(data); !IsSensitiveReadError(err) {
		t.Fatalf("读取敏感密钥 CKA_VALUE 应返回 CKR_ATTRIBUTE_SENSITIVE，实际: %v", err)
	}

	// 3) 明文测试向量在模块内加密（作为"密钥材料指纹"；CBC 要求 16 字节倍数）。
	if len(v3Plaintext)%16 != 0 {
		t.Fatalf("测试向量长度 %d 不是 16 的倍数", len(v3Plaintext))
	}
	ctOrig, err := p.Encrypt(data, []byte(v3Plaintext))
	if err != nil {
		t.Fatalf("原密钥加密失败: %v", err)
	}

	// 4) C_WrapKey → blob（密文，可跨域传输）。
	blob, err := p.WrapKey(kek, data)
	if err != nil {
		t.Fatalf("C_WrapKey 失败: %v", err)
	}
	if len(blob) == 0 {
		t.Fatalf("wrap blob 为空")
	}
	if string(blob) == string(v3Plaintext) {
		t.Fatalf("wrap blob 等于明文（wrap 未生效）")
	}
	t.Logf("C_WrapKey: 32B 数据密钥 → %dB blob（hex 前 16: %s…）", len(blob), hex.EncodeToString(blob)[:16])

	// 5) C_UnwrapKey 建对象，属性必须被模板强制。
	restored, err := p.UnwrapKey(kek, blob, v3DataID+"-restored", v3DataID+"-restored")
	if err != nil {
		t.Fatalf("C_UnwrapKey 失败: %v", err)
	}
	for _, tc := range []struct {
		attr uint
		want bool
		name string
	}{
		{pkcs11.CKA_SENSITIVE, true, "目标对象 CKA_SENSITIVE"},
		{pkcs11.CKA_EXTRACTABLE, false, "目标对象 CKA_EXTRACTABLE"},
		{pkcs11.CKA_TOKEN, true, "目标对象 CKA_TOKEN"},
	} {
		got, ok, err := p.GetBoolAttr(restored, tc.attr)
		if err != nil || !ok {
			t.Fatalf("读取 %s 失败: ok=%v err=%v", tc.name, ok, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %v，期望 %v", tc.name, got, tc.want)
		}
	}
	if _, err := p.ReadValueAttr(restored); !IsSensitiveReadError(err) {
		t.Fatalf("目标对象 CKA_VALUE 读取应失败，实际: %v", err)
	}

	// 6) 等价性：用还原对象加密同一明文，结果必须逐字节一致
	//    （不导出明文的前提下证明密钥材料被完整保留）。
	ctRestored, err := p.Encrypt(restored, []byte(v3Plaintext))
	if err != nil {
		t.Fatalf("还原对象加密失败: %v", err)
	}
	if string(ctRestored) != string(ctOrig) {
		t.Fatalf("还原对象加密结果与原密钥不一致（密钥材料未完整保留）")
	}
	// 解密往返。
	pt, err := p.Decrypt(restored, ctOrig)
	if err != nil {
		t.Fatalf("还原对象解密失败: %v", err)
	}
	if string(pt) != string(v3Plaintext) {
		t.Fatalf("解密往返不一致: %q", pt)
	}
	t.Logf("unwrap 等价性通过：原密钥与还原对象加解密结果逐字节一致")
}

// TestV3NonExtractableKeyWrapRejected 固化 D-20 真机发现：
// PKCS#11 语义下 CKA_EXTRACTABLE=false 的密钥不可 wrap（CKR_KEY_UNEXTRACTABLE）。
// ⇒ 「非导出数据密钥 + wrap 备份」必须由 CKA_TRUSTED 可信包装（①）或厂商克隆（②）实现。
func TestV3NonExtractableKeyWrapRejected(t *testing.T) {
	p := openV3Module(t)

	kek, err := p.GenerateSecret(v3KEKID, v3KEKID, 32, true, false, true, true, false, false)
	if err != nil {
		t.Fatalf("生成 KEK 失败: %v", err)
	}
	// 生产形态的数据密钥：敏感且**不可导出**（extractable=false）。
	data, err := p.GenerateSecret(v3DataID, v3DataID, 32, true, false, false, false, true, true)
	if err != nil {
		t.Fatalf("生成数据密钥失败: %v", err)
	}
	_, err = p.WrapKey(kek, data)
	if err == nil {
		t.Fatalf("非导出密钥的 wrap 必须失败（否则 EXTRACTABLE=false 失去意义）")
	}
	t.Logf("D-20 真机发现：非导出数据密钥 wrap 被拒：%v", err)
	if !isKeyUnextractable(err) {
		t.Logf("注意：wrap 失败原因不是 CKR_KEY_UNEXTRACTABLE，需人工判读：%v", err)
	}
	t.Logf("结论：SoftHSM(PKCS#11 v2.40 级) 不支持可信包装 ⇒ 非导出密钥的 wrap 备份需厂商 HSM（D-20 ①/②）")
}

// TestV3TrustedCapabilityProbe D-20 ① 能力探测：SoftHSM 是否接受 CKA_TRUSTED 包装键。
// 本用例只记录结果（能力探测，不构成契约通过/失败）。
func TestV3TrustedCapabilityProbe(t *testing.T) {
	p := openV3Module(t)
	h, err := p.GenerateSecretWithTrusted("p2-3-poc-trusted-probe", "p2-3-poc-trusted-probe", 32)
	if err != nil {
		t.Logf("D-20 ① 探测结果：SoftHSM 拒绝 CKA_TRUSTED=true 的包装键（%v）⇒ 可信包装档需厂商 HSM 支持", err)
		return
	}
	trusted, ok, err := p.GetBoolAttr(h, pkcs11.CKA_TRUSTED)
	if err != nil || !ok {
		t.Logf("D-20 ① 探测结果：生成成功但 CKA_TRUSTED 属性不可读（ok=%v err=%v）", ok, err)
		return
	}
	t.Logf("D-20 ① 探测结果：SoftHSM 接受 CKA_TRUSTED=%v（本 POC 主机能力，厂商 HSM 须另行探测）", trusted)
}

// TestV3BackupStoreContract KeyBackupStore 四方法契约（§6.2.5）。
func TestV3BackupStoreContract(t *testing.T) {
	p := openV3Module(t)
	ctx := context.Background()
	store := NewMemBackupStore()

	kek, err := p.GenerateSecret(v3KEKID, v3KEKID, 32, true, false, true, true, false, false)
	if err != nil {
		t.Fatalf("生成 KEK 失败: %v", err)
	}
	data, err := p.GenerateSecret(v3DataID, v3DataID, 32, true, true, false, false, true, true) // extractable=true：SoftHSM 机制级 wrap 前提（见 TestV3NonExtractableKeyWrapRejected）
	if err != nil {
		t.Fatalf("生成数据密钥失败: %v", err)
	}
	blob, err := p.WrapKey(kek, data)
	if err != nil {
		t.Fatalf("C_WrapKey 失败: %v", err)
	}
	mkWrapped := func(backupID string) WrappedKey {
		return WrappedKey{
			Version: 0x01, KeyID: v3KeyID, KEKID: v3KEKID, BackupID: backupID,
			Vendor: "SoftHSM", Model: "v2", Mechanism: "CKM_AES_KEY_WRAP",
			Alias: TestPartition + "|" + TestMemberA + "|poc-1",
			Blob:  blob, Checksum: HMACSM3(backupMACKey(), blob),
		}
	}
	memberCtx := WithMember(ctx, TestMemberA)

	// 1) backupID 为空 → 服务端分配并回填。
	meta, err := store.Put(memberCtx, TestGID, v3KeyID, "", mkWrapped(""))
	if err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if meta.BackupID == "" {
		t.Fatalf("服务端未分配 backup_id")
	}
	if meta.KeyID != v3KeyID || meta.Member != TestMemberA || meta.KEKID != v3KEKID {
		t.Fatalf("BackupMeta 绑定字段异常: %+v", meta)
	}
	if meta.WrappedSize != int64(len(blob)) {
		t.Fatalf("WrappedSize = %d，期望 %d", meta.WrappedSize, len(blob))
	}

	// 2) 重复 Put 同一 backupID + 同一内容 → 幂等返回既有 meta。
	meta2, err := store.Put(memberCtx, TestGID, v3KeyID, meta.BackupID, mkWrapped(meta.BackupID))
	if err != nil {
		t.Fatalf("幂等 Put 失败: %v", err)
	}
	if meta2.BackupID != meta.BackupID || string(meta2.Checksum) != string(meta.Checksum) {
		t.Fatalf("幂等 Put 返回了不同的 meta")
	}

	// 3) 同一 backupID + 不同内容 → 拒绝覆盖。
	tampered := mkWrapped(meta.BackupID)
	tampered.Blob = append([]byte(nil), blob...)
	tampered.Blob[0] ^= 0xFF
	if _, err := store.Put(memberCtx, TestGID, v3KeyID, meta.BackupID, tampered); err == nil {
		t.Fatalf("不同内容的重复 Put 应被拒绝（不得覆盖原 blob）")
	}

	// 4) checksum 错误的 Put 必须被拒。
	badSum := mkWrapped("")
	badSum.Checksum = []byte("short")
	if _, err := store.Put(memberCtx, TestGID, v3KeyID, "", badSum); err == nil {
		t.Fatalf("checksum 非法的 Put 应被拒")
	}

	// 5) 跨密钥复用同一 backupID → 绑定冲突。
	other := mkWrapped(meta.BackupID)
	other.KeyID = "ffffffffffffffffffffffffffffffff"
	if _, err := store.Put(memberCtx, TestGID, other.KeyID, meta.BackupID, other); err == nil {
		t.Fatalf("跨密钥复用 backup_id 应被拒")
	}

	// 6) 跨组 Get → not found。
	if _, _, err := store.Get(ctx, "other-group", meta.BackupID); err == nil {
		t.Fatalf("跨组 Get 应失败")
	}

	// 7) Get 往返一致 + checksum 复校。
	got, gotMeta, err := store.Get(ctx, TestGID, meta.BackupID)
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if string(got.Blob) != string(blob) || gotMeta.BackupID != meta.BackupID {
		t.Fatalf("Get 往返不一致")
	}

	// 8) List 按 gid+keyID 过滤。
	list, err := store.List(ctx, TestGID, v3KeyID)
	if err != nil || len(list) != 1 {
		t.Fatalf("List 异常: n=%d err=%v", len(list), err)
	}

	// 9) Delete 后 Get 失败。
	if err := store.Delete(ctx, TestGID, meta.BackupID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := store.Get(ctx, TestGID, meta.BackupID); err == nil {
		t.Fatalf("Delete 后 Get 应失败")
	}

	// 10) restore 流程：目录已销毁（tombstone）必须失败。
	store2 := NewMemBackupStore()
	meta3, err := store2.Put(memberCtx, TestGID, v3KeyID, "", mkWrapped(""))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	flow := RestoreFlow{
		Store:    store2,
		DirState: func(keyID string) (string, bool) { return "destroyed", keyID == v3KeyID },
		Import:   func(w WrappedKey) error { return nil },
	}
	if err := flow.Run(ctx, TestGID, v3KeyID, meta3.BackupID); err == nil {
		t.Fatalf("restore 对 tombstone 必须失败")
	}
	// 目录未销毁时 restore 成功（Import 由 unwrap 承担）。
	flow.DirState = func(keyID string) (string, bool) { return "ready", keyID == v3KeyID }
	if err := flow.Run(ctx, TestGID, v3KeyID, meta3.BackupID); err != nil {
		t.Fatalf("正常 restore 失败: %v", err)
	}
}

// TestV3EndToEndBackupRestore ExportWrapped → Put → Get → ImportWrapped → 等价性验证。
func TestV3EndToEndBackupRestore(t *testing.T) {
	p := openV3Module(t)
	ctx := context.Background()
	store := NewMemBackupStore()

	kek, err := p.GenerateSecret(v3KEKID, v3KEKID, 32, true, false, true, true, false, false)
	if err != nil {
		t.Fatalf("生成 KEK 失败: %v", err)
	}
	data, err := p.GenerateSecret(v3DataID, v3DataID, 32, true, true, false, false, true, true) // extractable=true：SoftHSM 机制级 wrap 前提（见 TestV3NonExtractableKeyWrapRejected）
	if err != nil {
		t.Fatalf("生成数据密钥失败: %v", err)
	}
	plaintext := []byte(v3Plaintext)
	ctOrig, err := p.Encrypt(data, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 源成员本地 ExportWrapped → 备份库 Put。
	blob, err := p.WrapKey(kek, data)
	if err != nil {
		t.Fatalf("ExportWrapped(C_WrapKey) 失败: %v", err)
	}
	wrapped := WrappedKey{
		Version: 0x01, KeyID: v3KeyID, KEKID: v3KEKID,
		Vendor: "SoftHSM", Model: "v2", Mechanism: "CKM_AES_KEY_WRAP",
		Alias: TestPartition + "|" + TestMemberA + "|poc-e2e",
		Blob:  blob, Checksum: HMACSM3(backupMACKey(), blob),
	}
	meta, err := store.Put(WithMember(ctx, TestMemberA), TestGID, v3KeyID, "", wrapped)
	if err != nil {
		t.Fatalf("KeyBackupStore.Put 失败: %v", err)
	}

	// 模拟跨成员传输：目标成员 Get（本 POC 同 token，跨成员分发见 D-20 说明）。
	got, _, err := store.Get(WithMember(ctx, TestMemberB), TestGID, meta.BackupID)
	if err != nil {
		t.Fatalf("KeyBackupStore.Get 失败: %v", err)
	}
	if string(got.Blob) != string(blob) {
		t.Fatalf("备份库往返 blob 不一致")
	}

	// 目标成员本地 ImportWrapped → 用还原密钥解密原密文。
	restored, err := p.UnwrapKey(kek, got.Blob, v3DataID+"-restored", v3DataID+"-restored")
	if err != nil {
		t.Fatalf("ImportWrapped(C_UnwrapKey) 失败: %v", err)
	}
	pt, err := p.Decrypt(restored, ctOrig)
	if err != nil {
		t.Fatalf("还原密钥解密失败: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("端到端备份恢复明文不一致: %q", pt)
	}

	// 销毁语义：DestroyWrapped + 备份库 Delete；tombstone 后 restore 失败。
	if err := p.Destroy(restored); err != nil {
		t.Fatalf("DestroyWrapped 失败: %v", err)
	}
	if err := store.Delete(ctx, TestGID, meta.BackupID); err != nil {
		t.Fatalf("备份库 Delete 失败: %v", err)
	}
	if _, _, err := store.Get(ctx, TestGID, meta.BackupID); err == nil {
		t.Fatalf("销毁后 Get 应失败")
	}
	t.Logf("端到端 backup→restore→decrypt 通过；销毁后备份不可取")
}
