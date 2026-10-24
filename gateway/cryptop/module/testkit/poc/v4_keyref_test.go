package poc

// V-4：GroupKeyRef 重启解析 POC（本体 §7.3.1 测试矩阵·契约层 / §6.2.2 D-10）。
//
// 验收判据（对齐证据包 README 的 PKCS#11 级等价验证）：
//   - GroupKeyRef.inner 使用持久地址（CKA_ID/label），sidecar 重启（重新 Login）
//     后业务侧持有的原 KeyRef 仍可解析并成功 Seal/Open；
//   - 解析不依赖 CK_OBJECT_HANDLE（重启后句柄必然失效）；
//   - 缺分区/路由信息 → fail-closed，不"猜成员"。
//
// 范围声明（如实登记）：原 cmd.txt 的 HTTP 级 E2E（cryptopsvc /v1/keys、/v1/seal、
// /v1/open）依赖 T-1/T-2 产品编码，门禁未开放；本用例在 PKCS#11 层验证同一契约的
// 承载体——持久寻址在完整 C_Finalize/C_Initialize 周期后依然成立。

import (
	"context"
	"encoding/hex"
	"testing"
)

// keyIDBytes 把 32 位 hex 字符串解析为 16 字节 key_id。
func keyIDBytes(t *testing.T, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		t.Fatalf("key_id %q 非合法 16 字节 hex: err=%v len=%d", s, err, len(b))
	}
	var kid [16]byte
	copy(kid[:], b)
	return kid
}

const (
	v4KeyID  = "11223344556677889900aabbccddeeff"
	v4Alias  = TestPartition + "|" + TestMemberA + "|poc-restart-1"
	v4CKAID  = "p2-3-poc-restart-1"
	v4Label  = TestPartition + "|" + TestMemberA + "|poc-restart-1"
	v4SealPt = "p2-3-poc-seal-open-vector-32byte"
)

// TestV4EnvelopeRoundtrip 信封编解码 + alias 三元组解析。
func TestV4EnvelopeRoundtrip(t *testing.T) {
	partition, member, name, err := ParseAlias(v4Alias)
	if err != nil {
		t.Fatalf("ParseAlias(%q) 失败: %v", v4Alias, err)
	}
	if partition != TestPartition || member != TestMemberA || name != "poc-restart-1" {
		t.Fatalf("alias 解析结果异常: %s/%s/%s", partition, member, name)
	}
	var kid [16]byte
	kid = keyIDBytes(t, v4KeyID)
	// inner 为持久地址（CKA_ID），非会话句柄。
	b64, err := EncodeKeyRefB64(kid, member, partition, []byte(v4CKAID))
	if err != nil {
		t.Fatalf("编码信封失败: %v", err)
	}
	ref, err := DecodeKeyRefB64(b64)
	if err != nil {
		t.Fatalf("解码信封失败: %v", err)
	}
	if ref.Member != member || ref.Partition != partition || string(ref.Inner) != v4CKAID {
		t.Fatalf("信封往返不一致: %+v", ref)
	}
	if KeyIDHex(ref.KeyID) != v4KeyID {
		t.Fatalf("key_id hex 不一致: %s", KeyIDHex(ref.KeyID))
	}
	// 路由信息缺失 → fail-closed。
	if _, _, _, err := ParseAlias("no-routing-info"); err == nil {
		t.Fatalf("缺分区的 alias 必须被拒")
	}
	if _, _, _, err := ParseAlias(TestPartition + "|" + TestMemberA + "|bad|alias"); err == nil {
		t.Fatalf("四段 alias 必须被拒")
	}
}

// TestV4RestartResolvesByPersistentAddress 完整重启（C_Finalize/Initialize/Login）后，
// 原 KeyRef 仍可解析并成功 Seal/Open，且不依赖会话句柄。
func TestV4RestartResolvesByPersistentAddress(t *testing.T) {
	module, pin, label := p11Config(t)
	p, err := OpenP11(module, label, pin)
	if err != nil {
		t.Fatalf("打开 PKCS#11 模块失败: %v", err)
	}
	defer p.Close()
	if err := p.CleanupIDs(v4CKAID); err != nil {
		t.Fatalf("清理 P11 对象失败: %v", err)
	}

	ctx := context.Background()
	_ = ctx

	// CBC 要求 16 字节倍数。
	if len(v4SealPt)%16 != 0 {
		t.Fatalf("测试向量长度 %d 不是 16 的倍数", len(v4SealPt))
	}

	// 1) 组模式生成：以 alias 名作持久 CKA_ID。
	key, err := p.GenerateSecret(v4CKAID, v4Label, 32, true, false, false, false, true, true)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	// 2) Seal：加密得到密文（业务侧只持有 KeyRef，不接触密钥）。
	ct, err := p.Encrypt(key, []byte(v4SealPt))
	if err != nil {
		t.Fatalf("Seal(加密) 失败: %v", err)
	}

	// 3) 重启：完整 C_Logout/C_CloseSession/C_Finalize 后重新初始化并登录
	//    （模拟 sidecar 进程重启 / Pod 重建 / 重新 Login）。
	if err := p.HardRestart(pin); err != nil {
		t.Fatalf("HardRestart 失败: %v", err)
	}

	// 4) 用**原** KeyRef 的持久地址重新寻址（禁止用旧句柄）。
	kid := keyIDBytes(t, v4KeyID)
	b64, err := EncodeKeyRefB64(kid, TestMemberA, TestPartition, []byte(v4CKAID))
	if err != nil {
		t.Fatalf("KeyRef 编码失败: %v", err)
	}
	ref, err := DecodeKeyRefB64(b64)
	if err != nil {
		t.Fatalf("KeyRef 解码失败: %v", err)
	}
	key2, err := p.FindByID(string(ref.Inner))
	if err != nil {
		t.Fatalf("重启后按持久 CKA_ID 解析失败: %v", err)
	}
	if key2 == key {
		t.Logf("注意：重启后对象句柄偶合相同（实现相关），断言以寻址方式为准")
	}
	// 5) Open：用重启后解析到的密钥解密重启前生成的密文。
	pt, err := p.Decrypt(key2, ct)
	if err != nil {
		t.Fatalf("Open(解密) 失败: %v", err)
	}
	if string(pt) != v4SealPt {
		t.Fatalf("Seal/Open 往返不一致: %q", pt)
	}
	t.Logf("重启（C_Finalize→C_Initialize→Login）后按 CKA_ID=%s 解析成功，Seal/Open 往返一致", v4CKAID)
}

// TestV4ResolveMissingIDFailsClosed 持久地址不存在时必须报错，不得静默回退。
func TestV4ResolveMissingIDFailsClosed(t *testing.T) {
	module, pin, label := p11Config(t)
	p, err := OpenP11(module, label, pin)
	if err != nil {
		t.Fatalf("打开 PKCS#11 模块失败: %v", err)
	}
	defer p.Close()
	if err := p.CleanupIDs("p2-3-poc-nonexistent"); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if _, err := p.FindByID("p2-3-poc-nonexistent"); err == nil {
		t.Fatalf("不存在的 CKA_ID 必须解析失败（fail-closed）")
	}
}
