package testkit

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// mustParse 解析 RFC3339Nano UTC 时间；解析失败直接 fail（测试用例内的固定值）。
func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("时间解析失败 %q: %v", s, err)
	}
	return ts.UTC()
}

// 冻结向量取自《P2--HSM集成》v0.5 §7.3.1（2026-10-24 已由独立实现复现，
// 证据见 docs/verify/crypto/p2-3/2026-10-24-canonical-mac-vectors/）。
// 这些字面值不得随实现漂移：任何键序、时间精度、整数格式、base64 变化都必须让本组用例失败。
const (
	v1Canonical = `{"created_by":"dc1-hsm-a","key_id":"0123456789abcdef0123456789abcdef","key_mode":"shared","lease_epoch":42,"replicas":[{"backup_id":"bk-0001","inner_b64":"AAECAwQ=","member":"dc1-hsm-a","partition":"tenant-a","state":"ready","updated_at":"2026-10-23T04:00:00.123456789Z"}],"state":"ready","updated_at":"2026-10-23T04:00:00.123456789Z","version":7,"writer_boot_id":"pod-uid-1:boot-1","writer_epoch":42}`
	v1SHA256    = "5befed061d8856d4bdd7f9efd915b5a1be03271e8fb8e2281b17a9fa84db05c9"
	v1MAC       = "3e40c5e53b33be11a1bcb45f2ea08bc5b7f2925a1ded461c38a4021f939914d2"

	v2Canonical = `{"created_by":"dc1-hsm-a","key_id":"fedcba9876543210fedcba9876543210","key_mode":"shared","lease_epoch":43,"replicas":[{"backup_id":"bk-0002","inner_b64":"AAECAwQFBgc=","member":"dc1-hsm-a","partition":"tenant-a","state":"ready","updated_at":"2026-10-23T04:00:01Z"},{"backup_id":"bk-0003","inner_b64":"BwgJCgsMDQ4=","member":"dc2-hsm-b","partition":"tenant-b","state":"creating","updated_at":"2026-10-23T04:00:02.5Z"}],"state":"degraded","updated_at":"2026-10-23T04:00:02.5Z","version":8,"writer_boot_id":"pod-uid-2:boot-2","writer_epoch":43}`
	v2SHA256    = "9c8c0fed445da2252653dfd4fb939629591e1a73cd9459c42cbbc5d7edd06b54"
	v2MAC       = "85ab63c070a475b2d4de0bbafb5bf9afa3cf85034f788f54050eff73472173fa"
)

// macKey 测试密钥 0x00..0x1f（文档既定公开测试值，非生产 MAC 密钥）。
func macKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func v1Dir(t *testing.T) KeyDirectory {
	return KeyDirectory{
		Version: 7, KeyID: "0123456789abcdef0123456789abcdef", KeyMode: "shared",
		Replicas: []KeyReplica{{
			Member: "dc1-hsm-a", Partition: "tenant-a", InnerB64: "AAECAwQ=",
			BackupID: "bk-0001", State: "ready",
			UpdatedAt: mustParse(t, "2026-10-23T04:00:00.123456789Z"),
		}},
		State: "ready", CreatedBy: "dc1-hsm-a", WriterEpoch: 42,
		WriterBootID: "pod-uid-1:boot-1", LeaseEpoch: 42,
		UpdatedAt: mustParse(t, "2026-10-23T04:00:00.123456789Z"),
	}
}

func v2Dir(t *testing.T) KeyDirectory {
	return KeyDirectory{
		Version: 8, KeyID: "fedcba9876543210fedcba9876543210", KeyMode: "shared",
		Replicas: []KeyReplica{
			{Member: "dc1-hsm-a", Partition: "tenant-a", InnerB64: "AAECAwQFBgc=",
				BackupID: "bk-0002", State: "ready", UpdatedAt: mustParse(t, "2026-10-23T04:00:01Z")},
			{Member: "dc2-hsm-b", Partition: "tenant-b", InnerB64: "BwgJCgsMDQ4=",
				BackupID: "bk-0003", State: "creating", UpdatedAt: mustParse(t, "2026-10-23T04:00:02.5Z")},
		},
		State: "degraded", CreatedBy: "dc1-hsm-a", WriterEpoch: 43,
		WriterBootID: "pod-uid-2:boot-2", LeaseEpoch: 43,
		UpdatedAt: mustParse(t, "2026-10-23T04:00:02.5Z"),
	}
}

func TestCanonicalFrozenVectors(t *testing.T) {
	cases := []struct {
		name      string
		kd        KeyDirectory
		canonical string
		sum       string
		mac       string
	}{
		{"V-1", v1Dir(t), v1Canonical, v1SHA256, v1MAC},
		{"V-2", v2Dir(t), v2Canonical, v2SHA256, v2MAC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalForMAC(tc.kd)
			if err != nil {
				t.Fatalf("canonical 失败: %v", err)
			}
			if string(got) != tc.canonical {
				t.Fatalf("canonical 串不一致:\n期望 %s\n实测 %s", tc.canonical, got)
			}
			s := sha256.Sum256(got)
			if hex.EncodeToString(s[:]) != tc.sum {
				t.Errorf("SHA-256 不一致: 期望 %s 实测 %x", tc.sum, s)
			}
			m := HMACSM3(macKey(), got)
			if hex.EncodeToString(m) != tc.mac {
				t.Errorf("HMAC-SM3 不一致: 期望 %s 实测 %x", tc.mac, m)
			}
		})
	}
}

// TestCanonicalKeyOrderRule 无论输入键序如何，输出必须按 UTF-8 字节升序。
func TestCanonicalKeyOrderRule(t *testing.T) {
	in := map[string]any{"zeta": 1, "alpha": 2, "Mid": 3, "_under": 4}
	got, err := CanonicalJSON(in)
	if err != nil {
		t.Fatalf("canonical 失败: %v", err)
	}
	want := `{"Mid":3,"_under":4,"alpha":2,"zeta":1}`
	if string(got) != want {
		t.Fatalf("键序错误: 期望 %s 实测 %s", want, got)
	}
}

// TestCanonicalIntegerDecimal 版本等整数字段必须是十进制字面值，不得出现 7.0 / 7e0。
func TestCanonicalIntegerDecimal(t *testing.T) {
	got, err := CanonicalForMAC(v1Dir(t))
	if err != nil {
		t.Fatalf("canonical 失败: %v", err)
	}
	s := string(got)
	for _, bad := range []string{"7.0", "7e0", "42.0", "4.2e1"} {
		if contains(s, bad) {
			t.Fatalf("canonical 出现非十进制整数字面值 %q: %s", bad, s)
		}
	}
	if !contains(s, `"version":7`) || !contains(s, `"writer_epoch":42`) {
		t.Fatalf("整数字面值不符合预期: %s", s)
	}
}

// TestCanonicalTimePrecision 整秒渲染为 …:01Z（不带 .000），纳秒精度不得被截断。
func TestCanonicalTimePrecision(t *testing.T) {
	got, err := CanonicalForMAC(v2Dir(t))
	if err != nil {
		t.Fatalf("canonical 失败: %v", err)
	}
	s := string(got)
	if !contains(s, `"2026-10-23T04:00:01Z"`) {
		t.Errorf("整秒时间应无小数部分: %s", s)
	}
	if !contains(s, `"2026-10-23T04:00:02.5Z"`) {
		t.Errorf("小数时间精度被改变: %s", s)
	}
	if contains(s, ".000Z") {
		t.Errorf("不得手工补零: %s", s)
	}
}

// TestMACInputExcludesMacField MAC 输入必须删除顶层 mac 字段。
func TestMACInputExcludesMacField(t *testing.T) {
	kd := v1Dir(t)
	withMAC := kd
	withMAC.MAC = v1MAC
	got, err := CanonicalForMAC(withMAC)
	if err != nil {
		t.Fatalf("canonical 失败: %v", err)
	}
	if contains(string(got), `"mac"`) {
		t.Fatalf("MAC 输入仍含 mac 字段: %s", got)
	}
	if string(got) != v1Canonical {
		t.Fatalf("带 mac 的目录 canonical 应等于冻结串:\n期望 %s\n实测 %s", v1Canonical, got)
	}
}

// TestVerifyDirectoryMAC 正例通过；篡改任一字段都应被 MAC 校验拒绝。
func TestVerifyDirectoryMAC(t *testing.T) {
	kd := v1Dir(t)
	kd.MAC = v1MAC
	if err := VerifyDirectoryMAC(kd, macKey()); err != nil {
		t.Fatalf("未篡改目录应校验通过: %v", err)
	}

	t.Run("篡改 version", func(t *testing.T) { assertTamperRejected(t, func(d *KeyDirectory) { d.Version = 8 }) })
	t.Run("篡改 key_id", func(t *testing.T) {
		assertTamperRejected(t, func(d *KeyDirectory) { d.KeyID = "ffffffffffffffffffffffffffffffff" })
	})
	t.Run("篡改 state", func(t *testing.T) { assertTamperRejected(t, func(d *KeyDirectory) { d.State = "destroyed" }) })
	t.Run("篡改副本 inner_b64", func(t *testing.T) { assertTamperRejected(t, func(d *KeyDirectory) { d.Replicas[0].InnerB64 = "AAAA" }) })
	t.Run("篡改 writer_epoch", func(t *testing.T) { assertTamperRejected(t, func(d *KeyDirectory) { d.WriterEpoch = 43 }) })
	t.Run("篡改时间精度", func(t *testing.T) {
		assertTamperRejected(t, func(d *KeyDirectory) { d.UpdatedAt = d.UpdatedAt.Truncate(time.Second) })
	})
	t.Run("追加副本", func(t *testing.T) {
		assertTamperRejected(t, func(d *KeyDirectory) {
			d.Replicas = append(d.Replicas, KeyReplica{Member: "dc2-hsm-b", Partition: "tenant-b",
				InnerB64: "BwgJCgsMDQ4=", BackupID: "bk-0003", State: "creating", UpdatedAt: mustParse(t, "2026-10-23T04:00:02.5Z")})
		})
	})
}

func assertTamperRejected(t *testing.T, mutate func(*KeyDirectory)) {
	t.Helper()
	kd := v1Dir(t)
	kd.MAC = v1MAC // MAC 为未篡改前的值
	mutate(&kd)
	if err := VerifyDirectoryMAC(kd, macKey()); err == nil {
		t.Fatalf("篡改后仍通过 MAC 校验（应被拒绝）")
	}
}

// TestDirectoryMACRejectsEmptyKey 空 MAC 密钥必须失败（§6.2.2：不得退化为无 MAC 目录）。
func TestDirectoryMACRejectsEmptyKey(t *testing.T) {
	kd := v1Dir(t)
	if _, err := DirectoryMAC(kd, nil); err == nil {
		t.Fatalf("空 MAC 密钥应报错")
	}
	if _, err := DirectoryMAC(kd, []byte{}); err == nil {
		t.Fatalf("空 MAC 密钥（非 nil 空切片）应报错")
	}
	// 正例：非空密钥可正常计算
	if _, err := DirectoryMAC(kd, macKey()); err != nil {
		t.Fatalf("非空 MAC 密钥应可用: %v", err)
	}
}

// TestDecodeStrictRejectsUnknown 未知字段必须拒绝（canonical 规则「未知字段拒绝」）。
func TestDecodeStrictRejectsUnknown(t *testing.T) {
	var kd KeyDirectory
	if err := DecodeStrict([]byte(v1Canonical), &kd); err != nil {
		t.Fatalf("合法输入应通过: %v", err)
	}
	bad := []byte(`{"key_id":"abc","unexpected_field":1}`)
	if err := DecodeStrict(bad, &kd); err == nil {
		t.Fatalf("未知字段应被拒绝")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
