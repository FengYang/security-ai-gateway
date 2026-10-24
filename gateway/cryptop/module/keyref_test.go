//go:build pkcs11

package cryptopmodule

import (
	"errors"
	"strings"
	"testing"
)

// TestKeyRefRoundTrip 编解码往返：slot/partition/handle 边界值。
func TestKeyRefRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		slot      int
		partition string
		handle    uint
	}{
		{"常规", 0, "", 0x1f},
		{"非零槽+分区", 3, "tenant-a", 0xdeadbeef},
		{"handle=0", 0, "", 0},
		{"handle 上限(32位)", 1, "p", 0xffffffff},
		{"分区含连字符/下划线/点", 2, "Tenant_A-01.x", 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, err := encodeKeyRef(c.slot, c.partition, c.handle)
			if err != nil {
				t.Fatalf("encodeKeyRef: %v", err)
			}
			if got := string(ref); !strings.HasPrefix(got, "pk11:v1:") {
				t.Fatalf("token 前缀异常: %q", got)
			}
			h, err := decodeKeyRef(ref, c.slot, c.partition)
			if err != nil {
				t.Fatalf("decodeKeyRef: %v", err)
			}
			if h != c.handle {
				t.Fatalf("handle 往返不一致: got 0x%x want 0x%x", h, c.handle)
			}
		})
	}
}

// TestKeyRefTokenNoSecretMaterial KeyRef.String() 可直接进日志（不含密钥
// 材料）；本测试以格式断言固化该属性。
func TestKeyRefTokenNoSecretMaterial(t *testing.T) {
	ref, err := encodeKeyRef(0, "tenant-a", 0x1f)
	if err != nil {
		t.Fatal(err)
	}
	s := ref.String()
	if strings.Contains(s, "key") || strings.Contains(s, "secret") || strings.Contains(s, "priv") {
		t.Fatalf("token 不应含密钥材料字样: %q", s)
	}
	if want := "pk11:v1:0:tenant-a:1f"; s != want {
		t.Fatalf("token 格式: got %q want %q", s, want)
	}
}

// TestEncodeKeyRefPartitionColonRejected partition 含冒号破坏 token 结构，
// encode 期拒绝（fail-closed）。
func TestEncodeKeyRefPartitionColonRejected(t *testing.T) {
	for _, p := range []string{"a:b", ":", "a:0:1f", ":"} {
		if _, err := encodeKeyRef(0, p, 1); err == nil {
			t.Fatalf("partition=%q 应被拒绝", p)
		}
	}
}

// TestDecodeKeyRefRejects 全部错误路径（表驱动；一律 ErrKeyNotFound）。
func TestDecodeKeyRefRejects(t *testing.T) {
	valid, err := encodeKeyRef(2, "tenant-a", 0x1f)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ref  KeyRef
		slot int
		part string
	}{
		{"空", KeyRef(""), 2, "tenant-a"},
		{"空字节", KeyRef(nil), 2, "tenant-a"},
		{"坏前缀(mock ref)", KeyRef("mock:tenant-a"), 2, "tenant-a"},
		{"版本不符", KeyRef("pk11:v2:2:tenant-a:1f"), 2, "tenant-a"},
		{"字段过少", KeyRef("pk11:v1:2:tenant-a"), 2, "tenant-a"},
		{"字段过多", KeyRef("pk11:v1:2:tenant-a:1f:x"), 2, "tenant-a"},
		{"slot 非数字", KeyRef("pk11:v1:x:tenant-a:1f"), 2, "tenant-a"},
		{"slot 负", KeyRef("pk11:v1:-1:tenant-a:1f"), 2, "tenant-a"},
		{"slot 不匹配", valid, 3, "tenant-a"},
		{"partition 不匹配", valid, 2, "tenant-b"},
		{"partition 应为空", valid, 2, ""},
		{"handle 非十六进制", KeyRef("pk11:v1:2:tenant-a:zz"), 2, "tenant-a"},
		{"handle 空", KeyRef("pk11:v1:2:tenant-a:"), 2, "tenant-a"},
		{"空 partition 不匹配", mustEnc(t, 0, "", 5), 0, "x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodeKeyRef(c.ref, c.slot, c.part)
			if err == nil {
				t.Fatalf("ref=%q slot=%d part=%q 应被拒绝", c.ref, c.slot, c.part)
			}
			if !isKeyNotFound(err) {
				t.Fatalf("错误应包装 ErrKeyNotFound: %v", err)
			}
		})
	}
}

func mustEnc(t *testing.T, slot int, part string, h uint) KeyRef {
	t.Helper()
	ref, err := encodeKeyRef(slot, part, h)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func isKeyNotFound(err error) bool {
	return errors.Is(err, ErrKeyNotFound)
}
