package testkit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func testKeyID() [16]byte {
	var id [16]byte
	b, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	copy(id[:], b)
	return id
}

func TestGroupKeyRefRoundTrip(t *testing.T) {
	inner := []byte("persistent-cka-id-0123")
	enc, err := EncodeGroupKeyRef(testKeyID(), "dc1-hsm-a", "tenant-a", inner)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	// 布局核对：version + key_id(16) + len(2) + member + len(2) + partition + len(4) + inner
	wantLen := 1 + 16 + 2 + len("dc1-hsm-a") + 2 + len("tenant-a") + 4 + len(inner)
	if len(enc) != wantLen {
		t.Fatalf("信封长度错误: 期望 %d 实测 %d", wantLen, len(enc))
	}
	if enc[0] != 0x01 {
		t.Fatalf("version 应为 0x01，实测 %d", enc[0])
	}
	ref, err := DecodeGroupKeyRef(enc)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if ref.Member != "dc1-hsm-a" || ref.Partition != "tenant-a" {
		t.Fatalf("成员/分区解码错误: %+v", ref)
	}
	if !bytes.Equal(ref.Inner, inner) {
		t.Fatalf("inner 解码错误: %x", ref.Inner)
	}
	if ref.KeyID != testKeyID() {
		t.Fatalf("key_id 解码错误: %x", ref.KeyID)
	}
}

func TestKeyIDHexIs32Lower(t *testing.T) {
	got := KeyIDHex(testKeyID())
	if got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("key_id hex 应为 32 位小写，实测 %s", got)
	}
	if len(got) != 32 {
		t.Fatalf("长度应为 32，实测 %d", len(got))
	}
}

func TestGroupKeyRefEncodeRejects(t *testing.T) {
	cases := []struct {
		name      string
		member    string
		partition string
		inner     []byte
	}{
		{"空成员", "", "tenant-a", []byte("x")},
		{"空分区", "dc1-hsm-a", "", []byte("x")},
		{"成员含斜杠", "dc1/hsm", "tenant-a", []byte("x")},
		{"成员含空格", "dc1 hsm", "tenant-a", []byte("x")},
		{"成员首字符非法", "-dc1", "tenant-a", []byte("x")},
		{"成员超长", strings.Repeat("a", 65), "tenant-a", []byte("x")},
		{"分区超长", "dc1-hsm-a", strings.Repeat("b", 65), []byte("x")},
		{"inner 为空", "dc1-hsm-a", "tenant-a", nil},
		{"inner 超长", "dc1-hsm-a", "tenant-a", bytes.Repeat([]byte("z"), 513)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EncodeGroupKeyRef(testKeyID(), tc.member, tc.partition, tc.inner); err == nil {
				t.Fatalf("应被拒绝")
			} else if !errors.Is(err, ErrGroupKeyRefInvalid) {
				t.Fatalf("错误应为 ErrGroupKeyRefInvalid，实测 %v", err)
			}
		})
	}
}

func TestGroupKeyRefDecodeRejects(t *testing.T) {
	good, err := EncodeGroupKeyRef(testKeyID(), "dc1-hsm-a", "tenant-a", []byte("inner-1"))
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	cases := []struct {
		name string
		in   []byte
	}{
		{"空输入", nil},
		{"version 非 0x01", append([]byte{0x02}, good[1:]...)},
		{"截断 key_id", good[:10]},
		{"截断 member 长度字段", good[:18]},
		{"截断 member 内容", good[:22]},
		{"截断 inner", good[:len(good)-3]},
		{"尾部多余字节", append(append([]byte(nil), good...), 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeGroupKeyRef(tc.in); err == nil {
				t.Fatalf("应被拒绝")
			} else if !errors.Is(err, ErrGroupKeyRefInvalid) {
				t.Fatalf("错误应为 ErrGroupKeyRefInvalid，实测 %v", err)
			}
		})
	}
}

func TestParseAliasValid(t *testing.T) {
	p, m, n, err := ParseAlias("tenant-a|dc1-hsm-a|root-key")
	if err != nil {
		t.Fatalf("合法 alias 应通过: %v", err)
	}
	if p != "tenant-a" || m != "dc1-hsm-a" || n != "root-key" {
		t.Fatalf("解析错误: %s/%s/%s", p, m, n)
	}
}

func TestParseAliasRejects(t *testing.T) {
	cases := []struct {
		name  string
		alias string
	}{
		{"缺段（仅两段）", "tenant-a|dc1-hsm-a"},
		{"缺段（一段）", "tenant-a"},
		{"空段", "tenant-a||root-key"},
		{"分区为空", "|dc1-hsm-a|root-key"},
		{"alias 名为空", "tenant-a|dc1-hsm-a|"},
		{"alias 名含分隔符（不转义）", "tenant-a|dc1-hsm-a|ro|ot"},
		{"含控制字符", "tenant-a|dc1-hsm-a|root\x01key"},
		{"含非 ASCII", "tenant-a|dc1-hsm-a|租户密钥"},
		{"分区含斜杠", "ten/ant|dc1-hsm-a|root-key"},
		{"成员超长", "tenant-a|" + strings.Repeat("m", 65) + "|root-key"},
		{"总长超限（227）", strings.Repeat("a", 64) + "|" + strings.Repeat("b", 64) + "|" + strings.Repeat("c", 97)},
		{"尾部多段不合并（SplitN 3 段后含 |）", "tenant-a|dc1-hsm-a|a|b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := ParseAlias(tc.alias); err == nil {
				t.Fatalf("应被拒绝")
			} else if !errors.Is(err, ErrGroupRoutingRequired) {
				t.Fatalf("错误应为 ErrGroupRoutingRequired，实测 %v", err)
			}
		})
	}
}

// TestParseAliasUpperBound 边界内最大值应通过（64+64+96+2=226）。
func TestParseAliasUpperBound(t *testing.T) {
	alias := strings.Repeat("a", 64) + "|" + strings.Repeat("b", 64) + "|" + strings.Repeat("c", 96)
	if len(alias) != 226 {
		t.Fatalf("构造的总长应为 226，实测 %d", len(alias))
	}
	if _, _, _, err := ParseAlias(alias); err != nil {
		t.Fatalf("边界内最大 alias 应通过: %v", err)
	}
	if _, _, _, err := ParseAlias(alias + "x"); err == nil {
		t.Fatalf("超过 226 应被拒绝")
	}
}
