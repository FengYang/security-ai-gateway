package poc

// GroupKeyRef 信封与 alias 三元组（镜像 testkit/groupkeyref.go，与本体 §6.2.2 D-10 / §6.2.3 对齐）。
//
// 契约边界：
//   - 信封不含密钥材料；
//   - inner 必须是重启/重新 Login 后仍可定位的**持久地址**（CKA_ID/label），
//     禁止 CK_OBJECT_HANDLE 类会话句柄；
//   - 解析失败一律 fail-closed，不得"猜成员"。

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	groupKeyRefVersion  = 0x01
	keyIDLen            = 16
	maxMemberLen        = 64
	maxPartitionLen     = 64
	maxInnerLen         = 512
	maxAliasTotalLen    = 226
	maxAliasNameLen     = 96
	aliasSeparator      = "|"
	aliasSeparatorASCII = 0x7C
)

// ErrGroupKeyRefInvalid 信封解析失败（fail-closed）。
var ErrGroupKeyRefInvalid = errors.New("poc: GroupKeyRef 信封非法")

// ErrGroupRoutingRequired alias 未携带合法 partition/member 路由信息。
var ErrGroupRoutingRequired = errors.New("poc: 需要显式组路由（alias 必须为 partition|member|alias）")

// GroupKeyRef 解码后的信封内容。
type GroupKeyRef struct {
	Version   uint8
	KeyID     [keyIDLen]byte
	Member    string
	Partition string
	Inner     []byte // 成员内持久地址（非密钥材料、非会话句柄）
}

func idCharOK(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '.' || b == '_' || b == '-':
		return true
	}
	return false
}

func validateID(s string, max int, what string) error {
	if len(s) < 1 || len(s) > max {
		return fmt.Errorf("%w: %s 长度 %d 超出 [1,%d]", ErrGroupKeyRefInvalid, what, len(s), max)
	}
	if !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= '0' && s[0] <= '9') {
		return fmt.Errorf("%w: %s 首字符必须为字母或数字", ErrGroupKeyRefInvalid, what)
	}
	for i := 0; i < len(s); i++ {
		if !idCharOK(s[i]) {
			return fmt.Errorf("%w: %s 含非法字符 %q", ErrGroupKeyRefInvalid, what, s[i])
		}
	}
	return nil
}

// EncodeGroupKeyRef 按 §6.2.2 字节布局编码信封。
func EncodeGroupKeyRef(keyID [keyIDLen]byte, member, partition string, inner []byte) ([]byte, error) {
	if err := validateID(member, maxMemberLen, "member"); err != nil {
		return nil, err
	}
	if err := validateID(partition, maxPartitionLen, "partition"); err != nil {
		return nil, err
	}
	if len(inner) < 1 || len(inner) > maxInnerLen {
		return nil, fmt.Errorf("%w: inner 长度 %d 超出 [1,%d]", ErrGroupKeyRefInvalid, len(inner), maxInnerLen)
	}
	buf := make([]byte, 0, 1+keyIDLen+2+len(member)+2+len(partition)+4+len(inner))
	buf = append(buf, groupKeyRefVersion)
	buf = append(buf, keyID[:]...)
	buf = append(buf, binary.BigEndian.AppendUint16(nil, uint16(len(member)))...)
	buf = append(buf, member...)
	buf = append(buf, binary.BigEndian.AppendUint16(nil, uint16(len(partition)))...)
	buf = append(buf, partition...)
	buf = append(buf, binary.BigEndian.AppendUint32(nil, uint32(len(inner)))...)
	buf = append(buf, inner...)
	return buf, nil
}

// DecodeGroupKeyRef 解析信封；任何越界/截断/非法字段均返回 ErrGroupKeyRefInvalid。
func DecodeGroupKeyRef(b []byte) (GroupKeyRef, error) {
	zero := GroupKeyRef{}
	if len(b) < 1 {
		return zero, fmt.Errorf("%w: 空信封", ErrGroupKeyRefInvalid)
	}
	if b[0] != groupKeyRefVersion {
		return zero, fmt.Errorf("%w: version %d 不支持", ErrGroupKeyRefInvalid, b[0])
	}
	off := 1
	if len(b) < off+keyIDLen {
		return zero, fmt.Errorf("%w: key_id 截断", ErrGroupKeyRefInvalid)
	}
	var ref GroupKeyRef
	ref.Version = b[0]
	copy(ref.KeyID[:], b[off:off+keyIDLen])
	off += keyIDLen

	readBlob := func(maxLen int, what string) (string, error) {
		if len(b) < off+2 {
			return "", fmt.Errorf("%w: %s 长度字段截断", ErrGroupKeyRefInvalid, what)
		}
		n := int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
		if n < 1 || n > maxLen {
			return "", fmt.Errorf("%w: %s 长度 %d 超出 [1,%d]", ErrGroupKeyRefInvalid, what, n, maxLen)
		}
		if len(b) < off+n {
			return "", fmt.Errorf("%w: %s 内容截断", ErrGroupKeyRefInvalid, what)
		}
		s := string(b[off : off+n])
		off += n
		if err := validateID(s, maxLen, what); err != nil {
			return "", err
		}
		return s, nil
	}

	member, err := readBlob(maxMemberLen, "member")
	if err != nil {
		return zero, err
	}
	partition, err := readBlob(maxPartitionLen, "partition")
	if err != nil {
		return zero, err
	}
	if len(b) < off+4 {
		return zero, fmt.Errorf("%w: inner 长度字段截断", ErrGroupKeyRefInvalid)
	}
	innerLen := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	if innerLen < 1 || innerLen > maxInnerLen {
		return zero, fmt.Errorf("%w: inner 长度 %d 超出 [1,%d]", ErrGroupKeyRefInvalid, innerLen, maxInnerLen)
	}
	if len(b) < off+innerLen {
		return zero, fmt.Errorf("%w: inner 内容截断", ErrGroupKeyRefInvalid)
	}
	ref.Member, ref.Partition = member, partition
	ref.Inner = append([]byte(nil), b[off:off+innerLen]...)
	off += innerLen
	if off != len(b) {
		return zero, fmt.Errorf("%w: 信封尾部存在 %d 字节多余数据", ErrGroupKeyRefInvalid, len(b)-off)
	}
	return ref, nil
}

// KeyIDHex 返回 32 位小写 hex（etcd 路径统一用此形式，禁止直接拼二进制）。
func KeyIDHex(keyID [keyIDLen]byte) string {
	return hex.EncodeToString(keyID[:])
}

// ParseAlias 解析组模式 alias：partition|member|alias。
//
// 规则（§6.2.3）：不提供转义——含 |（0x7C）、控制字符（0x00-0x1F、0x7F）或非 ASCII
// 字节一律拒绝，不做 URL/百分号解码。
func ParseAlias(alias string) (partition, member, name string, err error) {
	if len(alias) > maxAliasTotalLen {
		return "", "", "", fmt.Errorf("%w: alias 总长 %d 超过 %d", ErrGroupRoutingRequired, len(alias), maxAliasTotalLen)
	}
	for i := 0; i < len(alias); i++ {
		c := alias[i]
		if c < 0x20 || c == 0x7F {
			return "", "", "", fmt.Errorf("%w: alias 含控制字符", ErrGroupRoutingRequired)
		}
		if c >= 0x80 {
			return "", "", "", fmt.Errorf("%w: alias 含非 ASCII 字节", ErrGroupRoutingRequired)
		}
	}
	parts := strings.SplitN(alias, aliasSeparator, 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("%w: alias 必须为 partition|member|alias 三段", ErrGroupRoutingRequired)
	}
	partition, member, name = parts[0], parts[1], parts[2]
	if err := validateID(partition, maxPartitionLen, "partition"); err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrGroupRoutingRequired, err)
	}
	if err := validateID(member, maxMemberLen, "member"); err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrGroupRoutingRequired, err)
	}
	if len(name) < 1 || len(name) > maxAliasNameLen {
		return "", "", "", fmt.Errorf("%w: alias 名长度 %d 超出 [1,%d]", ErrGroupRoutingRequired, len(name), maxAliasNameLen)
	}
	if err := validateID(name, maxAliasNameLen, "alias"); err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrGroupRoutingRequired, err)
	}
	return partition, member, name, nil
}

// EncodeKeyRefB64 返回 base64url（无填充）信封串，模拟业务侧持有的 GroupKeyRef 句柄。
func EncodeKeyRefB64(keyID [keyIDLen]byte, member, partition string, inner []byte) (string, error) {
	raw, err := EncodeGroupKeyRef(keyID, member, partition, inner)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeKeyRefB64 解析 base64url 信封句柄。
func DecodeKeyRefB64(s string) (GroupKeyRef, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return GroupKeyRef{}, fmt.Errorf("%w: base64url 解码失败: %v", ErrGroupKeyRefInvalid, err)
	}
	return DecodeGroupKeyRef(raw)
}
