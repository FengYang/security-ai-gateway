package poc

// canonical JSON 与目录 MAC（镜像 testkit/canonical.go，与本体 §6.2.2 冻结规则一致）。
//
// 独立复制的理由：poc 是**黑盒一致性验证**，若直接 import testkit，
// "testkit 与自身一致"无法证伪。两份实现同源但独立编译/独立运行。

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

// KeyReplica 目录副本项（与本体 §6.2.6 KeyReplica 对齐）。
type KeyReplica struct {
	Member    string    `json:"member"`
	Partition string    `json:"partition"`
	InnerB64  string    `json:"inner_b64"`
	BackupID  string    `json:"backup_id"`
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KeyDirectory 密钥目录项（与本体 §6.2.6 KeyDirectory 对齐）。
//
// MAC 字段 omitempty：空值时整键不出现，使「目录序列化结果」与「MAC 计算输入」
// 严格一致（§6.2.2：MAC 计算时删除顶层 mac 字段）。
type KeyDirectory struct {
	Version      int64        `json:"version"`
	KeyID        string       `json:"key_id"`
	KeyMode      string       `json:"key_mode"`
	Replicas     []KeyReplica `json:"replicas"`
	State        string       `json:"state"`
	CreatedBy    string       `json:"created_by"`
	WriterEpoch  uint64       `json:"writer_epoch"`
	WriterBootID string       `json:"writer_boot_id"`
	LeaseEpoch   uint64       `json:"lease_epoch"`
	UpdatedAt    time.Time    `json:"updated_at"`
	MAC          string       `json:"mac,omitempty"`
}

// MACKeyName 目录 MAC 输入中被排除的顶层字段名。
const MACKeyName = "mac"

// CanonicalJSON 把任意 JSON 可序列化值规范化为 canonical 字节串。
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("poc: 预序列化失败: %w", err)
	}
	raw := bytes.TrimRight(buf.Bytes(), "\n")

	var top any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("poc: 预解析失败: %w", err)
	}

	var out bytes.Buffer
	if err := writeCanonical(&out, top); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// CanonicalForMAC 返回用于 MAC 计算的 canonical 串（删除顶层 mac 字段）。
func CanonicalForMAC(kd KeyDirectory) ([]byte, error) {
	var m map[string]json.RawMessage
	raw, err := json.Marshal(kd)
	if err != nil {
		return nil, fmt.Errorf("poc: 序列化目录失败: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("poc: 解析目录失败: %w", err)
	}
	delete(m, MACKeyName)
	return CanonicalJSON(m)
}

// DirectoryMAC 计算目录项的 HMAC-SM3。
//
// 空 MAC 密钥一律报错：§6.2.2 规定「无 MAC 密钥时的目录写入一律失败，
// 不得退化为无 MAC 目录」。
func DirectoryMAC(kd KeyDirectory, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("poc: 目录 MAC 密钥为空（§6.2.2：无 MAC 密钥时目录写入一律失败）")
	}
	input, err := CanonicalForMAC(kd)
	if err != nil {
		return nil, err
	}
	return HMACSM3(key, input), nil
}

// ErrDirectoryMACInvalid 读者侧 MAC 校验失败（篡改/键序不符/键不符）。
var ErrDirectoryMACInvalid = fmt.Errorf("poc: 目录 MAC 校验失败")

// VerifyDirectoryMAC 校验目录项 MAC 是否成立（常量时间比较）。
func VerifyDirectoryMAC(kd KeyDirectory, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("poc: 目录 MAC 密钥为空（拒绝无保护目录）")
	}
	want, err := DirectoryMAC(kd, key)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(kd.MAC)
	if err != nil {
		return fmt.Errorf("%w: mac 非合法 hex: %v", ErrDirectoryMACInvalid, err)
	}
	if !hmac.Equal(got, want) {
		return ErrDirectoryMACInvalid
	}
	return nil
}

// HMACSM3 标准 HMAC 构造，底层摘要为 SM3（块长 64 字节）。
func HMACSM3(key, msg []byte) []byte {
	m := hmac.New(sm3.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// DecodeStrict 严格反序列化：未知字段一律拒绝（对齐 canonical 规则「未知字段拒绝」）。
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			out.Write(kb)
			out.WriteByte(':')
			if err := writeCanonical(out, t[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case json.Number:
		out.WriteString(t.String())
	case string:
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(t); err != nil {
			return err
		}
		out.Write(bytes.TrimRight(buf.Bytes(), "\n"))
	case bool:
		out.WriteString(fmt.Sprintf("%t", t))
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("poc: 不支持的 canonical 类型 %T", v)
	}
	return nil
}
