// Package testkit 承载 P2-3「模块组」的契约参考实现与测试资产。
//
// 定位（本体 §4 M-8 测试基座 / 开发标准评审报告 §13.3 S-*）：
//   - 本包是**测试基座**，用于锁定《P2--HSM集成》§6.2.2 的 canonical JSON 与目录 MAC 契约；
//   - **不接入产品链路**：不改动 Provider 20 方法、ModuleBackend 22 方法签名，也不被
//     cryptopsvc / gateway-core 引用；
//   - 结论边界：本包用例通过不等于 S3-b 通过，也不构成生产合规/密评结论。
//
// canonical 规则（本体 §6.2.2，冻结）：
//
//	UTF-8、无 BOM/无多余空白；对象键按 UTF-8 字节升序；数组保持顺序；
//	整数用十进制（禁止浮点/指数）；时间用 RFC3339Nano UTC；
//	base64 用标准无换行；未知字段拒绝；MAC 计算时删除顶层 mac 字段。
package testkit

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
	UpdatedAt time.Time `json:"updated_at"` // RFC3339Nano UTC（Go 默认序列化即符合 canonical 时间规则）
}

// KeyDirectory 密钥目录项（与本体 §6.2.6 KeyDirectory 对齐）。
//
// MAC 字段用 omitempty：空值时整键不出现，使「目录序列化结果」与「MAC 计算输入」
// 严格一致（本体 §6.2.2：MAC 计算时删除顶层 mac 字段）。
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
//
// 约定：对象键升序、数组保序、数字沿用既有字面值（整数十进制）、
// 时间字段由调用方以 RFC3339Nano UTC 字符串给出（见 KeyDirectory.UpdatedAt）。
func CanonicalJSON(v any) ([]byte, error) {
	// 先用不转义 HTML 的编码器取得原始字面值，避免 <、>、& 被写成 \u003c 等。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("testkit: 预序列化失败: %w", err)
	}
	raw := bytes.TrimRight(buf.Bytes(), "\n")

	var top any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("testkit: 预解析失败: %w", err)
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
		return nil, fmt.Errorf("testkit: 序列化目录失败: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("testkit: 解析目录失败: %w", err)
	}
	delete(m, MACKeyName)
	return CanonicalJSON(m)
}

// DirectoryMAC 计算目录项的 HMAC-SM3（输入为删除 mac 后的 canonical 串）。
//
// 空 MAC 密钥一律报错：本体 §6.2.2 规定「无 MAC 密钥时的目录写入一律失败，
// 不得退化为无 MAC 目录」——此处不得静默用空密钥算出一个合法的"无保护"MAC。
func DirectoryMAC(kd KeyDirectory, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("testkit: 目录 MAC 密钥为空（§6.2.2：无 MAC 密钥时目录写入一律失败）")
	}
	input, err := CanonicalForMAC(kd)
	if err != nil {
		return nil, err
	}
	return HMACSM3(key, input), nil
}

// VerifyDirectoryMAC 校验目录项 MAC 是否成立（常量时间比较）。
func VerifyDirectoryMAC(kd KeyDirectory, key []byte) error {
	want, err := DirectoryMAC(kd, key)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(kd.MAC)
	if err != nil {
		return fmt.Errorf("testkit: 目录 mac 非合法 hex: %w", err)
	}
	if !hmac.Equal(got, want) {
		return fmt.Errorf("testkit: 目录 MAC 校验失败（可能被篡改或键序/格式不符合 canonical）")
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

// writeCanonical 递归输出 canonical 表示。
func writeCanonical(out *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // string 比较即 UTF-8 字节序比较
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
		return fmt.Errorf("testkit: 不支持的 canonical 类型 %T", v)
	}
	return nil
}
