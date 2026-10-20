package a2aregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// canonicalJSON 生成 RFC 8785（JCS）规范化字节序列，**并排除顶层 signatures**。
//
// ⚠️ 必须与 `a2acrypto.canonicalizeJSON` **逐字节一致**：content_hash 的输入
// 与签名 payload 同源（冻结 §3.5），二者不一致即导致"签名可验但哈希对不上"。
// 因此本实现严格对齐 RFC 8785：对象键按 **UTF-16 码元序** 排序（不是 UTF-8 字节序）、
// 数字按 ECMAScript Number::toString 序列化、字符串仅转义 " \\ 与 U+0000–U+001F
// （U+2028/U+2029 按 RFC 8785 §3.2.2.2 保持字面量）。
//
// 复核证据：a2acrypto 官方跨 SDK 固定向量（testdata/golden.json）——用本函数
// 规范化 card_json_unsigned 后拼装 JWS signing input，可复现官方 signature
// （见 jcs_test.go::TestJCSMatchesA2ACrypto）。
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: 解析失败: %w", err)
	}
	dropSignatures(v)
	var buf bytes.Buffer
	encodeValue(&buf, v)
	return buf.Bytes(), nil
}

// dropSignatures 移除顶层 signatures 字段（A2A §8.4.1：签名 payload 不含自身）。
// 与 a2acrypto.dropSignatures 同语义（非对象时不做处理）。
func dropSignatures(v any) {
	if obj, ok := v.(map[string]any); ok {
		delete(obj, "signatures")
	}
}

// encodeValue 编码单个 JSON 值（RFC 8785）。
func encodeValue(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(canonicalNumber(x))
	case string:
		encodeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeValue(buf, e)
		}
		buf.WriteByte(']')
	case map[string]any:
		buf.WriteByte('{')
		for i, k := range sortedKeys(x) {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodeString(buf, k)
			buf.WriteByte(':')
			encodeValue(buf, x[k])
		}
		buf.WriteByte('}')
	default:
		// 不应出现（json.Number 已覆盖数值；channel/func 不入 JSON）
		buf.WriteString("null")
	}
}

// encodeString 按 RFC 8785 §3.2.2.2 转义字符串。
// 仅转义 " 与 \ 与 U+0000–U+001F（其中 \b \t \n \f \r 用短形式）；
// U+2028/U+2029 保持字面量（与 a2acrypto 一致）。
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// sortedKeys 按 UTF-16 码元序排序对象键（RFC 8785 §3.2.3）。
// 注意：与 sort.Strings（UTF-8 字节序）在含非 BMP 字符的键上结论不同。
func sortedKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return utf16Compare(keys[i], keys[j]) < 0
	})
	return keys
}

// utf16Compare 按 UTF-16 码元序比较两个字符串。
func utf16Compare(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := min(len(ua), len(ub))
	for i := 0; i < n; i++ {
		if ua[i] < ub[i] {
			return -1
		}
		if ua[i] > ub[i] {
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

// canonicalNumber 按 RFC 8785 §3.2.2.3 序列化数字：先转 binary64，
// 再按 ECMAScript Number::toString 输出。
func canonicalNumber(n json.Number) string {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return string(n)
	}
	return canonicalFloat(f)
}

// canonicalFloat 复刻 ECMAScript Number::toString 的十进制输出规则。
func canonicalFloat(f float64) string {
	if f == 0 {
		return "0" // -0 也输出 "0"
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return normalizeExponent(strconv.FormatFloat(f, 'e', -1, 64))
}

// normalizeExponent 修正指数表示（"1e-07" → "1e-7"，去掉前导零与 "+"）。
func normalizeExponent(s string) string {
	i := strings.IndexByte(s, 'e')
	if i < 0 {
		return s
	}
	mant := s[:i+1]
	exp := s[i+1:]
	if exp != "" && (exp[0] == '+' || exp[0] == '-') {
		mant += string(exp[0])
		exp = exp[1:]
	}
	exp = strings.TrimLeft(exp, "0")
	if exp == "" {
		exp = "0"
	}
	return mant + exp
}

// contentHash 计算 content_hash = SHA-256(JCS(card 去 signatures))。
// 签名 payload 与 content_hash 输入同源（均排除顶层 signatures 后做 RFC 8785）。
func contentHash(raw []byte) (string, error) {
	c, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// rawHash 计算 raw_hash = SHA-256(原始卡字节)。
func rawHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
