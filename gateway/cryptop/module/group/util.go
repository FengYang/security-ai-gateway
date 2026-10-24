package group

import (
	"encoding/base64"
	"encoding/hex"
)

// hexKeyID 把 16 字节 key_id 规范化为十六进制字符串（目录键 / 审计标识）。
func hexKeyID(b [16]byte) string {
	return hex.EncodeToString(b[:])
}

// b64 标准无换行 base64（目录副本 InnerB64 字段用，与 canonical 规则一致）。
func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
