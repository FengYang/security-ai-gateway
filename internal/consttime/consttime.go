// Package consttime 提供密码路径所需的常数时间辅助函数。
//
// math/big 的相等性比较与 Bytes() 序列化非常数时间（长度与值依赖），
// 工业级实现须先规整为固定长度字节再使用 crypto/subtle 比较。
package consttime

import (
	"crypto/subtle"
	"math/big"
)

// CompareBigInt 以常数时间方式比较两个大整数是否相等。
//
// 方法：将两者填充到同一长度（以较长的位长为准）后按 big-endian 字节
// 比较。填充本身会暴露长度差，但对"相等性"比较而言，长度差本身就是
// 相等性的泄露（长度不同则必不相等），属可接受信息。
func CompareBigInt(a, b *big.Int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}

	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)
	copy(aPadded[maxLen-len(aBytes):], aBytes)
	copy(bPadded[maxLen-len(bBytes):], bBytes)

	return subtle.ConstantTimeCompare(aPadded, bPadded) == 1
}

// CompareBytes 比较两个字节切片是否相等（常数时间）。
// 长度不同直接返回 false（不等长必不相等）。
func CompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
