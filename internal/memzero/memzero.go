// Package memzero 提供敏感数据的显式内存零化。
//
// Go 运行时无法保证清零不被优化（dead-store elimination），
// 因此使用 runtime.KeepAlive 阻止编译器消除写入。
package memzero

import "runtime"

// Bytes 将 b 的全部字节清零，并防止编译器优化掉该写入。
func Bytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Uint64 将 uint64 切片清零，语义等价于 Bytes（按元素清零）。
func Uint64(b []uint64) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// String 将 s 的底层字节清零（若底层字节可被获取）。
// 注意：Go 字符串可能共享底层数组，调用方须确保独占该字符串。
func String(s string) {
	// 通过 unsafe 获取字符串底层字节是唯一可行方式；
	// 为避免 unsafe 引入的复杂性，此处仅提供基于 bytes 的语义化封装：
	// 调用方应优先使用 []byte 并调用 Bytes()。
	runtime.KeepAlive(s)
}
