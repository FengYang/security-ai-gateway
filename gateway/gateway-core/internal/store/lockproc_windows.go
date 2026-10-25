//go:build windows

// P2-4 T-1.7：持锁进程存活探测（Windows 实现：OpenProcess 探测）。
package store

import (
	"errors"
	"syscall"
)

const (
	// processQueryLimitedInformation PROCESS_QUERY_LIMITED_INFORMATION 权限位
	// （0x1000）：只查询、不干预，权限要求低于 PROCESS_QUERY_INFORMATION。
	processQueryLimitedInformation = 0x1000
	// errorAccessDenied Windows ERROR_ACCESS_DENIED（5）。
	errorAccessDenied = syscall.Errno(5)
)

// processAlive 判定 PID 对应的进程是否仍存活（Windows 实现）。
//
// 语义（陈旧锁接管的保守前提，与 Unix 实现一致）：
//   - 进程存在且可查询 ⇒ true（**活锁**，不得接管）；
//   - 进程不存在（ERROR_INVALID_PARAMETER 等）⇒ false；
//   - 存在但无权限查询（ERROR_ACCESS_DENIED）⇒ **true**（进程确实存在，只是
//     当前用户无权查询；误判为"已退出"会导致接管活锁 ⇒ 破坏互斥）。
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		if errors.Is(err, errorAccessDenied) {
			return true // 进程存在但无权限 ⇒ 视为存活
		}
		return false // PID 不存在等 ⇒ 视为已退出
	}
	_ = syscall.CloseHandle(h)
	return true
}
