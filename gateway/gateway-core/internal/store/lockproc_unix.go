//go:build !windows

// P2-4 T-1.7：持锁进程存活探测（Unix 实现：kill(pid, 0) 探测）。
package store

import (
	"errors"
	"os"
	"syscall"
)

// processAlive 判定 PID 对应的进程是否仍存活。
//
// 语义（陈旧锁接管的保守前提）：
//   - 进程存在且可探测 ⇒ true（**活锁**，不得接管）；
//   - 已退出（ESRCH / os.ErrProcessDone）⇒ false；
//   - 存在但无权限探测（EPERM）⇒ **true**（进程确实存在，只是当前用户无权
//     向其发信号；误判为"已退出"会导致接管活锁 ⇒ 破坏互斥）。
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) {
		return true // 进程存在但无权限 ⇒ 视为存活
	}
	return false
}
