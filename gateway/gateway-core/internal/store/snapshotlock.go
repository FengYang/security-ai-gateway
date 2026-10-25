// P2-4 T-1.7：快照写者串行化（lockfile 互斥）+ 陈旧锁接管告警。
//
// 为什么需要（TOCTOU）：内容级版本判据只能回答"**该不该写**"，但"判据比较"与
// "写盘"之间存在时间窗口——两个写者可能先后通过判据、随后互相覆盖
// （"读盘 → 比较 → 写盘"整体非原子）。lockfile 把**整段**纳入互斥临界区，
// 从根上消除该窗口。
//
// 锁文件：与快照同目录的 `<snapshotPath>.lock`（同目录 ⇒ 同卷、同生命周期）。
//   - 创建：O_CREATE|O_EXCL（原子；已存在即有人在持锁）；
//   - 内容：PID + 持有时间戳（Unix 纳秒），供陈旧判定与告警文案；
//   - 权限：0600（与快照一致；锁文件不含敏感内容）。
//
// 陈旧锁（进程崩溃残留）接管（**保守**）：
//   - 持有时长 ≥ staleLockThreshold（默认 30s）**且**持锁 PID 已确认不存在
//     ⇒ 判定为崩溃残留 ⇒ 接管并**告警**（明确告知发生过进程崩溃/强杀）；
//   - PID 仍存活 ⇒ **活锁**，**不接管**：等待至超时后**明确失败**（绝不覆盖他人快照）；
//   - 锁文件内容不可解析 ⇒ **不接管**（无法确认持锁 PID 已退出 ⇒ 保守优先），
//     等待至超时后明确失败，并在错误中提示人工清理。
//
// 零行为变化：快照关闭（path 为空）时完全不涉及锁；单写者路径仅多一次
// O_EXCL 创建 + 一次删除（合并写窗口 200ms，开销可忽略）。
//
// 前提假设：锁文件与快照**同目录同卷**（NFS/PVC 共享目录亦可），且底层
// 文件系统对 O_CREATE|O_EXCL 提供**原子性**（POSIX 与 NFSv3+ 满足）。若底层
// 不保证 O_EXCL 原子性，锁退化为"尽力互斥"——此时内容级判据仍能拦截
// "陈旧内容覆盖新内容"（但无法完全消除同时写导致的文件损坏风险）。
package store

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// staleLockThreshold 陈旧锁阈值：持锁时长超过它，才进入"是否接管"的判定。
	staleLockThreshold = 30 * time.Second
	// lockPollInterval 等待写锁的轮询间隔。
	lockPollInterval = 20 * time.Millisecond
	// lockSuffix 锁文件后缀（与快照同目录）。
	lockSuffix = ".lock"
)

// lockWaitTimeout 等待写锁的上限（超时 ⇒ 明确失败，绝不覆盖他人快照）。
//
// ⚠️ 变量而非常量：单测需**缩短**该上限以构造确定性时序（见
// TestSnapshotSecondWriterBlockedByLock）。
var lockWaitTimeout = 2 * time.Second

// snapshotLock 快照写锁（基于 O_EXCL 锁文件的互斥）。
type snapshotLock struct {
	path     string        // 锁文件路径（<快照路径>.lock）
	timeout  time.Duration // 等待超时（超时 ⇒ 明确失败）
	poll     time.Duration // 轮询间隔
	stale    time.Duration // 陈旧阈值
	logger   *log.Logger   // 日志出口（nil ⇒ log.Default）
	acquired bool          // 是否已持有锁（决定 release 是否删除文件）
}

// newSnapshotLock 构造快照写锁（锁文件与快照同目录）。
func newSnapshotLock(snapshotPath string, logger *log.Logger) *snapshotLock {
	if logger == nil {
		logger = log.Default()
	}
	return &snapshotLock{
		path:    snapshotPath + lockSuffix,
		timeout: lockWaitTimeout,
		poll:    lockPollInterval,
		stale:   staleLockThreshold,
		logger:  logger,
	}
}

// acquire 获取写锁：阻塞等待至超时。
//
// 返回错误 ⇒ 明确失败（调用方**不得**继续写盘）：持锁者可能是活着的另一个写者，
// 此时覆盖其快照会造成"配置静默回退"，比写失败严重得多。
func (l *snapshotLock) acquire() error {
	deadline := time.Now().Add(l.timeout)
	for {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			// 写入持有者信息（PID + 时间戳），供陈旧判定与告警文案使用。
			_, werr := fmt.Fprintf(f, "pid=%d\nacquired_at=%d\n", os.Getpid(), time.Now().UnixNano())
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(l.path)
				return fmt.Errorf("写快照锁文件失败: %w", errors.Join(werr, cerr))
			}
			l.acquired = true
			return nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("创建快照锁文件失败: %w", err)
		}
		// 锁已存在：判定是否陈旧（可接管）。
		if l.tryTakeOverStale() {
			continue // 陈旧锁已删除 ⇒ 立即重试创建（O_EXCL 保证只有一个成功）
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待快照写锁超时（%s）：可能有其它写者持有该锁（不覆盖其快照）", l.path)
		}
		time.Sleep(l.poll)
	}
}

// tryTakeOverStale 判定并接管陈旧锁（进程崩溃残留）。
//
// 返回 true = 已接管（锁文件已删除，调用方应重试创建）；
// 返回 false = 不可接管（活锁 / 内容不可解析 / 未达阈值 / 并发释放）。
func (l *snapshotLock) tryTakeOverStale() bool {
	info, err := os.Stat(l.path)
	if err != nil {
		return false // 并发释放或消失 ⇒ 交给下一轮重试（O_EXCL 创建）
	}
	if time.Since(info.ModTime()) < l.stale {
		return false // 未达陈旧阈值 ⇒ 视为活锁，不接管
	}
	pid, ok := readLockPID(l.path)
	if !ok {
		// 内容不可解析 ⇒ 无法确认持锁 PID 已退出 ⇒ **不接管**（保守优先于可用性）。
		l.logger.Printf("警告: 快照锁文件内容不可解析（%s），不接管（无法确认持锁进程已退出）；"+
			"若确认无其它写者，请人工删除该文件", l.path)
		return false
	}
	if processAlive(pid) {
		return false // 活锁：持锁进程仍在运行 ⇒ 绝不接管
	}
	// 陈旧锁（持锁进程已不存在）⇒ 接管并**告警**（说明发生过进程崩溃/强杀）。
	l.logger.Printf("错误: 接管陈旧快照锁（持锁进程 pid=%d 已不存在，说明发生过进程崩溃/强杀）: %s", pid, l.path)
	if err := os.Remove(l.path); err != nil {
		l.logger.Printf("警告: 删除陈旧快照锁失败（%s）: %v", l.path, err)
		return false
	}
	return true
}

// release 释放写锁（删除锁文件；幂等：未持有或已删除都不报错）。
func (l *snapshotLock) release() {
	if !l.acquired {
		return
	}
	l.acquired = false
	if err := os.Remove(l.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		l.logger.Printf("警告: 删除快照锁文件失败（%s，可能留下陈旧锁）: %v", l.path, err)
	}
}

// readLockPID 解析锁文件中的 PID（内容不可解析 ⇒ ok=false）。
func readLockPID(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pid=") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid=")))
		if err != nil || pid <= 0 {
			return 0, false
		}
		return pid, true
	}
	return 0, false
}
