// P2-4 T-1.7 快照写者串行化 + 内容级版本判据单测（三道防线）。
//
// 覆盖（与派发口径逐条对应）：
//  1. 内容级判据：本地版本 ≤ 磁盘版本 ⇒ 拒绝写入且**磁盘内容逐字节不变**；
//  2. 自动重试前重读磁盘：发现磁盘已更新 ⇒ **放弃写盘** + 独立计数 + 独立告警；
//  3. lockfile 生效时第二写者被阻塞/拒绝（不覆盖持锁者的快照）；
//  4. 陈旧锁（持锁 PID 已不存在）被接管并**告警**；
//  5. 活锁（持锁进程存活）**不被误接管**；
//  6. 单写者路径零回归（含：锁文件不残留、禁用态不涉及锁）。
package store

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/route"
)

// deadPIDForTest 一个**必然不存在**的 PID（远超各平台常见 PID 上限）：
// 用于构造"持锁进程已崩溃退出"的陈旧锁。
const deadPIDForTest = 2147483647

// newTestRouteTable 构造一张指定版本的路由表（内容随版本变化，便于区分）。
func newTestRouteTable(version int, engine string) *route.RouteTable {
	tbl := route.NewRouteTable(version, 1000)
	tbl.Routes = []route.TableRoute{{Tenant: "t", Model: "m", DefaultEngine: engine}}
	return tbl
}

// TestSnapshotContentBlockRejectsStaleWriter **内容级版本判据（主防线）**：
// 本地版本 ≤ 磁盘版本 ⇒ 拒绝写入，且**磁盘内容逐字节不变**。
//
// 子场景：
//   - 磁盘版本更高（本地 v3 / 磁盘 v9）⇒ 拒绝（QA 实跑复现的"内容回退"原样）；
//   - 版本相同但内容漂移 ⇒ 拒绝（版本契约被破坏，保守拒绝 + 告警）；
//   - 本地缺少磁盘已有的表 ⇒ 拒绝（写出会抹掉磁盘内容）；
//   - 版本相同且内容一致 ⇒ **放行**（单写者路径：本地未变更该表）。
func TestSnapshotContentBlockRejectsStaleWriter(t *testing.T) {
	t.Run("磁盘版本更高则拒绝", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "snap.json")

		// 写者 A：较新内容（路由表 v9）落盘。
		ssA := NewSnapshotStore(NewMemory(), path, nil)
		ssA.Memory.SaveRouteTable(newTestRouteTable(9, "new"))
		if err := ssA.Persist(); err != nil {
			t.Fatalf("写者 A 落盘失败: %v", err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读快照失败: %v", err)
		}

		// 写者 B：陈旧内容（路由表 v3）。
		var buf bytes.Buffer
		ssB := NewSnapshotStore(NewMemory(), path, log.New(&buf, "", 0))
		ssB.Memory.SaveRouteTable(newTestRouteTable(3, "old"))
		ssB.SetFlushInterval(0)

		err = ssB.Persist()
		if err == nil {
			t.Fatalf("陈旧写者应被内容判据拦截")
		}
		if !isContentBlock(err) {
			t.Fatalf("错误类型应为内容回退拦截: %T %v", err, err)
		}
		if !strings.Contains(err.Error(), "内容回退拦截") {
			t.Fatalf("错误文案应与“防回退拒绝”可区分: %v", err)
		}
		if strings.Contains(err.Error(), "防回退") {
			t.Fatalf("内容拦截文案不应复用“防回退”措辞: %v", err)
		}
		// 磁盘内容逐字节不变。
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读快照失败: %v", err)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("内容回退拦截必须保持磁盘快照逐字节不变")
		}
		// 磁盘内容仍是新版本。
		if got := readPayload(t, path).RouteTable.Version; got != 9 {
			t.Fatalf("磁盘路由表版本应保持 9: got %d", got)
		}
		// 独立计数可观测。
		if ssB.ContentBlocks() == 0 {
			t.Fatalf("内容拦截次数应可观测（ContentBlocks）")
		}
		if ssB.RollbackRejects() != 0 {
			t.Fatalf("内容拦截不应计入 revision 判据的拒绝计数")
		}
		// 独立告警文案。
		if !strings.Contains(buf.String(), "快照内容回退拦截") {
			t.Fatalf("应有独立的内容回退告警文案: %s", buf.String())
		}
	})

	t.Run("同版本内容漂移则拒绝", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "snap.json")

		ssA := NewSnapshotStore(NewMemory(), path, nil)
		ssA.Memory.SaveRouteTable(newTestRouteTable(9, "new"))
		if err := ssA.Persist(); err != nil {
			t.Fatalf("写者 A 落盘失败: %v", err)
		}
		before, _ := os.ReadFile(path)

		// 写者 B：版本相同（9）但内容不同 ⇒ 版本号不可信 ⇒ 保守拒绝。
		ssB := NewSnapshotStore(NewMemory(), path, nil)
		ssB.Memory.SaveRouteTable(newTestRouteTable(9, "drifted"))
		ssB.SetFlushInterval(0)
		if err := ssB.Persist(); err == nil {
			t.Fatalf("同版本内容漂移应被拒绝")
		} else if !isContentBlock(err) {
			t.Fatalf("错误类型应为内容回退拦截: %T %v", err, err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatalf("拦截后磁盘快照必须逐字节不变")
		}
	})

	t.Run("本地缺表则拒绝", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "snap.json")

		ssA := NewSnapshotStore(NewMemory(), path, nil)
		ssA.Memory.SaveRouteTable(newTestRouteTable(9, "new"))
		if err := ssA.Persist(); err != nil {
			t.Fatalf("写者 A 落盘失败: %v", err)
		}
		before, _ := os.ReadFile(path)

		// 写者 B：没有该表 ⇒ 写出会抹掉磁盘上的表 ⇒ 拒绝。
		ssB := NewSnapshotStore(NewMemory(), path, nil)
		ssB.SetFlushInterval(0)
		if err := ssB.Persist(); err == nil {
			t.Fatalf("本地缺少磁盘已有的表时应被拒绝")
		} else if !isContentBlock(err) {
			t.Fatalf("错误类型应为内容回退拦截: %T %v", err, err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatalf("拦截后磁盘快照必须逐字节不变")
		}
	})

	t.Run("同版本同内容放行", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "snap.json")

		// 两个写者持有**完全相同**的表对象（同版本同内容）。
		tbl := newTestRouteTable(9, "same")
		ssA := NewSnapshotStore(NewMemory(), path, nil)
		ssA.Memory.SaveRouteTable(tbl)
		if err := ssA.Persist(); err != nil {
			t.Fatalf("写者 A 落盘失败: %v", err)
		}

		ssB := NewSnapshotStore(NewMemory(), path, nil)
		ssB.Memory.SaveRouteTable(tbl)
		// revision 高于磁盘 ⇒ 不触发 revision 判据；内容一致 ⇒ 不触发内容判据。
		if err := ssB.writeSnapshotAt(2, 2000); err != nil {
			t.Fatalf("同版本同内容应放行: %v", err)
		}
		if ssB.ContentBlocks() != 0 {
			t.Fatalf("放行路径不应产生内容拦截计数")
		}
	})
}

// TestSnapshotAutoRetryAbandonsOnNewerDiskContent **第三道防线**：
// 自动重试前**必须重读磁盘做内容比对**；若磁盘内容已被他人推进 ⇒ **放弃本次
// 写盘**（不重试、不推进基线），并产生**独立告警文案 + 独立计数**。
//
// 时序构造：写者 A 的首次写被 revision 判据拒绝（磁盘内容与 A 相同）⇒ 基线推进
// 并调度自动重试；重试窗口内写者 B 把磁盘内容推进到更新版本 ⇒ 重试必须**重读
// 磁盘**并被内容判据拦下 ⇒ 磁盘内容保持 B 的新版本（不被 A 的旧内容覆盖）。
func TestSnapshotAutoRetryAbandonsOnNewerDiskContent(t *testing.T) {
	// 拉长自动重试延迟 ⇒ 构造确定性时序（重试窗口足够长，便于窗口内写盘）。
	oldDelay := rollbackRetryDelay
	rollbackRetryDelay = 600 * time.Millisecond
	defer func() { rollbackRetryDelay = oldDelay }()

	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	// 写者 A 与 B 持有**完全相同**的表（⇒ 内容判据不触发，仅 revision 判据触发）。
	tbl := newTestRouteTable(3, "same")
	memA := NewMemory()
	memA.SaveRouteTable(tbl)
	var buf bytes.Buffer
	ssA := NewSnapshotStore(memA, path, log.New(&buf, "", 0))
	if err := ssA.Persist(); err != nil {
		t.Fatalf("写者 A 首次落盘失败: %v", err)
	}

	// 写者 B：把磁盘推进到 revision=9（内容与 A 相同）⇒ A 的下一次写被 revision 判据拒绝。
	memB := NewMemory()
	memB.SaveRouteTable(tbl)
	ssB := NewSnapshotStore(memB, path, nil)
	if err := ssB.writeSnapshotAt(9, 2000); err != nil {
		t.Fatalf("写者 B 落盘失败: %v", err)
	}

	// A 触发一次变更 ⇒ 同步写被拒（revision 判据）⇒ 基线推进 + 调度自动重试。
	ssA.SetFlushInterval(0)
	_ = ssA.Save(&route.RoutePrescription{PrescriptionID: "rx-1", Tenant: "t"})
	if ssA.RollbackRejects() == 0 {
		t.Fatalf("首次写应被 revision 判据拒绝")
	}
	if ssA.ContentBlocks() != 0 {
		t.Fatalf("首次写内容相同，不应触发内容判据")
	}

	// 重试窗口内：写者 B 把磁盘内容推进到更新版本（路由表 v9）。
	memB.SaveRouteTable(newTestRouteTable(9, "newer"))
	if err := ssB.Persist(); err != nil {
		t.Fatalf("写者 B 推进内容失败: %v", err)
	}
	diskBeforeRetry, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}

	// 等待自动重试触发（重试会重读磁盘 ⇒ 应被内容判据拦下 ⇒ 放弃写盘）。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ssA.ContentBlocks() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ssA.ContentBlocks() == 0 {
		t.Fatalf("自动重试前重读磁盘，应发现磁盘已更新并放弃写盘（ContentBlocks 应 >0）")
	}
	// 独立告警文案（与“防回退拒绝”不共用）。
	if !strings.Contains(buf.String(), "快照内容回退拦截") {
		t.Fatalf("应有独立的内容回退告警文案: %s", buf.String())
	}
	// 磁盘内容保持写者 B 的新版本（未被陈旧写者 A 覆盖）。
	diskAfterRetry, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读快照失败: %v", err)
	}
	if !bytes.Equal(diskAfterRetry, diskBeforeRetry) {
		t.Fatalf("放弃写盘后磁盘快照必须逐字节不变")
	}
	if got := readPayload(t, path).RouteTable.Version; got != 9 {
		t.Fatalf("磁盘路由表版本应为写者 B 的 9: got %d", got)
	}
	// 不推进基线：被内容拦截时不得推进（否则 A 会用更大的 revision 强行覆盖）。
	if got := readPayload(t, path).Revision; got != 10 {
		t.Fatalf("磁盘 revision 应为写者 B 写入的 10: got %d", got)
	}
}

// TestSnapshotSecondWriterBlockedByLock **写者串行化**：lockfile 生效时第二写者
// 被阻塞等待（超时后明确失败），**绝不覆盖**持锁者的快照。
func TestSnapshotSecondWriterBlockedByLock(t *testing.T) {
	// 缩短等待上限（构造确定性时序，不拖慢单测）。
	oldTimeout := lockWaitTimeout
	lockWaitTimeout = 200 * time.Millisecond
	defer func() { lockWaitTimeout = oldTimeout }()

	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	// 写者 A 先落一版（建立基线内容）。
	ssA := NewSnapshotStore(NewMemory(), path, nil)
	ssA.Memory.SaveRouteTable(newTestRouteTable(3, "a"))
	if err := ssA.Persist(); err != nil {
		t.Fatalf("写者 A 落盘失败: %v", err)
	}
	before, _ := os.ReadFile(path)

	// 预置"他人正在持锁"的锁文件：PID = 本进程（存活）⇒ 活锁。
	lockPath := path + lockSuffix
	lockBody := fmt.Sprintf("pid=%d\nacquired_at=%d\n", os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(lockPath, []byte(lockBody), 0o600); err != nil {
		t.Fatalf("写锁文件失败: %v", err)
	}

	// 写者 B：必须被阻塞并在超时后明确失败，**不得覆盖** A 的快照。
	var buf bytes.Buffer
	ssB := NewSnapshotStore(NewMemory(), path, log.New(&buf, "", 0))
	ssB.SetFlushInterval(0)
	err := ssB.Persist()
	if err == nil {
		t.Fatalf("持锁时第二写者应被拒绝（不得覆盖）")
	}
	if !strings.Contains(err.Error(), "写锁") {
		t.Fatalf("错误信息应说明写锁失败: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatalf("第二写者不得覆盖持锁者的快照")
	}
	// 锁文件仍在（持锁者未被踢掉）。
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("持锁者的锁文件不应被删除: %v", err)
	}
}

// TestSnapshotStaleLockTakenOverWithAlert **陈旧锁接管**：持锁进程已不存在且
// 超过阈值 ⇒ 接管并**告警**（说明发生过进程崩溃/强杀）。
func TestSnapshotStaleLockTakenOverWithAlert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	lockPath := path + lockSuffix

	// 预置陈旧锁：PID 不存在 + mtime 远超阈值。
	body := fmt.Sprintf("pid=%d\nacquired_at=%d\n", deadPIDForTest, time.Now().UnixNano())
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatalf("写锁文件失败: %v", err)
	}
	old := time.Now().Add(-2 * staleLockThreshold)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatalf("设置锁文件 mtime 失败: %v", err)
	}

	var buf bytes.Buffer
	ss := NewSnapshotStore(NewMemory(), path, log.New(&buf, "", 0))
	if err := ss.Persist(); err != nil {
		t.Fatalf("陈旧锁应被接管并成功写盘: %v", err)
	}
	if !strings.Contains(buf.String(), "接管陈旧快照锁") {
		t.Fatalf("接管陈旧锁必须告警: %s", buf.String())
	}
	// 写盘结束后锁文件应被释放。
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("写盘结束后锁文件应被释放（实际 err=%v）", err)
	}
}

// TestSnapshotLiveLockNotTakenOver **活锁不得误接管**：持锁进程仍存活时，
// 即使锁文件 mtime 已超过阈值，也**不得**接管（否则互斥失效 ⇒ 内容回退）。
func TestSnapshotLiveLockNotTakenOver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	lockPath := path + lockSuffix

	// 持锁 PID = 本进程（存活）⇒ 活锁；mtime 拉旧以排除"未达阈值"这一解释。
	body := fmt.Sprintf("pid=%d\nacquired_at=%d\n", os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(lockPath, []byte(body), 0o600); err != nil {
		t.Fatalf("写锁文件失败: %v", err)
	}
	old := time.Now().Add(-2 * staleLockThreshold)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatalf("设置锁文件 mtime 失败: %v", err)
	}

	var buf bytes.Buffer
	lock := newSnapshotLock(path, log.New(&buf, "", 0))
	lock.timeout = 200 * time.Millisecond
	if err := lock.acquire(); err == nil {
		t.Fatalf("活锁不得被接管（应等待超时后明确失败）")
	} else if !strings.Contains(err.Error(), "等待快照写锁超时") {
		t.Fatalf("错误信息应说明等待写锁超时: %v", err)
	}
	if strings.Contains(buf.String(), "接管陈旧快照锁") {
		t.Fatalf("活锁不得触发接管告警: %s", buf.String())
	}
	// 活锁文件不得被删除。
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("活锁文件不应被删除: %v", err)
	}
}

// TestSnapshotSingleWriterNoRegression **单写者路径零回归**：
//   - 正常写盘/读回一致；内容未变时重复写入放行；
//   - 锁文件在写盘结束后**不残留**；
//   - 快照关闭（path=""）时**完全不涉及锁**（零文件 I/O）。
func TestSnapshotSingleWriterNoRegression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")

	ss := NewSnapshotStore(NewMemory(), path, nil)
	ss.SetFlushInterval(0)
	fillSampleState(ss.Memory)
	ss.Memory.SaveRouteTable(newTestRouteTable(3, "only"))

	if err := ss.Persist(); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}
	p := readPayload(t, path)
	if p.RouteTable == nil || p.RouteTable.Version != 3 {
		t.Fatalf("路由表内容不符: %+v", p.RouteTable)
	}
	if len(p.Prescriptions) != 2 {
		t.Fatalf("处方数量不符: %d", len(p.Prescriptions))
	}
	// 锁文件不残留。
	if _, err := os.Stat(path + lockSuffix); !os.IsNotExist(err) {
		t.Fatalf("写盘结束后不应残留锁文件（实际 err=%v）", err)
	}
	// 内容未变 + revision 递增 ⇒ 放行（单写者常态）。
	if err := ss.writeSnapshotAt(2, 2000); err != nil {
		t.Fatalf("单写者重复写盘应放行: %v", err)
	}
	if ss.ContentBlocks() != 0 {
		t.Fatalf("单写者路径不应产生内容拦截")
	}
	if ss.RollbackRejects() != 0 {
		t.Fatalf("单写者路径不应产生 revision 拒绝")
	}

	// 禁用态：完全不涉及锁（不产生任何 .lock 文件）。
	ssOff := NewSnapshotStore(NewMemory(), "", nil)
	if err := ssOff.Persist(); err != nil {
		t.Fatalf("禁用态 Persist 应为 no-op: %v", err)
	}
	if ssOff.ContentBlocks() != 0 || ssOff.RollbackRejects() != 0 {
		t.Fatalf("禁用态不应有拦截计数")
	}
}

// TestSnapshotContentDomainsRegistered **防回归断言**：快照的每个持久化域
// 必须**要么参与内容判据、要么显式登记为"不参与"**（不允许默认漏判）。
func TestSnapshotContentDomainsRegistered(t *testing.T) {
	covered := map[string]bool{}
	for _, d := range contentDomains {
		covered[d.payload] = true
	}
	registered := map[string]bool{}
	for _, nv := range nonVersionedDomains {
		registered[nv.payload] = true
		if nv.Reason == "" {
			t.Fatalf("域 %s 登记为不参与内容判据时必须写明理由", nv.Name)
		}
	}
	for _, e := range snapshotCoverage {
		if e.Kind != coveragePersisted {
			continue
		}
		if !covered[e.Payload] && !registered[e.Payload] {
			t.Fatalf("持久化域 %s 既未参与内容判据，也未登记为“不参与内容判据”⇒ 漏判（防回退缺口）", e.Payload)
		}
	}
}
