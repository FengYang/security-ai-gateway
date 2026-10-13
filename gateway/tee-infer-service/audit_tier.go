package main

// P1-7 T5/T6（MOD4 分层存储与生命周期，§7.5 / §7.6）。
//
// T5：分层声明与确定性采样（tierOf / shouldSampleMiss）。
//   - tierOf：按事件时间戳与当前时刻差返回 hot|warm|cold。
//   - shouldSampleMiss：读取/导出侧未命中事件**确定性**降采样，算法 = SHA-256(requestID)%100<rate；
//     同 request_id 跨进程/重启结果一致（固定 SHA-256，与 profile 解耦，A3-08）。
//     **仅用于读取/导出侧**（§6.3 sample_miss_rate）；归档（温层）全量（D-16）。
//
// T6：归档器（archiveOnce）——把热层事件按分层迁移为只读副本。
//   - 温层全量（prev_hash 连续、audit-verify 可从创世全链校验，A3-04）；
//   - 冷层仅命中事件（必为不完整链，段自带 first_prev_hash 供窗口抽样）；
//   - 去重（三元组 instance_id,request_id,action，A3-23）、限速、退避重试、水位幂等；
//   - 写入经 tierSink 抽象（默认本地文件系统实现；对象存储为可插拔后端，待 T0 存储供给）。
//
// 服务**永不删除**热层数据（C-4）：仅复制为归档副本；源 WORM 由本地日分段移交（A3-15）在
// 取得归档成功回执后 unlink。

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// archiveMaxRatePerSec 归档限速（默认 ≤1000 事件/秒，不阻塞推理路径，§7.6）。
	archiveMaxRatePerSec = 1000
	// archiveMaxRetries 归档失败指数退避重试上限（§7.6）。
	archiveMaxRetries = 5
	// archiveBackoffBase 退避基数（最大间隔 5 分钟）。
	archiveBackoffBase = 2 * time.Second
	archiveBackoffMax  = 5 * time.Minute
)

// tierOf 按事件时间戳与当前时刻差返回层级（§7.5 T5）。
func (p RetentionPolicy) tierOf(tsNano, nowNano int64) string {
	day := int64(24 * 3600 * 1e9)
	ageDays := (nowNano - tsNano) / day
	switch {
	case ageDays <= int64(p.HotDays):
		return "hot"
	case ageDays <= int64(p.HotDays+p.WarmDays):
		return "warm"
	default:
		return "cold"
	}
}

// shouldSampleMiss 读取/导出侧未命中事件确定性降采样（§7.5 T5 / §3.4 R-采样-2）。
// rate<=0 ⇒ 不采样（合规档默认）；rate>=100 ⇒ 全采样。确定性：SHA-256(requestID)%100<rate。
// 调用方须保证仅对未命中事件调用（命中事件与配置/策略变更类 action 恒保留）。
func shouldSampleMiss(requestID string, rate int) bool {
	if rate <= 0 {
		return false
	}
	if rate >= 100 {
		return true
	}
	sum := sha256.Sum256([]byte(requestID))
	v := binary.BigEndian.Uint32(sum[:4])
	return int(v%100) < rate
}

// isHitEvent 判定命中事件（§3.4 注：result != ok 或 hit_policies 非空）。
func isHitEvent(e AuditEvent) bool {
	return e.Result != "ok" && e.Result != "" || e.HitPolicies != ""
}

// ---- T6 归档器 ----

// tierSink 归档写入后端抽象（便于插拔对象存储；默认本地文件系统实现，见 localFSArchiveSink）。
type tierSink interface {
	// WriteArchive 写一个归档对象（tenant/yyyy-mm-dd/part-<water>.jsonl），返回写入条数。
	// 已实现幂等：同 (tenant,date,part) 已存在则视为成功（返回 0，不重复写）。
	WriteArchive(ctx context.Context, tier, tenant, date, part string, events []AuditEvent) (int, error)
}

// localFSArchiveSink 本地文件系统归档后端（T6 默认可测实现；对象存储后端待 T0 供给）。
type localFSArchiveSink struct {
	root string // 归档根目录
	mu   sync.Mutex
}

func newLocalFSArchiveSink(root string) *localFSArchiveSink {
	return &localFSArchiveSink{root: root}
}

// WriteArchive 写 tenant/yyyy-mm-dd/part-<water>.jsonl（O_EXCL 语义：已存在即跳过）。
func (s *localFSArchiveSink) WriteArchive(_ context.Context, tier, tenant, date, part string, events []AuditEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	// 禁止用户输入直接参与路径（防路径穿越）：各段经 filepath.Clean + 基名校验。
	if !isSafeSegment(tenant) || !isSafeSegment(date) || !isSafeSegment(part) || !isSafeSegment(tier) {
		return 0, fmt.Errorf("archive: 非法的分段标识 %q/%q/%q/%q", tier, tenant, date, part)
	}
	dir := filepath.Join(s.root, tier, tenant, date)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	fp := filepath.Join(dir, "part-"+part+".jsonl")
	// O_EXCL：已存在 ⇒ 幂等跳过（视为上一次成功），不重复写。
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	for _, e := range events {
		line, _ := json.Marshal(e)
		if _, err := f.Write(append(line, '\n')); err != nil {
			return 0, err
		}
	}
	return len(events), nil
}

// isSafeSegment 校验归档路径分段（仅允许字母数字与有限标点，防路径穿越）。
func isSafeSegment(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// archiveOnce 执行一次归档（§7.6 T6）。
//   - 温层全量复制；冷层仅复制命中事件；
//   - 去重（三元组 instance_id,request_id,action，保留最早一条，A3-23）；
//   - 限速 ≤1000/s、失败指数退避重试 ≤5；
//   - 水位幂等：已归档事件（EventID 集合）与 part 序号持久化，重入只补增量（A3-24）。
//     服务永不删除热层数据（C-4）：仅复制为归档副本；源 WORM 由本地日分段移交（A3-15）
//     在取得归档成功回执后 unlink（T0 职责，本函数不负责删除源）。
//
// 返回 (归档条数, 去重条数, error)。error 非 nil 仅表示本次归档失败（计入指标，后续补归档）。
func (s *teeServer) archiveOnce(ctx context.Context, now int64) (int, int, error) {
	if s.archiveSink == nil {
		return 0, 0, nil // 未配置归档后端（待 T0 存储供给），本次跳過
	}
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()

	s.audit.mu.Lock()
	snapshot := make([]AuditEvent, len(s.audit.events))
	copy(snapshot, s.audit.events)
	s.audit.mu.Unlock()

	// 水位与已归档集合：重入跳过已归档事件，仅补增量（A3-24）。
	prog := s.loadArchiveProgress()
	archivedSet := make(map[string]struct{}, len(prog.Archived))
	for _, id := range prog.Archived {
		archivedSet[id] = struct{}{}
	}
	water := prog.Water

	// 限速令牌桶（简单计数窗口）。
	limiter := newRateLimiter(archiveMaxRatePerSec)
	seen := map[[3]string]bool{} // (instance_id,request_id,action) 去重
	byPart := map[string][]AuditEvent{}
	byPartIDs := map[string][]string{} // 与 byPart 一一对应，回写已归档集合
	deduped := 0
	policy := s.retentionSnapshot() // T9：并发安全读取分层声明

	for _, e := range snapshot {
		key := [3]string{e.InstanceID, e.RequestID, e.Action}
		if _, done := archivedSet[e.EventID]; done {
			// 已归档：仍标记 dedup 键，避免同一三元组的后续重复被误当新事件归档。
			seen[key] = true
			continue
		}
		if seen[key] {
			deduped++
			if auditMetrics != nil {
				auditMetrics.incAuditDuplicateRequest()
			}
			continue
		}
		seen[key] = true
		tier := policy.tierOf(e.Timestamp, now)
		if tier == "cold" && !isHitEvent(e) {
			// 冷层仅保留命中事件（未命中不保留，W-16/R-16：回溯窗口缺口须客户书面认可）。
			continue
		}
		if tier == "hot" {
			continue // 仍在热层，不归档
		}
		date := time.Unix(0, e.Timestamp).UTC().Format("2006-01-02")
		part := fmt.Sprintf("%s-%d", date, water)
		k := tier + "/" + e.TenantID + "/" + date + "/" + part
		byPart[k] = append(byPart[k], e)
		byPartIDs[k] = append(byPartIDs[k], e.EventID)
		limiter.take()
	}

	archived := 0
	wroteIDs := []string{}
	for k, evs := range byPart {
		wids := byPartIDs[k]
		tier, tenant, date, part := splitArchiveKey(k)
		var n int
		var err error
		for attempt := 0; attempt <= archiveMaxRetries; attempt++ {
			n, err = s.archiveSink.WriteArchive(ctx, tier, tenant, date, part, evs)
			if err == nil {
				break
			}
			if auditMetrics != nil {
				auditMetrics.incAuditArchiveFailure()
			}
			backoff := archiveBackoffBase << uint(attempt)
			if backoff > archiveBackoffMax {
				backoff = archiveBackoffMax
			}
			select {
			case <-ctx.Done():
				return archived, deduped, ctx.Err()
			case <-time.After(backoff):
			}
		}
		if err != nil {
			return archived, deduped, fmt.Errorf("archive: 分区 %s 写入失败（已重试 %d 次）: %w", k, archiveMaxRetries, err)
		}
		archived += n
		wroteIDs = append(wroteIDs, wids...)
	}

	if archived > 0 {
		if auditMetrics != nil {
			auditMetrics.incAuditRecordsTier("warm", int64(archived))
		}
		// 持久化水位与已归档集合（重入幂等，A3-24）。
		newArchived := make([]string, 0, len(prog.Archived)+len(wroteIDs))
		newArchived = append(newArchived, prog.Archived...)
		newArchived = append(newArchived, wroteIDs...)
		s.saveArchiveProgress(archiveProgress{Water: water + 1, Archived: newArchived})
	}
	return archived, deduped, nil
}

// splitArchiveKey 解析 "tier/tenant/date/part" 键（各分段已校验不含 '/'）。
func splitArchiveKey(k string) (tier, tenant, date, part string) {
	parts := strings.SplitN(k, "/", 4)
	if len(parts) == 4 {
		return parts[0], parts[1], parts[2], parts[3]
	}
	return "", "", "", ""
}

// archiveProgress 归档水位与已归档事件集合（重入幂等，A3-24）。
//   - Water：当前 part 序号（按 (tier,tenant,date) 维度单调递增，用于同段多分片、O_EXCL 幂等，避免重入碰撞）。
//   - Archived：已成功复制的事件 EventID 集合；重入时跳过，只补增量。
//     服务永不删除热层（C-4）；源 WORM 日分段移交 unlink 属 T0 职责。
type archiveProgress struct {
	Water    int64    `json:"water"`
	Archived []string `json:"archived"`
}

// loadArchiveProgress 读取归档进度（文件不存在 ⇒ 空，从头归档）。持久化于 archiveRoot/.audit-progress.json。
func (s *teeServer) loadArchiveProgress() archiveProgress {
	if s.archiveRoot == "" {
		return archiveProgress{}
	}
	raw, err := os.ReadFile(filepath.Join(s.archiveRoot, ".audit-progress.json"))
	if err != nil {
		return archiveProgress{}
	}
	var p archiveProgress
	if err := json.Unmarshal(raw, &p); err != nil {
		return archiveProgress{}
	}
	return p
}

// saveArchiveProgress 持久化归档进度（水位续写 + 已归档集合，重入只补增量）。
func (s *teeServer) saveArchiveProgress(p archiveProgress) {
	if s.archiveRoot == "" {
		return
	}
	if err := os.MkdirAll(s.archiveRoot, 0o700); err != nil {
		return
	}
	raw, _ := json.Marshal(p)
	_ = os.WriteFile(filepath.Join(s.archiveRoot, ".audit-progress.json"), raw, 0o600)
}

// rateLimiter 简单令牌桶（按秒限速，不阻塞太久）。
type rateLimiter struct {
	mu       sync.Mutex
	limit    int
	allow    int
	window   time.Time
	windowNs int64
}

func newRateLimiter(perSec int) *rateLimiter {
	return &rateLimiter{limit: perSec, windowNs: int64(time.Second)}
}

// take 取一个令牌；超过窗口速率则短暂休眠（上限受调用方上下文控制）。
func (r *rateLimiter) take() {
	r.mu.Lock()
	now := time.Now()
	if now.Sub(r.window) >= time.Duration(r.windowNs) {
		r.window = now
		r.allow = r.limit
	}
	if r.allow <= 0 {
		r.mu.Unlock()
		time.Sleep(time.Duration(r.windowNs) / time.Duration(r.limit))
		return
	}
	r.allow--
	r.mu.Unlock()
}
