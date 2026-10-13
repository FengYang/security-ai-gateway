package main

// audit_tier_test.go — P1-7 T5/T6（分层存储与生命周期）验收 V-3/V-4/§7.5/§7.6。
//   T5：tierOf 分层、shouldSampleMiss 确定性、validateRetentionPolicy fail-closed。
//   T6：archiveOnce 温层全量、冷层仅命中、三元组去重、水位幂等、热层不归档。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dayNano = int64(24 * 3600 * 1e9)

func TestT5ValidateRetentionPolicy(t *testing.T) {
	ok := RetentionPolicy{HotDays: 7, WarmDays: 30, ColdDays: 180, SampleMissRate: 0}
	if err := validateRetentionPolicy(ok); err != nil {
		t.Fatalf("合法声明应过：%v", err)
	}
	cases := []RetentionPolicy{
		{HotDays: 0, WarmDays: 30, ColdDays: 180},                    // Hot<1
		{HotDays: 7, WarmDays: 7, ColdDays: 180},                     // Warm<=Hot
		{HotDays: 7, WarmDays: 30, ColdDays: 20},                     // Cold<Warm
		{HotDays: 1, WarmDays: 2, ColdDays: 3},                       // 合计<180
		{HotDays: 7, WarmDays: 30, ColdDays: 180, SampleMissRate: -1}, // rate<0
		{HotDays: 7, WarmDays: 30, ColdDays: 180, SampleMissRate: 101}, // rate>100
	}
	for i, c := range cases {
		if err := validateRetentionPolicy(c); err == nil {
			t.Fatalf("用例 %d 应被拒绝：%+v", i, c)
		}
	}
}

func TestT5TierOf(t *testing.T) {
	p := RetentionPolicy{HotDays: 7, WarmDays: 30, ColdDays: 180}
	now := int64(1700000000) * 1_000_000_000
	cases := []struct {
		ageDays int64
		want    string
	}{
		{0, "hot"}, {7, "hot"}, {8, "warm"}, {37, "warm"}, {38, "cold"}, {1000, "cold"},
	}
	for _, c := range cases {
		got := p.tierOf(now-int64(c.ageDays)*dayNano, now)
		if got != c.want {
			t.Fatalf("ageDays=%d 应为 %s，得 %s", c.ageDays, c.want, got)
		}
	}
}

func TestT5ShouldSampleMissDeterministic(t *testing.T) {
	// rate=0 ⇒ 不采样；rate>=100 ⇒ 全采样
	if shouldSampleMiss("req-x", 0) {
		t.Fatal("rate=0 不应采样")
	}
	if !shouldSampleMiss("req-x", 100) {
		t.Fatal("rate>=100 应全采样")
	}
	// 同一 request_id 多次结果一致（确定性）
	const id = "req-deterministic-001"
	a := shouldSampleMiss(id, 50)
	b := shouldSampleMiss(id, 50)
	if a != b {
		t.Fatal("同 request_id 两次采样结果应一致")
	}
	// 10% 在 10k 样本上偏差 ≤ ±1%（≈100±100）
	const rate = 10
	const n = 10000
	count := 0
	for i := 0; i < n; i++ {
		if shouldSampleMiss(fmt.Sprintf("req-%d", i), rate) {
			count++
		}
	}
	if count < rate*n/100-100 || count > rate*n/100+100 {
		t.Fatalf("10%% 采样偏差过大：%d/10000", count)
	}
	// 两次运行集合相同（确定性，跨进程/重启）
	set1 := map[string]bool{}
	set2 := map[string]bool{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("req-%d", i)
		if shouldSampleMiss(id, rate) {
			set1[id] = true
		}
		if shouldSampleMiss(id, rate) {
			set2[id] = true
		}
	}
	if len(set1) != len(set2) {
		t.Fatalf("两次运行采样集合大小应相同：%d vs %d", len(set1), len(set2))
	}
	for k := range set1 {
		if !set2[k] {
			t.Fatal("两次运行采样集合应完全相同")
		}
	}
}

// buildArchiveChain 构造一条链（prev_hash 自洽），specs 指定各事件年龄与是否命中。
func buildArchiveChain(t *testing.T, now int64, specs []struct {
	ageDays int
	hit     bool
	reqID   string
}) *auditChain {
	t.Helper()
	c := newAuditChain()
	prev := ""
	for i, sp := range specs {
		e := baseEvent()
		e.EventID = fmt.Sprintf("evt-%d", i)
		e.RequestID = sp.reqID
		if sp.reqID == "" {
			e.RequestID = fmt.Sprintf("req-%d", i)
		}
		e.Timestamp = now - int64(sp.ageDays)*dayNano
		e.PrevHash = prev
		e.Result = "ok"
		if sp.hit {
			e.Result = "guardrail_pii"
			e.HitPolicies = "guardrail_pii"
		}
		h, err := e.hashWithErr()
		if err != nil {
			t.Fatal(err)
		}
		prev = h
		c.events = append(c.events, e)
	}
	c.lastHex = prev
	return c
}

func countArchiveLines(root string) (int, error) {
	n := 0
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(p, ".jsonl") {
			raw, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(line) != "" {
					n++
				}
			}
		}
		return nil
	})
	return n, err
}

func TestT6ArchiveOnce(t *testing.T) {
	now := int64(1700000000) * 1_000_000_000
	specs := []struct {
		ageDays int
		hit     bool
		reqID   string
	}{
		{1, false, "r-hot"},    // hot：不归档
		{10, false, "r-warm1"}, // warm miss：归档（全量）
		{10, true, "r-warm2"},  // warm hit：归档
		{200, false, "r-cold1"}, // cold miss：跳过
		{200, true, "r-cold2"},  // cold hit：归档
		{10, false, "r-warm1"}, // 重复（同 req_id,action）→ 去重
	}
	c := buildArchiveChain(t, now, specs)
	s := &teeServer{
		audit:     c,
		retention: RetentionPolicy{HotDays: 7, WarmDays: 30, ColdDays: 180},
	}
	root := t.TempDir()
	s.archiveRoot = root
	s.archiveSink = newLocalFSArchiveSink(root)

	archived, deduped, err := s.archiveOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("archiveOnce 失败：%v", err)
	}
	// 期望归档 = warm(2) + cold hit(1) = 3；去重 = 1
	if archived != 3 {
		t.Fatalf("归档条数应为 3，得 %d", archived)
	}
	if deduped != 1 {
		t.Fatalf("去重条数应为 1，得 %d", deduped)
	}
	total, err := countArchiveLines(root)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("归档文件总行数应为 3，得 %d", total)
	}
	// 重入：同水位已存在 ⇒ 增量补 0（幂等，不重复写）
	archived2, _, err := s.archiveOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("archiveOnce 重入失败：%v", err)
	}
	if archived2 != 0 {
		t.Fatalf("重入应增量补 0，得 %d", archived2)
	}
	total2, _ := countArchiveLines(root)
	if total2 != 3 {
		t.Fatalf("重入后归档文件总行数应仍为 3，得 %d", total2)
	}
}
