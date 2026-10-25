package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ---------- P2-4 T-1.8：billing cluster_id 维度（R-4/A5(6)）计费打标验收用例（C7(7)）----------
//
// 覆盖矩阵：
//  1. 打标写入与读回（账本 + 账单）
//  2. 按 cluster 过滤（含"仅未打标"）
//  3. 按 cluster 聚合正确（用量/金额）
//  4. 既有数据（无 cluster_id）聚合不丢不重
//  5. 链一致性不被打标破坏（Verify() 仍通过 + 旧条目哈希可复算不变）

// newClusterStore 打开一个内存账本（测试用）。
func newClusterStore(t *testing.T) Store {
	t.Helper()
	s, err := OpenSQLiteStore(":memory:", false)
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// appendEntries 在单事务内追加一批条目。
func appendEntries(t *testing.T, s Store, entries []LedgerEntry) int {
	t.Helper()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	added, _, err := s.Ledger().Append(tx, entries)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("Append: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return added
}

// clusterEntry 构造一条带集群打标的账本条目。
func clusterEntry(clusterID, tenant, model, day, eventKey string, tokensIn, tokensOut int64) LedgerEntry {
	return LedgerEntry{
		TenantID:  tenant,
		ModelKey:  model,
		Day:       day,
		ClusterID: clusterID,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
		Requests:  1,
		Source:    "pull",
		PriceVer:  "v1",
		EventKey:  eventKey,
		CreatedAt: 1,
	}
}

// ---------- ① 打标写入与读回 ----------

func TestClusterID_LedgerTagWriteAndReadBack(t *testing.T) {
	s := newClusterStore(t)
	added := appendEntries(t, s, []LedgerEntry{
		clusterEntry("cluster-a", "t1", "m1", "2026-10-01", "k-1", 100, 50),
		clusterEntry("cluster-b", "t1", "m1", "2026-10-01", "k-2", 200, 80),
		clusterEntry("", "t1", "m1", "2026-10-01", "k-3", 300, 90), // 未打标
	})
	if added != 3 {
		t.Fatalf("expected 3 added, got %d", added)
	}

	got, err := s.Ledger().Range(LedgerQuery{TenantID: "t1", DayFrom: "2026-10-01", DayTo: "2026-10-01"})
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	want := []string{"cluster-a", "cluster-b", ""}
	for i, e := range got {
		if e.ClusterID != want[i] {
			t.Errorf("entry seq=%d event=%s: ClusterID = %q, want %q", e.Seq, e.EventKey, e.ClusterID, want[i])
		}
	}
}

func TestClusterID_BillTagWriteAndReadBack(t *testing.T) {
	s := newClusterStore(t)
	b := &Bill{
		ID: "daily-t1-2026-10-01", TenantID: "t1", Kind: BillKindDaily,
		Period: "2026-10-01", ClusterID: "cluster-a", Total: 1234, Currency: "CNY",
		Status: BillStatusIssued, GeneratedAt: 1,
	}
	if err := s.Bills().Put(b); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Bills().Get(b.ID)
	if err != nil || got == nil {
		t.Fatalf("Get: %v / nil", err)
	}
	if got.ClusterID != "cluster-a" {
		t.Errorf("bill ClusterID = %q, want %q", got.ClusterID, "cluster-a")
	}
	list, err := s.Bills().List(BillQuery{TenantID: "t1"})
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v / %d", err, len(list))
	}
	if list[0].ClusterID != "cluster-a" {
		t.Errorf("listed bill ClusterID = %q, want %q", list[0].ClusterID, "cluster-a")
	}
}

// ---------- ② 按 cluster 过滤 ----------

func TestClusterID_FilterByCluster(t *testing.T) {
	s := newClusterStore(t)
	appendEntries(t, s, []LedgerEntry{
		clusterEntry("cluster-a", "t1", "m1", "2026-10-01", "k-1", 100, 50),
		clusterEntry("cluster-a", "t1", "m2", "2026-10-01", "k-2", 10, 5),
		clusterEntry("cluster-b", "t1", "m1", "2026-10-01", "k-3", 200, 80),
		clusterEntry("", "t1", "m1", "2026-10-01", "k-4", 300, 90),
	})

	// 精确过滤
	got, err := s.Ledger().Range(LedgerQuery{TenantID: "t1", ClusterID: "cluster-a"})
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("cluster-a: expected 2, got %d", len(got))
	}
	for _, e := range got {
		if e.ClusterID != "cluster-a" {
			t.Errorf("filter leak: got ClusterID %q", e.ClusterID)
		}
	}

	// 仅未打标
	unset, err := s.Ledger().Range(LedgerQuery{TenantID: "t1", ClusterUnset: true})
	if err != nil {
		t.Fatalf("Range unset: %v", err)
	}
	if len(unset) != 1 || unset[0].EventKey != "k-4" {
		t.Fatalf("ClusterUnset: expected 1 (k-4), got %d", len(unset))
	}

	// 不过滤（默认既有行为）
	all, err := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Range all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("no filter: expected 4, got %d", len(all))
	}

	// 账单过滤（period 各不相同，避开 UNIQUE(tenant,kind,period)）
	for i, cid := range []string{"cluster-a", "cluster-b", ""} {
		bb := &Bill{
			ID: "daily-t1-2026-10-0" + string(rune('1'+i)), TenantID: "t1", Kind: BillKindDaily,
			Period: "2026-10-0" + string(rune('1'+i)), ClusterID: cid, Currency: "CNY",
			Status: BillStatusIssued, GeneratedAt: int64(i + 1),
		}
		if err := s.Bills().Put(bb); err != nil {
			t.Fatalf("Put %q: %v", cid, err)
		}
	}
	bl, err := s.Bills().List(BillQuery{TenantID: "t1", ClusterID: "cluster-a"})
	if err != nil || len(bl) != 1 || bl[0].ClusterID != "cluster-a" {
		t.Fatalf("bill filter cluster-a: %v / %d", err, len(bl))
	}
	bu, err := s.Bills().List(BillQuery{TenantID: "t1", ClusterUnset: true})
	if err != nil || len(bu) != 1 || bu[0].ClusterID != "" {
		t.Fatalf("bill filter unset: %v / %d", err, len(bu))
	}

	// 账单金额按集群汇总
	bs, ok := s.Bills().(*sqliteBillStore)
	if !ok {
		t.Fatalf("unexpected bill store type %T", s.Bills())
	}
	totals, err := bs.SumByCluster(BillQuery{TenantID: "t1"})
	if err != nil {
		t.Fatalf("SumByCluster(bills): %v", err)
	}
	if len(totals) != 3 {
		t.Fatalf("expected 3 bill cluster groups, got %d: %+v", len(totals), totals)
	}
	// 升序："" / cluster-a / cluster-b，各 1 张
	for i, wantID := range []string{"", "cluster-a", "cluster-b"} {
		if totals[i].ClusterID != wantID {
			t.Errorf("bill group[%d] = %q, want %q", i, totals[i].ClusterID, wantID)
		}
		if totals[i].Bills != 1 {
			t.Errorf("bill group[%d] Bills = %d, want 1", i, totals[i].Bills)
		}
	}
}

// ---------- ③ 按 cluster 聚合正确 ----------

func TestClusterID_AggregateByCluster(t *testing.T) {
	s := newClusterStore(t)
	// 模型用单价表内的键（cheap-model / gpt-4o），以便服务层计价路径可跑通。
	appendEntries(t, s, []LedgerEntry{
		clusterEntry("cluster-a", "t1", "cheap-model", "2026-10-01", "k-1", 100, 50),
		clusterEntry("cluster-a", "t1", "gpt-4o", "2026-10-01", "k-2", 10, 5),
		clusterEntry("cluster-b", "t1", "cheap-model", "2026-10-01", "k-3", 200, 80),
		clusterEntry("", "t1", "cheap-model", "2026-10-01", "k-4", 300, 90),
	})

	ledger := concreteLedger(s)
	got, err := ledger.SumByCluster("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("SumByCluster: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 clusters (a/b/''), got %d: %+v", len(got), got)
	}
	// 升序："" < "cluster-a" < "cluster-b"
	wantOrder := []string{"", "cluster-a", "cluster-b"}
	wantIn := []int64{300, 110, 200}
	wantOut := []int64{90, 55, 80}
	wantEntries := []int64{1, 2, 1}
	for i, cu := range got {
		if cu.ClusterID != wantOrder[i] {
			t.Errorf("group[%d] ClusterID = %q, want %q", i, cu.ClusterID, wantOrder[i])
		}
		if cu.TokensIn != wantIn[i] {
			t.Errorf("group[%d] TokensIn = %d, want %d", i, cu.TokensIn, wantIn[i])
		}
		if cu.TokensOut != wantOut[i] {
			t.Errorf("group[%d] TokensOut = %d, want %d", i, cu.TokensOut, wantOut[i])
		}
		if cu.Entries != wantEntries[i] {
			t.Errorf("group[%d] Entries = %d, want %d", i, cu.Entries, wantEntries[i])
		}
		if cu.Requests != wantEntries[i] {
			t.Errorf("group[%d] Requests = %d, want %d", i, cu.Requests, wantEntries[i])
		}
	}

	// 服务层：金额维度（逐集群独立计价）
	svc := newTestBillingService(s, nil)
	rep, err := svc.ClusterUsageReport("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("ClusterUsageReport: %v", err)
	}
	if len(rep) != 3 {
		t.Fatalf("report: expected 3 groups, got %d", len(rep))
	}
	var sumIn int64
	for _, cu := range rep {
		sumIn += cu.TokensIn
		if cu.Amount < 0 {
			t.Errorf("cluster %q: negative amount %d", cu.ClusterID, cu.Amount)
		}
	}
	if sumIn != 610 { // 300 + 110 + 200
		t.Errorf("report TokensIn sum = %d, want 610（不丢不重）", sumIn)
	}
}

// ---------- ④ 既有数据（无 cluster_id）聚合不丢不重 ----------

func TestClusterID_LegacyDataNotLostOrDuplicated(t *testing.T) {
	s := newClusterStore(t)
	// 1) 先写入"历史"未打标数据（模拟打标功能上线前的既有账本）
	legacy := []LedgerEntry{
		clusterEntry("", "t1", "m1", "2026-10-01", "legacy-1", 100, 40),
		clusterEntry("", "t1", "m2", "2026-10-01", "legacy-2", 60, 20),
	}
	appendEntries(t, s, legacy)
	// 2) 再写入打标数据
	appendEntries(t, s, []LedgerEntry{
		clusterEntry("cluster-a", "t1", "m1", "2026-10-01", "new-1", 7, 3),
	})

	ledger := concreteLedger(s)
	got, err := ledger.SumByCluster("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("SumByCluster: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 groups ('' + cluster-a), got %d", len(got))
	}
	// 未打标组必须原样保留（不丢）
	if got[0].ClusterID != "" {
		t.Fatalf("group[0] = %q, want ''（既有数据组）", got[0].ClusterID)
	}
	if got[0].TokensIn != 160 || got[0].TokensOut != 60 || got[0].Entries != 2 {
		t.Errorf("legacy group = %+v, want TokensIn=160 TokensOut=60 Entries=2", got[0])
	}
	// 打标组
	if got[1].ClusterID != "cluster-a" || got[1].TokensIn != 7 || got[1].Entries != 1 {
		t.Errorf("tagged group = %+v, want cluster-a/7/1", got[1])
	}

	// 全量合计必须与账本 SumNet 一致（不重）
	var sumIn, sumOut int64
	for _, cu := range got {
		sumIn += cu.TokensIn
		sumOut += cu.TokensOut
	}
	net, err := ledger.SumNet("t1", "2026-10-01", "2026-10-01")
	if err != nil {
		t.Fatalf("SumNet: %v", err)
	}
	if net.TokensIn != sumIn || net.TokensOut != sumOut {
		t.Errorf("cluster 聚合合计 (%d,%d) != 账本净量 (%d,%d)", sumIn, sumOut, net.TokensIn, net.TokensOut)
	}
}

// ---------- ⑤ 链一致性不被打标破坏 ----------

// TestComputeEntryHash_ClusterIDNotInHashDomain 断言 cluster_id 不在哈希域：
// 仅 cluster_id 不同的两条条目，哈希必须完全相同（否则既有链必断）。
func TestComputeEntryHash_ClusterIDNotInHashDomain(t *testing.T) {
	base := clusterEntry("", "t1", "m1", "2026-10-01", "k-1", 100, 50)
	tagged := base
	tagged.ClusterID = "cluster-a"
	other := base
	other.ClusterID = "cluster-b"

	hBase, err := ComputeEntryHash(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}
	hTagged, err := ComputeEntryHash(tagged)
	if err != nil {
		t.Fatalf("hash tagged: %v", err)
	}
	hOther, err := ComputeEntryHash(other)
	if err != nil {
		t.Fatalf("hash other: %v", err)
	}
	if hBase != hTagged || hBase != hOther {
		t.Fatalf("cluster_id 进入了哈希域（§7.6 违规）：base=%s a=%s b=%s", hBase, hTagged, hOther)
	}
	// 反向哨兵：改一个**在域内**的字段必须改变哈希（证明哈希函数确实敏感于载荷）
	sentinel := base
	sentinel.TokensIn = 101
	hSentinel, err := ComputeEntryHash(sentinel)
	if err != nil {
		t.Fatalf("hash sentinel: %v", err)
	}
	if hSentinel == hBase {
		t.Fatalf("哨兵失败：改动 tokens_in 未改变哈希，哈希函数可能被短路")
	}
}

// TestClusterID_ChainIntegrityPreserved 断言：打标写入不破坏链，且旧条目哈希可复算不变。
func TestClusterID_ChainIntegrityPreserved(t *testing.T) {
	s := newClusterStore(t)

	// 1) 先建一条"历史"链（未打标）
	appendEntries(t, s, []LedgerEntry{
		clusterEntry("", "t1", "m1", "2026-10-01", "legacy-1", 100, 40),
		clusterEntry("", "t1", "m2", "2026-10-01", "legacy-2", 60, 20),
	})
	before, err := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(before) != 2 {
		t.Fatalf("expected 2 legacy entries, got %d", len(before))
	}
	if broken, err := s.Ledger().Verify(); err != nil || broken != -1 {
		t.Fatalf("legacy chain broken at %d: %v", broken, err)
	}

	// 2) 再写入带 cluster_id 的条目
	appendEntries(t, s, []LedgerEntry{
		clusterEntry("cluster-a", "t1", "m1", "2026-10-01", "new-1", 7, 3),
		clusterEntry("cluster-b", "t1", "m1", "2026-10-02", "new-2", 8, 4),
	})

	// 3) 旧条目哈希必须逐字节不变（cluster_id 未回填到历史行 ⇒ 链未重算）
	after, err := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Range after: %v", err)
	}
	if len(after) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(after))
	}
	for i := range before {
		if after[i].Seq != before[i].Seq ||
			after[i].EntryHash != before[i].EntryHash ||
			after[i].PrevHash != before[i].PrevHash {
			t.Errorf("历史条目 seq=%d 被改动：hash %s→%s prev %s→%s",
				before[i].Seq, before[i].EntryHash, after[i].EntryHash,
				before[i].PrevHash, after[i].PrevHash)
		}
		// 4) 旧条目哈希可复算（不依赖 cluster_id）
		recomputed, err := ComputeEntryHash(after[i])
		if err != nil {
			t.Fatalf("recompute seq=%d: %v", after[i].Seq, err)
		}
		if recomputed != after[i].EntryHash {
			t.Errorf("旧条目 seq=%d 哈希复算不一致：%s != %s", after[i].Seq, recomputed, after[i].EntryHash)
		}
	}

	// 5) 打标后整链仍完好
	if broken, err := s.Ledger().Verify(); err != nil || broken != -1 {
		t.Fatalf("打标后链断裂 at seq=%d: %v", broken, err)
	}
	// 6) 新条目（带标）自身也可复算
	for _, e := range after[2:] {
		recomputed, err := ComputeEntryHash(e)
		if err != nil {
			t.Fatalf("recompute tagged seq=%d: %v", e.Seq, err)
		}
		if recomputed != e.EntryHash {
			t.Errorf("打标条目 seq=%d 哈希复算不一致", e.Seq)
		}
		if e.ClusterID == "" {
			t.Errorf("打标条目 seq=%d cluster_id 为空（读写回失败）", e.Seq)
		}
	}
}

// ---------- ⑥ 签名域不变（账单打标不使既有签名失效）----------

func TestClusterID_BillSignatureDomainUnchanged(t *testing.T) {
	s := newClusterStore(t)
	signer := NewBillSigner([]byte("cluster-dim-test-key"))
	svc := newTestBillingService(s, nil)
	svc.SetSigner(signer)

	b := &Bill{
		ID: "daily-t1-2026-10-01", TenantID: "t1", Kind: BillKindDaily,
		Period: "2026-10-01", Currency: "CNY", Status: BillStatusIssued,
		Total: 5000, GeneratedAt: 1,
		Items: []BillItem{{ModelKey: "m1", StandardTokens: 10, TokensIn: 6, TokensOut: 4, Amount: 5000}},
	}
	sigUntagged := signer.Sign(b)
	if sigUntagged == "" {
		t.Fatal("空签名")
	}
	b.Sig = sigUntagged
	if !signer.Verify(b) {
		t.Fatal("未打标账单验签失败")
	}

	// 打标后签名必须不变（cluster_id 不在签名域）
	b.ClusterID = "cluster-a"
	if got := signer.Sign(b); got != sigUntagged {
		t.Fatalf("cluster_id 进入了账单签名域（§7.2/§7.6 违规）：%s != %s", got, sigUntagged)
	}
	// 打标后原签名仍可验（既有账单补标不失效）
	if !signer.Verify(b) {
		t.Fatal("打标后原签名验签失败 ⇒ 既有账单补标会使签名失效")
	}
}

// ---------- ⑦ 默认零行为变化（JSON / 迁移）----------

// TestClusterID_EmptyTagKeepsJSONCompatible 断言未打标时 JSON 不含 cluster_id（既有断言不受影响）。
func TestClusterID_EmptyTagKeepsJSONCompatible(t *testing.T) {
	e := clusterEntry("", "t1", "m1", "2026-10-01", "k-1", 1, 1)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "cluster_id") {
		t.Errorf("未打标条目序列化出现 cluster_id（omitempty 失效）：%s", raw)
	}
	tagged := e
	tagged.ClusterID = "cluster-a"
	rawTagged, err := json.Marshal(tagged)
	if err != nil {
		t.Fatalf("marshal tagged: %v", err)
	}
	if !strings.Contains(string(rawTagged), `"cluster_id":"cluster-a"`) {
		t.Errorf("打标条目序列化缺少 cluster_id：%s", rawTagged)
	}

	// 账单同理
	rawBill, err := json.Marshal(&Bill{ID: "b1", TenantID: "t1"})
	if err != nil {
		t.Fatalf("marshal bill: %v", err)
	}
	if strings.Contains(string(rawBill), "cluster_id") {
		t.Errorf("未打标账单序列化出现 cluster_id：%s", rawBill)
	}
}

// TestClusterID_LegacySchemaMigration 断言既有库（无 cluster_id 列）可平滑迁移并可写读打标数据。
func TestClusterID_LegacySchemaMigration(t *testing.T) {
	dir := t.TempDir()
	dsn := dir + "/legacy-billing.db"

	// 手工构造"打标上线前"的老库结构（billing_ledger 无 cluster_id、bills 无 cluster_id）
	db, err := openLegacyBillingDB(dsn)
	if err != nil {
		t.Fatalf("openLegacyBillingDB: %v", err)
	}
	if _, err := db.Exec(legacyLedgerDDL); err != nil {
		t.Fatalf("legacy ledger ddl: %v", err)
	}
	if _, err := db.Exec(legacyBillsDDL); err != nil {
		t.Fatalf("legacy bills ddl: %v", err)
	}
	if _, err := db.Exec(legacyLedgerHeadDDL); err != nil {
		t.Fatalf("legacy head ddl: %v", err)
	}

	// 铺一条"历史"账本行（哈希按冻结口径算好，使迁移后 Verify() 仍能通过）
	legacyEntry := LedgerEntry{
		Seq: 1, TenantID: "t1", ModelKey: "m1", Day: "2026-10-01",
		TokensIn: 1, TokensOut: 1, Requests: 1, Source: "pull", PriceVer: "v1",
		EventKey: "legacy-0", PrevHash: "", CreatedAt: 1,
	}
	legacyHash, err := ComputeEntryHash(legacyEntry)
	if err != nil {
		t.Fatalf("ComputeEntryHash(legacy): %v", err)
	}
	if _, err := db.Exec(`INSERT INTO billing_ledger
		(seq, tenant_id, model_key, day, tokens_in, tokens_out, requests, retry_toks,
		 std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, hash_alg, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?, ?, ?, ?, '', ?)`,
		legacyEntry.Seq, legacyEntry.TenantID, legacyEntry.ModelKey, legacyEntry.Day,
		legacyEntry.TokensIn, legacyEntry.TokensOut, legacyEntry.Requests,
		legacyEntry.Source, legacyEntry.PriceVer, legacyEntry.EventKey,
		legacyEntry.PrevHash, legacyHash, legacyEntry.CreatedAt); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO billing_ledger_head (id, seq, entry_hash, updated_at) VALUES (1, ?, ?, ?)`,
		legacyEntry.Seq, legacyHash, legacyEntry.CreatedAt); err != nil {
		t.Fatalf("seed legacy head: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	// 用新代码打开老库 ⇒ 迁移补列，且既有行保持 cluster_id = ''
	s, err := OpenSQLiteStore(dsn, false)
	if err != nil {
		t.Fatalf("OpenSQLiteStore(migrated): %v", err)
	}
	defer s.Close()

	appendEntries(t, s, []LedgerEntry{clusterEntry("cluster-a", "t1", "m1", "2026-10-01", "k-1", 5, 2)})
	got, err := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	// 老库预置 1 行 + 新增 1 行
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].ClusterID != "" {
		t.Errorf("既有行 cluster_id = %q, want ''（迁移默认空串）", got[0].ClusterID)
	}
	if got[1].ClusterID != "cluster-a" {
		t.Errorf("新增行 cluster_id = %q, want cluster-a", got[1].ClusterID)
	}
	if broken, err := s.Ledger().Verify(); err != nil || broken != -1 {
		t.Fatalf("迁移后链断裂 at %d: %v", broken, err)
	}
	// 账单侧补列同样可用
	if err := s.Bills().Put(&Bill{
		ID: "daily-t1-2026-10-01", TenantID: "t1", Kind: BillKindDaily,
		Period: "2026-10-01", ClusterID: "cluster-a", Currency: "CNY",
		Status: BillStatusIssued, GeneratedAt: 1,
	}); err != nil {
		t.Fatalf("Put on migrated bills: %v", err)
	}
	bb, err := s.Bills().Get("daily-t1-2026-10-01")
	if err != nil || bb == nil || bb.ClusterID != "cluster-a" {
		t.Fatalf("Get on migrated bills: %v / %+v", err, bb)
	}
}

// ---------- ⑧ 入账路径打标透传 ----------

func TestClusterID_AggToEntriesPropagatesTag(t *testing.T) {
	win := &UsageWindow{
		FromNs: 1, ToNs: 2, Source: "pull", EventKey: "w-1", ClusterID: "cluster-a", Day: "2026-10-01",
		Tenants: map[string]*TenantAgg{
			"t1": {
				TokensIn: 10, TokensOut: 5, Requests: 1,
				ByModel: map[string]*ModelAgg{"m1": {TokensIn: 10, TokensOut: 5, Requests: 1}},
			},
		},
	}
	entries := AggToEntries(win)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ClusterID != "cluster-a" {
		t.Errorf("AggToEntries 未透传 cluster_id：%q", entries[0].ClusterID)
	}

	// 未打标（默认）⇒ 空，行为与改动前一致
	win.ClusterID = ""
	entries = AggToEntries(win)
	if len(entries) != 1 || entries[0].ClusterID != "" {
		t.Errorf("未打标窗口应产出空 cluster_id，got %+v", entries)
	}

	// push 侧透传
	pw := pushEventToWindow(PushEvent{
		EventID: "e-1", TenantID: "t1", Model: "m1", TokensIn: 3, TokensOut: 1,
		Result: pushResultOK, TS: "2026-10-01T00:00:00Z", ClusterID: "cluster-b",
	})
	if pw == nil {
		t.Fatal("pushEventToWindow returned nil")
	}
	if pw.ClusterID != "cluster-b" {
		t.Errorf("push 未透传 cluster_id：%q", pw.ClusterID)
	}
	pe := AggToEntries(pw)
	if len(pe) != 1 || pe[0].ClusterID != "cluster-b" {
		t.Errorf("push 条目未打标：%+v", pe)
	}
}

// ---------- ⑨ 拉取源打标（不改 NewTEEPullSource 签名）----------

func TestClusterID_PullSourceTagging(t *testing.T) {
	src := NewTEEPullSource("http://127.0.0.1:1", "", time.Second)
	if !TagPullSourceCluster(src, "cluster-a") {
		t.Fatal("TagPullSourceCluster 未生效（可选接口未命中）")
	}
	// 对端不可达 ⇒ Pull 报错；改用一个可达的桩来验打标透传。
	if _, err := src.Pull(context.Background(), 0, int64(time.Second)); err == nil {
		t.Log("pull 意外成功（不应发生）")
	}

	// 用本地 httptest 服务端验证：响应体 → UsageWindow.ClusterID
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"from":"1","to":"2","tenants":{"t1":{"tokens_in_net":10,"tokens_out_net":5,"requests":1,"by_model":{"cheap-model":{"tokens_in_net":10,"tokens_out_net":5,"requests":1}}}}}`))
	}))
	defer srv.Close()

	src2 := NewTEEPullSource(srv.URL, "tok", time.Second)
	if TagPullSourceCluster(src2, "cluster-b") != true {
		t.Fatal("TagPullSourceCluster(src2)")
	}
	win, err := src2.Pull(context.Background(), int64(time.Second), 2*int64(time.Second))
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if win == nil {
		t.Fatal("Pull returned nil window")
	}
	if win.ClusterID != "cluster-b" {
		t.Errorf("pull 窗口 cluster_id = %q, want cluster-b", win.ClusterID)
	}
	if gotPath == "" {
		t.Error("服务端未收到请求")
	}
	// 未标注 ⇒ 空（既有行为）
	src3 := NewTEEPullSource(srv.URL, "", time.Second)
	win3, err := src3.Pull(context.Background(), int64(time.Second), 2*int64(time.Second))
	if err != nil {
		t.Fatalf("Pull(untagged): %v", err)
	}
	if win3.ClusterID != "" {
		t.Errorf("未标注拉取源 cluster_id = %q, want ''", win3.ClusterID)
	}
	// 端到端：打标窗口入账 → 账本带 cluster_id 且链完好
	s := newClusterStore(t)
	svc := newTestBillingService(s, nil)
	svc.SetMeteringSource(src2, 0, SyncModePull)
	if _, err := svc.IngestWindow(context.Background(), win, SyncModePull); err != nil {
		t.Fatalf("IngestWindow: %v", err)
	}
	got, err := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if err != nil || len(got) != 1 {
		t.Fatalf("Range: %v / %d", err, len(got))
	}
	if got[0].ClusterID != "cluster-b" {
		t.Errorf("入账后 cluster_id = %q, want cluster-b", got[0].ClusterID)
	}
	if broken, err := s.Ledger().Verify(); err != nil || broken != -1 {
		t.Fatalf("打标入账后链断裂 at %d: %v", broken, err)
	}
}

// ---------- 迁移测试用：打标上线前的老库结构 ----------

// legacyLedgerDDL 老版 billing_ledger（无 cluster_id）。
const legacyLedgerDDL = `
CREATE TABLE IF NOT EXISTS billing_ledger (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT    NOT NULL,
  model_key   TEXT    NOT NULL,
  day         TEXT    NOT NULL,
  tokens_in   INTEGER NOT NULL DEFAULT 0,
  tokens_out  INTEGER NOT NULL DEFAULT 0,
  requests    INTEGER NOT NULL DEFAULT 0,
  retry_toks  INTEGER NOT NULL DEFAULT 0,
  std_in      INTEGER NOT NULL DEFAULT 0,
  std_out     INTEGER NOT NULL DEFAULT 0,
  source      TEXT    NOT NULL,
  price_ver   TEXT    NOT NULL DEFAULT '',
  event_key   TEXT    NOT NULL,
  prev_hash   TEXT    NOT NULL,
  entry_hash  TEXT    NOT NULL,
  hash_alg    TEXT    NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  UNIQUE(event_key)
);
`

// legacyLedgerHeadDDL 老版链尾表（无 poll_end_ns，一并验证 ★ BUG-001 迁移）。
const legacyLedgerHeadDDL = `
CREATE TABLE IF NOT EXISTS billing_ledger_head (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  seq         INTEGER NOT NULL DEFAULT 0,
  entry_hash  TEXT    NOT NULL DEFAULT '',
  updated_at  INTEGER NOT NULL DEFAULT 0
);
`

// legacyBillsDDL 老版 bills（无 cluster_id）。
const legacyBillsDDL = `
CREATE TABLE IF NOT EXISTS bills (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  kind          TEXT NOT NULL,
  period        TEXT NOT NULL,
  total         INTEGER NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'CNY',
  price_version TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL,
  sig           TEXT NOT NULL DEFAULT '',
  ledger_head   TEXT NOT NULL,
  audit_head    TEXT NOT NULL,
  generated_at  INTEGER NOT NULL,
  UNIQUE(tenant_id, kind, period)
);
`

// openLegacyBillingDB 打开待迁移的老库（供手工铺老结构）。
func openLegacyBillingDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}
