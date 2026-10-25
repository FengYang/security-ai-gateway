package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// T-2.1 集群注册表（模型 / 存储 / 状态机）的单测。

// openTestClusterStore 打开内存 sqlite 注册表。
func openTestClusterStore(t *testing.T) *sqlClusterStore {
	t.Helper()
	st, err := OpenClusterStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("打开集群注册表失败: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st.(*sqlClusterStore)
}

// 样例注册记录。
func sampleCluster(id string) *ClusterRecord {
	return &ClusterRecord{
		ID:       id,
		Name:     "集群 " + id,
		Endpoint: "https://" + id + ".example.com",
		Form:     ClusterFormSameCity,
		Capacity: ClusterCapacity{RPS: 100, Concurrency: 200},
	}
}

func TestClusterRegistry_RegisterGetList(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)

	for _, id := range []string{"cluster-b", "cluster-a"} {
		if err := st.Register(ctx, sampleCluster(id)); err != nil {
			t.Fatalf("注册 %s 失败: %v", id, err)
		}
	}
	rec, err := st.Get(ctx, "cluster-a")
	if err != nil {
		t.Fatalf("读取 cluster-a 失败: %v", err)
	}
	if rec.Name != "集群 cluster-a" || rec.Form != ClusterFormSameCity {
		t.Errorf("记录内容不符：%+v", rec)
	}
	if rec.Capacity.RPS != 100 || rec.Capacity.Concurrency != 200 {
		t.Errorf("容量画像不符：%+v", rec.Capacity)
	}
	if rec.Status != ClusterStatusActive {
		t.Errorf("注册后状态 = %q, want active", rec.Status)
	}
	if rec.RegisteredAt.IsZero() || rec.UpdatedAt.IsZero() {
		t.Errorf("注册/更新时间未落库：%+v", rec)
	}
	// 列表按 ID 升序
	list, err := st.List(ctx)
	if err != nil {
		t.Fatalf("列出集群失败: %v", err)
	}
	if len(list) != 2 || list[0].ID != "cluster-a" || list[1].ID != "cluster-b" {
		t.Fatalf("列表顺序/数量不符：%+v", list)
	}
	// 不存在的集群
	if _, err := st.Get(ctx, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("不存在集群 err = %v, want sql.ErrNoRows", err)
	}
	// 重复注册走 upsert（幂等更新，不报错）
	upd := sampleCluster("cluster-a")
	upd.Name = "改名"
	if err := st.Register(ctx, upd); err != nil {
		t.Fatalf("重复注册失败: %v", err)
	}
	rec, _ = st.Get(ctx, "cluster-a")
	if rec.Name != "改名" {
		t.Errorf("重复注册未更新名称：%q", rec.Name)
	}
}

func TestClusterRegistry_Validate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ClusterRecord)
		want string
	}{
		{"ID 为空", func(r *ClusterRecord) { r.ID = "  " }, "ID 为空"},
		{"ID 过长", func(r *ClusterRecord) { r.ID = string(make([]byte, 65)) }, "ID 过长"},
		{"名称为空", func(r *ClusterRecord) { r.Name = "" }, "名称为空"},
		{"端点为空", func(r *ClusterRecord) { r.Endpoint = "" }, "端点为空"},
		{"端点非 http", func(r *ClusterRecord) { r.Endpoint = "ftp://x/y" }, "端点非法"},
		{"端点无主机", func(r *ClusterRecord) { r.Endpoint = "https://" }, "端点非法"},
		{"形态非法", func(r *ClusterRecord) { r.Form = "境外" }, "形态非法"},
		{"容量为负", func(r *ClusterRecord) { r.Capacity.RPS = -1 }, "容量画像不得为负"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := sampleCluster("c1")
			tc.mut(rec)
			if err := ValidateClusterRecord(rec); err == nil {
				t.Fatal("期望校验失败")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息 = %q，未包含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestClusterRegistry_Heartbeat(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	if err := st.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	now := time.Now()
	rec, err := st.Heartbeat(ctx, "c1", "v-42", now)
	if err != nil {
		t.Fatalf("心跳失败: %v", err)
	}
	if rec.Applied != "v-42" {
		t.Errorf("配置版本 = %q, want v-42", rec.Applied)
	}
	if rec.MissedHeartbeats != 0 {
		t.Errorf("缺失计数 = %d, want 0", rec.MissedHeartbeats)
	}
	if rec.LastHeartbeatAt.Unix() != now.Unix() {
		t.Errorf("最近心跳 = %v, want %v", rec.LastHeartbeatAt, now)
	}
	if rec.Status != ClusterStatusActive {
		t.Errorf("心跳后状态 = %q, want active", rec.Status)
	}
	// 空版本不覆盖既有版本
	rec, err = st.Heartbeat(ctx, "c1", "", now.Add(time.Second))
	if err != nil {
		t.Fatalf("心跳失败: %v", err)
	}
	if rec.Applied != "v-42" {
		t.Errorf("空版本心跳覆盖了配置版本：%q", rec.Applied)
	}
	// 不存在的集群
	if _, err := st.Heartbeat(ctx, "nope", "v1", now); err == nil {
		t.Error("不存在集群心跳应报错")
	}
}

// 已摘除集群拒绝心跳（不得被"复活"）。
func TestClusterRegistry_HeartbeatRejectedAfterRemoval(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	if err := st.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if err := st.SetStatus(ctx, "c1", ClusterStatusRemoved, time.Now()); err != nil {
		t.Fatalf("设置状态失败: %v", err)
	}
	if _, err := st.Heartbeat(ctx, "c1", "v1", time.Now()); err == nil {
		t.Fatal("已摘除集群心跳应被拒绝")
	}
	rec, err := st.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if rec.Status != ClusterStatusRemoved {
		t.Errorf("状态被心跳改写 = %q, want removed", rec.Status)
	}
}

func TestEvaluateClusterStatus(t *testing.T) {
	cfg := DefaultClusterHeartbeatConfig()
	base := time.Now().Add(-10 * time.Minute)
	cases := []struct {
		name string
		rec  *ClusterRecord
		now  time.Time
		want ClusterStatus
	}{
		{
			name: "刚心跳过 → active",
			rec:  &ClusterRecord{Status: ClusterStatusActive, LastHeartbeatAt: base.Add(9 * time.Minute)},
			now:  base.Add(10 * time.Minute),
			want: ClusterStatusActive,
		},
		{
			name: "缺失 3 个周期 → degraded",
			rec:  &ClusterRecord{Status: ClusterStatusActive, LastHeartbeatAt: base},
			now:  base.Add(3 * 30 * time.Second),
			want: ClusterStatusDegraded,
		},
		{
			name: "缺失 10 个周期 → unreachable",
			rec:  &ClusterRecord{Status: ClusterStatusDegraded, LastHeartbeatAt: base},
			now:  base.Add(10 * 30 * time.Second),
			want: ClusterStatusUnreachable,
		},
		{
			name: "恢复心跳 → active",
			rec:  &ClusterRecord{Status: ClusterStatusUnreachable, LastHeartbeatAt: base},
			now:  base.Add(1 * time.Second),
			want: ClusterStatusActive,
		},
		{
			name: "removed 为终态",
			rec:  &ClusterRecord{Status: ClusterStatusRemoved, LastHeartbeatAt: base},
			now:  base.Add(10 * time.Minute),
			want: ClusterStatusRemoved,
		},
		{
			name: "quarantined 为终态",
			rec:  &ClusterRecord{Status: ClusterStatusQuarantined, LastHeartbeatAt: base},
			now:  base.Add(10 * time.Minute),
			want: ClusterStatusQuarantined,
		},
		{
			name: "时钟回拨 → unreachable（保守）",
			rec:  &ClusterRecord{Status: ClusterStatusActive, LastHeartbeatAt: base},
			now:  base.Add(-time.Minute),
			want: ClusterStatusUnreachable,
		},
		{
			name: "从未心跳且无注册时间 → unreachable",
			rec:  &ClusterRecord{Status: ClusterStatusActive},
			now:  time.Now(),
			want: ClusterStatusUnreachable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateClusterStatus(tc.rec, tc.now, cfg); got != tc.want {
				t.Errorf("状态 = %q, want %q", got, tc.want)
			}
		})
	}
}

// RecomputeStatuses 应把超时的集群推进到 degraded / unreachable，并返回跃迁集合。
func TestClusterRegistry_RecomputeStatuses(t *testing.T) {
	ctx := context.Background()
	st := openTestClusterStore(t)
	if err := st.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	// 人为把最近心跳推到很久以前
	old := time.Now().Add(-10 * time.Minute)
	if _, err := st.db.ExecContext(ctx, `UPDATE clusters SET last_heartbeat_at = ? WHERE id = ?`, old.Unix(), "c1"); err != nil {
		t.Fatalf("造数失败: %v", err)
	}
	changed, err := st.RecomputeStatuses(ctx, time.Now())
	if err != nil {
		t.Fatalf("重算状态失败: %v", err)
	}
	if len(changed) != 1 || changed[0].ID != "c1" {
		t.Fatalf("状态跃迁集合 = %+v, want 仅 c1", changed)
	}
	if changed[0].Status != ClusterStatusUnreachable {
		t.Errorf("状态 = %q, want unreachable", changed[0].Status)
	}
	rec, _ := st.Get(ctx, "c1")
	if rec.Status != ClusterStatusUnreachable {
		t.Errorf("库中状态 = %q, want unreachable", rec.Status)
	}
	// 心跳恢复后重算回到 active
	if _, err := st.Heartbeat(ctx, "c1", "v1", time.Now()); err != nil {
		t.Fatalf("心跳失败: %v", err)
	}
	changed, err = st.RecomputeStatuses(ctx, time.Now())
	if err != nil {
		t.Fatalf("重算状态失败: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("恢复后仍有跃迁 = %+v", changed)
	}
	rec, _ = st.Get(ctx, "c1")
	if rec.Status != ClusterStatusActive {
		t.Errorf("恢复后状态 = %q, want active", rec.Status)
	}
}

// PG 门控集成用例：无 ADMIN_TEST_PG_DSN 时 skip（不伪装通过）。
func TestClusterRegistryPGGate(t *testing.T) {
	dsn := os.Getenv("ADMIN_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 ADMIN_TEST_PG_DSN，跳过 PostgreSQL 集成用例")
	}
	ctx := context.Background()
	st, err := OpenClusterStore(sqlutil.Postgres, dsn)
	if err != nil {
		t.Fatalf("打开 PG 注册表失败: %v", err)
	}
	defer st.Close()
	id := "pg-gate-" + time.Now().Format("150405")
	if err := st.Register(ctx, sampleCluster(id)); err != nil {
		t.Fatalf("PG 注册失败: %v", err)
	}
	rec, err := st.Get(ctx, id)
	if err != nil {
		t.Fatalf("PG 读取失败: %v", err)
	}
	if rec.Status != ClusterStatusActive || rec.Name == "" {
		t.Errorf("PG 记录不符：%+v", rec)
	}
	if _, err := st.Heartbeat(ctx, id, "pg-v1", time.Now()); err != nil {
		t.Fatalf("PG 心跳失败: %v", err)
	}
	rec, _ = st.Get(ctx, id)
	if rec.Applied != "pg-v1" {
		t.Errorf("PG 配置版本 = %q, want pg-v1", rec.Applied)
	}
	// 清理
	if err := st.SetStatus(ctx, id, ClusterStatusRemoved, time.Now()); err != nil {
		t.Fatalf("PG 置摘除失败: %v", err)
	}
}
