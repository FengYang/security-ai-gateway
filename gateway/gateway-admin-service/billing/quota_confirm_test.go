package billing

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------- 配额回读确认（P-1/M6，§6.4.1 2c；T-6.4-6） ----------

// fakeQuotaReader 脚本化回读器：按序返回预设序列（越界则重复最后一个）。
type fakeQuotaReader struct {
	seq  [][]QuotaLimit
	errs []error
	i    int
}

func (f *fakeQuotaReader) GetQuota(context.Context, string) ([]QuotaLimit, error) {
	idx := f.i
	if idx >= len(f.seq) {
		idx = len(f.seq) - 1
	}
	f.i++
	if idx < len(f.errs) && f.errs[idx] != nil {
		return nil, f.errs[idx]
	}
	return f.seq[idx], nil
}

func wantMonthlyQuota(n int64) []QuotaUpdate {
	return []QuotaUpdate{{Tenant: "t1", Limits: []QuotaLimit{{Window: "month", MaxTokens: n}}}}
}

// 立即命中 → nil
func TestConfirmQuotaApplied_Immediate(t *testing.T) {
	rd := &fakeQuotaReader{seq: [][]QuotaLimit{{{Window: "month", MaxTokens: 100}}}}
	if err := ConfirmQuotaApplied(context.Background(), rd, "t1", wantMonthlyQuota(100),
		time.Second, 10*time.Millisecond); err != nil {
		t.Fatalf("应立即确认: %v", err)
	}
}

// T-6.4-6：POST 2xx 但回读未生效 → 继续轮询，延迟命中后返回 nil
func TestConfirmQuotaApplied_Delayed(t *testing.T) {
	rd := &fakeQuotaReader{seq: [][]QuotaLimit{{{}}, {{}}, {{Window: "month", MaxTokens: 100}}}}
	if err := ConfirmQuotaApplied(context.Background(), rd, "t1", wantMonthlyQuota(100),
		time.Second, 5*time.Millisecond); err != nil {
		t.Fatalf("延迟命中应确认: %v", err)
	}
}

// 单次读取失败不致命：后续成功即确认
func TestConfirmQuotaApplied_RecoversFromReadError(t *testing.T) {
	rd := &fakeQuotaReader{
		seq:  [][]QuotaLimit{{}, {{Window: "month", MaxTokens: 100}}},
		errs: []error{errors.New("boom"), nil},
	}
	if err := ConfirmQuotaApplied(context.Background(), rd, "t1", wantMonthlyQuota(100),
		time.Second, 5*time.Millisecond); err != nil {
		t.Fatalf("读失败后恢复应确认: %v", err)
	}
}

// 始终不符 → 超时报错（M6 违约）
func TestConfirmQuotaApplied_Timeout(t *testing.T) {
	rd := &fakeQuotaReader{seq: [][]QuotaLimit{{{Window: "month", MaxTokens: 1}}}}
	if err := ConfirmQuotaApplied(context.Background(), rd, "t1", wantMonthlyQuota(100),
		30*time.Millisecond, 5*time.Millisecond); err == nil {
		t.Fatal("应超时报错（M6 违约）")
	}
}

// 期望为空（套餐不限量）→ 视为已确认
func TestConfirmQuotaApplied_EmptyWant(t *testing.T) {
	rd := &fakeQuotaReader{seq: [][]QuotaLimit{{}}}
	if err := ConfirmQuotaApplied(context.Background(), rd, "t1", nil, time.Second, time.Millisecond); err != nil {
		t.Fatalf("期望为空应立即确认: %v", err)
	}
}

// nil reader → 报错（不 panic）
func TestConfirmQuotaApplied_NilReader(t *testing.T) {
	if err := ConfirmQuotaApplied(context.Background(), nil, "t1", wantMonthlyQuota(1),
		time.Second, time.Millisecond); err == nil {
		t.Fatal("nil reader 应报错")
	}
}

// 超限集合比对：仅覆盖期望的子集即可（多余维度不影响）
func TestQuotaLimitsCovered(t *testing.T) {
	want := []QuotaLimit{{Window: "month", MaxTokens: 100}}
	got := []QuotaLimit{{Window: "minute", MaxTokens: 5}, {Window: "month", MaxTokens: 100}}
	if !quotaLimitsCovered(want, got) {
		t.Error("子集覆盖应判定为已生效")
	}
	if quotaLimitsCovered(want, []QuotaLimit{{Window: "month", MaxTokens: 99}}) {
		t.Error("值不符不应判定为已生效")
	}
}

// 指标 #13（M6）可渲染
func TestObserveQuotaApply_Renders(t *testing.T) {
	ObserveQuotaApply(1.25)
	if !strings.Contains(renderDefaultMetrics(), "gateway_admin_billing_quota_apply_duration_seconds_count") {
		t.Error("M6 直方图未渲染（#13）")
	}
}
