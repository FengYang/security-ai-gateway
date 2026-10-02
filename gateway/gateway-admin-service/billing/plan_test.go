package billing

import (
	"strings"
	"testing"
)

// ---------- T-6.4 套餐与配额单元测试 ----------

func TestPlan_PutGet(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	p := &Plan{
		ID:            "pro",
		Name:          "专业版",
		MonthlyTokens: 500_000_000,
		Concurrency:   50,
		CacheTier:     "semantic",
		OverQuota:     "charge",
		PayMode:       "postpaid",
		ModelScopes:   []string{"gpt-4o", "claude"},
		ExtraLimits: []QuotaLimit{
			{Window: "minute", MaxTokens: 2_000_000},
		},
	}
	if err := s.Plans().PutPlan(p); err != nil {
		t.Fatalf("PutPlan err: %v", err)
	}

	got, err := s.Plans().GetPlan("pro")
	if err != nil {
		t.Fatalf("GetPlan err: %v", err)
	}
	if got == nil {
		t.Fatal("GetPlan returned nil")
	}
	if got.MonthlyTokens != 500_000_000 {
		t.Errorf("MonthlyTokens = %d, want 500000000", got.MonthlyTokens)
	}
	if got.OverQuota != "charge" {
		t.Errorf("OverQuota = %q, want charge", got.OverQuota)
	}
	if len(got.ModelScopes) != 2 {
		t.Errorf("ModelScopes len = %d, want 2", len(got.ModelScopes))
	}
	if len(got.ExtraLimits) != 1 || got.ExtraLimits[0].Window != "minute" {
		t.Errorf("ExtraLimits not round-tripped: %+v", got.ExtraLimits)
	}
}

func TestPlan_GetNotExist(t *testing.T) {
	// T-6.4-1: 套餐不存在返回 (nil, nil)
	s := openTestStore(t)
	defer s.Close()

	got, err := s.Plans().GetPlan("nonexistent")
	if err != nil {
		t.Fatalf("GetPlan err: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for nonexistent plan, got %+v", got)
	}
}

func TestPlan_BindAndResolve(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	if err := InitDefaultPlans(s); err != nil {
		t.Fatalf("InitDefaultPlans err: %v", err)
	}

	now := int64(1_700_000_000_000_000_000)
	// T-6.4-2: 绑定期望生效
	if err := s.Plans().Bind(Subscription{
		TenantID:    "t1",
		PlanID:      "basic",
		EffectiveAt: now - 1000,
		BoundBy:     "admin",
	}); err != nil {
		t.Fatalf("Bind err: %v", err)
	}

	p, err := s.Plans().Resolve("t1", now)
	if err != nil {
		t.Fatalf("Resolve err: %v", err)
	}
	if p == nil || p.ID != "basic" {
		t.Fatalf("Resolve = %+v, want basic", p)
	}
}

func TestPlan_ResolveBeforeEffective(t *testing.T) {
	// T-6.4-3: 绑定未生效（effective_at > now）应返回 nil
	s := openTestStore(t)
	defer s.Close()
	InitDefaultPlans(s)

	now := int64(1_700_000_000_000_000_000)
	s.Plans().Bind(Subscription{
		TenantID:    "t1",
		PlanID:      "pro",
		EffectiveAt: now + 1_000_000_000, // 未来生效
		BoundBy:     "admin",
	})

	p, err := s.Plans().Resolve("t1", now)
	if err != nil {
		t.Fatalf("Resolve err: %v", err)
	}
	if p != nil {
		t.Errorf("expected nil before effective time, got %+v", p)
	}
}

func TestPlan_ResolveLatestWins(t *testing.T) {
	// 多次绑定取最新生效的一条
	s := openTestStore(t)
	defer s.Close()
	InitDefaultPlans(s)

	now := int64(1_700_000_000_000_000_000)
	s.Plans().Bind(Subscription{TenantID: "t1", PlanID: "basic", EffectiveAt: now - 1000, BoundBy: "a"})
	s.Plans().Bind(Subscription{TenantID: "t1", PlanID: "pro", EffectiveAt: now - 500, BoundBy: "b"})

	p, _ := s.Plans().Resolve("t1", now)
	if p == nil || p.ID != "pro" {
		t.Errorf("latest subscription should win: got %+v, want pro", p)
	}
}

func TestPlan_ResolveExpired(t *testing.T) {
	// P-4: 过期订阅不生效
	s := openTestStore(t)
	defer s.Close()
	InitDefaultPlans(s)

	now := int64(1_700_000_000_000_000_000)
	s.Plans().Bind(Subscription{
		TenantID:    "t1",
		PlanID:      "basic",
		EffectiveAt: now - 2000,
		ExpiresAt:   now - 1000, // 已过期
		BoundBy:     "a",
	})

	p, _ := s.Plans().Resolve("t1", now)
	if p != nil {
		t.Errorf("expired subscription should not resolve, got %+v", p)
	}
}

func TestInitDefaultPlans_Idempotent(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	if err := InitDefaultPlans(s); err != nil {
		t.Fatalf("first init err: %v", err)
	}
	if err := InitDefaultPlans(s); err != nil {
		t.Fatalf("second init err: %v", err)
	}
	plans, _ := s.Plans().ListPlans()
	if len(plans) != 4 {
		t.Errorf("plans count = %d, want 4", len(plans))
	}
}

func TestValidatePlan(t *testing.T) {
	tests := []struct {
		name    string
		plan    *Plan
		wantErr bool
	}{
		{"valid", &Plan{ID: "x", Name: "X", CacheTier: "none", OverQuota: "reject", PayMode: "postpaid"}, false},
		{"no id", &Plan{Name: "X", PayMode: "postpaid"}, true},
		{"bad cache", &Plan{ID: "x", Name: "X", CacheTier: "bogus", OverQuota: "reject", PayMode: "postpaid"}, true},
		{"bad over_quota", &Plan{ID: "x", Name: "X", CacheTier: "none", OverQuota: "bogus", PayMode: "postpaid"}, true},
		{"bad pay_mode", &Plan{ID: "x", Name: "X", CacheTier: "none", OverQuota: "reject", PayMode: "prepaid"}, true},
		{"negative tokens", &Plan{ID: "x", Name: "X", MonthlyTokens: -1, CacheTier: "none", OverQuota: "reject", PayMode: "postpaid"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlan(tt.plan)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePlan err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---------- 配额编译测试 ----------

func TestQuotaCompiler_MonthLimit(t *testing.T) {
	// T-6.4-6: MonthlyTokens>0 编译出 window="month" 配额
	c := NewQuotaCompiler()
	p := &Plan{ID: "basic", MonthlyTokens: 50_000_000}
	updates, err := c.Compile("t1", p)
	if err != nil {
		t.Fatalf("Compile err: %v", err)
	}
	if len(updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(updates))
	}
	if updates[0].Tenant != "t1" {
		t.Errorf("tenant = %q, want t1", updates[0].Tenant)
	}
	if len(updates[0].Limits) != 1 {
		t.Fatalf("limits = %d, want 1", len(updates[0].Limits))
	}
	if updates[0].Limits[0].Window != "month" {
		t.Errorf("window = %q, want month", updates[0].Limits[0].Window)
	}
	if updates[0].Limits[0].MaxTokens != 50_000_000 {
		t.Errorf("max_tokens = %d, want 50000000", updates[0].Limits[0].MaxTokens)
	}
}

func TestQuotaCompiler_UnlimitedNoMonthLimit(t *testing.T) {
	// MonthlyTokens=0（不限量）→ 不发 month 配额
	c := NewQuotaCompiler()
	p := &Plan{ID: "enterprise", MonthlyTokens: 0}
	updates, _ := c.Compile("t1", p)
	if len(updates[0].Limits) != 0 {
		t.Errorf("unlimited plan should have no month limit, got %+v", updates[0].Limits)
	}
}

func TestQuotaCompiler_OrderNormalized(t *testing.T) {
	// 维度顺序规范化：minute < day < month
	c := NewQuotaCompiler()
	p := &Plan{
		ID:            "pro",
		MonthlyTokens: 500_000_000,
		ExtraLimits: []QuotaLimit{
			{Window: "day", MaxTokens: 30_000_000},
			{Window: "minute", MaxTokens: 2_000_000},
		},
	}
	updates, _ := c.Compile("t1", p)
	limits := updates[0].Limits
	if len(limits) != 3 {
		t.Fatalf("limits = %d, want 3", len(limits))
	}
	want := []string{"minute", "day", "month"}
	for i, w := range want {
		if limits[i].Window != w {
			t.Errorf("limits[%d].Window = %q, want %q", i, limits[i].Window, w)
		}
	}
}

func TestQuotaCompiler_Errors(t *testing.T) {
	c := NewQuotaCompiler()
	if _, err := c.Compile("", &Plan{ID: "x"}); err == nil {
		t.Error("expected error for empty tenant")
	}
	if _, err := c.Compile("t1", nil); err == nil {
		t.Error("expected error for nil plan")
	}
}

// ---------- R-29 交叉约束（charge 套餐须非免费档 + 单价非全 0） ----------

func TestValidatePlanPricing_R29(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	chargeFree := &Plan{ID: "c1", OverQuota: "charge", MonthlyTokens: 0}
	chargePaid := &Plan{ID: "c2", OverQuota: "charge", MonthlyTokens: 1000}
	rejectPlan := &Plan{ID: "r1", OverQuota: "reject", MonthlyTokens: 0}

	// 价格表含非 0 单价（testPriceTable）
	svc := newTestBillingService(s, nil)
	if err := svc.ValidatePlanPricing(chargeFree); err == nil || !strings.Contains(err.Error(), "R-29") {
		t.Errorf("免费档 charge 应拒（R-29），got %v", err)
	}
	if err := svc.ValidatePlanPricing(chargePaid); err != nil {
		t.Errorf("付费 charge 应通过，got %v", err)
	}
	if err := svc.ValidatePlanPricing(rejectPlan); err != nil {
		t.Errorf("非 charge 套餐应跳过 R-29，got %v", err)
	}

	// 全 0 价单价表 → charge 拒（防免费版产出金额账单）
	eng, _ := NewRatingEngineWithCache("half_up", concreteLedger(s))
	zeroSvc := NewBillingService(s, eng, NewStaticPriceTable(&PriceTable{Version: "v1"}), nil, s.Freezes())
	if err := zeroSvc.ValidatePlanPricing(chargePaid); err == nil || !strings.Contains(err.Error(), "R-29") {
		t.Errorf("全 0 价 charge 应拒（R-29），got %v", err)
	}
}
