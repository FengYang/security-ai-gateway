package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

// newSubscriptionHandler 构造启用 billing（含默认套餐）的测试 handler。
func newSubscriptionHandler(t *testing.T) (*tenantHandler, billing.Store) {
	t.Helper()
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, st := newTenantBillingTestHandler(t)
	if err := billing.InitDefaultPlans(st); err != nil {
		t.Fatalf("初始化默认套餐失败: %v", err)
	}
	h.billing = bh
	return h, st
}

// ---------- 套餐列表 ----------

func TestTenantPlans_BillingDisabled_503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil) // billing nil
	w := httptest.NewRecorder()
	h.handleTenantPlans(w, tenantRequest("GET", tenantPlansPath, "", "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 未启用应 503, got=%d", w.Code)
	}
}

func TestTenantPlans_List(t *testing.T) {
	h, _ := newSubscriptionHandler(t)
	w := httptest.NewRecorder()
	h.handleTenantPlans(w, tenantRequest("GET", tenantPlansPath, "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var resp struct {
		Plans []tenantPlanView `json:"plans"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Plans) != 4 {
		t.Fatalf("应有 4 档套餐, got=%d", len(resp.Plans))
	}
	// 金额列不出现（C-10）
	body := w.Body.String()
	for _, forbidden := range []string{`"price`, `"amount`, `"total`, `"currency`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("响应不应含金额字段 %s: %s", forbidden, body)
		}
	}
	// 顺序不做假设：按 ID 查 free
	var freePlan *tenantPlanView
	for i := range resp.Plans {
		if resp.Plans[i].ID == "free" {
			freePlan = &resp.Plans[i]
		}
	}
	if freePlan == nil || freePlan.MonthlyTokens != 1000000 || freePlan.Concurrency != 5 {
		t.Errorf("free 套餐字段不对: %+v", resp.Plans)
	}
}

// ---------- 当前订阅 ----------

func TestTenantSubscription_NoSubscription(t *testing.T) {
	h, _ := newSubscriptionHandler(t)
	w := httptest.NewRecorder()
	h.handleTenantSubscription(w, tenantRequest("GET", tenantSubscriptionPath, "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tenant"] != "t_1" {
		t.Errorf("tenant 不对: %v", resp["tenant"])
	}
	if resp["subscription"] != nil {
		t.Errorf("无订阅应为 null, got=%v", resp["subscription"])
	}
}

func TestTenantSubscription_WithSubscription(t *testing.T) {
	h, st := newSubscriptionHandler(t)
	if err := st.Plans().Bind(billing.Subscription{
		TenantID: "t_1", PlanID: "pro", EffectiveAt: 1, BoundBy: "admin", BoundAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.handleTenantSubscription(w, tenantRequest("GET", tenantSubscriptionPath, "", "t_1", "u1"))
	var resp struct {
		Subscription *billing.Subscription `json:"subscription"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Subscription == nil || resp.Subscription.PlanID != "pro" {
		t.Errorf("应返回 pro 订阅: %+v", resp.Subscription)
	}
}

// ---------- 升级/降级请求 ----------

func TestSubscriptionUpgrade_Upgrade_Success(t *testing.T) {
	h, _ := newSubscriptionHandler(t)
	// 无订阅 → 当前视为 free；请求 pro → upgrade
	w := httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath+"/upgrade", `{"plan_id":"pro"}`, "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "pending" || resp["request_id"] == "" {
		t.Errorf("响应不对: %+v", resp)
	}
	// 待确认单落库
	reqs, err := h.store.ListSubscriptionRequests("t_1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Direction != "upgrade" || reqs[0].ToPlan != "pro" || reqs[0].FromPlan != "free" {
		t.Errorf("待确认单不对: %+v", reqs)
	}
}

func TestSubscriptionUpgrade_Downgrade(t *testing.T) {
	h, st := newSubscriptionHandler(t)
	if err := st.Plans().Bind(billing.Subscription{
		TenantID: "t_1", PlanID: "pro", EffectiveAt: 1, BoundBy: "admin", BoundAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath+"/upgrade", `{"plan_id":"basic"}`, "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	reqs, _ := h.store.ListSubscriptionRequests("t_1", 10)
	if len(reqs) != 1 || reqs[0].Direction != "downgrade" {
		t.Errorf("应识别为降级: %+v", reqs)
	}
}

func TestSubscriptionUpgrade_UnknownPlan_400(t *testing.T) {
	h, _ := newSubscriptionHandler(t)
	w := httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath+"/upgrade", `{"plan_id":"nonexistent"}`, "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("未知套餐应 400, got=%d", w.Code)
	}
}

func TestSubscriptionUpgrade_SamePlan_400(t *testing.T) {
	h, st := newSubscriptionHandler(t)
	if err := st.Plans().Bind(billing.Subscription{
		TenantID: "t_1", PlanID: "pro", EffectiveAt: 1, BoundBy: "admin", BoundAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath+"/upgrade", `{"plan_id":"pro"}`, "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("同套餐应 400, got=%d", w.Code)
	}
}

func TestSubscriptionUpgrade_MissingPlanID_400(t *testing.T) {
	h, _ := newSubscriptionHandler(t)
	w := httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath+"/upgrade", `{}`, "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("缺 plan_id 应 400, got=%d", w.Code)
	}
}

func TestSubscriptionUpgrade_BillingDisabled_503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath+"/upgrade", `{"plan_id":"pro"}`, "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 未启用应 503, got=%d", w.Code)
	}
}

func TestPlanRank(t *testing.T) {
	if !(planRank("free") < planRank("basic") && planRank("basic") < planRank("pro") && planRank("pro") < planRank("enterprise")) {
		t.Error("档位排序应递增")
	}
	if planRank("unknown") <= planRank("enterprise") {
		t.Error("未知档应视为最高（保守按升级）")
	}
}
