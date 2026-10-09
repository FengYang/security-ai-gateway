package main

import (
	"context"
	"errors"
	"testing"
)

func TestCompensateOnce_RecoversToActive(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "q@example.com", "Password123!", tenantUserStatusActive, tenantStatusQuotaPending)
	binder := &fakeBinder{res: bindResult{Status: tenantStatusActive}}
	h.binder = binder

	h.compensateOnce(context.Background())

	if binder.calls != 1 || binder.tenant != tid {
		t.Errorf("binder 调用异常: %+v", binder)
	}
	tn, _ := store.GetTenantByID(tid)
	if tn.Status != tenantStatusActive {
		t.Errorf("应恢复 active, got=%s", tn.Status)
	}
}

func TestCompensateOnce_StaysPendingOnBindError(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "q2@example.com", "Password123!", tenantUserStatusActive, tenantStatusQuotaPending)
	h.binder = &fakeBinder{err: errors.New("boom")}

	h.compensateOnce(context.Background())

	tn, _ := store.GetTenantByID(tid)
	if tn.Status != tenantStatusQuotaPending {
		t.Errorf("应保持 quota_pending, got=%s", tn.Status)
	}
}

func TestCompensateOnce_StaysPendingWhenQuotaUnconfirmed(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "q3@example.com", "Password123!", tenantUserStatusActive, tenantStatusQuotaPending)
	h.binder = &fakeBinder{res: bindResult{Status: tenantStatusQuotaPending}}

	h.compensateOnce(context.Background())

	tn, _ := store.GetTenantByID(tid)
	if tn.Status != tenantStatusQuotaPending {
		t.Errorf("配额未确认应保持 quota_pending, got=%s", tn.Status)
	}
}

func TestCompensateOnce_NoopWithoutBinder(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.binder = nil
	h.compensateOnce(context.Background()) // 不应 panic
}
