package billing

import "fmt"

// ---------- 冻结控制器（T8，§6.10） ----------

// FreezeAuditSink 冻结/解冻审计落链回调（可选；admin-service 审计链）。
type FreezeAuditSink interface {
	RecordFreeze(action, tenant, reason, severity, by string)
}

// FreezeController 冻结状态机（触发/解除）。
type FreezeController struct {
	store FreezeStore
	audit FreezeAuditSink
	now   func() int64
}

// NewFreezeController 构造冻结控制器。
func NewFreezeController(store FreezeStore, audit FreezeAuditSink, now func() int64) *FreezeController {
	if now == nil {
		now = func() int64 { return 0 }
	}
	return &FreezeController{store: store, audit: audit, now: now}
}

// Frozen 判定租户是否处于冻结（含到期自动失效）。
func (c *FreezeController) Frozen(tenant string) (bool, error) {
	rec, err := c.store.Get(tenant)
	if err != nil {
		return false, err
	}
	if rec == nil {
		return false, nil
	}
	if rec.Until != 0 && rec.Until <= c.now() {
		return false, nil // 已自动到期
	}
	return true, nil
}

// Freeze 冻结租户（幂等：已冻结则更新原因/严重级）。落审计 bill_freeze。
func (c *FreezeController) Freeze(tenant, reason, severity, by string) error {
	if tenant == "" {
		return fmt.Errorf("billing: freeze: tenant is required")
	}
	if severity != string(SeverityWarning) && severity != string(SeverityCritical) {
		return fmt.Errorf("billing: freeze: invalid severity %q", severity)
	}
	rec := FreezeRecord{
		TenantID: tenant,
		Reason:   reason,
		Severity: severity,
		FrozenAt: c.now(),
		Until:    0, // 默认无限（人工解除）
		By:       by,
	}
	if err := c.store.Put(rec); err != nil {
		return err
	}
	IncFreeze() // 指标 #14
	if c.audit != nil {
		c.audit.RecordFreeze("bill_freeze", tenant, reason, severity, by)
	}
	return nil
}

// Unfreeze 人工解除冻结（幂等）。落审计 bill_unfreeze。
func (c *FreezeController) Unfreeze(tenant, by string) error {
	if err := c.store.Delete(tenant); err != nil {
		return err
	}
	if c.audit != nil {
		c.audit.RecordFreeze("bill_unfreeze", tenant, "", "", by)
	}
	return nil
}
