// 留存期声明校验（fail-closed）与缺省值约束。
package main

import "testing"

// TestValidateAuditRetentionDays 校验边界：0=不声明合法；≥180 合法；(0,180) 与负数非法。
func TestValidateAuditRetentionDays(t *testing.T) {
	cases := []struct {
		days    int
		wantErr bool
	}{
		{0, false},   // 显式不声明
		{180, false}, // 法定硬底
		{365, false}, // 缺省声明值
		{179, true},  // 硬底之下 → 拒绝启动
		{1, true},    //
		{-1, true},   // 负值非法
	}
	for _, c := range cases {
		err := validateAuditRetentionDays(c.days)
		if c.wantErr && err == nil {
			t.Fatalf("audit-retention-days=%d 应非法", c.days)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("audit-retention-days=%d 应合法，得: %v", c.days, err)
		}
	}
}

// TestAuditRetentionDefaults 缺省声明值不得低于法定硬底（防"缺省即违法"）。
func TestAuditRetentionDefaults(t *testing.T) {
	if defaultAuditRetentionDays < minAuditRetentionDays {
		t.Fatalf("缺省声明值 %d 低于法定硬底 %d", defaultAuditRetentionDays, minAuditRetentionDays)
	}
}
