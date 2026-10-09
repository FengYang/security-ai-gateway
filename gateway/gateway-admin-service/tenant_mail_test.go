package main

import (
	"strings"
	"testing"
)

func TestBuildMailMessage(t *testing.T) {
	msg := buildMailMessage("from@x.com", "to@y.com", "主题测试", "正文内容")
	for _, want := range []string{
		"From: from@x.com", "To: to@y.com", "Subject: =?", "MIME-Version: 1.0", "正文内容",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("缺少 %q\n%s", want, msg)
		}
	}
}

func TestNewTenantMailer(t *testing.T) {
	// SMTP_HOST 缺失 → nil
	cfg := testTenantCfg()
	cfg.smtpHost = ""
	if m := newTenantMailer(cfg); m != nil {
		t.Error("SMTP_HOST 空应返回 nil")
	}
	// SMTP_FROM 缺失 → nil
	cfg2 := testTenantCfg()
	cfg2.smtpFrom = ""
	if m := newTenantMailer(cfg2); m != nil {
		t.Error("SMTP_FROM 空应返回 nil")
	}
	// 完整配置 → smtpMailer
	cfg3 := testTenantCfg()
	m := newTenantMailer(cfg3)
	sm, ok := m.(*smtpMailer)
	if !ok {
		t.Fatal("应返回 *smtpMailer")
	}
	if sm.host != cfg3.smtpHost || sm.from != cfg3.smtpFrom || !sm.useTLS {
		t.Errorf("mailer 字段不对: %+v", sm)
	}
}

func TestMailer_LinkContainsPortalBase(t *testing.T) {
	cfg := testTenantCfg()
	sm := newTenantMailer(cfg).(*smtpMailer)
	if sm.portalBaseURL != "https://portal.example.com" {
		t.Errorf("portalBaseURL 不对: %s", sm.portalBaseURL)
	}
}
