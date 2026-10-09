// Package main — 租户门户邮件实发（SMTP，§10.3 D）。
//
// 契约（§10.3 D）：SMTP_HOST/SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD/SMTP_FROM/SMTP_TLS
// + PORTAL_BASE_URL。SMTP_HOST 或 SMTP_FROM 缺失 = mailer 为 nil → 相关端点 503（C-12）。
// SMTP_TLS=true（缺省）强制 STARTTLS 且证书校验不可关闭。
//
// 邮件链接由 PORTAL_BASE_URL 拼接（https 门户外部基址）。
package main

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// tenantMailer 邮件发送接口（测试可注入假实现）。
type tenantMailer interface {
	// SendVerifyEmail 发送注册验证邮件（含验证链接）。
	SendVerifyEmail(to, tenantName, token string) error
	// SendResetEmail 发送密码重置邮件（含重置链接）。
	SendResetEmail(to, token string) error
	// SendAlreadyRegisteredEmail 邮箱已注册提示（注册防枚举的副作用通知）。
	SendAlreadyRegisteredEmail(to string) error
}

// smtpMailer SMTP 实现。
type smtpMailer struct {
	host          string
	port          string
	username      string
	password      string
	from          string
	portalBaseURL string
	useTLS        bool
	timeout       time.Duration
}

// newTenantMailer 依配置构造 mailer；SMTP_HOST 或 SMTP_FROM 缺失 → nil（未启用）。
func newTenantMailer(cfg *config) tenantMailer {
	if cfg.smtpHost == "" || cfg.smtpFrom == "" {
		return nil
	}
	return &smtpMailer{
		host:          cfg.smtpHost,
		port:          fmt.Sprintf("%d", cfg.smtpPort),
		username:      cfg.smtpUsername,
		password:      cfg.smtpPassword,
		from:          cfg.smtpFrom,
		portalBaseURL: cfg.portalBaseURL,
		useTLS:        cfg.smtpTLS,
		timeout:       15 * time.Second,
	}
}

func (m *smtpMailer) SendVerifyEmail(to, tenantName, token string) error {
	link := m.portalBaseURL + "/tenant/verify?token=" + token
	subject := "验证您的邮箱 - AI 网关自助门户"
	body := fmt.Sprintf("您好 %s：\r\n\r\n请点击以下链接完成邮箱验证（24 小时内有效）：\r\n%s\r\n\r\n如非本人操作请忽略本邮件。\r\n",
		tenantName, link)
	return m.send(to, subject, body)
}

func (m *smtpMailer) SendResetEmail(to, token string) error {
	link := m.portalBaseURL + "/tenant/password-reset?token=" + token
	subject := "重置您的密码 - AI 网关自助门户"
	body := fmt.Sprintf("您好：\r\n\r\n请点击以下链接重置密码（1 小时内有效）：\r\n%s\r\n\r\n如非本人操作请忽略本邮件。\r\n",
		link)
	return m.send(to, subject, body)
}

func (m *smtpMailer) SendAlreadyRegisteredEmail(to string) error {
	subject := "您的邮箱已注册 - AI 网关自助门户"
	body := "您好：\r\n\r\n该邮箱已在本平台注册。如忘记密码请使用「忘记密码」功能重置。\r\n"
	return m.send(to, subject, body)
}

// send 执行一次 SMTP 投递（缺省 STARTTLS + 认证）。
func (m *smtpMailer) send(to, subject, body string) error {
	addr := net.JoinHostPort(m.host, m.port)
	conn, err := net.DialTimeout("tcp", addr, m.timeout)
	if err != nil {
		return fmt.Errorf("tenant: smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("tenant: smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	// STARTTLS（缺省强制；证书校验使用默认 tls.Config，不提供 InsecureSkipVerify 逃逸）
	if m.useTLS {
		if err := c.StartTLS(&tls.Config{ServerName: m.host}); err != nil {
			return fmt.Errorf("tenant: smtp starttls: %w", err)
		}
	}
	// 认证（用户名非空时）
	if m.username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
			return fmt.Errorf("tenant: smtp auth: %w", err)
		}
	}
	if err := c.Mail(m.from); err != nil {
		return fmt.Errorf("tenant: smtp mail from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("tenant: smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("tenant: smtp data: %w", err)
	}
	if _, err := w.Write([]byte(buildMailMessage(m.from, to, subject, body))); err != nil {
		_ = w.Close()
		return fmt.Errorf("tenant: smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("tenant: smtp close data: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("tenant: smtp quit: %w", err)
	}
	return nil
}

// buildMailMessage 构造 RFC 5322 消息（Subject 按 RFC 2047 编码，正文 UTF-8）。
func buildMailMessage(from, to, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}
