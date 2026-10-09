package main

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
	"time"
)

func TestCaptcha_IssueAndVerify(t *testing.T) {
	s := newCaptchaStore(5, 30)
	id, img, err := s.Issue("1.2.3.4")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(img, "data:image/png;base64,") {
		t.Errorf("image 前缀不对: %.30s", img)
	}
	s.mu.Lock()
	code := s.items[id].code
	s.mu.Unlock()

	if !s.Verify(id, code) {
		t.Error("正确验证码应通过")
	}
	if s.Verify(id, code) {
		t.Error("验证码应一次性（已消费）")
	}
}

func TestCaptcha_UnknownID(t *testing.T) {
	s := newCaptchaStore(5, 30)
	if s.Verify("no-such-id", "ABCD") {
		t.Error("不存在的 id 应失败")
	}
	if s.Verify("", "ABCD") {
		t.Error("空 id 应失败")
	}
}

func TestCaptcha_Expired(t *testing.T) {
	s := newCaptchaStore(5, 30)
	id, _, _ := s.Issue("1.2.3.4")
	s.mu.Lock()
	code := s.items[id].code
	s.items[id].expiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if s.Verify(id, code) {
		t.Error("过期应失败")
	}
}

func TestCaptcha_CaseInsensitive(t *testing.T) {
	s := newCaptchaStore(5, 30)
	id, _, _ := s.Issue("1.2.3.4")
	s.mu.Lock()
	code := s.items[id].code
	s.mu.Unlock()
	if !s.Verify(id, strings.ToLower(code)) {
		t.Error("应大小写不敏感")
	}
}

func TestCaptcha_IPRateLimit(t *testing.T) {
	s := newCaptchaStore(5, 2)
	if _, _, err := s.Issue("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Issue("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Issue("1.1.1.1"); err == nil {
		t.Error("超过限流应报错")
	}
	// 不同 IP 不受影响
	if _, _, err := s.Issue("2.2.2.2"); err != nil {
		t.Errorf("不同 IP 不应受限: %v", err)
	}
}

func TestRandomCaptchaCode(t *testing.T) {
	for i := 0; i < 20; i++ {
		code, err := randomCaptchaCode(4)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 4 {
			t.Fatalf("长度不对: %s", code)
		}
		for _, ch := range code {
			if !strings.ContainsRune(captchaCharset, ch) {
				t.Errorf("字符 %c 不在字符集", ch)
			}
		}
	}
}

func TestRenderCaptchaPNG(t *testing.T) {
	b, err := renderCaptchaPNG("AB23")
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("PNG 解码失败: %v", err)
	}
	if img.Bounds().Dx() <= 0 || img.Bounds().Dy() <= 0 {
		t.Error("图像尺寸非法")
	}
}
