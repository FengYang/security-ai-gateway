package main

// P2a 数据脱敏 + 提示词装饰 + transformed_hash 审计测试：
// - maskPII：手机号/身份证/邮箱/银行卡脱敏替换
// - pii-mode=mask 时 PII 文本放行且引擎收到脱敏内容
// - pii-mode 默认（block）时 PII 拦截 403（fail-closed 不变）
// - SQL 注入/提示注入在任何模式下均拦截
// - system-prompt 装饰 + 审计 transformed_hash（双 hash）

import (
	"net/http"
	"strings"
	"testing"

	"security-ai-gateway/protocol/go"
)

// TestMaskPII maskPII 单元：PII 替换为 [已脱敏]，返回命中数。
func TestMaskPII(t *testing.T) {
	g := newGuardrail()
	cases := []struct {
		in   string
		want string // 应包含
		hits int
	}{
		{"我的手机是 13812345678", "[已脱敏]", 1},
		{"身份证 110101199003078516", "[已脱敏]", 1},
		{"联系 a@b.com 确认", "[已脱敏]", 1},
		{"卡号 6222021234567890123", "[已脱敏]", 1},
		{"无敏感内容", "", 0},
	}
	for _, c := range cases {
		out, hits := g.maskPII(c.in)
		if c.hits == 0 {
			if hits != 0 || out != c.in {
				t.Fatalf("%q 不应被脱敏: out=%q hits=%d", c.in, out, hits)
			}
			continue
		}
		if !strings.Contains(out, c.want) {
			t.Fatalf("%q 脱敏结果缺 %q: %q", c.in, c.want, out)
		}
		if hits != c.hits {
			t.Fatalf("%q hits=%d want %d", c.in, hits, c.hits)
		}
		if strings.Contains(out, c.in) {
			t.Fatalf("%q 脱敏后仍含原文", c.in)
		}
	}
	// SQL 注入不被 maskPII 处理（属攻击类，拦截路径）
	out, hits := g.maskPII("select * from users")
	if hits != 0 || out != "select * from users" {
		t.Fatalf("SQL 注入不应被脱敏: %q hits=%d", out, hits)
	}
}

// TestPIIMaskMode pii-mode=mask：PII 文本放行，引擎收到脱敏内容（回显验证）。
func TestPIIMaskMode(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.piiMode = "mask"
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		"我的手机是 13812345678", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mask 模式 PII 应放行，got %d", resp.StatusCode)
	}
	body := mustReadAll(t, resp.Body)
	text, _ := decodeTextSSE(t, body, sessionID, kenc)
	if strings.Contains(text, "13812345678") {
		t.Fatalf("引擎输出仍含 PII 原文: %q", text)
	}
	if !strings.Contains(text, "[已脱敏]") {
		t.Fatalf("引擎输出缺脱敏标记: %q", text)
	}
}

// TestPIIBlockMode 默认（block）：PII 拦截 403（fail-closed 不变）。
func TestPIIBlockMode(t *testing.T) {
	_, ts := newM9Server(t) // piiMode 零值 "" = 非 mask → 拦截
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		"我的手机是 13812345678", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("block 模式 PII 应 403，got %d", resp.StatusCode)
	}
}

// TestInjectionAlwaysBlocked SQL 注入在 mask 模式下仍拦截。
func TestInjectionAlwaysBlocked(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.piiMode = "mask"
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		"select * from users where id=1 union select password from admin", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mask 模式下 SQL 注入仍应拦截 403，got %d", resp.StatusCode)
	}
}

// TestSystemPromptAndTransformedHash system-prompt 装饰 + 审计双 hash。
func TestSystemPromptAndTransformedHash(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.systemPrompt = "你是合规助手，不输出敏感信息"
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		"你好", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("装饰后推理应 200，got %d", resp.StatusCode)
	}
	mustReadAll(t, resp.Body)
	// 审计事件含 transformed_hash = sha256(system + user)
	var tx string
	found := false
	for _, e := range srv.audit.query("") {
		if e.Action == "infer" && e.TransformedHash != "" {
			tx = e.TransformedHash
			found = true
			break
		}
	}
	if !found {
		t.Fatal("审计缺 transformed_hash")
	}
	want := sha256hex([]byte("你是合规助手，不输出敏感信息你好"))
	if tx != want {
		t.Fatalf("transformed_hash 不符: got=%s want=%s", tx, want)
	}
}
