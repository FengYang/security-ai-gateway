package main

// 端点凭证管理器单测（纯逻辑部分，不依赖 proxywasm 运行时）。
// 注意：env:// scheme 的实际读取依赖 proxywasm 运行时，
// 此处仅测试 parseSecretRef / Register / Invalidate / Remove / Close 等纯逻辑。

import (
	"strings"
	"testing"
)

// parseSecretRef：合法输入
func TestParseSecretRef_Valid(t *testing.T) {
	tests := []struct {
		ref      string
		scheme   string
		path     string
	}{
		{"km://otp/keys/endpoint-a", "km", "otp/keys/endpoint-a"},
		{"file:///etc/secrets/api.key", "file", "/etc/secrets/api.key"},
		{"env://MY_API_TOKEN", "env", "MY_API_TOKEN"},
		{"km://simple", "km", "simple"},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			scheme, path, err := parseSecretRef(tt.ref)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if scheme != tt.scheme {
				t.Fatalf("scheme 应为 %q，got %q", tt.scheme, scheme)
			}
			if path != tt.path {
				t.Fatalf("path 应为 %q，got %q", tt.path, path)
			}
		})
	}
}

// parseSecretRef：非法输入
func TestParseSecretRef_Invalid(t *testing.T) {
	tests := []struct {
		name string
		ref  string
	}{
		{"空串", ""},
		{"无 scheme", "just-a-string"},
		{"无路径", "km://"},
		{"不支持 scheme", "vault://secret/foo"},
		{"http scheme", "http://example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseSecretRef(tt.ref)
			if err == nil {
				t.Fatalf("应返回错误，got nil")
			}
		})
	}
}

// CredentialManager：注册 + 查询引用存在
func TestCredMgr_RegisterAndHas(t *testing.T) {
	mgr := newEndpointCredentialManager()

	err := mgr.Register("ep-a", "km://keys/ep-a")
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	if !mgr.HasCredentials("ep-a") {
		t.Fatalf("ep-a 应有凭证配置")
	}
	if mgr.HasCredentials("ep-b") {
		t.Fatalf("ep-b 不应有凭证配置")
	}
}

// CredentialManager：注册非法 secret_ref
func TestCredMgr_RegisterInvalid(t *testing.T) {
	mgr := newEndpointCredentialManager()
	err := mgr.Register("ep-bad", "not-a-valid-ref")
	if err == nil {
		t.Fatalf("非法 secret_ref 应返回错误")
	}
	if mgr.HasCredentials("ep-bad") {
		t.Fatalf("注册失败的端点不应存在于管理器中")
	}
}

// CredentialManager：同端点重复注册（相同引用不重复）
func TestCredMgr_RegisterSame(t *testing.T) {
	mgr := newEndpointCredentialManager()
	if err := mgr.Register("ep", "km://keys/ep"); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	// 第二次注册相同引用 → 应成功（幂等）
	if err := mgr.Register("ep", "km://keys/ep"); err != nil {
		t.Fatalf("重复注册相同引用应成功: %v", err)
	}
}

// CredentialManager：同端点更新引用
func TestCredMgr_RegisterUpdate(t *testing.T) {
	mgr := newEndpointCredentialManager()
	if err := mgr.Register("ep", "km://keys/v1"); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	// 更新为不同引用 → 应成功
	if err := mgr.Register("ep", "km://keys/v2"); err != nil {
		t.Fatalf("更新引用应成功: %v", err)
	}
}

// CredentialManager：Invalidate 失效缓存
func TestCredMgr_Invalidate(t *testing.T) {
	mgr := newEndpointCredentialManager()
	mgr.Register("ep", "km://keys/ep")

	// km:// 方案 Get 返回引用原样（不走环境变量）
	val, err := mgr.Get("ep")
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if val != "km://keys/ep" {
		t.Fatalf("km:// 应返回引用原样，got %q", val)
	}

	// Invalidate 不应删除注册（仅清空已解析缓存）
	mgr.Invalidate()
	if !mgr.HasCredentials("ep") {
		t.Fatalf("Invalidate 后端点注册应保留")
	}

	// 重新 Get 仍可获取（km:// 不依赖缓存，直接返回）
	val2, err := mgr.Get("ep")
	if err != nil {
		t.Fatalf("Invalidate 后 Get 应仍成功: %v", err)
	}
	if val2 != "km://keys/ep" {
		t.Fatalf("Invalidate 后值应不变（km:// 方案），got %q", val2)
	}
}

// CredentialManager：Remove 移除端点
func TestCredMgr_Remove(t *testing.T) {
	mgr := newEndpointCredentialManager()
	mgr.Register("ep", "km://keys/ep")
	mgr.Remove("ep")

	if mgr.HasCredentials("ep") {
		t.Fatalf("Remove 后端点应不存在")
	}

	_, err := mgr.Get("ep")
	if err == nil {
		t.Fatalf("Remove 后 Get 应失败")
	}
}

// CredentialManager：Close 清零全部
func TestCredMgr_Close(t *testing.T) {
	mgr := newEndpointCredentialManager()
	mgr.Register("ep1", "km://keys/ep1")
	mgr.Register("ep2", "km://keys/ep2")

	mgr.Close()

	if mgr.HasCredentials("ep1") || mgr.HasCredentials("ep2") {
		t.Fatalf("Close 后所有端点应被清除")
	}
}

// maskSecret：密钥脱敏
func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "****"},
		{"1234", "****"},
		{"abcdef", "ab***ef"},
		{"1234567890", "12***90"},
		{"", "****"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := maskSecret(tt.input)
			if result != tt.expected {
				t.Fatalf("期望 %q，got %q", tt.expected, result)
			}
			// 脱敏后不应包含原文（长度 > 4 时）
			if len(tt.input) > 4 && strings.Contains(result, tt.input) {
				t.Fatalf("脱敏结果不应包含原文")
			}
		})
	}
}

// zeroString：清零字符串
func TestZeroString(t *testing.T) {
	s := "sensitive-data-12345"
	zeroString(&s)
	if s != "" {
		t.Fatalf("清零后字符串应为空，got %q", s)
	}

	// nil 指针安全
	var nilStr *string
	zeroString(nilStr) // 不应 panic

	// 空串安全
	empty := ""
	zeroString(&empty)
	if empty != "" {
		t.Fatalf("空串清零后应仍为空")
	}
}

// Get 未注册端点：返回错误
func TestCredMgr_GetNotFound(t *testing.T) {
	mgr := newEndpointCredentialManager()
	_, err := mgr.Get("nonexistent")
	if err == nil {
		t.Fatalf("未注册端点 Get 应返回错误")
	}
}
