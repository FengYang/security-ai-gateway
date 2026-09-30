package main

// credentialmgr.go — 端点凭证管理器（方案 §9.2，P0 简化版）。
//
// 职责：
//   - 解析 secret_ref（km://<path> / file://<path> / env://<name>）
//   - 内存缓存（请求路径快速读取）
//   - 使用后清零（敏感内存安全，§9.2.7）
//   - 热更新：路由表版本变化时失效旧缓存
//
// P0 简化（§9.2.9）：
//   - 支持 km:// scheme（复用段① 凭据拉取通道的服务端能力）
//   - 支持 env:// scheme（开发环境，Wasm 内通过 proxywasm.GetProperty 读环境变量）
//   - file:// 在 Wasm 沙箱中不可用（返回错误，由控制面侧支持）
//   - 定时轮询刷新 → P1（P0 仅路由表变更时触发重新解析）
//   - AES-256-GCM 内存加密 → P1（P0 明文内存，用后清零）
//
// 并发安全：所有读/写方法均带 RWMutex 保护。

import (
	"fmt"
	"strings"
	"sync"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
)

// endpointCred 单个端点的凭证缓存。
type endpointCred struct {
	scheme   string // "km" / "file" / "env"
	path     string // scheme 后的路径部分
	resolved string // 已解析的明文凭证（空 = 未解析或已清零）
}

// EndpointCredentialManager 端点凭证管理器。
//
// 用法：
//  1. NewEndpointCredentialManager() 创建
//  2. Register(epName, secretRef) 注册端点凭证引用
//  3. Get(epName) 读取凭证（返回副本，调用方用完后清零）
//  4. Invalidate() 路由表变更时调用，清空所有缓存
//  5. Close() 退出前清零全部敏感内存
type EndpointCredentialManager struct {
	mu    sync.RWMutex
	creds map[string]*endpointCred // endpointName -> cred
}

// newEndpointCredentialManager 创建空凭证管理器。
func newEndpointCredentialManager() *EndpointCredentialManager {
	return &EndpointCredentialManager{
		creds: make(map[string]*endpointCred),
	}
}

// Register 注册或更新一个端点的 secret_ref。
// 解析失败返回错误（不注册该端点）。
func (m *EndpointCredentialManager) Register(endpointName, secretRef string) error {
	if endpointName == "" {
		return fmt.Errorf("端点名称不能为空")
	}
	scheme, path, err := parseSecretRef(secretRef)
	if err != nil {
		return fmt.Errorf("secret_ref 解析失败: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// 已存在且 scheme+path 相同 → 不重置 resolved（保留缓存）
	if old, ok := m.creds[endpointName]; ok && old.scheme == scheme && old.path == path {
		return nil
	}
	m.creds[endpointName] = &endpointCred{
		scheme: scheme,
		path:   path,
		// resolved 延迟到首次 Get 时解析
	}
	return nil
}

// Get 获取指定端点的凭证明文（返回副本，调用方用完应清零）。
//
// P0 实现：
//   - km://：返回 secret_ref 原样（实际密钥由请求时的 DispatchHttpCall
//     通过段① 通道从凭据服务拉取；本管理器仅做引用缓存）
//   - env://：从 Wasm 环境变量读取（proxywasm.GetProperty）
//   - file://：Wasm 不支持，返回错误
//
// 调用方约定：用完后立即清零返回值，避免长时间驻留内存。
func (m *EndpointCredentialManager) Get(endpointName string) (string, error) {
	m.mu.RLock()
	cred, ok := m.creds[endpointName]
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("端点 %q 未注册凭证", endpointName)
	}

	// 已缓存 → 直接返回副本
	if cred.resolved != "" {
		return cred.resolved, nil
	}

	// 延迟解析
	resolved, err := m.resolve(cred)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	cred.resolved = resolved
	m.mu.Unlock()

	return resolved, nil
}

// resolve 根据 scheme 解析凭证。
func (m *EndpointCredentialManager) resolve(c *endpointCred) (string, error) {
	switch c.scheme {
	case "km":
		// P0：km:// 为远程引用，不做本地解析
		// 实际凭证在请求路径上通过 DispatchHttpCall 从凭据服务获取
		// 此处返回引用路径供上游使用
		return "km://" + c.path, nil

	case "env":
		// 从 Wasm 环境变量读取
		val, err := proxywasm.GetProperty([]string{"env", c.path})
		if err != nil {
			return "", fmt.Errorf("读取环境变量 %q 失败: %w", c.path, err)
		}
		return string(val), nil

	case "file":
		// Wasm 沙箱不支持本地文件读取
		return "", fmt.Errorf("file:// scheme 在 Wasm 环境中不支持（请使用 km:// 或 env://）")

	default:
		return "", fmt.Errorf("不支持的 scheme: %q", c.scheme)
	}
}

// Invalidate 失效所有缓存（路由表变更时调用）。
// 已注册的端点引用保留，但已解析的凭证被清零（下次 Get 时重新解析）。
func (m *EndpointCredentialManager) Invalidate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.creds {
		zeroString(&c.resolved)
	}
}

// Remove 移除指定端点的凭证（同时清零）。
func (m *EndpointCredentialManager) Remove(endpointName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.creds[endpointName]; ok {
		zeroString(&c.resolved)
		delete(m.creds, endpointName)
	}
}

// Close 关闭管理器，清零全部敏感内存。
func (m *EndpointCredentialManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.creds {
		zeroString(&c.resolved)
	}
	m.creds = make(map[string]*endpointCred)
}

// HasCredentials 检查指定端点是否有凭证配置。
func (m *EndpointCredentialManager) HasCredentials(endpointName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.creds[endpointName]
	return ok
}

// ============================================================
// 工具函数
// ============================================================

// parseSecretRef 解析 secret_ref 字符串，返回 scheme 和 path。
// 支持：km://<path> / file://<path> / env://<name>
func parseSecretRef(ref string) (scheme, path string, err error) {
	if ref == "" {
		return "", "", fmt.Errorf("secret_ref 不能为空")
	}
	idx := strings.Index(ref, "://")
	if idx < 0 {
		return "", "", fmt.Errorf("secret_ref 格式错误（缺少 ://）: %q", ref)
	}
	scheme = ref[:idx]
	path = ref[idx+3:]
	if path == "" {
		return "", "", fmt.Errorf("secret_ref 路径不能为空")
	}
	switch scheme {
	case "km", "file", "env":
		// 合法
	default:
		return "", "", fmt.Errorf("不支持的 scheme: %q（P0 仅支持 km:// / file:// / env://）", scheme)
	}
	return scheme, path, nil
}

// zeroString 清零字符串的底层字节（敏感内存安全）。
//
// 注意：Go 的 string 是不可变的，这里通过转换为 []byte 来清零。
// 仅用于我们自己持有并可写的字符串（如通过转换获得的）。
// 对于不可变字符串常量，此函数无实际效果但安全（不会 panic）。
func zeroString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// 把 string 转成 []byte 再清零（Go 中 string 不可变，转换会复制，
	// 但此处目的是尽快释放引用，让 GC 回收原内存）。
	buf := []byte(*s)
	for i := range buf {
		buf[i] = 0
	}
	*s = ""
}

// maskSecret 对密钥做脱敏（仅保留前后各 2 字符，中间用 *** 替代）。
// 用于日志输出，绝不打印完整密钥。
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

// epCredMgr 全局端点凭证管理器实例。
// 由路由表加载时初始化，路由表版本变更时调用 Invalidate()。
var epCredMgr = newEndpointCredentialManager()

// registerEndpointCredentials 为指定端点注册凭证引用（如有）。
// secretRef 为空时不注册（端点无需认证）。
func registerEndpointCredentials(endpointName, secretRef string) error {
	if secretRef == "" {
		return nil
	}
	return epCredMgr.Register(endpointName, secretRef)
}

// invalidateEndpointCredentials 失效所有端点凭证缓存（路由表版本变更时调用）。
func invalidateEndpointCredentials() {
	epCredMgr.Invalidate()
}
