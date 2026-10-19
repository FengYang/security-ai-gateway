// mcp-acl 插件（P2-1 T-4）：网关侧（元数据级）工具级 ACL，public 轨。
//
// 执行点：Higress WasmPlugin，绑定 public 轨路由（mcp-public-demo / mcp-public-fs；
// defaultConfigDisable + 白名单 matchRules）。请求头阶段裁决，**不读 body**（R-6/D-3）。
//
// 判定（本体 §7.2 ③/④）：
//   - `Mcp-Method: tools/call` → `Mcp-Name` 头 × 租户 → RBAC 放行表 × 目录联合校验
//     （policycache.Decide；default deny）；
//   - 非调用类方法（tools/list / initialize / notifications/* 等白名单）→ 放行；
//   - 方法头缺失 / 未知方法 / 判定拒绝 → fail-closed，HTTP 200 + JSON-RPC error
//     （-32602，C-MCP-2 §5.7.3 分层口径：401/403 仅鉴权层；统一码防 oracle 区分）。
//
// 覆盖口径（U-9 实测登记，C-MCP-2 v1.9 §6.2/§6.3）：本实例（Higress 2.2.5）mcp-server
// 处理器忽略 MCP 头且不做头/体一致性校验（无 -32020）→ 元数据级 ACL 的残余绕过面＝
// 主动伪造头/体不一致的调用（声明 tools/list 而体为 tools/call 等）；纵深防御路径＝
// 新版 mcp-server 插件（-32020）或 secure 轨 TEE。本插件侧可控口径＝「声明缺失/未知
// 一律拒绝」＋「声明为调用即校验」，见 decide()。
//
// 硬约束：零密码 import（R-4；验签经 cryptop sidecar）；与 secure 轨目录同源但执行点
// 独立（R-5，不共享工具）；策略拉取失败**保留旧策略**、从未拉到一律拒绝（fail-closed）。
//
// 构建：GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o main.wasm ./gateway/wasm/mcp-acl-plugin
package main

import (
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/mcp-acl-plugin/policycache"
)

// 请求头名（MCP 2026-07-28 无状态协议头 + 关联 id）。
const (
	hdrMcpMethod = "Mcp-Method"
	hdrMcpName   = "Mcp-Name"
	hdrRequestID = "X-Request-Id"
	hdrHTTPVerb  = ":method"
)

// methodToolsCall 唯一的工具调用方法名（触发授权判定的方法）。
const methodToolsCall = "tools/call"

// denyBody 拒绝响应体（HTTP 200 + JSON-RPC error；-32602 统一码，见文件头注释）。
//
// id 恒为 null：插件不读 body（R-6），无法回显请求 id——JSON-RPC 2.0 对无法判别 id 的
// 错误响应允许以 null 填充。响应不携带拒绝原因（防 oracle）；原因只进日志与指标。
const denyBody = `{"jsonrpc":"2.0","id":null,"error":{"code":-32602,"message":"mcp-acl: request denied"}}`

func main() {}

func init() {
	wrapper.SetCtx(
		"mcp-acl",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

// onHttpRequestHeaders 请求头阶段裁决：拒绝即回 JSON-RPC error 并短路；否则放行上游。
func onHttpRequestHeaders(ctx wrapper.HttpContext, config PluginConfig, log logs.Log) types.Action {
	metricRequests.incr()
	// 工具调用仅经 POST；非 POST（GET/OPTIONS 等，含 SSE 端点探测）不介入。
	if m := requestMethod(ctx); m != "" && !strings.EqualFold(m, "POST") {
		return types.HeaderContinue
	}
	method := reqHeader(hdrMcpMethod)
	tenant := reqHeader(config.TenantHeader)
	name := reqHeader(hdrMcpName)
	allow, reason := decide(method, tenant, name, aclRuntime.cache)
	if allow {
		if method == methodToolsCall {
			metricAllows.incr()
		}
		return types.HeaderContinue
	}
	deny(log, tenant, name, method, reason)
	return types.ActionContinue
}

// requestMethod 取 HTTP 动词（优先 wrapper 上下文；兜底读 :method 伪头）。
func requestMethod(ctx wrapper.HttpContext) string {
	if m := ctx.Method(); m != "" {
		return m
	}
	return reqHeader(hdrHTTPVerb)
}

// decide 纯判定函数（与 hostcall 解耦，便于单测）：
//   - tools/call → 双源缓存联合校验（缓存未装配/未就绪一律保守拒绝）；
//   - 白名单非调用方法 → 放行；
//   - 方法头缺失/未知方法 → 拒绝（fail-closed；大小写变体按未知方法拒绝）。
func decide(method, tenant, name string, cache *policycache.Cache) (bool, string) {
	if method == methodToolsCall {
		if cache == nil {
			return false, "policy_unavailable"
		}
		d := cache.Decide(tenant, name)
		return d.Allow, d.Reason
	}
	if method == "" {
		return false, "missing_method"
	}
	if _, ok := nonCallMethods[method]; ok {
		return true, ""
	}
	return false, "method_not_allowed"
}

// nonCallMethods 非调用类方法白名单（MCP 2026-07-28 + 兼容集）。
// 显式枚举、未知方法一律拒绝——未来方法按 fail-closed 登记，扩展须经评审。
var nonCallMethods = map[string]struct{}{
	"initialize":                {},
	"ping":                      {},
	"tools/list":                {},
	"resources/list":            {},
	"resources/read":            {},
	"resources/templates/list":  {},
	"resources/subscribe":       {},
	"resources/unsubscribe":     {},
	"prompts/list":              {},
	"prompts/get":               {},
	"completion/complete":       {},
	"logging/setLevel":          {},
	"server/discover":           {},
	"notifications/initialized": {},
	"notifications/cancelled":   {},
	"notifications/progress":    {},
}

// deny 记录拒绝线索（结构化日志：reason/tenant/tool/method/rid）并回 JSON-RPC error。
//
// 审计口径（T-4 登记）：插件侧无审计链写权限（R-3 边界）——拒绝的可审计性由结构化
// 日志与 mcpacl_denies_total 指标承接；集群验收以网关 Pod 日志 + 指标采样为证。
func deny(log logs.Log, tenant, name, method, reason string) {
	metricDenies.incr()
	log.Warnf("mcp-acl: 拒绝 reason=%s tenant=%s tool=%s method=%s rid=%s",
		reason, tenant, name, method, reqHeader(hdrRequestID))
	_ = proxywasm.SendHttpResponse(200,
		[][2]string{{"Content-Type", "application/json"}, {"Cache-Control", "no-store"}},
		[]byte(denyBody), -1)
}

// reqHeader 读请求头（名字统一小写化对齐 Envoy 头表；缺失/错误返回空串）。
func reqHeader(name string) string {
	v, err := proxywasm.GetHttpRequestHeader(strings.ToLower(name))
	if err != nil {
		return ""
	}
	return v
}
