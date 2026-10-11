// Package mcpproto 实现 **TEE 内 MCP 协议层（T-4）**：
//   - 经官方 go-sdk（github.com/modelcontextprotocol/go-sdk）承载 server/discover、
//     tools/list、tools/call；无状态传输（对齐 MCP 2026-07-28 会话模型）。
//   - tools/list 仅暴露【敏感轨（mcpsec.TrackSecure）+ 该租户已授权】的工具；
//     非敏感轨工具不在 TEE 终结（分轨结构性保障，C-MCP-4）。
//   - tools/call **一律经 mcpguard.Evaluate 裁决**（裁决必须在 TEE 内，C-MCP-3/§1.2）；
//     拒绝细节不外泄（客户端仅收粗粒度错误，Reason/ParamsHash 供审计）。
//
// 边界（§12.1.2 T-4「不做」）：不实现 MCP 工具业务后端；不实现采样/资源订阅。
package mcpproto

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"security-ai-gateway/gateway/mcpsec"
	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
)

const (
	serverName = "otpmask-tee-mcp"
	serverVer  = "v1"

	// tenantHeader 与 tee-infer 既有租户头一致（段① 会话注入）。
	tenantHeader = "X-Tenant-ID"
	// 传输层一致性校验头（纵深防御，§12.2 T-4 步 6）。
	hdrMcpMethod = "Mcp-Method"
	hdrMcpName   = "Mcp-Name"
)

// CallAudit tools/call 审计回调（T-9 / V-6）。**仅**携带 hash 与决策元数据，不含明文参数；
// 唯一生产者＝tee-infer（本包只回调，不落链）。
type CallAudit func(tenant, tool, decision, paramsHash, reason string, policyVersion int)

// Deps 依赖注入：mcpguard 引擎（裁决）与策略缓存（目录/策略/版本）。
type Deps struct {
	Guard *mcpguard.Engine
	Cache *mcpguard.PolicyCache
	// Audit 可选：tools/call 审计回调（nil = 不审计；生产由 tee-infer 注入，见 V-6）。
	Audit CallAudit
}

// NewHandler 返回可挂在 tee-infer mux 上的 MCP HTTP handler。
func NewHandler(d Deps) http.Handler {
	h := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return buildServer(d, r.Header.Get(tenantHeader)) },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 纵深防御：tools/call 的 Mcp-Name 与 body 一致性（-32020）。
		if code, msg, bad := transportConsistency(r); bad {
			writeJSONRPCError(w, code, msg)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// buildServer 按租户构造 MCP Server：仅注册【敏感轨 + 该租户已授权】的工具。
func buildServer(d Deps, tenant string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVer}, nil)
	if d.Guard == nil || d.Cache == nil || !d.Cache.Ready() {
		return s // 未就绪（冷启动/策略未达）→ 空工具表（fail-closed，O-3）
	}
	cat, pol := d.Cache.Catalog(), d.Cache.Policy()
	if cat == nil || pol == nil {
		return s
	}
	for _, t := range selectTools(cat, pol, tenant) {
		tool := &mcp.Tool{
			Name:        t.Name,
			Description: "otpmask secure tool: " + t.Name,
			InputSchema: inputSchema(&t),
		}
		s.AddTool(tool, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return callTool(d, tenant, req)
		})
	}
	return s
}

// selectTools 返回该租户在 TEE 终结的敏感轨工具：Track==secure 且 RBAC 授权；
// 顺序按名字典序（确定性，缓存友好，§12.2 T-4 步 3）。
func selectTools(cat *mcpsec.ToolCatalog, pol *mcpsec.RBACPolicy, tenant string) []mcpsec.TableTool {
	out := make([]mcpsec.TableTool, 0, len(cat.Tools))
	for i := range cat.Tools {
		t := cat.Tools[i]
		if t.ToolTrack() != mcpsec.TrackSecure { // 非敏感轨不在 TEE 终结（分轨结构性保障）
			continue
		}
		if !mcpguard.EvaluateRBAC(pol, tenant, t.Name).Allowed { // 该租户未授权 → 不暴露
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// callTool 经 mcpguard 裁决；拒绝细节不外泄。
func callTool(d Deps, tenant string, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if req == nil || req.Params == nil {
		return denied(), nil
	}
	params := map[string]any{}
	if len(req.Params.Arguments) > 0 {
		_ = json.Unmarshal(req.Params.Arguments, &params)
	}
	dec := d.Guard.Evaluate(tenant, requestIDOf(req), req.Params.Name, params)
	// V-6：每次 tools/call（放行/拒绝）产一条审计事件；仅 hash，无明文参数。
	if d.Audit != nil {
		decision, reason := "allow", ""
		if !dec.Allow {
			decision, reason = "deny", string(dec.Reason)
		}
		d.Audit(tenant, req.Params.Name, decision, dec.ParamsHash, reason, dec.PolicyVersion)
	}
	if !dec.Allow {
		return denied(), nil
	}
	// 工具业务后端不在 T-4 范围（§12.1.2「不做」）：返回已裁决通过的占位结果，
	// 承载 ParamsHash/PolicyVersion 供审计关联（无明文）。
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
		Meta:    mcp.Meta{"params_hash": dec.ParamsHash, "policy_version": dec.PolicyVersion},
	}, nil
}

// denied 粗粒度拒绝结果（不泄露 Reason/策略细节）。
func denied() *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "denied"}},
	}
}

// requestIDOf 从 _meta.request_id 取审计关联 ID；缺失则为空（ParamsHash 仍绑 tenant+params）。
func requestIDOf(req *mcp.CallToolRequest) string {
	if req == nil || req.Params == nil {
		return ""
	}
	if v, ok := req.Params.Meta["request_id"].(string); ok {
		return v
	}
	return ""
}

// inputSchema 由 mcpsec 字段约束构造 JSON Schema（type/pattern/whitelist→enum/required）。
func inputSchema(t *mcpsec.TableTool) map[string]any {
	props := map[string]any{}
	for name, fc := range t.Schema {
		p := map[string]any{}
		if fc != nil {
			if fc.Type != "" {
				p["type"] = fc.Type
			}
			if fc.Pattern != "" {
				p["pattern"] = fc.Pattern
			}
			if len(fc.Whitelist) > 0 {
				p["enum"] = append([]string{}, fc.Whitelist...)
			}
		}
		props[name] = p
	}
	sch := map[string]any{"type": "object", "properties": props}
	if len(t.Required) > 0 {
		sch["required"] = append([]string{}, t.Required...)
	}
	return sch
}
