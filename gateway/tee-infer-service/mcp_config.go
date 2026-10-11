package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"security-ai-gateway/gateway/mcpsec"
)

// handleMCPConfig GET /config/mcp：MCP 工具治理只读快照（管理令牌）。
func (s *teeServer) handleMCPConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	catV, polV := s.mcpCache.Version()
	tools := 0
	if c := s.mcpCache.Catalog(); c != nil {
		tools = len(c.Tools)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ready":           s.mcpCache.Ready(),
		"catalog_version": catV,
		"policy_version":  polV,
		"tools":           tools,
	})
}

// mcpPolicyRequest POST /config/mcp/policy 请求体：可含已签名的目录与/或策略。
type mcpPolicyRequest struct {
	Catalog *mcpsec.ToolCatalog `json:"catalog,omitempty"`
	Policy  *mcpsec.RBACPolicy  `json:"policy,omitempty"`
}

// handleMCPPolicy POST /config/mcp/policy：下发签名目录/策略（管理令牌）。
// 加载：验签 → 版本单调校验 → 更新缓存；**失败保留旧策略不覆盖**（UpdateCatalog/
// UpdatePolicy 天然拒绝非法签名与版本回退）并告警。
func (s *teeServer) handleMCPPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req mcpPolicyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Catalog == nil && req.Policy == nil {
		http.Error(w, "bad request: catalog/policy 至少一项", http.StatusBadRequest)
		return
	}
	resp := map[string]any{}
	if req.Catalog != nil {
		ok := s.mcpCache.UpdateCatalog(req.Catalog)
		resp["catalog_applied"] = ok
		if !ok {
			resp["catalog_reason"] = "verify_failed_or_version_rollback"
			log.Printf("tee-infer: MCP 目录下发被拒（验签失败/版本回退），保留旧目录")
		}
	}
	if req.Policy != nil {
		ok := s.mcpCache.UpdatePolicy(req.Policy)
		resp["policy_applied"] = ok
		if !ok {
			resp["policy_reason"] = "verify_failed_or_version_rollback"
			log.Printf("tee-infer: MCP 策略下发被拒（验签失败/版本回退），保留旧策略")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
