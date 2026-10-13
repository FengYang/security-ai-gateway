package main

// audit_retention_api.go — P1-7 T9（§6.4）：tee-infer 侧留存/分层声明读写端点。
//
// 端点（均在管理令牌之下，与 /audit 同档）：
//
//	GET /audit/retention   读取当前声明快照（declared_days/hot_days/warm_days/cold_days/sample_miss_rate/enabled）
//	PUT /audit/retention   更新声明（校验 fail-closed：declared_days ∈ {0} ∪ [180,∞)、分层合计 ≥180）
//
// 声明式纪律（C-4）：本端点只改**声明值**，服务**不执行删除**——审计链只追加（WORM），
// 就地裁剪会破坏哈希链；实际清理由存储层生命周期策略按声明值执行。
// 管理面 gateway-admin-service（T9）PUT 前先落 G1 链，链写失败即 fail-closed 不下发。

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

// auditRetentionReq 留存声明更新请求体（与 admin 侧 auditRetentionRequest 契约一致）。
type auditRetentionReq struct {
	DeclaredDays   int   `json:"declared_days"`
	HotDays        int   `json:"hot_days"`
	WarmDays       int   `json:"warm_days"`
	ColdDays       int   `json:"cold_days"`
	SampleMissRate int   `json:"sample_miss_rate"`
	Enabled        *bool `json:"enabled,omitempty"`
}

// auditRetentionView 留存声明快照（§6.4 视图口径）。
type auditRetentionView struct {
	DeclaredDays   int  `json:"declared_days"`
	HotDays        int  `json:"hot_days"`
	WarmDays       int  `json:"warm_days"`
	ColdDays       int  `json:"cold_days"`
	SampleMissRate int  `json:"sample_miss_rate"`
	Enabled        bool `json:"enabled"`
}

// retentionSnapshot 读取分层声明（并发安全；archiveOnce 读取用）。
func (s *teeServer) retentionSnapshot() RetentionPolicy {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	return s.retention
}

// handleAuditRetention GET/PUT /audit/retention。
func (s *teeServer) handleAuditRetention(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.retentionMu.RLock()
		view := auditRetentionView{
			DeclaredDays:   s.auditRetentionDays,
			HotDays:        s.retention.HotDays,
			WarmDays:       s.retention.WarmDays,
			ColdDays:       s.retention.ColdDays,
			SampleMissRate: s.retention.SampleMissRate,
			Enabled:        true,
		}
		s.retentionMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view)
	case http.MethodPut:
		var req auditRetentionReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "非法请求体: "+err.Error(), http.StatusBadRequest)
			return
		}
		policy := RetentionPolicy{
			HotDays:        req.HotDays,
			WarmDays:       req.WarmDays,
			ColdDays:       req.ColdDays,
			SampleMissRate: req.SampleMissRate,
		}
		if err := validateRetentionPolicy(policy); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateAuditRetentionDays(req.DeclaredDays); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.retentionMu.Lock()
		s.retention = policy
		s.auditRetentionDays = req.DeclaredDays
		s.retentionMu.Unlock()
		log.Printf("[audit-retention] 声明已更新 declared_days=%d hot=%d warm=%d cold=%d sample_miss_rate=%d",
			req.DeclaredDays, policy.HotDays, policy.WarmDays, policy.ColdDays, policy.SampleMissRate)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auditRetentionView{
			DeclaredDays: req.DeclaredDays, HotDays: policy.HotDays, WarmDays: policy.WarmDays,
			ColdDays: policy.ColdDays, SampleMissRate: policy.SampleMissRate, Enabled: true,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
