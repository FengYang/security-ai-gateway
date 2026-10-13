// S4-4：租户处置状态机（SaaS 版，build tag saas）。
// 四状态：warning → throttled → suspended → terminated。
// 私有化部署不编译此文件，减少二进制体积与攻击面。
//
//go:build saas

package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// 处置状态枚举（从轻到重）。
const (
	dispositionWarning    = "warning"    // 警告：正常服务，仅标记
	dispositionThrottled  = "throttled"  // 限流：允许推理但降速
	dispositionSuspended  = "suspended"  // 暂停：拒绝推理请求
	dispositionTerminated = "terminated" // 终止：拒绝+密钥失效（最严重）
)

// 有效状态集合（校验用）。
var validDispositions = map[string]bool{
	dispositionWarning:    true,
	dispositionThrottled:  true,
	dispositionSuspended:  true,
	dispositionTerminated: true,
}

// 阻断服务的状态（suspended / terminated → 拒绝推理）。
var blockingDispositions = map[string]bool{
	dispositionSuspended:  true,
	dispositionTerminated: true,
}

// tenantDispositionRecord 单租户处置记录。
type tenantDispositionRecord struct {
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Actor     string `json:"actor"`
	SetAtNS   int64  `json:"set_at_ns"`
	RequestID string `json:"request_id,omitempty"`
}

// tenantDispositionStore 内存态租户处置存储（SaaS 轻量版）。
// 持久化由 gateway-admin-service 的 D8 变更事件驱动，此处仅内存缓存。
type tenantDispositionStore struct {
	mu           sync.RWMutex
	dispositions map[string]*tenantDispositionRecord
	audit        *auditChain
}

func newTenantDispositionStore(a *auditChain) *tenantDispositionStore {
	return &tenantDispositionStore{
		dispositions: make(map[string]*tenantDispositionRecord),
		audit:        a,
	}
}

// Check 推理入口检查：返回是否允许继续推理 + 拒绝原因（若拒绝）。
// warning / throttled 放行（throttled 的速率限制由 quota 系统承担，此处仅打标）；
// suspended / terminated 直接拒绝。
func (s *tenantDispositionStore) Check(tenant string) (allowed bool, reason string) {
	if s == nil || tenant == "" {
		return true, ""
	}
	s.mu.RLock()
	rec, ok := s.dispositions[tenant]
	s.mu.RUnlock()
	if !ok {
		return true, ""
	}
	if blockingDispositions[rec.State] {
		return false, "tenant_disposition: " + rec.State + " (" + rec.Reason + ")"
	}
	return true, ""
}

// Set 设置租户处置状态（幂等）。
func (s *tenantDispositionStore) Set(tenant, state, actor, reason, requestID string) error {
	if s == nil {
		return nil
	}
	if !validDispositions[state] {
		return errBadDispositionState
	}
	if tenant == "" {
		return errEmptyTenant
	}
	s.mu.Lock()
	old := s.dispositions[tenant]
	s.dispositions[tenant] = &tenantDispositionRecord{
		State:     state,
		Reason:    reason,
		Actor:     actor,
		SetAtNS:   time.Now().UnixNano(),
		RequestID: requestID,
	}
	s.mu.Unlock()

	if s.audit != nil {
		oldState := ""
		if old != nil {
			oldState = old.State
		}
		s.audit.append(AuditEvent{
			TenantID:  tenant,
			UserID:    actor,
			RequestID: requestID,
			Action:    "tenant_disposition_change",
			Result:    state,
			// 附加证据：状态迁移轨迹（与 OG 类审计的 TransformedHash 同性质，不进 hash()）
			TransformedHash: "from=" + oldState + " to=" + state,
		})
	}
	return nil
}

// Snapshot 导出全部处置状态（GET 只读视图）。
func (s *tenantDispositionStore) Snapshot() map[string]*tenantDispositionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*tenantDispositionRecord, len(s.dispositions))
	for k, v := range s.dispositions {
		rec := *v
		out[k] = &rec
	}
	return out
}

// handleTenantDisposition 处置状态管理端点（D8 高敏变更，受管理员认证保护）。
//
//	GET  /config/tenant-disposition          查看全部租户处置状态
//	POST /config/tenant-disposition          设置单租户处置状态（body: {tenant,state,reason}）
func (s *teeServer) handleTenantDisposition(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		s.auditAdminExit(r, "tenant_disposition_change", "rejected_admin_auth", http.StatusUnauthorized)
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return
	}
	store, ok := s.disposition.(*tenantDispositionStore)
	if !ok || store == nil {
		s.auditAdminExit(r, "tenant_disposition_change", "rejected_not_found", http.StatusNotFound)
		http.Error(w, "tenant disposition not enabled (SaaS mode)", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		snap := store.Snapshot()
		// 按 tenant 排序输出，方便 diff
		keys := make([]string, 0, len(snap))
		for k := range snap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make([]map[string]any, 0, len(keys))
		for _, k := range keys {
			rec := snap[k]
			ordered = append(ordered, map[string]any{
				"tenant":      k,
				"state":       rec.State,
				"reason":      rec.Reason,
				"actor":       rec.Actor,
				"set_at_ns":   rec.SetAtNS,
				"request_id":  rec.RequestID,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"dispositions": ordered})

	case http.MethodPost:
		var body struct {
			Tenant string `json:"tenant"`
			State  string `json:"state"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			s.auditAdminExit(r, "tenant_disposition_change", "rejected_bad_request", http.StatusBadRequest)
			http.Error(w, "请求体解析失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		actor := r.Header.Get("X-Admin-Actor")
		reqID := r.Header.Get("X-Request-ID")
		if err := store.Set(body.Tenant, body.State, actor, body.Reason, reqID); err != nil {
			s.auditAdminExit(r, "tenant_disposition_change", "rejected_bad_request", http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"tenant": body.Tenant,
			"state":  body.State,
		})

	default:
		recordExemptExit("handleTenantDisposition", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// initTenantDisposition SaaS 构建下初始化租户处置存储并注册管理端点。
func initTenantDisposition(s *teeServer, mux *http.ServeMux) {
	s.disposition = newTenantDispositionStore(s.audit)
	mux.HandleFunc("/config/tenant-disposition", s.handleTenantDisposition)
}
