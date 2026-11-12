// accel_schedule.go — M5-2 加速后端动态调度（与 AccelPool 同进程，技术方案 §4.2/计划 M5-2）。
//
// 端点（管理令牌之下，沿用 /config/* 惯例）：
//   - GET  /config/accel          只读快照（候选列表/当前默认/路由表版本）
//   - GET  /config/accel/routes   路由表快照
//   - POST /config/accel/routes   原子换入路由表（按 tenant/model/请求 hint 优先级解析）
//   - POST /config/accel/switch   运行期切换全局默认后端（执行 masked-infer SwitchDefaultBackend）
//
// 信任输入不变：所有 backend key 必须是安装期候选列表（ACCEL_BACKEND_LIB）内的
// 受信绝对路径；非法 key 一律拒绝（fail-closed），不新增远程加载能力（INV-3）。
// 变更落审计（action/result/detail），失败保持旧表/旧默认不变（fail-safe）。

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	maskedinfer "github.com/FengYang/masked-infer/core"
)

// accelRoute 一条调度规则（tenant/model 支持 "*" 通配）。
type accelRoute struct {
	Tenant  string `json:"tenant"`
	Model   string `json:"model"`
	Backend string `json:"backend"` // 候选列表内 key 或 ""（= 全局默认）
}

// accelRouteTable 不可变路由表快照（atomic.Pointer 换入，评估无锁读）。
type accelRouteTable struct {
	routes    map[string]string // "tenant|model" → backend key
	version   string            // 规范化内容 sha256 前 12 位（进审计与快照）
	updatedAt int64
	raw       []accelRoute
}

// accelScheduler 调度器（候选列表在构造期固定；表变更原子换入）。
type accelScheduler struct {
	cur         atomic.Pointer[accelRouteTable]
	candidates  map[string]bool
	candidateLs []string
	onAudit     func(action, result, detail string)
}

func newAccelScheduler() *accelScheduler {
	s := &accelScheduler{candidates: map[string]bool{}}
	s.candidateLs = maskedinfer.AccelCandidates()
	for _, k := range s.candidateLs {
		s.candidates[k] = true
	}
	s.cur.Store(&accelRouteTable{routes: map[string]string{}, raw: []accelRoute{}})
	return s
}

// normalizeRoutes 规范化 + 校验（非法 key / 重复规则 / 空字段一律拒绝）。
func (s *accelScheduler) normalizeRoutes(routes []accelRoute) ([]accelRoute, error) {
	seen := map[string]bool{}
	out := make([]accelRoute, 0, len(routes))
	for i, r := range routes {
		r.Tenant, r.Model, r.Backend = strings.TrimSpace(r.Tenant), strings.TrimSpace(r.Model), strings.TrimSpace(r.Backend)
		if r.Tenant == "" || r.Model == "" {
			return nil, fmt.Errorf("routes[%d]: tenant/model 不可为空（通配用 \"*\"）", i)
		}
		if r.Backend != "" && !s.candidates[r.Backend] {
			return nil, fmt.Errorf("routes[%d]: backend %q 不在安装期候选列表（拒绝运行期注入）", i, r.Backend)
		}
		key := r.Tenant + "|" + r.Model
		if seen[key] {
			return nil, fmt.Errorf("routes[%d]: 重复规则 tenant=%s model=%s", i, r.Tenant, r.Model)
		}
		seen[key] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tenant+"|"+out[i].Model < out[j].Tenant+"|"+out[j].Model })
	return out, nil
}

// SetRoutes 原子换入路由表（失败保持旧表）；变更落审计。
func (s *accelScheduler) SetRoutes(routes []accelRoute) (string, error) {
	norm, err := s.normalizeRoutes(routes)
	if err != nil {
		if s.onAudit != nil {
			s.onAudit("accel_routes_change", "rejected", err.Error())
		}
		return "", err
	}
	b, _ := json.Marshal(norm)
	sum := sha256.Sum256(b)
	tbl := &accelRouteTable{
		routes: map[string]string{}, version: hex.EncodeToString(sum[:])[:12],
		updatedAt: time.Now().UnixNano(), raw: norm,
	}
	for _, r := range norm {
		tbl.routes[r.Tenant+"|"+r.Model] = r.Backend
	}
	s.cur.Store(tbl)
	if s.onAudit != nil {
		s.onAudit("accel_routes_change", "applied", "version="+tbl.version+" routes="+fmt.Sprint(len(norm)))
	}
	return tbl.version, nil
}

// HintFor 解析本请求应使用的后端 hint（优先级：请求显式 > 精确 > 租户通配 >
// 模型通配 > 全局通配 > ""=池默认）。请求 hint 仅接受候选列表内 key。
func (s *accelScheduler) HintFor(tenant, model, reqHint string) string {
	if h := strings.TrimSpace(reqHint); h != "" && s.candidates[h] {
		return h
	}
	tbl := s.cur.Load()
	if tbl == nil {
		return ""
	}
	for _, key := range []string{
		tenant + "|" + model, tenant + "|*", "*|" + model, "*|*",
	} {
		if v, ok := tbl.routes[key]; ok {
			return v // v="" 亦为显式规则：走池默认
		}
	}
	return ""
}

// Snapshot 只读快照（管理端点/对账）。
func (s *accelScheduler) Snapshot() map[string]any {
	tbl := s.cur.Load()
	return map[string]any{
		"candidates":      append([]string(nil), s.candidateLs...),
		"current_default": maskedinfer.CurrentDefaultBackend(),
		"routes":          append([]accelRoute(nil), tbl.raw...),
		"version":         tbl.version,
		"updated_at":      tbl.updatedAt,
	}
}

// audit 便利方法（审计链由 main 装配；nil 时仅日志）。
func (s *accelScheduler) audit(action, result, detail string) {
	if s.onAudit != nil {
		s.onAudit(action, result, detail)
	}
}

// ---------- 管理端点 ----------

func (s *teeServer) accelConfigOrDenied(w http.ResponseWriter, r *http.Request, action string) bool {
	if !s.checkAdmin(r) {
		s.accelSched.audit(action, "rejected_admin_auth", "")
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
		return false
	}
	return true
}

// handleAccelConfig GET /config/accel：只读快照。
func (s *teeServer) handleAccelConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.accelConfigOrDenied(w, r, "accel_config_read") {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.accelSched.Snapshot())
}

// handleAccelRoutes GET/POST /config/accel/routes：路由表读写（POST 须管理令牌 + 落审计）。
func (s *teeServer) handleAccelRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.accelConfigOrDenied(w, r, "accel_routes_read") {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.accelSched.Snapshot())
	case http.MethodPost:
		if !s.accelConfigOrDenied(w, r, "accel_routes_change") {
			return
		}
		var req struct {
			Routes []accelRoute `json:"routes"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			s.accelSched.audit("accel_routes_change", "rejected_bad_request", err.Error())
			http.Error(w, "请求体须为 JSON（routes[]）", http.StatusBadRequest)
			return
		}
		version, err := s.accelSched.SetRoutes(req.Routes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied", "version": version})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAccelSwitch POST /config/accel/switch：运行期切换全局默认后端。
func (s *teeServer) handleAccelSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.accelConfigOrDenied(w, r, "accel_default_switch") {
		return
	}
	var req struct {
		Backend string `json:"backend"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		s.accelSched.audit("accel_default_switch", "rejected_bad_request", err.Error())
		http.Error(w, "请求体须为 JSON（backend）", http.StatusBadRequest)
		return
	}
	backend := strings.TrimSpace(req.Backend)
	if !s.accelSched.candidates[backend] {
		s.accelSched.audit("accel_default_switch", "rejected_untrusted_key", backend)
		http.Error(w, "backend 不在安装期候选列表（拒绝运行期注入）", http.StatusBadRequest)
		return
	}
	if err := maskedinfer.SwitchDefaultBackend(backend); err != nil {
		s.accelSched.audit("accel_default_switch", "rejected_engine", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.accelSched.audit("accel_default_switch", "applied", "backend="+backend)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "applied", "current_default": maskedinfer.CurrentDefaultBackend(),
	})
}
