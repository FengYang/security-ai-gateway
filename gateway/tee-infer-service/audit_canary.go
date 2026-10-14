package main

// audit_canary.go — P1-7 T15（§7.10）：租户级审计灰度开关与一键回退。
//
// 目标（本体 §7.10 T15）：保证审计改造可**安全上线**与**快速回退**——
//  ① 租户级灰度：仅对名单租户开启留痕（上线初期小流量验证）；
//  ② 一键回退：运行时关闭留痕（mode=off）或停止归档，**不回删已归档数据**；
//  ③ 开关的每次变更自身落链（action=audit_canary_change），回退操作可追溯。
//
// 三档模式（canaryMode）：
//   - all    （缺省）：所有租户留痕——生产终态，与未装配本开关时行为逐字节一致；
//   - canary ：仅 canaryTenants 名单内租户留痕（灰度）；
//   - off    ：所有租户归属事件不落链（一键回退态；控制类事件仍落链，见下）。
//
// 过滤口径（重要，写测试与 SOP 时引用）：
//   - 仅**租户归属事件**受灰度约束：TenantID 非空且不为 "-"。
//     名单外/off 态下的事件**不构造哈希、不写 WORM、不进内存链**，但**不报错**
//     （append 签名不变，请求路径无感——回退不得破坏业务）。
//   - **控制类事件**（TenantID 为空或 "-"：管理面拒绝留痕、开关变更自身、
//     锚定等）**恒落链**，不受任何档位约束——否则"回退"这一动作本身没有留痕，
//     违背审计原则；这也是 off 档仍能在链上看到"谁在何时关了审计"的原因。
//   - 被跳过的事件从未进入链 ⇒ 后续事件 PrevHash 仍指向上一条**已落链**事件，
//     哈希链连续、WORM 文件无空洞、audit-verify 复核通过（链只是更短）。
//   - 哨兵租户 _unauthenticated（网关级回灌，D-18）是真实租户形态，受灰度约束；
//     需要留痕时由运营方显式列入名单（与 A3-10 令牌绑定集合语义区分：那是上报
//     鉴权，这是留痕灰度）。
//
// 并发：canary 状态由 auditChain.mu 保护（与 append 同锁）——切换是低频运维动作，
// 每事件一次模式比较/查表可忽略；不引入第二把锁以避免锁序问题。

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
)

// canaryMode 灰度模式枚举（T15）。
type canaryMode string

const (
	// canaryAll 全量留痕（缺省；生产终态）。
	canaryAll canaryMode = "all"
	// canaryList 灰度：仅名单内租户留痕。
	canaryList canaryMode = "canary"
	// canaryOff 一键回退：租户归属事件不落链（控制类事件仍落链）。
	canaryOff canaryMode = "off"
)

// parseCanaryMode 校验并归一化模式字面量（fail-closed：未知值拒绝）。
func parseCanaryMode(s string) (canaryMode, error) {
	switch canaryMode(strings.TrimSpace(s)) {
	case canaryAll:
		return canaryAll, nil
	case canaryList:
		return canaryList, nil
	case canaryOff:
		return canaryOff, nil
	case "":
		return canaryAll, nil // 缺省 = all（与现网零差异）
	}
	return "", fmt.Errorf("未知灰度模式 %q（all|canary|off）", s)
}

// canaryView GET /audit/canary 快照（视图口径：模式 + 名单 + 累计跳过数）。
type canaryView struct {
	Mode    string   `json:"mode"`            // all|canary|off
	Tenants []string `json:"tenants"`         // canary 档生效的名单（排序稳定，便于比对）
	Skipped uint64   `json:"skipped_total"`   // 累计被灰度跳过的事件数（counter）
	Note    string   `json:"note,omitempty"`  // 档位语义说明（SOP 引用）
}

// auditCanaryReq PUT /audit/canary 请求体。
type auditCanaryReq struct {
	Mode    string   `json:"mode"`
	Tenants []string `json:"tenants,omitempty"`
}

// ---- auditChain 侧状态与方法 ----

// SetCanary 运行时切换灰度模式与名单（T15；管理端点调用，持 c.mu）。
// 校验 fail-closed：模式字面量非法 / canary 档空名单 ⇒ 拒绝且**不改变**现状态。
// 注意：调用方不得持有 c.mu（本函数自持锁）。
func (c *auditChain) SetCanary(mode, tenants string) error {
	m, err := parseCanaryMode(mode)
	if err != nil {
		return err
	}
	list := parseTenantSet(tenants)
	if m == canaryList && len(list) == 0 {
		return fmt.Errorf("canary 档要求非空租户名单（空名单等价于 off，易误操作，拒绝）")
	}
	c.mu.Lock()
	c.canaryMode = m
	c.canaryTenants = list
	c.mu.Unlock()
	log.Printf("[audit-canary] 灰度开关已切换 mode=%s tenants=%v", m, canaryTenantList(list))
	return nil
}

// CanarySnapshot 读取灰度状态快照（并发安全；端点 GET 与 /config 暴露用）。
func (c *auditChain) CanarySnapshot() (mode canaryMode, tenants []string, skipped uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.canaryMode, canaryTenantList(c.canaryTenants), c.canarySkipped
}

// canaryAllowsLocked 判定租户归属事件是否允许落链（调用方须持 c.mu）。
// 控制类事件（TenantID 空或 "-"）恒允许；其余按模式过滤。
// 返回 false 时累加跳过计数（counter，无标签——租户基数不可控，防指标爆炸）。
func (c *auditChain) canaryAllowsLocked(tenant string) bool {
	if tenant == "" || tenant == "-" {
		return true // 控制类事件：任何档位恒落链
	}
	switch c.canaryMode {
	case canaryList:
		if c.canaryTenants[tenant] {
			return true
		}
	case canaryOff:
		// 不回退控制类事件（上面已放过）；租户归属事件一律跳过。
	default: // canaryAll
		return true
	}
	c.canarySkipped++
	if c.onCanarySkip != nil {
		c.onCanarySkip() // T15 指标：otpmask_audit_canary_skipped_total
	}
	return false
}

// ---- 管理端点（管理令牌之下，与 /audit/retention 同档）----

// handleAuditCanary GET/PUT /audit/canary（T15 灰度开关读写）。
//
//	GET   返回当前快照 {mode, tenants, skipped_total}
//	PUT   切换 {mode, tenants}；校验 fail-closed；成功后把切换动作自身落链
//	      （tenant="-" 控制类事件，恒落链 ⇒ off 档下回退动作仍有留痕）。
func (s *teeServer) handleAuditCanary(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(r) {
		s.auditAdminExit(r, "audit_canary_change", "rejected_forbidden", http.StatusForbidden)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		mode, tenants, skipped := s.audit.CanarySnapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(canaryView{
			Mode:    string(mode),
			Tenants: tenants,
			Skipped: skipped,
			Note:    canaryNote(mode),
		})
	case http.MethodPut:
		var req auditCanaryReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			s.auditAdminExit(r, "audit_canary_change", "rejected_bad_request", http.StatusBadRequest)
			http.Error(w, "非法请求体: "+err.Error(), http.StatusBadRequest)
			return
		}
		m, err := parseCanaryMode(req.Mode)
		if err != nil {
			s.auditAdminExit(r, "audit_canary_change", "rejected_bad_request", http.StatusBadRequest)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		joined := strings.Join(req.Tenants, ",")
		if m == canaryList && len(parseTenantSet(joined)) == 0 {
			s.auditAdminExit(r, "audit_canary_change", "rejected_bad_request", http.StatusBadRequest)
			http.Error(w, "canary 档要求非空 tenants 名单", http.StatusBadRequest)
			return
		}
		if err := s.audit.SetCanary(string(m), joined); err != nil {
			// SetCanary 内部二次校验（并发下理论上不可达）；按 500 处置并留痕。
			s.auditAdminExit(r, "audit_canary_change", "rejected_invalid", http.StatusInternalServerError)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 开关变更自身落链（T15③；tenant="-" ⇒ 任何档位恒落链，含 off 档回退动作）。
		// 事件构造对齐既有控制类留痕（output_guard_policy_reload，main.go:2616）：
		// TenantID="-" + Origin 留空（=tee 本进程）+ actor/reqID 取请求头。
		s.audit.append(AuditEvent{
			TenantID:  "-",
			UserID:    r.Header.Get("X-Admin-Actor"),
			RequestID: r.Header.Get("X-Request-ID"),
			Action:    "audit_canary_change",
			Result:    "ok",
		})
		mode, tenants, skipped := s.audit.CanarySnapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(canaryView{
			Mode:    string(mode),
			Tenants: tenants,
			Skipped: skipped,
			Note:    canaryNote(mode),
		})
	default:
		recordExemptExit("handleAuditCanary", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// canaryNote 档位语义一句话（随快照返回，SOP 可直接引用，避免口径漂移）。
func canaryNote(m canaryMode) string {
	switch m {
	case canaryList:
		return "灰度中：仅名单内租户留痕；控制类事件（tenant=-）恒落链"
	case canaryOff:
		return "已回退：租户归属事件不落链（已落数据不回删）；控制类事件仍落链"
	default:
		return "全量留痕（生产终态）"
	}
}

// canaryTenantList 稳定排序的名单视图（map 遍历顺序随机，端点快照须可比对）。
// 注：与 outputguard_golden_test.go 的 sortedKeys（map[string]int）同名不同签名，故另起名。
func canaryTenantList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
