package main

// P1-7 T4（MOD3 脱敏规则引擎）。
//
// 设计目标（§7.4 / D-6 / C-1 / C-2）：
//   - allow-list 由 AuditEvent 的 JSON tag **反射生成**（新增证据字段加 tag 即自动纳入，
//     防文档/代码双写漂移）；
//   - 写链前与导出前对事件做白名单裁剪 + 自由文本长度上限 + path 去 query 值，
//     确保链上与导出**永不出现** prompt/response 原文、embedding 向量、密钥材料；
//   - TEE 侧 `result` 取值做**登记与告警**（A3-20/R-17）：非登记值**不改写事件、不拒绝落链**，
//     仅打点计数（由 T3b 产出权威 action×result 矩阵后替换本 interim 登记集）。
//
// 调用点（显式，避免改动已验证的 append 核心路径）：
//   - 数据面上报 ingestion（T2a 构造 AuditEvent 后）；
//   - 既有 TEE 落链点填充（T3a）；
//   - 归档/导出前二次裁剪兜底（T8/T9，D-6）。

import (
	"encoding/json"
	"log"
	"reflect"
	"strings"
	"sync"
)

// redactMaxFieldBytes 自由文本字段长度上限（§7.4）。超长截断并计数。
const redactMaxFieldBytes = 1024

var (
	auditAllowList     map[string]struct{}
	auditAllowListOnce sync.Once
)

// allowListFromStruct 反射 AuditEvent 的 JSON tag（去 omitempty）生成白名单全集（§6.1(A)）。
// 白名单 = 所有 json 字段名；任何不在此集合的键（prompt/response/key/embedding 等）一律丢弃。
func allowListFromStruct() map[string]struct{} {
	auditAllowListOnce.Do(func() {
		m := map[string]struct{}{}
		t := reflect.TypeOf(AuditEvent{})
		for i := 0; i < t.NumField(); i++ {
			tag := t.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "" {
				continue
			}
			m[name] = struct{}{}
		}
		auditAllowList = m
	})
	return auditAllowList
}

// RedactRaw 对外部 JSON（扁平 map，字段名须为 AuditEvent JSON 名）做 allow-list 裁剪：
// 仅保留白名单键，丢弃任意敏感键（C-1/C-2）。用于数据面上报 ingestion 与导出前二次裁剪兜底（D-6）。
// 返回裁剪后字节；非法输入原样返回错误（交由调用方按 400 处理）。
func RedactRaw(raw []byte) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	allow := allowListFromStruct()
	clean := make(map[string]interface{}, len(m))
	for k, v := range m {
		if _, ok := allow[k]; ok {
			clean[k] = v
		}
	}
	return json.Marshal(clean)
}

// redactTruncateFields 可安全截断的自由文本字段。
// 链关键字段（request_id/event_id/prev_hash/payload_hash/hash_alg/instance_id 等）**不在列**，
// 避免截断破坏哈希链/幂等（C-3）。
var redactTruncateFields = map[string]bool{
	"path": true, "model": true, "hit_policies": true, "user_id": true,
	"tenant_id": true, "origin": true, "path_mode": true,
	"reporter_id": true, "mcp_session_id": true, "tenant_id_resolution": true,
	"mcp_tool": true, "mcp_reason": true,
}

// truncateField 超长字段截断为 redactMaxFieldBytes 并计数；未超长原样返回。
func truncateField(s string) string {
	if len(s) <= redactMaxFieldBytes {
		return s
	}
	if auditMetrics != nil {
		auditMetrics.incAuditRedactTruncated()
	}
	return s[:redactMaxFieldBytes]
}

// redactEvent 对 typed 审计事件做脱敏（path 去 query 值 + 自由文本长度上限 + result 取值登记）。
// 纯内存操作，不产生业务失败；返回（副本）。**不改写 result**（A3-20：登记不改链、不拒落链）。
func redactEvent(e *AuditEvent) *AuditEvent {
	out := *e
	// path 规范化：去 query 值（只保留路径，防 query 泄漏密钥/令牌，D-6）。
	if i := strings.IndexByte(out.Path, '?'); i >= 0 {
		out.Path = out.Path[:i]
	}
	out.Path = truncateField(out.Path)
	out.Model = truncateField(out.Model)
	out.HitPolicies = truncateField(out.HitPolicies)
	out.UserID = truncateField(out.UserID)
	out.TenantID = truncateField(out.TenantID)
	out.Origin = truncateField(out.Origin)
	out.PathMode = truncateField(out.PathMode)
	out.ReporterID = truncateField(out.ReporterID)
	out.MCPSessionID = truncateField(out.MCPSessionID)
	out.TenantIDResolution = truncateField(out.TenantIDResolution)
	out.MCPTool = truncateField(out.MCPTool)
	out.MCPReason = truncateField(out.MCPReason)
	// result 取值登记与告警（A3-20/R-17）。
	registerResultValue(out.Result)
	return &out
}

// ---- TEE 侧 result 取值登记（权威矩阵由 T3b 产出，V-14）----
//
// T3b 已产出「action × result 组合矩阵」（docs/详细设计/P1/审计落链覆盖矩阵.md）；
// 本集合即该矩阵的代码侧登记基准。非登记值仅打点计数 + 告警，**不改写事件、不拒绝落链**
// （A3-20/R-17，避免与 C-3/C-7 冲突）。

// knownResultExact 已知合法 result 取值（精确匹配）。覆盖：TEE 实测冻结集（§6.1(D)）+ 数据面
// 上报 7 项白名单（§6.5；v1.13 由 6 项增补 consumer_unauthorized，T-4）
// + 既有 deny/would_reject + T3b 新增出口的精确取值。
var knownResultExact = map[string]bool{
	"ok": true, "deny": true, "would_reject": true,
	"route_rejected": true, "unknown_nonce": true, "quota_exceeded": true,
	"decrypt_error": true, "engine_unavailable": true, "encrypt_error": true,
	"text_without_session": true, "text_payload_invalid": true,
	"bad_signature": true, "replay_attack": true,
	"cache_negative": true, "cache_hit": true, "cache_hit_dataplane": true,
	"output_blocked": true, "output_masked": true, "shadow_reject": true,
	"rate_limited": true, "auth_failed": true, "ip_blocked": true,
	// 【v1.13 新增·T-4】403 路由授权拒绝子类（实测可归真实租户），与 ip_blocked 语义相反。
	"consumer_unauthorized": true,
	"non_infer": true, "quota_deny": true, "rpm_limit": true,
	"tpm_limit": true, "daily_budget": true,
	// T3b：请求体超限（limitBody 413）。
	"body_too_large": true,
	// T3b：管理面/数据面接口失败出口的统一 rejection 结果（精确项，非族）。
	"rejected_public_facing_lock": true,
}

// knownResultPrefix 已知合法 result 前缀族（* 通配）。
//
// §6.1(B) 枚举族：guardrail_ / mcp_ / recompute_；
// T3b 出口族：attest_（挑战-响应）/ attest_complete_ / keyissue_ / tenant_auth_ / report_
// （数据面上报 D-13 防护）/ infer_（推理面读取失败）/ rejected_（B 类管理面/数据面接口失败）。
var knownResultPrefix = []string{
	"guardrail_", "mcp_", "recompute_",
	"attest_", "keyissue_", "tenant_auth_", "report_", "infer_", "rejected_",
}

// isRegisteredResult 判断 result 是否为登记合法值（精确或前缀族匹配）。
func isRegisteredResult(r string) bool {
	if r == "" {
		return true // 空 = 缺省（部分事件无 result 语义），不记为异常
	}
	if knownResultExact[r] {
		return true
	}
	for _, p := range knownResultPrefix {
		if strings.HasPrefix(r, p) {
			return true
		}
	}
	return false
}

// registerResultValue 对非登记 result 取值做计数 + 告警（A3-20/R-17）。
// 不改写事件、不拒绝落链（避免与 C-3/C-7 冲突）。
func registerResultValue(result string) {
	if isRegisteredResult(result) {
		return
	}
	if auditMetrics != nil {
		auditMetrics.incAuditUnregisteredResult()
	}
	log.Printf("[audit] 非登记 result 取值（仅登记告警，不改链、不拒落链）: %q", result)
}
