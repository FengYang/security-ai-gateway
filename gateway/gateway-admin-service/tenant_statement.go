// Package main — N4 · 承诺边界声明生成（§4.3.4，V-S5）。
//
// 端点：
//
//	GET  /v1/adminext/tenant/statement              当前生效承诺边界声明（租户会话，§6.12）
//	POST /v1/adminext/tenant-statements/reissue     运维批量重签发（管理面内部端点，admin；触发③）
//
// 职责：按场景与接入形态自动生成"对外承诺边界声明"，防误导性安全承诺；生成后**即存证**于
// 表 ⑨ tenant_statements（content 全文 + content_hash + supersedes 重签链），防事后篡改承诺口径。
//
// 生成触发（§4.3.4 item 7）：① N1 开通完成生成首版；② 场景/可信域档/接入形态变更重签
// （supersedes 前一版，关联审计 `provisioning_update`）；③ 模板版本升级由运维任务批量重签发
// （逐租户 supersedes，落审计 `statement_reissue`）。模板以 Go 常量 + 版本号内置（不引外部文件，
// 避免声明口径与二进制不同步）。
//
// 红线校验（V-S5，生成即校验，违规 fail-closed 绝不落存证）：
//   - A 型声明不含"端到端"（接入形态恒 A 型分段密态，禁 B 型/端到端口径）；
//   - S3-b 声明不含"整链在 TEE 内"/"整条链路在 TEE 内"；
//   - S2 必须披露"证明未闭环"（C-19）；
//   - 全局禁"官方合作/官方认证"（未经授权）与"转售"（D-6 红线）。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// 端点路径。
const (
	tenantStatementPath        = tenantSessionBase + "/statement"
	adminStatementsReissuePath = "/v1/adminext/tenant-statements/reissue"
)

// 模板版本与内容 schema 版本（Go 常量 + 版本号内置，§4.3.4 item 7）。
const (
	statementTemplateVersion = "n4-1.0.0"
	statementContentVersion  = "n4/1"
)

// 各场景"明文边界"基线（红线安全口径：A 型一律不出现"端到端"字样）。
const (
	statementPlaintextS1 = "明文在客户可信域（私有化机房 / 客户 VPC）内处理，无 TEE 要求；" +
		"我方提供网关侧治理，不涉及密态通道。"
	statementPlaintextS2 = "分段密态（A 型治理）：明文在企业可信域经 tee-infer 短暂存在后转第三方厂商密态通道；" +
		"我方提供网关侧治理，属分段密态而非全程密态，不作全程密态承诺。"
	statementPlaintextS3a = "明文在 TEE 飞地内处理，不出飞地（含显存须 GPU-CC 支持）；" +
		"治理（段① / Guardrail / 语义缓存 / 审计链）均在飞地内完成。"
	statementPlaintextS3b = "明文不出扩展信任域；多机多卡跨节点经 mTLS 密态互联，" +
		"调度层（llm-d 等）可能接触明文（Q-9），不作明文全程不出 TEE 的承诺。"
	statementPlaintextS4 = "明文不出扩展信任域（路线2 掩码向量后端）；掩码向量引擎经密钥信封保护，" +
		"治理（段① / Guardrail / 审计链）均在受控域内完成。"
)

// statementPlaintextBoundary 场景 → 明文边界基线文案。
func statementPlaintextBoundary(scenario string) (string, bool) {
	switch scenario {
	case scenarioS1:
		return statementPlaintextS1, true
	case scenarioS2:
		return statementPlaintextS2, true
	case scenarioS3a:
		return statementPlaintextS3a, true
	case scenarioS3b:
		return statementPlaintextS3b, true
	case scenarioS4:
		return statementPlaintextS4, true
	}
	return "", false
}

// statementContent 声明全文（JSON 存证；字段均为对外承诺口径，禁含密钥 / 凭据 / 指纹）。
type statementContent struct {
	SchemaVersion     string   `json:"schema_version"`
	TenantID          string   `json:"tenant_id"`
	Scenario          string   `json:"scenario"`
	TrustTier         string   `json:"trust_tier"`
	AccessMode        string   `json:"access_mode"`
	Segment2Mode      string   `json:"segment2_mode,omitempty"`
	Headline          string   `json:"headline"`
	PlaintextBoundary string   `json:"plaintext_boundary"`
	Governance        []string `json:"governance"`
	Disclosures       []string `json:"disclosures"`
	TemplateVersion   string   `json:"template_version"`
	GeneratedAt       int64    `json:"generated_at"`
}

// StatementInput 声明生成输入快照（场景 / 可信域档 / 接入形态）。
type StatementInput struct {
	TenantID        string
	Scenario        string
	TrustTier       string
	AccessMode      string
	Segment2Mode    string
	GeneratedAt     int64
	TemplateVersion string // 空 = 用内置当前版本
}

// statementGovernance 治理面上限说明（按场景；内容来自 §3.6.2 矩阵）。
func statementGovernance(scenario string) []string {
	g := []string{
		"网关侧治理：内容安全（qwen3guard）、Token 限流（ai-token-ratelimit）、配额（ai-quota）、" +
			"IP 白名单（ip-restriction）、请求校验（request-validation）、全量审计链。",
	}
	switch scenario {
	case scenarioS3a, scenarioS3b, scenarioS4:
		g = append(g, "密态轨自研组件：段① otpmask、Guardrail、语义缓存、审计锚点，均在受控信任域内完成。")
	}
	return g
}

// statementDisclosures 必要披露项（B 型边界 / 非可信部署 / S2 未闭环 / S3-b 调度层明文）。
func statementDisclosures(scenario, trustTier string) []string {
	d := []string{
		"客户绕过网关直连第三方时为纯第三方（B 型）形态：我方治理能力不适用，" +
			"其证明由厂商出具、覆盖层级以厂商声明为准。",
	}
	if trustTier == trustTierUntrusted {
		d = append(d, "非可信基础设施下，门户控制面自身经 TEE 化（N10）：密钥不出域、最小明文面、"+
			"启动度量自检 fail-closed。")
	}
	switch scenario {
	case scenarioS2:
		d = append(d, "厂商远程证明未闭环：第三方证明通道尚未打通（我方验证器当前为自签），"+
			"证明结论仅供参考。")
	case scenarioS3b:
		d = append(d, "多机多卡跨节点密态互联为业界空白（Q-9）：调度层（llm-d 等）可能接触明文，"+
			"故不作明文全程不出 TEE 的承诺。")
	}
	return d
}

// buildStatementContent 生成声明全文（纯函数）。
func buildStatementContent(in StatementInput) (*statementContent, error) {
	scenario := strings.ToLower(strings.TrimSpace(in.Scenario))
	boundary, ok := statementPlaintextBoundary(scenario)
	if !ok {
		return nil, fmt.Errorf("tenant: 未知场景 %q（无法生成声明）", in.Scenario)
	}
	accessMode := strings.TrimSpace(in.AccessMode)
	if accessMode == "" {
		accessMode = accessModeASegmented
	}
	trust := strings.TrimSpace(in.TrustTier)
	if trust == "" {
		trust = trustTierTrusted
	}
	ver := strings.TrimSpace(in.TemplateVersion)
	if ver == "" {
		ver = statementTemplateVersion
	}
	return &statementContent{
		SchemaVersion:     statementContentVersion,
		TenantID:          in.TenantID,
		Scenario:          scenario,
		TrustTier:         trust,
		AccessMode:        accessMode,
		Segment2Mode:      in.Segment2Mode,
		Headline:          "承诺边界声明（场景 " + scenario + "，A 型分段密态，治理由我方提供）",
		PlaintextBoundary: boundary,
		Governance:        statementGovernance(scenario),
		Disclosures:       statementDisclosures(scenario, trust),
		TemplateVersion:   ver,
		GeneratedAt:       in.GeneratedAt,
	}, nil
}

// statementRedlineBanned 全局红线禁词（声明口径不得出现）。
var statementRedlineBanned = []string{"官方合作", "官方认证", "转售"}

// statementRedlineError 声明红线违规（生成即 fail-closed，绝不落存证）。
type statementRedlineError struct{ Reason string }

func (e *statementRedlineError) Error() string { return "tenant: 声明红线违规：" + e.Reason }

// checkStatementRedlines 红线校验（V-S5）。
func checkStatementRedlines(scenario, accessMode, content string) error {
	for _, w := range statementRedlineBanned {
		if strings.Contains(content, w) {
			return &statementRedlineError{Reason: "含禁词 " + w}
		}
	}
	// A 型（分段密态）不得宣称端到端。
	if accessMode == accessModeASegmented && strings.Contains(content, "端到端") {
		return &statementRedlineError{Reason: "A 型声明不得含“端到端”"}
	}
	// S3-b 不得宣称整链在 TEE 内。
	if scenario == scenarioS3b {
		for _, w := range []string{"整链在 TEE 内", "整条链路在 TEE 内"} {
			if strings.Contains(content, w) {
				return &statementRedlineError{Reason: "S3-b 声明不得含“" + w + "”"}
			}
		}
	}
	// S2 强制披露证明未闭环（C-19）。
	if scenario == scenarioS2 && !strings.Contains(content, "未闭环") {
		return &statementRedlineError{Reason: "S2 声明必须披露“证明未闭环”（C-19）"}
	}
	return nil
}

// renderStatementContent 生成声明 content JSON + content_hash + template_version，并做红线校验。
func renderStatementContent(in StatementInput) (content, hash, ver string, err error) {
	c, err := buildStatementContent(in)
	if err != nil {
		return "", "", "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", "", "", fmt.Errorf("tenant: 声明序列化失败: %w", err)
	}
	content = string(raw)
	if err := checkStatementRedlines(c.Scenario, c.AccessMode, content); err != nil {
		return "", "", "", err
	}
	return content, sha256Hex(content), c.TemplateVersion, nil
}

// ---------- 存证（表 ⑨）----------

// reissueStatementCore 重签并存证承诺边界声明（N1 触发② / 运维批量触发③ 共用）：
// supersedes 指向当前生效版本；auditReissue=true 时落 `statement_reissue` 审计（target=statement_id）。
func (h *tenantHandler) reissueStatementCore(tenantID, reason string, now int64, auditReissue bool, actor string) (string, error) {
	prov, err := h.store.GetProvisioning(tenantID)
	if err != nil {
		return "", err
	}
	if prov == nil {
		return "", nil // 未开通 → 无声明（首版随 N1 开通生成）
	}
	cur, err := h.store.GetCurrentStatement(tenantID)
	if err != nil {
		return "", err
	}
	content, hash, ver, err := renderStatementContent(StatementInput{
		TenantID:     prov.TenantID,
		Scenario:     prov.Scenario,
		TrustTier:    prov.TrustTier,
		AccessMode:   prov.AccessMode,
		Segment2Mode: prov.Segment2Mode,
		GeneratedAt:  now,
	})
	if err != nil {
		return "", err
	}
	rid, err := randomToken(6) // st- + 12 位随机
	if err != nil {
		return "", fmt.Errorf("tenant: 生成声明 ID 失败: %w", err)
	}
	st := &TenantStatement{
		StatementID:     "st-" + rid,
		TenantID:        prov.TenantID,
		Scenario:        prov.Scenario,
		AccessMode:      prov.AccessMode,
		TemplateVersion: ver,
		Content:         content,
		ContentHash:     hash,
		CreatedAt:       now,
	}
	if cur != nil {
		st.SupersedesID = cur.StatementID
	}
	tx, err := h.store.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.CreateStatement(tx, st); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if auditReissue {
		// 附录 D：Target=statement_id；Tenant 标注归属；Detail=模板版本/被取代版本/原因。
		h.auditAppendTenantDetail(actor, auditActionStatementReissue, tenantID, st.StatementID,
			fmt.Sprintf("template_version=%s supersedes=%s reason=%s", ver, st.SupersedesID, reason))
	}
	return st.StatementID, nil
}

// reissueStatementForTenant N1 联动入口（触发②；审计由 provisioning_update 覆盖，不重复落 statement_reissue）。
func (h *tenantHandler) reissueStatementForTenant(tenantID string) error {
	_, err := h.reissueStatementCore(tenantID, "provisioning_change", time.Now().Unix(), false, "")
	return err
}

// ---------- 端点：租户读当前生效声明 ----------

// statementView GET /tenant/statement 响应（content 为声明全文 JSON）。
type statementView struct {
	Available       bool            `json:"available"`
	StatementID     string          `json:"statement_id,omitempty"`
	Scenario        string          `json:"scenario,omitempty"`
	AccessMode      string          `json:"access_mode,omitempty"`
	TemplateVersion string          `json:"template_version,omitempty"`
	ContentHash     string          `json:"content_hash,omitempty"`
	Content         json.RawMessage `json:"content,omitempty"`
	CreatedAt       int64           `json:"created_at,omitempty"`
}

// statementViewOf 把存证行映射为视图（nil → 未生成）。
func statementViewOf(st *TenantStatement) statementView {
	if st == nil {
		return statementView{Available: false}
	}
	return statementView{
		Available:       true,
		StatementID:     st.StatementID,
		Scenario:        st.Scenario,
		AccessMode:      st.AccessMode,
		TemplateVersion: st.TemplateVersion,
		ContentHash:     st.ContentHash,
		Content:         json.RawMessage(st.Content),
		CreatedAt:       st.CreatedAt,
	}
}

func (h *tenantHandler) handleTenantStatement(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	st, err := h.store.GetCurrentStatement(tenantID)
	if err != nil {
		log.Printf("[tenant-statement] 读取当前声明失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	tenantWriteJSON(w, http.StatusOK, statementViewOf(st))
}

// registerTenantStatementMux 注册声明读取端点（租户令牌；只读无需 CSRF）。
func (h *tenantHandler) registerTenantStatementMux(mux *http.ServeMux) {
	mux.HandleFunc("GET "+tenantStatementPath, tenantAuthMiddleware(h.cfg, h.handleTenantStatement))
}

// ---------- 端点：运维批量重签发（管理面内部端点，admin）----------

// registerAdminStatementOps 注册 N4 运维批量重签发端点（触发③；admin + authMiddleware）。
func (h *tenantHandler) registerAdminStatementOps(mux *http.ServeMux, cfg *config) {
	mux.HandleFunc("POST "+adminStatementsReissuePath, authMiddleware(cfg, h.handleAdminStatementsReissue))
}

// handleAdminStatementsReissue 模板版本升级批量重签发（逐租户 supersedes + statement_reissue 审计）。
func (h *tenantHandler) handleAdminStatementsReissue(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, roleAdmin) {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	// 请求体可空（运维任务无 body）；有体则解析 reason。
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSONBody(r, &req); err != nil {
			tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
			return
		}
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "template_upgrade"
	}
	if len(reason) > 256 {
		tenantWriteError(w, http.StatusBadRequest, "reason 长度须为 1-256")
		return
	}

	ids, err := h.store.ListProvisionedTenants()
	if err != nil {
		log.Printf("[tenant-statement] 批量重签枚举租户失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	actor := ""
	if c := claimsFrom(r.Context()); c != nil {
		actor = c.Sub
	}
	now := time.Now().Unix()
	reissued := 0
	var failed []string
	for _, tid := range ids {
		if _, err := h.reissueStatementCore(tid, reason, now, true, actor); err != nil {
			log.Printf("[tenant-statement] 批量重签失败 tenant=%s: %v", tid, err)
			failed = append(failed, tid)
			continue
		}
		reissued++
	}
	if failed == nil {
		failed = []string{}
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{
		"reissued":         reissued,
		"failed":           failed,
		"template_version": statementTemplateVersion,
	})
}
