// Package main — M3-C 高敏变更复核（D8 状态机）。
//
// 设计：docs/管理门户-细化方案.md §5.3「高敏变更复核（D8）」。
//
// 状态机：草稿（提交即 pending）→ 待复核 → 已执行 / 已驳回；执行失败单独标记 failed
// （保留变更单与错误，供人工回滚判定，不自动重试）。
//
// 本期覆盖动作（高敏清单内的可执行子集）：
//   - guardrail_pii_mode：Guardrail 降级（block↔mask），执行 = tee-infer POST /config/guardrail；
//   - output_guard_mode：输出侧审查模式切换（off↔shadow；enforcing 属 M4 不开放），
//     执行 = tee-infer POST /config/output-guard（OG-8 D8 扩列）；
//   - output_guard_policy_reload：输出侧策略/词库热加载（重读策略目录，失败由 tee 侧保留旧版），
//     执行 = tee-infer POST /config/policy/reload（OG-8/OG-9 D8 扩列）；
//   - credential_rotate：厂商换 Key（**两阶段**：提交时新 Key 落 0600 暂存文件，
//     复核通过才提升为正式凭据；暂存内容绝不入变更单/日志/审计链，变更单只记指纹）；
//   - credential_delete：删除厂商凭据。
//
// 清单内其余项（TEE sig/token 轮换、otpmask 密态配置）本期登记为边界外（无对应执行端点），
// 提交时拒绝并明示，避免"建了单却执行不了"的假闭环。
//
// 安全约束：
//   - **submitter ≠ reviewer 强制**（服务端校验，前端置灰仅为体验层）。Go 侧不掌握账号表
//     （账号在控制台 Java 层），故"admin 组人数 < 2 时不可发起"由本约束等价承载——
//     单 admin 场景下任何复核都会被拒，无法形成单人闭环；
//   - 变更状态流转全部落 G1 审计链（submit / execute / reject / execute_failed）；
//   - 变更单文件原子写（tmp + rename），进程重建后状态保持；
//   - 纯读（列表）允许 auditor。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// changeAPIBase 高敏变更端点前缀。
const changeAPIBase = "/v1/adminext/changes"

// 变更动作（高敏清单内本期可执行子集）。
const (
	changeActionGuardrailPIIMode  = "guardrail_pii_mode"
	changeActionOutputGuardMode   = "output_guard_mode"
	changeActionOutputGuardReload = "output_guard_policy_reload"
	changeActionCredentialRotate  = "credential_rotate"
	changeActionCredentialDelete  = "credential_delete"
)

// 变更单状态。
const (
	changeStatusPending  = "pending"  // 待复核
	changeStatusExecuted = "executed" // 已执行
	changeStatusRejected = "rejected" // 已驳回
	changeStatusFailed   = "failed"   // 复核通过但执行失败（保留错误供人工处置）
)

// 变更相关审计动作（G1 链）。
const (
	auditActionChangeSubmit        = "change_submit"
	auditActionChangeExecute       = "change_execute"
	auditActionChangeReject        = "change_reject"
	auditActionChangeExecuteFailed = "change_execute_failed"
)

// changeMaxItems 变更单保留上限（超出裁剪最旧已决单，避免文件无界增长）。
const changeMaxItems = 2000

// changeRequest 高敏变更单。**不含任何凭据明文**（凭据走独立 0600 暂存文件）。
type changeRequest struct {
	ID             string            `json:"id"`
	Action         string            `json:"action"`
	Target         string            `json:"target"`
	Diff           string            `json:"diff"`
	Payload        map[string]string `json:"payload,omitempty"`
	KeyFingerprint string            `json:"key_fingerprint,omitempty"`
	Status         string            `json:"status"`
	Submitter      string            `json:"submitter"`
	Reviewer       string            `json:"reviewer,omitempty"`
	RejectReason   string            `json:"reject_reason,omitempty"`
	CreatedAt      int64             `json:"created_at"`
	DecidedAt      int64             `json:"decided_at,omitempty"`
	ExecutedAt     int64             `json:"executed_at,omitempty"`
	ExecError      string            `json:"exec_error,omitempty"`
}

// pendingSecret 凭据轮换的暂存内容（0600 文件；执行后立即删除）。
type pendingSecret struct {
	Target   string   `json:"target"`
	Upstream string   `json:"upstream,omitempty"`
	Key      string   `json:"key"`
	Prefixes []string `json:"prefixes,omitempty"`
}

// changeStore 变更单存储与执行器。
type changeStore struct {
	mu     sync.Mutex
	path   string
	items  []*changeRequest
	audit  *adminAuditChain
	broker *brokerSecretHandler // nil = broker 未启用（凭据类动作执行时拒绝）
	teeURL string
	token  string
	client *http.Client
}

// newChangeStore 构造变更单存储并从文件恢复（文件缺失 = 空表）。
// path 为空 → 返回 nil（特性关闭，端点不注册）。
func newChangeStore(path string, audit *adminAuditChain, broker *brokerSecretHandler, teeURL, teeToken string) (*changeStore, error) {
	if path == "" {
		return nil, nil
	}
	s := &changeStore{
		path:   path,
		audit:  audit,
		broker: broker,
		teeURL: strings.TrimRight(teeURL, "/"),
		token:  teeToken,
		client: &http.Client{Timeout: 10 * time.Second},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("change: 读取变更单文件失败: %w", err)
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &s.items); err != nil {
			return nil, fmt.Errorf("change: 变更单文件解析失败: %w", err)
		}
	}
	return s, nil
}

// saveLocked 原子落盘（须持锁调用）：tmp 写入 + rename，避免半截文件。
func (s *changeStore) saveLocked() error {
	if len(s.items) > changeMaxItems {
		s.items = s.items[len(s.items)-changeMaxItems:]
	}
	raw, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return fmt.Errorf("change: 序列化失败: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("change: 写入失败: %w", err)
	}
	return os.Rename(tmp, s.path)
}

// pendingPath 凭据暂存文件路径（与变更单同目录下的 .pending/）。
func (s *changeStore) pendingPath(id string) string {
	return filepath.Join(filepath.Dir(s.path), ".pending", id+".json")
}

// auditAppend 落 G1 链（失败仅告警：变更单状态已本身持久化，审计为留痕增强）。
// 与凭据写路径的 fail-closed 不同：此处状态机已落盘，重复落链失败不应让用户重试整单。
func (s *changeStore) auditAppend(e adminAuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.append(e); err != nil {
		metrics.incBrokerAuditWriteFailed()
		log.Printf("[change] 审计落链失败 action=%s id=%s: %v", e.Action, e.Target, err)
	}
}

// validChangeAction 动作是否在本期可执行子集内。
func validChangeAction(a string) bool {
	switch a {
	case changeActionGuardrailPIIMode,
		changeActionOutputGuardMode,
		changeActionOutputGuardReload,
		changeActionCredentialRotate,
		changeActionCredentialDelete:
		return true
	}
	return false
}

// changeSubmitRequest 发起变更请求体。
type changeSubmitRequest struct {
	Action  string            `json:"action"`
	Target  string            `json:"target"`
	Diff    string            `json:"diff"`
	Payload map[string]string `json:"payload,omitempty"`
	// Secret 仅凭据轮换使用：请求体内一次性传递，落 0600 暂存文件；
	// **绝不写入变更单、日志或审计链**。
	Secret string `json:"secret,omitempty"`
}

// handleList GET 列表（auditor 可读）/ POST 发起（admin）。
func (s *changeStore) handleList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireReadAccess(w, r) {
			return
		}
		s.mu.Lock()
		out := make([]*changeRequest, len(s.items))
		copy(out, s.items)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": out, "total": len(out)})
	case http.MethodPost:
		if !requireRole(w, r, roleAdmin) {
			return
		}
		s.submit(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/POST")
	}
}

// submit 发起变更单：校验动作与参数，凭据类落暂存，写状态机 + 落链。
func (s *changeStore) submit(w http.ResponseWriter, r *http.Request) {
	var req changeSubmitRequest
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if !validChangeAction(req.Action) {
		writeError(w, http.StatusBadRequest,
			"不支持的高敏动作（本期可执行：guardrail_pii_mode / output_guard_mode / output_guard_policy_reload / credential_rotate / credential_delete）")
		return
	}
	sub := operationSub(r)
	now := time.Now().UnixNano()
	c := &changeRequest{
		Action: req.Action, Target: req.Target, Diff: req.Diff,
		Payload: req.Payload, Status: changeStatusPending,
		Submitter: sub, CreatedAt: now,
	}

	switch req.Action {
	case changeActionGuardrailPIIMode:
		if c.Payload == nil {
			c.Payload = map[string]string{}
		}
		mode := c.Payload["pii_mode"]
		if mode != "block" && mode != "mask" {
			writeError(w, http.StatusBadRequest, "pii_mode 仅允许 block|mask（不提供 Guardrail 关闭）")
			return
		}
		c.Target = "guardrail"
	case changeActionOutputGuardMode:
		if c.Payload == nil {
			c.Payload = map[string]string{}
		}
		mode := c.Payload["mode"]
		// 与 tee-infer 侧安全闸门一致：仅 off/shadow，enforcing 属 M4 不开放（双闸拒绝）。
		if mode != "off" && mode != "shadow" {
			writeError(w, http.StatusBadRequest, "mode 仅允许 off|shadow（enforcing 属 M4，当前不开放）")
			return
		}
		c.Target = "output-guard"
	case changeActionOutputGuardReload:
		// 无请求参数：执行 = tee 重读策略目录；失败（409）由 tee 侧保留上一有效版本。
		c.Target = "output-guard-policy"
	case changeActionCredentialRotate:
		if req.Target == "" || req.Secret == "" {
			writeError(w, http.StatusBadRequest, "credential_rotate 须提供 target 与新 Key")
			return
		}
		c.KeyFingerprint = keyFingerprint([]byte(req.Secret))
	case changeActionCredentialDelete:
		if req.Target == "" {
			writeError(w, http.StatusBadRequest, "credential_delete 须提供 target")
			return
		}
	}

	s.mu.Lock()
	c.ID = fmt.Sprintf("chg-%d", now)
	s.items = append(s.items, c)
	// 凭据轮换：明文落 0600 暂存（与变更单分离），失败则整单不成立。
	if req.Action == changeActionCredentialRotate {
		if err := s.writePendingLocked(c, req); err != nil {
			s.items = s.items[:len(s.items)-1] // 回滚内存表
			s.mu.Unlock()
			log.Printf("[change] 暂存凭据失败 id=%s: %v", c.ID, err)
			writeError(w, http.StatusInternalServerError, "凭据暂存失败")
			return
		}
	}
	if err := s.saveLocked(); err != nil {
		if req.Action == changeActionCredentialRotate {
			_ = os.Remove(s.pendingPath(c.ID))
		}
		s.items = s.items[:len(s.items)-1]
		s.mu.Unlock()
		log.Printf("[change] 变更单落盘失败 id=%s: %v", c.ID, err)
		writeError(w, http.StatusInternalServerError, "变更单落盘失败")
		return
	}
	s.mu.Unlock()

	s.auditAppend(adminAuditEvent{
		Actor: sub, Action: auditActionChangeSubmit, Target: c.Target,
		KeyFingerprint: c.KeyFingerprint, RequestID: r.Header.Get("X-Request-ID"), Result: "ok",
	})
	writeJSON(w, http.StatusCreated, c)
}

// writePendingLocked 写凭据暂存文件（须持锁调用）。
func (s *changeStore) writePendingLocked(c *changeRequest, req changeSubmitRequest) error {
	upstream := ""
	var prefixes []string
	if s.broker != nil {
		if route := s.broker.broker.currentRoutes()[req.Target]; route != nil {
			upstream = route.p.upstream.Scheme + "://" + route.p.upstream.Host
			prefixes = route.p.allowPathPrefixes
		}
	}
	raw, err := json.Marshal(pendingSecret{Target: req.Target, Upstream: upstream, Key: req.Secret, Prefixes: prefixes})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.pendingPath(c.ID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.pendingPath(c.ID), raw, 0o600)
}

// handleItem 处理 /v1/adminext/changes/{id}/{approve|reject}。
func (s *changeStore) handleItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, roleAdmin) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, changeAPIBase+"/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "路径须为 /v1/adminext/changes/{id}/{approve|reject}")
		return
	}
	id, op := parts[0], parts[1]
	switch op {
	case "approve":
		s.approve(w, r, id)
	case "reject":
		s.reject(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "未知操作: "+op)
	}
}

// findLocked 按 ID 查找（须持锁调用）。
func (s *changeStore) findLocked(id string) *changeRequest {
	for _, c := range s.items {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// approve 复核通过并执行（submitter ≠ reviewer 强制）。
func (s *changeStore) approve(w http.ResponseWriter, r *http.Request, id string) {
	reviewer := operationSub(r)

	s.mu.Lock()
	c := s.findLocked(id)
	if c == nil {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "变更单不存在: "+id)
		return
	}
	if c.Status != changeStatusPending {
		st := c.Status
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "变更单状态非待复核（当前 "+st+"）")
		return
	}
	if c.Submitter == reviewer {
		submitter := c.Submitter
		s.mu.Unlock()
		log.Printf("[change] 拒绝自审 id=%s sub=%s", id, submitter)
		writeError(w, http.StatusForbidden, "发起人不得复核本人提交的变更（submitter≠reviewer）")
		return
	}
	// 执行前先记录复核人：执行器以其身份对外留痕（tee-infer 侧 X-Admin-Actor）。
	// 注意必须在 execute 之前赋值，否则执行留痕 actor 为空（曾实测踩到）。
	c.Reviewer = reviewer
	c.DecidedAt = time.Now().UnixNano()
	s.mu.Unlock()

	// 执行（不加锁：执行含外部 IO；状态变更再取锁）。
	err := s.execute(c)

	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.findLocked(id)
	if cur == nil { // 理论上不可达
		writeError(w, http.StatusNotFound, "变更单不存在: "+id)
		return
	}
	cur.Reviewer = reviewer
	cur.DecidedAt = time.Now().UnixNano()
	if err != nil {
		cur.Status = changeStatusFailed
		cur.ExecError = err.Error()
	} else {
		cur.Status = changeStatusExecuted
		cur.ExecutedAt = cur.DecidedAt
	}
	if saveErr := s.saveLocked(); saveErr != nil {
		log.Printf("[change] 状态落盘失败 id=%s: %v", id, saveErr)
		writeError(w, http.StatusInternalServerError, "变更状态落盘失败（执行结果请人工核查）")
		return
	}
	snapshot := *cur
	execErr := err

	if execErr != nil {
		s.auditAppend(adminAuditEvent{
			Actor: reviewer, Action: auditActionChangeExecuteFailed, Target: snapshot.Target,
			RequestID: r.Header.Get("X-Request-ID"), Result: "failed",
		})
		writeError(w, http.StatusInternalServerError, "复核通过但执行失败: "+execErr.Error())
		return
	}
	s.auditAppend(adminAuditEvent{
		Actor: reviewer, Action: auditActionChangeExecute, Target: snapshot.Target,
		KeyFingerprint: snapshot.KeyFingerprint,
		RequestID:      r.Header.Get("X-Request-ID"), Result: "ok",
	})
	writeJSON(w, http.StatusOK, snapshot)
}

// reject 驳回变更（submitter ≠ reviewer 强制），并清理凭据暂存。
func (s *changeStore) reject(w http.ResponseWriter, r *http.Request, id string) {
	reviewer := operationSub(r)
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.findLocked(id)
	if c == nil {
		writeError(w, http.StatusNotFound, "变更单不存在: "+id)
		return
	}
	if c.Status != changeStatusPending {
		writeError(w, http.StatusConflict, "变更单状态非待复核（当前 "+c.Status+"）")
		return
	}
	if c.Submitter == reviewer {
		writeError(w, http.StatusForbidden, "发起人不得复核本人提交的变更（submitter≠reviewer）")
		return
	}
	c.Status = changeStatusRejected
	c.Reviewer = reviewer
	c.RejectReason = body.Reason
	c.DecidedAt = time.Now().UnixNano()
	if c.Action == changeActionCredentialRotate {
		_ = os.Remove(s.pendingPath(c.ID)) // 清理暂存明文
	}
	if err := s.saveLocked(); err != nil {
		log.Printf("[change] 驳回落盘失败 id=%s: %v", id, err)
		writeError(w, http.StatusInternalServerError, "变更状态落盘失败")
		return
	}
	s.auditAppend(adminAuditEvent{
		Actor: reviewer, Action: auditActionChangeReject, Target: c.Target,
		RequestID: r.Header.Get("X-Request-ID"), Result: "ok",
	})
	writeJSON(w, http.StatusOK, c)
}

// execute 按动作执行变更（执行失败原因回写变更单）。
func (s *changeStore) execute(c *changeRequest) error {
	switch c.Action {
	case changeActionGuardrailPIIMode:
		return s.execGuardrailPIIMode(c)
	case changeActionOutputGuardMode:
		return s.execOutputGuardMode(c)
	case changeActionOutputGuardReload:
		return s.execOutputGuardPolicyReload(c)
	case changeActionCredentialRotate:
		return s.execCredentialRotate(c)
	case changeActionCredentialDelete:
		return s.execCredentialDelete(c)
	}
	return errors.New("未知动作: " + c.Action)
}

// execGuardrailPIIMode 调 tee-infer 生效 PII 模式（执行者身份随请求透传留痕）。
func (s *changeStore) execGuardrailPIIMode(c *changeRequest) error {
	if s.teeURL == "" {
		return errors.New("tee-infer 未配置（ADMIN_TEE_INFER_URL）")
	}
	payload, err := json.Marshal(map[string]string{"pii_mode": c.Payload["pii_mode"]})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.teeURL+"/config/guardrail", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(teeAdminHeader, s.token)
	req.Header.Set("X-Admin-Actor", c.Reviewer)
	req.Header.Set("X-Request-ID", c.ID)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("tee-infer 不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("tee-infer 拒绝（HTTP %d）: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// execOutputGuardMode 调 tee-infer 切换输出侧审查模式（OG-8；仅 off/shadow，提交时已校验）。
func (s *changeStore) execOutputGuardMode(c *changeRequest) error {
	return s.postTeeConfig(c, "/config/output-guard", map[string]string{"mode": c.Payload["mode"]})
}

// execOutputGuardPolicyReload 调 tee-infer 热加载策略/词库（OG-9；无请求体；
// tee 侧加载失败回 409 并保留上一有效版本，此处按执行失败回写变更单）。
func (s *changeStore) execOutputGuardPolicyReload(c *changeRequest) error {
	return s.postTeeConfig(c, "/config/policy/reload", nil)
}

// postTeeConfig 以复核人身份调 tee-infer 配置端点（输出侧动作共用）：
// 管理令牌鉴权 + X-Admin-Actor/X-Request-ID 留痕（与 execGuardrailPIIMode 同口径）；非 2xx 即失败。
func (s *changeStore) postTeeConfig(c *changeRequest, path string, payload interface{}) error {
	if s.teeURL == "" {
		return errors.New("tee-infer 未配置（ADMIN_TEE_INFER_URL）")
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(http.MethodPost, s.teeURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(teeAdminHeader, s.token)
	req.Header.Set("X-Admin-Actor", c.Reviewer)
	req.Header.Set("X-Request-ID", c.ID)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("tee-infer 不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("tee-infer 拒绝（HTTP %d）: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// execCredentialRotate 提升暂存凭据为正式凭据（读暂存 → 写正式 → reload → 删除暂存）。
func (s *changeStore) execCredentialRotate(c *changeRequest) error {
	if s.broker == nil {
		return errors.New("broker 未启用，无法执行凭据轮换")
	}
	pending := s.pendingPath(c.ID)
	raw, err := os.ReadFile(pending)
	if err != nil {
		return fmt.Errorf("读取暂存凭据失败（可能已过期或被清理）: %w", err)
	}
	var ps pendingSecret
	if err := json.Unmarshal(raw, &ps); err != nil {
		return fmt.Errorf("暂存凭据解析失败: %w", err)
	}
	if ps.Upstream == "" {
		return errors.New("无法确定 upstream（provider 未托管且提交时未提供）")
	}
	if err := s.broker.applyProvider(ps.Target, ps.Upstream, ps.Key, ps.Prefixes); err != nil {
		return err
	}
	_ = os.Remove(pending) // 执行成功后清理暂存明文
	return nil
}

// execCredentialDelete 删除 provider 凭据并重载。
func (s *changeStore) execCredentialDelete(c *changeRequest) error {
	if s.broker == nil {
		return errors.New("broker 未启用，无法执行删除")
	}
	if s.broker.broker.currentRoutes()[c.Target] == nil {
		return errors.New("provider 未托管: " + c.Target)
	}
	if err := deleteProviderFile(s.broker.settings.secretsDir, c.Target); err != nil {
		return err
	}
	return s.broker.reloadNow()
}
