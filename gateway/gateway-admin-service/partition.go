// Package main — T-4 租户分区编排：管理面端点（P2-3 §6.3 / §7.2）。
//
// 端点：
//   POST /v1/adminext/cryptop/partition   租户分区开通/更新/回收（幂等，admin:write）
//   GET  /v1/adminext/cryptop/partition   分区与配额清单（auditor 可读）
//
// 语义（§6.3 + T-4 核心逻辑步骤）：
//   ① 分区对象（租户↔分区↔成员映射）+ 幂等开通/更新/回收；
//   ② 配额（会话/QPS）校验 + desired 下发；
//   ③ 隔离验证（D-11 一成员一登录域：同成员多租户配置直接拒）；
//   ④ 审计与状态快照；
//   ⑤ 删除前 drain + 无活动 KeyRef 检查（否则 409 group_partition_not_empty）。
//
// 不接真实 HSM、不宣称 S3-b/生产合规（Wave A：协作者以接口注入，单测 mock 覆盖）。
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// cryptopPartitionPath 分区编排端点路径（§6.3）。
const cryptopPartitionPath = "/v1/adminext/cryptop/partition"

var partitionNameRegexp = regexp.MustCompile(partitionNameRE)

// partitionRequest POST /partition 请求体（§6.3 契约）。
type partitionRequest struct {
	Tenant          string   `json:"tenant"`                     // 租户 ID（全局唯一）
	Partition       string   `json:"partition"`                  // 分区/登录域（全局唯一）
	Members         []string `json:"members"`                    // 该租户可用成员 ID（至少 1）
	QuotaSessions   int      `json:"quota_sessions"`             // ≤ 成员 max_sessions 之和
	QuotaQPS        int      `json:"quota_qps"`                  // 0=不限；>0 启用配额
	Action          string   `json:"action"`                     // update（默认）| delete
	ExpectedVersion uint64   `json:"expected_version"`           // 乐观并发：CAS desired 版本
	ApprovalID      string   `json:"approval_id,omitempty"`      // 删除/降配额/改成员双签
	Confirm         bool     `json:"confirm"`                    // 删除/降配额/改成员必须 true
	Drain           bool     `json:"drain,omitempty"`            // 删除前必须 drain
}

// partitionApplyResponse 开通/更新/回收响应（§6.3：202 + operation_id/desired_version/status）。
type partitionApplyResponse struct {
	OperationID   string `json:"operation_id"`
	DesiredVersion uint64 `json:"desired_version"`
	Status        string `json:"status"` // applying
}

// partitionListItem GET 清单项（不含口令/密钥材料）。
type partitionListItem struct {
	Tenant         string   `json:"tenant"`
	Partition      string   `json:"partition"`
	Members        []string `json:"members"`
	QuotaSessions  int      `json:"quota_sessions"`
	QuotaQPS       int      `json:"quota_qps"`
	Version        uint64   `json:"version"`
	Drain          bool     `json:"drain"`
}

// partitionError 错误体（§6.3 契约 code 对齐）。
type partitionError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// partitionHandler 分区编排处理器（依赖注入）。
type partitionHandler struct {
	chain   *adminAuditChain
	store   *partitionStore
	members MemberRegistry
	keyRefs KeyRefStore
	desired DesiredPublisher
	idem    *idemStore
}

// newPartitionHandler 构造处理器。
func newPartitionHandler(chain *adminAuditChain, store *partitionStore, members MemberRegistry, keyRefs KeyRefStore, desired DesiredPublisher) *partitionHandler {
	if members == nil {
		members = newMemMemberRegistry(nil)
	}
	if keyRefs == nil {
		keyRefs = staticKeyRefStore{}
	}
	if desired == nil {
		desired = &memDesiredPublisher{}
	}
	if store == nil {
		store = newPartitionStore()
	}
	if chain == nil {
		// 审计关闭时透传 nil，handler 跳过审计落链（与既有端点同构）。
	}
	return &partitionHandler{
		chain:   chain,
		store:   store,
		members: members,
		keyRefs: keyRefs,
		desired: desired,
		idem:    newIdemStore(),
	}
}

// handle 路由：POST=开通/更新/回收，GET=清单，其余 405。
func (h *partitionHandler) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.apply(w, r)
	case http.MethodGet:
		h.list(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, partitionError{Code: "method_not_allowed", Message: "仅接受 GET/POST"})
	}
}

// writePartitionErr 按契约输出 {code,message}。
func writePartitionErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, partitionError{Code: code, Message: msg})
}

// apply 处理 POST /partition（开通/更新/回收）。
func (h *partitionHandler) apply(w http.ResponseWriter, r *http.Request) {
	if !requireRule(w, r, epCryptopPartitionWrite) {
		return
	}

	body, err := readAll(r)
	if err != nil {
		writePartitionErr(w, http.StatusBadRequest, "bad_request", "请求体读取失败")
		return
	}

	// 幂等键（§6.3：POST 必填）。
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		writePartitionErr(w, http.StatusBadRequest, "bad_request", "Idempotency-Key 必填（POST 幂等）")
		return
	}
	sha := bodySHA256(body)
	if cached := h.idem.get(key); cached != nil {
		if cached.BodySHA != sha {
			writePartitionErr(w, http.StatusConflict, "group_idempotency_conflict",
				"同一 Idempotency-Key 的两次请求 body 不一致")
			return
		}
		// 同键同体：回放原响应。
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(cached.Status)
		_, _ = w.Write(cached.Response)
		return
	}

	var req partitionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writePartitionErr(w, http.StatusBadRequest, "bad_request", "请求体 JSON 解析失败")
		return
	}
	if req.Action == "" {
		req.Action = "update"
	}
	if req.Action != "update" && req.Action != "delete" {
		writePartitionErr(w, http.StatusBadRequest, "bad_request", "action 仅接受 update/delete")
		return
	}

	// 命名校验（§6.1）。
	if !partitionNameRegexp.MatchString(req.Tenant) {
		writePartitionErr(w, http.StatusBadRequest, "group_config_invalid", "tenant 命名非法")
		return
	}
	if !partitionNameRegexp.MatchString(req.Partition) {
		writePartitionErr(w, http.StatusBadRequest, "group_config_invalid", "partition 命名非法")
		return
	}

	now := time.Now().UnixNano()

	if req.Action == "delete" {
		h.doDelete(w, r, req, key, sha, now)
		return
	}
	h.doUpdate(w, r, req, key, sha, now)
}

// doUpdate 开通/更新。
func (h *partitionHandler) doUpdate(w http.ResponseWriter, r *http.Request, req partitionRequest, key, sha string, now int64) {
	if len(req.Members) == 0 {
		writePartitionErr(w, http.StatusBadRequest, "group_config_invalid", "members 至少 1 个")
		return
	}
	if req.QuotaQPS < 0 {
		writePartitionErr(w, http.StatusBadRequest, "group_config_invalid", "quota_qps 不得为负")
		return
	}

	existing := h.store.get(req.Partition)

	// tenant 全局唯一：新建且 tenant 已被其它 partition 占用 → 409。
	if existing == nil {
		if other := h.store.getByTenant(req.Tenant); other != nil {
			writePartitionErr(w, http.StatusConflict, "group_config_invalid",
				"tenant 已被分区 "+other.Partition+" 占用")
			return
		}
	}

	// D-11 一成员一登录域：每个成员须已注册，且其已注册 partition 必须与本次一致；
	// 已归属于其它分区的成员 → 403 group_partition_mismatch（同成员多租户配置直接拒）。
	var sumMaxSessions int
	seen := map[string]bool{}
	for _, m := range req.Members {
		if seen[m] {
			writePartitionErr(w, http.StatusBadRequest, "group_config_invalid", "members 含重复 ID: "+m)
			return
		}
		seen[m] = true
		info, ok := h.members.Member(m)
		if !ok {
			writePartitionErr(w, http.StatusBadRequest, "group_config_invalid", "成员未注册: "+m)
			return
		}
		if info.Partition != "" && info.Partition != req.Partition {
			writePartitionErr(w, http.StatusForbidden, "group_partition_mismatch",
				"成员 "+m+" 已归属分区 "+info.Partition+"，违反 D-11 一成员一登录域")
			return
		}
		sumMaxSessions += info.MaxSessions
	}

	// 配额：quota_sessions ≤ 成员 max_sessions 之和（>0 时校验）。
	if req.QuotaSessions > 0 && req.QuotaSessions > sumMaxSessions {
		writePartitionErr(w, http.StatusTooManyRequests, "group_quota_exceeded",
			"quota_sessions 超出成员 max_sessions 之和")
		return
	}

	// 乐观并发：existing 已发布版本须与 expected_version 匹配（>0 时）。
	if existing != nil && req.ExpectedVersion != 0 && req.ExpectedVersion != existing.Version {
		writePartitionErr(w, http.StatusConflict, "group_stale_epoch",
			"expected_version 与当前版本不符（当前 "+itoa(existing.Version)+"）")
		return
	}

	rec := &partitionRecord{
		Tenant:        req.Tenant,
		Partition:     req.Partition,
		Members:       append([]string(nil), req.Members...),
		QuotaSessions: req.QuotaSessions,
		QuotaQPS:      req.QuotaQPS,
		Drain:         false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if existing != nil {
		rec.CreatedAt = existing.CreatedAt
		rec.Version = existing.Version
	}

	// 下发 desired（控制面）并取回版本号。
	ver, err := h.desired.PublishDesired(r.Context(), PartitionDesiredOut{
		Tenant:        rec.Tenant,
		Partition:     rec.Partition,
		Members:       rec.Members,
		QuotaSessions: rec.QuotaSessions,
		QuotaQPS:      rec.QuotaQPS,
		Action:        "apply",
	})
	if err != nil {
		writePartitionErr(w, http.StatusInternalServerError, "internal", "desired 下发失败: "+err.Error())
		return
	}
	rec.Version = ver
	h.store.put(rec)

	// 审计（失败 = 受理失败，fail-closed）。
	if h.chain != nil {
		if err := h.chain.append(adminAuditEvent{
			Actor:     operationSub(r),
			Action:    auditActionCryptopPartition,
			Tenant:    rec.Tenant,
			Target:    rec.Partition,
			RequestID: r.Header.Get("X-Request-ID"),
			Result:    "ok",
			Detail:    partitionDetail(req.Action, req.Members, req.QuotaSessions, req.QuotaQPS),
		}); err != nil {
			writePartitionErr(w, http.StatusInternalServerError, "internal",
				"审计链写入失败（分区变更未受理，fail-closed）: "+err.Error())
			return
		}
	}

	metrics.incPartitionOp("update", "ok")
	resp := partitionApplyResponse{OperationID: newOperationID(), DesiredVersion: ver, Status: "applying"}
	raw, _ := json.Marshal(resp)
	h.idem.put(key, &idemRecord{Method: http.MethodPost, Path: cryptopPartitionPath, BodySHA: sha, Status: http.StatusAccepted, Response: raw})
	writeJSON(w, http.StatusAccepted, resp)
}

// doDelete 回收（删除前须 drain + 无活动 KeyRef）。
func (h *partitionHandler) doDelete(w http.ResponseWriter, r *http.Request, req partitionRequest, key, sha string, now int64) {
	if !req.Confirm {
		writePartitionErr(w, http.StatusBadRequest, "bad_request", "删除须 confirm=true")
		return
	}
	existing := h.store.get(req.Partition)
	if existing == nil {
		// 幂等：已不存在视为成功（返回当前版本 0）。
		metrics.incPartitionOp("delete", "ok")
		resp := partitionApplyResponse{OperationID: newOperationID(), DesiredVersion: 0, Status: "applying"}
		raw, _ := json.Marshal(resp)
		h.idem.put(key, &idemRecord{Method: http.MethodPost, Path: cryptopPartitionPath, BodySHA: sha, Status: http.StatusAccepted, Response: raw})
		writeJSON(w, http.StatusAccepted, resp)
		return
	}
	if req.ExpectedVersion != 0 && req.ExpectedVersion != existing.Version {
		writePartitionErr(w, http.StatusConflict, "group_stale_epoch",
			"expected_version 与当前版本不符（当前 "+itoa(existing.Version)+"）")
		return
	}
	if !req.Drain {
		writePartitionErr(w, http.StatusBadRequest, "bad_request", "删除前须 drain=true（摘流）")
		return
	}
	// 无活动 KeyRef 检查（§6.3：否则 409 group_partition_not_empty）。
	n, err := h.keyRefs.ActiveKeyRefCount(r.Context(), req.Partition)
	if err != nil {
		writePartitionErr(w, http.StatusInternalServerError, "internal", "KeyRef 计数查询失败: "+err.Error())
		return
	}
	if n > 0 {
		writePartitionErr(w, http.StatusConflict, "group_partition_not_empty",
			"分区仍有 "+itoa(uint64(n))+" 个活动 KeyRef，须先回收密钥")
		return
	}

	// 下发 desired（remove）并取回版本号。
	ver, err := h.desired.PublishDesired(r.Context(), PartitionDesiredOut{
		Tenant:    existing.Tenant,
		Partition: existing.Partition,
		Action:    "remove",
	})
	if err != nil {
		writePartitionErr(w, http.StatusInternalServerError, "internal", "desired 下发失败: "+err.Error())
		return
	}
	h.store.remove(req.Partition)

	if h.chain != nil {
		if err := h.chain.append(adminAuditEvent{
			Actor:     operationSub(r),
			Action:    auditActionCryptopPartition,
			Tenant:    existing.Tenant,
			Target:    existing.Partition,
			RequestID: r.Header.Get("X-Request-ID"),
			Result:    "ok",
			Detail:    partitionDetail("delete", nil, 0, 0),
		}); err != nil {
			writePartitionErr(w, http.StatusInternalServerError, "internal",
				"审计链写入失败（分区回收未受理，fail-closed）: "+err.Error())
			return
		}
	}

	metrics.incPartitionOp("delete", "ok")
	resp := partitionApplyResponse{OperationID: newOperationID(), DesiredVersion: ver, Status: "applying"}
	raw, _ := json.Marshal(resp)
	h.idem.put(key, &idemRecord{Method: http.MethodPost, Path: cryptopPartitionPath, BodySHA: sha, Status: http.StatusAccepted, Response: raw})
	writeJSON(w, http.StatusAccepted, resp)
}

// list 处理 GET /partition?tenant=。
func (h *partitionHandler) list(w http.ResponseWriter, r *http.Request) {
	if !requireRule(w, r, epCryptopPartitionRead) {
		return
	}
	tenant := r.URL.Query().Get("tenant")
	recs := h.store.list(tenant)
	sort.Slice(recs, func(i, j int) bool { return recs[i].Partition < recs[j].Partition })
	out := make([]partitionListItem, 0, len(recs))
	for _, rec := range recs {
		out = append(out, partitionListItem{
			Tenant:        rec.Tenant,
			Partition:     rec.Partition,
			Members:       rec.Members,
			QuotaSessions: rec.QuotaSessions,
			QuotaQPS:      rec.QuotaQPS,
			Version:       rec.Version,
			Drain:         rec.Drain,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"partitions": out})
}

// partitionDetail 构造审计 detail（仅摘要，不含密钥材料/口令）。
func partitionDetail(action string, members []string, qSessions, qQPS int) string {
	if action == "delete" {
		return "action=delete"
	}
	return "action=update members=" + strings.Join(members, ",") +
		" quota_sessions=" + itoa(uint64(qSessions)) + " quota_qps=" + itoa(uint64(qQPS))
}

// itoa 小工具：uint64 → 十进制字符串（避免引入 strconv 多处 import 干扰可读性）。
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// readAll 读取请求体。
func readAll(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}
