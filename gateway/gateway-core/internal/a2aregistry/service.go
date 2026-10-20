package a2aregistry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// PublicMode 取值（§3.3）。
const (
	PublicModeHost = "host"
	PublicModePath = "path"
)

// Config 是 A2A 注册中心配置（冻结 §3.3/§5.4/§5.9）。
type Config struct {
	DSN           string
	PublicMode    string
	TenantDomains map[string]string // host 模式：tenant → base domain
	GatewayBase   string            // path 模式基址（如 https://gateway）
	CardMaxBytes  int
	JKUAllowlist  []string
	JWTSecret     string
	StaticToken   string
	SnapshotToken string
	DevMode       bool
	// DevAllowLoopback 仅用于本地联调：允许 backend_url 指向环回地址。
	// 生产必须为 false（冻结 §5.9 禁止 loopback 后端）。
	DevAllowLoopback bool
}

// Registry 是 A2A 控制面核心服务。
type Registry struct {
	store *Store
	audit *policyaudit.Chain
	cfg   Config
	// metrics 是注册中心控制面观测指标（T-5；§6.5）。始终非 nil。
	metrics *Metrics
	// degraded=true 表示存储不可用（DB 打开失败）→ 所有写/读返回 503 registry_unavailable。
	degraded bool
}

// New 构造 Registry（打开 SQLite；失败返回 error）。
//
// ⚠️ 失败分级（冻结 §5.1「启动：迁移校验（schema 新于代码→拒绝启动）」）：
//   - ErrSchemaTooNew（库比代码新）→ **致命**，调用方须拒绝启动；
//   - 其余打开失败 → **降级**为 registry_unavailable（控制面 503），不拖垮其它服务。
func New(cfg Config, audit *policyaudit.Chain) (*Registry, error) {
	if cfg.CardMaxBytes <= 0 {
		cfg.CardMaxBytes = 64 << 10
	}
	if cfg.PublicMode == "" {
		cfg.PublicMode = PublicModePath
	}
	st, err := OpenStore(cfg.DSN)
	if err != nil {
		if errors.Is(err, ErrSchemaTooNew) {
			return nil, err // 致命：拒绝启动
		}
		// 降级：存储不可用（DB 打不开/磁盘故障）→ 控制面返回 503，其余功能不受影响。
		return &Registry{store: NewUnavailable(), audit: audit, cfg: cfg, metrics: newMetrics(), degraded: true}, nil
	}
	return &Registry{store: st, audit: audit, cfg: cfg, metrics: newMetrics()}, nil
}

// Close 关闭存储。
func (r *Registry) Close() error { return r.store.Close() }

// Store 暴露底层存储（测试/快照用）。
func (r *Registry) Store() *Store { return r.store }

// Config 返回当前配置（只读）。
func (r *Registry) Config() Config { return r.cfg }

// agentURLs 计算网关形态 public/discovery URL（§3.3）。
func (r *Registry) agentURLs(tenant, name string) (publicURL, discoveryURL string) {
	if r.cfg.PublicMode == PublicModeHost {
		base := "https://" + name + "." + r.cfg.TenantDomains[tenant]
		return base + "/a2a", base + "/.well-known/agent-card.json"
	}
	base := strings.TrimRight(r.cfg.GatewayBase, "/")
	return base + "/a2a/" + tenant + "/" + name,
		base + "/a2a/" + tenant + "/" + name + "/.well-known/agent-card.json"
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedNames 是禁止注册的 agent 名（§5.9 保留词）。
var reservedNames = map[string]bool{
	"www": true, "api": true, "admin": true, "health": true,
	"metrics": true, "status": true, "root": true,
}

// RegisterRequest 是 POST /v1/a2a/agents 请求体。
type RegisterRequest struct {
	Name       string            `json:"name"`
	ProviderID string            `json:"provider_id"`
	Card       json.RawMessage   `json:"card"`
	BackendURL string            `json:"backend_url"`
	Labels     map[string]string `json:"labels"`
}

// SignatureInfo 是签名元数据（不回显 key 材料）。
type SignatureInfo struct {
	Kid      string `json:"kid"`
	Alg      string `json:"alg"`
	Verified bool   `json:"verified"`
}

// AgentDetail 是 agent 详情响应体（§3.2 AgentRecord schema）。
// backend_url 仅 admin 可见；签名状态由签名结果元数据体现。
type AgentDetail struct {
	Name             string            `json:"name"`
	ProviderID       string            `json:"provider_id"`
	Revision         int               `json:"revision"`
	RegistryRevision int               `json:"registry_revision"`
	AgentVersion     string            `json:"agent_version"`
	ContentHash      string            `json:"content_hash"`
	RawHash          string            `json:"raw_hash"`
	Signature        SignatureInfo     `json:"signature"`
	PublicURL        string            `json:"public_url"`
	DiscoveryURL     string            `json:"discovery_url"`
	BackendURL       string            `json:"backend_url,omitempty"`
	Skills           []SkillSummary    `json:"skills"`
	Status           string            `json:"status"`
	Source           string            `json:"source"`
	Labels           map[string]string `json:"labels,omitempty"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at"`
}

// SkillSummary 是响应中的 skill 摘要。
type SkillSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Register 注册 agent（§5.3/§5.5）。返回 (响应, HTTP 状态码, 错误)。
func (r *Registry) Register(ctx context.Context, authn Authn, actor, reqID, traceID string, req RegisterRequest, idemKey string) (*AgentDetail, int, error) {
	if err := authn.requireAdmin(); err != nil {
		return nil, http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return nil, http.StatusBadRequest, errInvalid("%v", terr)
	}
	if req.Name == "" || len(req.Name) > 63 {
		return nil, http.StatusBadRequest, errInvalid("name 必填且为 DNS label（≤63 字符）")
	}
	if !nameRe.MatchString(req.Name) {
		return nil, http.StatusBadRequest, errInvalid("name 须为 DNS label（^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$）")
	}
	if reservedNames[req.Name] {
		return nil, http.StatusBadRequest, errInvalid("name %q 为保留词", req.Name)
	}
	if req.ProviderID == "" {
		return nil, http.StatusBadRequest, errInvalid("provider_id 必填")
	}
	if len(req.Card) == 0 {
		return nil, http.StatusBadRequest, errInvalid("card 必填")
	}
	if len(req.Card) > r.cfg.CardMaxBytes {
		return nil, http.StatusRequestEntityTooLarge, errPayloadTooLarge("card 超过 %d 字节", r.cfg.CardMaxBytes)
	}
	if req.BackendURL == "" {
		return nil, http.StatusBadRequest, errInvalid("backend_url 必填")
	}
	if len(req.Labels) > 16 {
		return nil, http.StatusBadRequest, errInvalid("labels 不得超过 16 对")
	}
	for k, v := range req.Labels {
		if len(k) > 64 || len(v) > 256 {
			return nil, http.StatusBadRequest, errInvalid("labels 的 key≤64/value≤256")
		}
	}

	tx, err := r.store.Begin()
	if err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	// 幂等：同 key + 同 body → 返回首次响应；同 key + 不同 body → 409 idempotency_conflict。
	reqHash := hashBytes(req.Card)
	if idemKey != "" {
		cached, cachedHash, ok := r.store.IdempotencyGet(tx, tenant, idemKey, "/v1/a2a/agents")
		if ok {
			_ = r.store.Rollback(tx)
			if cachedHash != reqHash {
				return nil, http.StatusConflict, errConflict(codeIdempotencyConflict,
					"Idempotency-Key %q 已用于不同的请求体", idemKey)
			}
			var resp AgentDetail
			if err := json.Unmarshal([]byte(cached), &resp); err == nil {
				return &resp, http.StatusOK, nil
			}
			return nil, http.StatusOK, nil
		}
	}
	existing, err := r.store.GetAgent(tx, tenant, req.Name, true)
	if err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("查询 agent 失败: %v", err)
	}
	if existing != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusConflict, errConflict(codeNameConflict, "agent %s 已存在（恢复须 PUT + If-Match）", req.Name)
	}
	publicURL, _ := r.agentURLs(tenant, req.Name)
	vres, verr := r.validateAndVerify(ctx, tx, tenant, req.ProviderID, req.Card, req.BackendURL, publicURL)
	if verr != nil {
		_ = r.store.Rollback(tx)
		// 治理拒绝须留痕（§5.7）：同步落链，失败则 fail-closed。
		if aerr := r.auditRejected(auditCtx{
			Action: "a2a.agent.register", Agent: req.Name, Provider: req.ProviderID,
			Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
			ReqID: reqID, TraceID: traceID, Reason: verr.Code,
		}); aerr != nil {
			return nil, http.StatusServiceUnavailable, aerr
		}
		return nil, verr.Status, verr
	}
	rev, err := r.store.bumpRegistryRevision(tx)
	if err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("递增 registry_revision 失败: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rec := &AgentRecord{
		Tenant: tenant, Name: req.Name, ProviderID: req.ProviderID,
		CardJSON: req.Card, ContentHash: vres.contentHash, RawHash: vres.rawHash,
		Revision: 1, RegistryRevision: rev, AgentVersion: vres.card.Version,
		BackendURL: req.BackendURL, Labels: req.Labels,
		SignatureKid: vres.sigKid, SignatureAlg: vres.sigAlg,
		SignatureVerified: vres.verified, SignatureVerifiedAt: now,
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := r.store.UpsertAgent(tx, rec); err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("写入 agent 失败: %v", err)
	}
	r.writeAudit(tx, auditCtx{
		Action: "a2a.agent.register", Agent: req.Name, Provider: req.ProviderID,
		ContentHash: vres.contentHash, OldRevision: 0, NewRevision: rec.Revision,
		Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Result: "ok", Change: "added",
	})
	if idemKey != "" {
		pubURL, discURL := r.agentURLs(tenant, req.Name)
		resp := buildDetail(rec, vres.card, pubURL, discURL, true)
		jb, _ := json.Marshal(resp)
		_ = r.store.IdempotencySet(tx, tenant, idemKey, "/v1/a2a/agents", hashBytes(req.Card), string(jb))
	}
	if err := r.store.Commit(tx); err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	pubURL, discURL := r.agentURLs(tenant, req.Name)
	resp := buildDetail(rec, vres.card, pubURL, discURL, true)
	return resp, http.StatusCreated, nil
}

// ETag 计算（§5.5）。
func agentETag(name string, revision int) string { return fmt.Sprintf("a2a-%s-%d", name, revision) }

// normalizeETag 归一化实体标签：去 W/ 前缀、去首尾引号、去空白。
//
// HTTP 头中的实体标签带引号（"a2a-name-1"），但部分客户端会回传裸值；
// 两种都要接受，故比较前统一归一化。
func normalizeETag(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "W/") {
		v = strings.TrimSpace(v[2:])
	}
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = v[1 : len(v)-1]
	}
	return strings.TrimSpace(v)
}

// etagValueMatches 判断 If-Match 头是否命中给定实体标签（支持逗号分隔的列表）。
//
// ⚠️ 与 If-None-Match 的差异：**不接受 "*"**。
// If-Match 的作用是乐观并发控制，必须由客户端给出确切版本；
// 放行 "*" 会绕过 revision 比较，使并发写互相覆盖。
func etagValueMatches(header, expected string) bool {
	want := normalizeETag(expected)
	if want == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		p := normalizeETag(part)
		if p == "" {
			continue
		}
		if p == want {
			return true
		}
	}
	return false
}

// Replace 全量替换（PUT /v1/a2a/agents/{name}；§5.5）。
func (r *Registry) Replace(ctx context.Context, authn Authn, actor, reqID, traceID, name, ifMatch string, req RegisterRequest, idemKey string) (*AgentDetail, int, error) {
	if err := authn.requireAdmin(); err != nil {
		return nil, http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return nil, http.StatusBadRequest, errInvalid("%v", terr)
	}
	if ifMatch == "" {
		return nil, http.StatusPreconditionRequired, errPreconditionRequired("缺 If-Match")
	}
	if len(req.Card) == 0 {
		return nil, http.StatusBadRequest, errInvalid("card 必填")
	}
	if len(req.Card) > r.cfg.CardMaxBytes {
		return nil, http.StatusRequestEntityTooLarge, errPayloadTooLarge("card 超过 %d 字节", r.cfg.CardMaxBytes)
	}
	if req.BackendURL == "" {
		return nil, http.StatusBadRequest, errInvalid("backend_url 必填")
	}
	tx, err := r.store.Begin()
	if err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	// 幂等：同 key + 同 body → 同响应；同 key + 不同 body → 409 idempotency_conflict。
	idemEndpoint := "PUT:/v1/a2a/agents/" + name
	reqHash := hashBytes(req.Card)
	if idemKey != "" {
		cached, cachedHash, ok := r.store.IdempotencyGet(tx, tenant, idemKey, idemEndpoint)
		if ok {
			_ = r.store.Rollback(tx)
			if cachedHash != reqHash {
				return nil, http.StatusConflict, errConflict(codeIdempotencyConflict,
					"Idempotency-Key %q 已用于不同的请求体", idemKey)
			}
			var resp AgentDetail
			if err := json.Unmarshal([]byte(cached), &resp); err == nil {
				return &resp, http.StatusOK, nil
			}
			return nil, http.StatusOK, nil
		}
	}
	cur, err := r.store.GetAgent(tx, tenant, name, true)
	if err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("查询 agent 失败: %v", err)
	}
	if cur == nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusNotFound, errNotFound("agent %s", name)
	}
	if !etagValueMatches(ifMatch, agentETag(name, cur.Revision)) {
		_ = r.store.Rollback(tx)
		return nil, http.StatusPreconditionFailed, errPreconditionFailed("If-Match 不匹配")
	}
	publicURL, _ := r.agentURLs(tenant, name)
	vres, verr := r.validateAndVerify(ctx, tx, tenant, req.ProviderID, req.Card, req.BackendURL, publicURL)
	if verr != nil {
		_ = r.store.Rollback(tx)
		// 治理拒绝须留痕（§5.7）：同步落链，失败则 fail-closed。
		if aerr := r.auditRejected(auditCtx{
			Action: "a2a.agent.update", Agent: name, Provider: req.ProviderID,
			OldRevision: cur.Revision, NewRevision: cur.Revision,
			Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
			ReqID: reqID, TraceID: traceID, Reason: verr.Code,
		}); aerr != nil {
			return nil, http.StatusServiceUnavailable, aerr
		}
		return nil, verr.Status, verr
	}
	// 状态迁移：墓碑（deleted）→ active 视为「恢复」（revision+1，审计 restore，冻结 §5.5）。
	wasDeleted := cur.Status == "deleted"
	// 内容与后端均未变且状态未变 → 幂等：同 revision 返回（§5.5）。
	sameContent := cur.ContentHash == vres.contentHash && cur.BackendURL == req.BackendURL && !wasDeleted
	newRev := cur.Revision
	regRev := cur.RegistryRevision
	change := "updated"
	switch {
	case wasDeleted:
		change = "restore"
		newRev = cur.Revision + 1
		regRev, err = r.store.bumpRegistryRevision(tx)
		if err != nil {
			_ = r.store.Rollback(tx)
			return nil, http.StatusServiceUnavailable, errUnavailable("递增 registry_revision 失败: %v", err)
		}
	case sameContent:
		change = "unchanged"
	default:
		newRev = cur.Revision + 1
		regRev, err = r.store.bumpRegistryRevision(tx)
		if err != nil {
			_ = r.store.Rollback(tx)
			return nil, http.StatusServiceUnavailable, errUnavailable("递增 registry_revision 失败: %v", err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rec := &AgentRecord{
		Tenant: tenant, Name: name, ProviderID: req.ProviderID,
		CardJSON: req.Card, ContentHash: vres.contentHash, RawHash: vres.rawHash,
		Revision: newRev, RegistryRevision: regRev, AgentVersion: vres.card.Version,
		BackendURL: req.BackendURL, Labels: req.Labels,
		SignatureKid: vres.sigKid, SignatureAlg: vres.sigAlg,
		SignatureVerified: vres.verified, SignatureVerifiedAt: now,
		Status: "active", CreatedAt: cur.CreatedAt, UpdatedAt: now,
	}
	if err := r.store.UpsertAgent(tx, rec); err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("写入 agent 失败: %v", err)
	}
	if change != "unchanged" {
		r.writeAudit(tx, auditCtx{
			Action: "a2a.agent.update", Agent: name, Provider: req.ProviderID,
			ContentHash: vres.contentHash, OldRevision: cur.Revision, NewRevision: newRev,
			Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
			ReqID: reqID, TraceID: traceID, Result: "ok", Change: change,
		})
	}
	if idemKey != "" {
		pubURL, discURL := r.agentURLs(tenant, name)
		resp := buildDetail(rec, vres.card, pubURL, discURL, true)
		jb, _ := json.Marshal(resp)
		_ = r.store.IdempotencySet(tx, tenant, idemKey, idemEndpoint, reqHash, string(jb))
	}
	if err := r.store.Commit(tx); err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	pubURL, discURL := r.agentURLs(tenant, name)
	resp := buildDetail(rec, vres.card, pubURL, discURL, true)
	return resp, http.StatusOK, nil
}

// Get 取详情（GET /v1/a2a/agents/{name}；§5.3）。admin 可见 backend_url。
func (r *Registry) Get(authn Authn, name string) (*AgentDetail, int, error) {
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return nil, http.StatusBadRequest, errInvalid("%v", terr)
	}
	tx, err := r.store.Begin()
	if err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	rec, err := r.store.GetAgent(tx, tenant, name, false)
	if err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("查询 agent 失败: %v", err)
	}
	_ = r.store.Rollback(tx)
	if rec == nil {
		return nil, http.StatusNotFound, errNotFound("agent %s", name)
	}
	pubURL, discURL := r.agentURLs(tenant, name)
	detail := buildDetail(rec, nil, pubURL, discURL, isAdminRole(authn.Role))
	return detail, http.StatusOK, nil
}

// List 列表（GET /v1/a2a/agents；§5.3）。
func (r *Registry) List(authn Authn, namePrefix, skill, status string, includeDeleted bool, limit int, cursor string) ([]*AgentDetail, int, error) {
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return nil, http.StatusBadRequest, errInvalid("%v", terr)
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	tx, err := r.store.Begin()
	if err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	recs, err := r.store.ListAgents(tx, tenant, namePrefix, skill, status, includeDeleted, limit, cursor)
	if err != nil {
		_ = r.store.Rollback(tx)
		return nil, http.StatusServiceUnavailable, errUnavailable("列出 agent 失败: %v", err)
	}
	_ = r.store.Rollback(tx)
	out := make([]*AgentDetail, 0, len(recs))
	for _, rec := range recs {
		pubURL, discURL := r.agentURLs(tenant, rec.Name)
		out = append(out, buildDetail(rec, nil, pubURL, discURL, isAdminRole(authn.Role)))
	}
	return out, http.StatusOK, nil
}

// Delete 软删（DELETE /v1/a2a/agents/{name}；§5.5）。
func (r *Registry) Delete(authn Authn, actor, reqID, traceID, name, ifMatch string) (int, error) {
	if err := authn.requireAdmin(); err != nil {
		return http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return http.StatusBadRequest, errInvalid("%v", terr)
	}
	if ifMatch == "" {
		return http.StatusPreconditionRequired, errPreconditionRequired("缺 If-Match")
	}
	tx, err := r.store.Begin()
	if err != nil {
		return http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	cur, err := r.store.GetAgent(tx, tenant, name, false)
	if err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("查询 agent 失败: %v", err)
	}
	if cur == nil {
		_ = r.store.Rollback(tx)
		return http.StatusNotFound, errNotFound("agent %s", name)
	}
	if !etagValueMatches(ifMatch, agentETag(name, cur.Revision)) {
		_ = r.store.Rollback(tx)
		return http.StatusPreconditionFailed, errPreconditionFailed("If-Match 不匹配")
	}
	if _, err := r.store.bumpRegistryRevision(tx); err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("递增 registry_revision 失败: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := r.store.SoftDeleteAgent(tx, tenant, name, now); err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("软删 agent 失败: %v", err)
	}
	r.writeAudit(tx, auditCtx{
		Action: "a2a.agent.delete", Agent: name, Provider: cur.ProviderID,
		ContentHash: cur.ContentHash, OldRevision: cur.Revision, NewRevision: cur.Revision,
		Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Result: "ok", Change: "removed",
	})
	if err := r.store.Commit(tx); err != nil {
		return http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	return http.StatusNoContent, nil
}

// Verify 用当前信任库重验（POST /v1/a2a/agents/{name}/verify；§5.3）。
func (r *Registry) Verify(ctx context.Context, authn Authn, actor, reqID, traceID, name string) (int, error) {
	if err := authn.requireAdmin(); err != nil {
		return http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return http.StatusBadRequest, errInvalid("%v", terr)
	}
	tx, err := r.store.Begin()
	if err != nil {
		return http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	cur, err := r.store.GetAgent(tx, tenant, name, true)
	if err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("查询 agent 失败: %v", err)
	}
	if cur == nil {
		_ = r.store.Rollback(tx)
		return http.StatusNotFound, errNotFound("agent %s", name)
	}
	publicURL, _ := r.agentURLs(tenant, name)
	vres, verr := r.validateAndVerify(ctx, tx, tenant, cur.ProviderID, cur.CardJSON, cur.BackendURL, publicURL)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	verified := verr == nil && vres.verified
	_ = r.store.UpdateSignatureStatus(tx, tenant, name, verified, now)
	reason := "ok"
	if !verified {
		reason = "signature_invalid"
		// T-5：a2a_signature_failures_total{reason}
		r.metrics.ObserveSignatureFailure(reason)
	}
	r.writeAudit(tx, auditCtx{
		Action: "a2a.agent.verify", Agent: name, Provider: cur.ProviderID,
		ContentHash: cur.ContentHash, OldRevision: cur.Revision, NewRevision: cur.Revision,
		Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Result: resultOf(verified), Reason: reason, Change: "updated",
	})
	if err := r.store.Commit(tx); err != nil {
		return http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	if !verified {
		// T-5：a2a_signature_failures_total{reason}
		r.metrics.ObserveSignatureFailure(SigFailSignatureInvalid)
		return http.StatusUnprocessableEntity, errValidation(codeSignatureInvalid, "重验失败：签名不可信或已失效")
	}
	return http.StatusOK, nil
}

// ProviderKeyInput 是导入密钥请求体（§5.3/§4.2）。
type ProviderKeyInput struct {
	Kid       string  `json:"kid"`
	Alg       string  `json:"alg"`
	PublicJWK string  `json:"public_jwk"`
	NotBefore *string `json:"not_before,omitempty"`
	NotAfter  *string `json:"not_after,omitempty"`
}

// ImportKey 导入 pinned 公钥（POST /v1/a2a/providers/{provider}/keys；§5.3/§4.2）。
func (r *Registry) ImportKey(authn Authn, actor, reqID, traceID, provider string, key ProviderKeyInput) (int, error) {
	if err := authn.requireAdmin(); err != nil {
		return http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return http.StatusBadRequest, errInvalid("%v", terr)
	}
	if provider == "" || key.Kid == "" || key.Alg == "" || key.PublicJWK == "" {
		return http.StatusBadRequest, errInvalid("provider/kid/alg/public_jwk 必填")
	}
	if !algAllowed(key.Alg) {
		verr := errValidation(codeSignatureInvalid, "alg %q 不在白名单内", key.Alg)
		return r.rejectKeyImport(authn, actor, reqID, traceID, tenant, provider, key, verr)
	}
	pub, perr := parsePublicJWK(key.PublicJWK)
	if perr != nil {
		verr := errValidation(codeUntrustedKey, "public_jwk 非法: %v", perr)
		return r.rejectKeyImport(authn, actor, reqID, traceID, tenant, provider, key, verr)
	}
	if !algMatchesKey(key.Alg, pub) {
		verr := errValidation(codeUntrustedKey, "alg %q 与公钥类型不匹配", key.Alg)
		return r.rejectKeyImport(authn, actor, reqID, traceID, tenant, provider, key, verr)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	k := &ProviderKey{
		TenantID: tenant, ProviderID: provider, Kid: key.Kid, Alg: key.Alg,
		PublicJWK: key.PublicJWK, Status: "active",
		NotBefore: key.NotBefore, NotAfter: key.NotAfter,
		CreatedAt: now, UpdatedAt: now,
	}
	tx, err := r.store.Begin()
	if err != nil {
		return http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	if err := r.store.ImportProviderKey(tx, k); err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("导入密钥失败: %v", err)
	}
	r.writeAudit(tx, auditCtx{
		Action: "a2a.key.import", Provider: provider, Kid: key.Kid, Alg: key.Alg,
		ContentHash: keyFingerprint(key.PublicJWK), OldRevision: 0, NewRevision: 0,
		Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Result: "ok", Change: "added",
	})
	if err := r.store.Commit(tx); err != nil {
		return http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	return http.StatusCreated, nil
}

// rejectKeyImport 记录密钥导入的治理拒绝并返回原错误（§5.7 fail-closed）。
func (r *Registry) rejectKeyImport(authn Authn, actor, reqID, traceID, tenant, provider string, key ProviderKeyInput, verr *regError) (int, error) {
	if aerr := r.auditRejected(auditCtx{
		Action: "a2a.key.import", Provider: provider, Kid: key.Kid, Alg: key.Alg,
		Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Reason: verr.Code,
	}); aerr != nil {
		return http.StatusServiceUnavailable, aerr
	}
	return http.StatusUnprocessableEntity, verr
}

// ListKeys 列出 provider 密钥（GET；§5.3）。
func (r *Registry) ListKeys(authn Authn, provider string) ([]*ProviderKey, int, error) {
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return nil, http.StatusBadRequest, errInvalid("%v", terr)
	}
	tx, err := r.store.Begin()
	if err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	ks, err := r.store.ListProviderKeys(tx, tenant, provider)
	_ = r.store.Rollback(tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, errUnavailable("列出密钥失败: %v", err)
	}
	return ks, http.StatusOK, nil
}

// RevokeKey 吊销密钥并触发受影响 agent 重验（§4.1/§5.3）。
func (r *Registry) RevokeKey(ctx context.Context, authn Authn, actor, reqID, traceID, provider, kid string) (int, error) {
	if err := authn.requireAdmin(); err != nil {
		return http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return http.StatusBadRequest, errInvalid("%v", terr)
	}
	tx, err := r.store.Begin()
	if err != nil {
		return http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	k, err := r.store.GetProviderKey(tx, tenant, provider, kid)
	if err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("查询密钥失败: %v", err)
	}
	if k == nil {
		_ = r.store.Rollback(tx)
		return http.StatusNotFound, errNotFound("key %s", kid)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := r.store.SetProviderKeyStatus(tx, tenant, provider, kid, "revoked", now); err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("吊销密钥失败: %v", err)
	}
	rows, _ := r.store.ListAgents(tx, tenant, "", "", "", false, 1000, "")
	for _, rec := range rows {
		if rec.ProviderID != provider {
			continue
		}
		publicURL, _ := r.agentURLs(tenant, rec.Name)
		vres, verr := r.validateAndVerify(ctx, tx, tenant, provider, rec.CardJSON, rec.BackendURL, publicURL)
		verified := verr == nil && vres.verified
		_ = r.store.UpdateSignatureStatus(tx, tenant, rec.Name, verified, now)
		reason := "ok"
		if !verified {
			reason = "key_revoked"
			// T-5：a2a_signature_failures_total{reason}
			r.metrics.ObserveSignatureFailure(reason)
		}
		r.writeAudit(tx, auditCtx{
			Action: "a2a.agent.verify", Agent: rec.Name, Provider: provider,
			ContentHash: rec.ContentHash, OldRevision: rec.Revision, NewRevision: rec.Revision,
			Actor: actor, ActorTenant: authn.Tenant, Target: tenant,
			ReqID: reqID, TraceID: traceID, Result: resultOf(verified), Reason: reason, Change: "updated",
		})
	}
	r.writeAudit(tx, auditCtx{
		Action: "a2a.key.revoke", Provider: provider, Kid: kid, Alg: k.Alg,
		ContentHash: keyFingerprint(k.PublicJWK),
		Actor:       actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Result: "ok", Change: "removed",
	})
	if err := r.store.Commit(tx); err != nil {
		return http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	return http.StatusOK, nil
}

// DeleteKey 删除密钥（仅 revoked 或无引用；§5.3）。
func (r *Registry) DeleteKey(authn Authn, actor, reqID, traceID, provider, kid string) (int, error) {
	if err := authn.requireAdmin(); err != nil {
		return http.StatusForbidden, errForbidden("%v", err)
	}
	tenant, terr := authn.targetTenant()
	if terr != nil {
		return http.StatusBadRequest, errInvalid("%v", terr)
	}
	tx, err := r.store.Begin()
	if err != nil {
		return http.StatusServiceUnavailable, errUnavailable("打开事务失败: %v", err)
	}
	k, err := r.store.GetProviderKey(tx, tenant, provider, kid)
	if err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("查询密钥失败: %v", err)
	}
	if k == nil {
		_ = r.store.Rollback(tx)
		return http.StatusNotFound, errNotFound("key %s", kid)
	}
	if k.Status != "revoked" {
		affected, _ := r.store.AffectedAgentsByProvider(tx, tenant, provider)
		if affected > 0 {
			_ = r.store.Rollback(tx)
			return http.StatusConflict, errConflict(codeNameConflict, "key 仍被引用（须先吊销）")
		}
	}
	n, err := r.store.DeleteProviderKey(tx, tenant, provider, kid)
	if err != nil {
		_ = r.store.Rollback(tx)
		return http.StatusServiceUnavailable, errUnavailable("删除密钥失败: %v", err)
	}
	if n == 0 {
		_ = r.store.Rollback(tx)
		return http.StatusNotFound, errNotFound("key %s", kid)
	}
	r.writeAudit(tx, auditCtx{
		Action: "a2a.key.delete", Provider: provider, Kid: kid, Alg: k.Alg,
		ContentHash: keyFingerprint(k.PublicJWK),
		Actor:       actor, ActorTenant: authn.Tenant, Target: tenant,
		ReqID: reqID, TraceID: traceID, Result: "ok", Change: "removed",
	})
	if err := r.store.Commit(tx); err != nil {
		return http.StatusServiceUnavailable, errUnavailable("提交事务失败: %v", err)
	}
	r.flushAudit()
	return http.StatusNoContent, nil
}

// Health 返回健康检查字段（§5.3）。
// a2a_registry_ready=false 表示注册中心不可用（存储降级）——数据面据此 fail-closed。
func (r *Registry) Health() map[string]any {
	if r.degraded {
		return map[string]any{
			"a2a_registry_ready":    false,
			"a2a_registry_revision": 0,
			"a2a_registry_db":       "unavailable",
		}
	}
	rev := r.store.GetRegistryRevision()
	return map[string]any{
		"a2a_registry_ready":    true,
		"a2a_registry_revision": rev,
		"a2a_registry_db":       "ok",
	}
}

// --- 审计 ---

// auditCtx 是一次审计事件的上下文（§5.7 字段集）。
type auditCtx struct {
	Action      string // a2a.agent.register / a2a.key.import …
	Agent       string // agent 名（key 事件为空）
	Provider    string // provider_id
	Kid         string // 密钥 kid（key 事件）
	Alg         string // 密钥 alg（key 事件）
	ContentHash string // content_hash（key 事件为公钥指纹）
	OldRevision int
	NewRevision int
	Actor       string
	ActorTenant string // 操作者所属租户
	Target      string // 目标租户
	ReqID       string
	TraceID     string
	Result      string // ok | rejected
	Reason      string
	Change      string // added | updated | removed | restore
}

// writeAudit 在事务内写入审计 outbox（§5.7）。
//
// 事件字段集按冻结 §5.7 补齐：event_id/timestamp/actor/actor_tenant/target_tenant/
// action/agent/provider/old_revision/new_revision/content_hash/result/reason/request_id/trace_id。
//
// ⚠️ 不回显卡正文/公钥材料（公钥以 SHA-256 指纹入链）——冻结 §5.7 明文要求。
func (r *Registry) writeAudit(tx *sql.Tx, c auditCtx) {
	e := policyaudit.Event{
		EventID:     newEventID(),
		Timestamp:   time.Now().UnixNano(),
		Actor:       c.Actor,
		Action:      c.Action,
		VersionFrom: c.OldRevision,
		VersionTo:   c.NewRevision,
		RuleID:      c.Target + "/" + c.Agent,
		Change:      c.Change,
		Field:       c.Field(),
		NewValue:    c.ContentHash,
		RequestID:   c.ReqID,
		Result:      c.Result,
		// 扩展元数据（证据字段，不进 hash）。
		ActorTenant:  c.ActorTenant,
		TargetTenant: c.Target,
		Agent:        c.Agent,
		Provider:     c.Provider,
		OldRevision:  c.OldRevision,
		NewRevision:  c.NewRevision,
		ContentHash:  c.ContentHash,
		Reason:       c.Reason,
		TraceID:      c.TraceID,
	}
	b, _ := json.Marshal(e)
	_ = r.store.InsertOutbox(tx, string(b))
}

// Field 返回审计事件的 field 值（key 事件为 kid/alg，agent 事件为 provider）。
func (c auditCtx) Field() string {
	if c.Kid != "" {
		if c.Alg != "" {
			return c.Kid + "/" + c.Alg
		}
		return c.Kid
	}
	return c.Provider
}

// auditRejected 记录**治理拒绝**事件并同步落链（冻结 §5.7）。
//
// 语义（§5.7「治理拒绝类事件同步写链失败则 fail-closed」）：
//   - 拒绝事件无数据变更，故**独立事务**写入（调用方的事务已回滚）；
//   - 事件**同步**追加到既有审计链（不等 outbox 异步排空）——拒绝不留痕即不可接受；
//   - 写链失败 → 返回 error，由调用方以 503 fail-closed 拒绝请求（不得放行）。
//
// ⚠️ 未配置审计链（r.audit == nil）时同样 fail-closed：
// 无处留痕的治理拒绝不得被当作"已拒绝"而放行。
func (r *Registry) auditRejected(c auditCtx) error {
	c.Result = "rejected"
	if c.Change == "" {
		c.Change = "rejected"
	}
	tx, err := r.store.Begin()
	if err != nil {
		return errUnavailable("写拒绝审计事件失败: %v", err)
	}
	r.writeAudit(tx, c)
	if err := r.store.Commit(tx); err != nil {
		_ = r.store.Rollback(tx)
		return errUnavailable("提交拒绝审计事件失败: %v", err)
	}
	// 同步落链：取 outbox 中本条事件直接 Append（不等异步排空）。
	rows, derr := r.store.DrainOutbox(64)
	if derr != nil {
		return errUnavailable("读取审计 outbox 失败: %v", derr)
	}
	if r.audit == nil {
		// 无审计链 → 无法留痕 → fail-closed（事件保留在 outbox 待重试，不静默丢弃）。
		return errUnavailable("未配置审计链，拒绝事件无法留痕（fail-closed）")
	}
	for _, row := range rows {
		var e policyaudit.Event
		if err := json.Unmarshal([]byte(row.EventJSON), &e); err != nil {
			_ = r.store.MarkOutboxError(row.ID, err.Error())
			continue
		}
		if _, err := r.audit.Append(e); err != nil {
			_ = r.store.MarkOutboxError(row.ID, err.Error())
			return errUnavailable("拒绝事件落链失败（fail-closed）: %v", err)
		}
		_ = r.store.DeleteOutbox(row.ID)
	}
	return nil
}

// newEventID 生成事件 ID。
func newEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "a2a-" + hex.EncodeToString(b)
}

// flushAudit 排空 outbox → 既有审计链（§5.7；不丢/重试/告警）。
func (r *Registry) flushAudit() {
	rows, err := r.store.DrainOutbox(64)
	if err != nil {
		return
	}
	for _, row := range rows {
		var e policyaudit.Event
		if err := json.Unmarshal([]byte(row.EventJSON), &e); err != nil {
			_ = r.store.MarkOutboxError(row.ID, err.Error())
			continue
		}
		if r.audit == nil {
			// 无审计链（如未配置 WORM 文件）→ 保留在 outbox 待重试，不静默丢弃。
			_ = r.store.MarkOutboxError(row.ID, "未配置审计链")
			continue
		}
		if _, err := r.audit.Append(e); err != nil {
			_ = r.store.MarkOutboxError(row.ID, err.Error())
			continue
		}
		_ = r.store.DeleteOutbox(row.ID)
	}
}

func resultOf(ok bool) string {
	if ok {
		return "ok"
	}
	return "rejected"
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}
