// P2-4 T-1.7：gateway-core 存储持久化（文件快照 + 原子写 + 启动恢复）。
//
// 设计要点（P2 多集群管理设计 v0.10 · T-1.7/U-1 裁决：本期以文件快照落地，
// PG/Redis 仅登记口径不实现）：
//   - 内存为准：Memory 仍是事实源，快照只是重启恢复的旁路；
//     快照写入失败仅告警，不阻断控制面操作；
//   - 显式开关：GATEWAY_CORE_STORE_SNAPSHOT_PATH 非空才启用（main 装配处接线）；
//     空 = 纯内存，零行为变化；
//   - 原子写：临时文件 + fsync + rename 原子替换，杜绝半写/截断文件被读到；
//   - 完整性：快照整体携带 SHA-256 校验和，截断/篡改/损坏 → 拒绝加载；
//   - 防回退：快照带 saved_at 时间戳与 schema 版本号；磁盘快照比待写快照新
//     → 拒绝覆盖（防陈旧进程回写旧状态）；schema 版本不识别 → 拒绝加载；
//   - fail-open：损坏快照拒绝加载后回退空内存启动并明确告警——理由：core
//     重启可用性优先，策略/路由配置可由管理面重新下发；若因快照损坏拒绝启动，
//     整个网关控制面失联，代价远大于短暂回退空态。
//
// 快照内容覆盖（store 全部状态域）：路由处方、默认路由表、限流/预算表、
// A2A ACL 表、A2A 复合限流表、MCP 工具目录、RBAC 授权策略、MCP 后端注册域。
package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/gateway-core/internal/mcpsrv"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/mcpsec"
)

// snapshotSchemaVersion 快照 schema 版本：结构不兼容变更时递增；
// 加载端只认当前版本，其余拒绝（防旧代码误读新格式 / 新代码误读旧格式）。
const snapshotSchemaVersion = 1

// checksumPrefix 校验和字段前缀（算法显式化，便于后续演进）。
const checksumPrefix = "sha256:"

// tmpPattern 原子写临时文件命名模式（隐藏文件，落在目标同目录保证 rename 原子性）。
const tmpPattern = ".gateway-core-snapshot-*.tmp"

// snapshotPayload 快照业务载荷：store 全部状态域 + 元数据。
type snapshotPayload struct {
	SchemaVersion int                        `json:"schema_version"`
	SavedAt       int64                      `json:"saved_at"` // unix 秒，防回退时间戳
	Prescriptions []*route.RoutePrescription `json:"prescriptions,omitempty"`
	RouteTable    *route.RouteTable          `json:"route_table,omitempty"`
	// 限流/预算表（Phase 1 门禁 #7）
	RateLimitTable *ratelimit.Table `json:"rate_limit_table,omitempty"`
	// A2A ACL 表（P2-2 T-3，独立策略域 R-6）
	ACLTable *a2aproxy.ACLTable `json:"acl_table,omitempty"`
	// A2A 复合限流表（P2-2 T-3a，独立策略域 R-6）
	A2ARateLimitTable *a2aproxy.RateLimitTable `json:"a2a_rate_limit_table,omitempty"`
	ToolCatalog       *mcpsec.ToolCatalog      `json:"tool_catalog,omitempty"`
	RBACPolicy        *mcpsec.RBACPolicy       `json:"rbac_policy,omitempty"`
	MCPServers        []*mcpsrv.Server         `json:"mcp_servers,omitempty"` // T-3 后端注册域
}

// snapshotEnvelope 快照外层信封：原始载荷字节 + 校验和。
// Payload 用 RawMessage 保存写盘时的原始字节，保证校验和逐字节可复算。
type snapshotEnvelope struct {
	Payload  json.RawMessage `json:"payload"`
	Checksum string          `json:"checksum"`
}

// SnapshotStore 在 Memory 之上叠加文件快照持久化的 Store 实现（P2-4 T-1.7）。
//
// 语义：内嵌 *Memory 直接继承全部读/写行为（不改内存实现既有行为）；
// 仅拦截变更方法，在内存变更成功后同步落快照。快照写入失败只告警不回滚——
// 内存是事实源，符合 T-1.7「内存为准」口径。
//
// 接口实现完全经内嵌提升，未改动 store.Store 接口签名。
type SnapshotStore struct {
	*Memory

	path     string      // 快照文件路径；"" = 持久化关闭（零行为变化）
	disabled bool        // path 为空时置位：所有持久化动作退化为 no-op
	writeMu  sync.Mutex  // 串行化快照写盘（含防回退检查 + rename）
	logger   *log.Logger // nil 时用 log.Default()
}

// NewSnapshotStore 构造快照持久化存储。
//
// path 为空 = 显式关闭持久化（纯内存、零行为变化，仅保留告警便于排障）；
// 构造不读盘，恢复由调用方显式调用 LoadSnapshot（main 处 fail-open 接线）。
func NewSnapshotStore(mem *Memory, path string, logger *log.Logger) *SnapshotStore {
	if logger == nil {
		logger = log.Default()
	}
	ss := &SnapshotStore{Memory: mem, path: path, logger: logger}
	if path == "" {
		ss.disabled = true
		logger.Printf("store: 快照持久化未启用（纯内存，重启丢失）")
	}
	return ss
}

// LoadSnapshot 从磁盘加载快照并恢复内存态。
//
// 返回 nil 的情形：文件不存在（首次启动，正常空内存启动）或恢复成功。
// 返回错误的情形（快照损坏/被篡改/不识别）：调用方应告警并以空内存启动
// （fail-open，理由见包注释），内存态保持空、不受半恢复污染。
func (s *SnapshotStore) LoadSnapshot() error {
	if s.disabled {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.logf("store: 快照文件不存在，空内存启动: %s", s.path)
			return nil
		}
		return fmt.Errorf("store: 读取快照失败: %w", err)
	}
	payload, err := decodeSnapshot(b)
	if err != nil {
		return err // 损坏快照：拒绝加载（截断/校验失败/schema 不识别）
	}
	if err := s.restore(payload); err != nil {
		return err
	}
	s.logf("store: 快照恢复完成: %s（saved_at=%d 处方=%d 路由表=v%d 限流表=v%d ACL表=v%d A2A限流表=v%d 工具目录=v%d RBAC=v%d MCP后端=%d）",
		s.path, payload.SavedAt, len(payload.Prescriptions),
		tableVersion(payload.RouteTable), rlVersion(payload.RateLimitTable),
		aclVersion(payload.ACLTable), a2aRLVersion(payload.A2ARateLimitTable),
		catalogVersion(payload.ToolCatalog), rbacVersion(payload.RBACPolicy),
		len(payload.MCPServers))
	return nil
}

// Persist 将当前内存状态同步原子落盘。供变更路径与运维工具显式触发。
func (s *SnapshotStore) Persist() error {
	return s.persistAt(time.Now().Unix())
}

// persistAt 以指定 saved_at 落盘（测试注入时间戳用）。
// 防回退：磁盘已有更新的快照（saved_at 更大）→ 跳过本次写入并告警。
func (s *SnapshotStore) persistAt(savedAt int64) error {
	if s.disabled {
		return nil
	}
	payload := s.buildPayload(savedAt)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("store: 快照载荷编码失败: %w", err)
	}
	sum := sha256.Sum256(payloadBytes)
	env := snapshotEnvelope{
		Payload:  payloadBytes,
		Checksum: checksumPrefix + hex.EncodeToString(sum[:]),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("store: 快照信封编码失败: %w", err)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// 防回退：磁盘快照可解析且比待写快照新 → 拒绝覆盖（陈旧进程回写保护）。
	// 磁盘不可解析（损坏/截断）→ 允许覆盖：正好用新快照修复损坏文件。
	if cur, derr := readSnapshotFile(s.path); derr == nil && cur.SavedAt > savedAt {
		s.logf("警告: store: 磁盘快照 saved_at=%d 比待写快照 saved_at=%d 新，防回退跳过写入: %s",
			cur.SavedAt, savedAt, s.path)
		return nil
	}
	return atomicWriteFile(s.path, envBytes)
}

// buildPayload 在读锁下采集内存全量状态（ID 字典序，输出确定）。
func (s *SnapshotStore) buildPayload(savedAt int64) *snapshotPayload {
	m := s.Memory
	m.mu.RLock()
	defer m.mu.RUnlock()

	p := &snapshotPayload{
		SchemaVersion:     snapshotSchemaVersion,
		SavedAt:           savedAt,
		Prescriptions:     make([]*route.RoutePrescription, 0, len(m.byID)),
		RouteTable:        m.routeTable,
		RateLimitTable:    m.rateLimitTable,
		ACLTable:          m.aclTable,
		A2ARateLimitTable: m.a2aRLTable,
		ToolCatalog:       m.toolCatalog,
		RBACPolicy:        m.rbacPolicy,
		MCPServers:        make([]*mcpsrv.Server, 0, len(m.mcpServers)),
	}
	ids := make([]string, 0, len(m.byID))
	for id := range m.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p.Prescriptions = append(p.Prescriptions, m.byID[id])
	}
	svIDs := make([]string, 0, len(m.mcpServers))
	for id := range m.mcpServers {
		svIDs = append(svIDs, id)
	}
	sort.Strings(svIDs)
	for _, id := range svIDs {
		p.MCPServers = append(p.MCPServers, m.mcpServers[id])
	}
	return p
}

// restore 将快照载荷整体恢复进内存（先在锁外构造完整新态，校验全部通过后
// 一次性换入，避免半恢复污染）。
func (s *SnapshotStore) restore(p *snapshotPayload) error {
	byID := make(map[string]*route.RoutePrescription, len(p.Prescriptions))
	byT := make(map[string][]string)
	for _, rx := range p.Prescriptions {
		if rx == nil || rx.PrescriptionID == "" {
			return errors.New("store: 快照含空处方条目，拒绝加载")
		}
		if _, dup := byID[rx.PrescriptionID]; dup {
			return fmt.Errorf("store: 快照处方 ID 重复: %s，拒绝加载", rx.PrescriptionID)
		}
		byID[rx.PrescriptionID] = rx
		byT[rx.Tenant] = append(byT[rx.Tenant], rx.PrescriptionID)
	}
	servers := make(map[string]*mcpsrv.Server, len(p.MCPServers))
	for _, sv := range p.MCPServers {
		if sv == nil || sv.ID == "" {
			return errors.New("store: 快照含空 MCP 后端条目，拒绝加载")
		}
		if _, dup := servers[sv.ID]; dup {
			return fmt.Errorf("store: 快照 MCP 后端 ID 重复: %s，拒绝加载", sv.ID)
		}
		servers[sv.ID] = sv
	}

	m := s.Memory
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID = byID
	m.byT = byT
	m.routeTable = p.RouteTable
	m.rateLimitTable = p.RateLimitTable
	m.aclTable = p.ACLTable
	m.a2aRLTable = p.A2ARateLimitTable
	m.toolCatalog = p.ToolCatalog
	m.rbacPolicy = p.RBACPolicy
	m.mcpServers = servers
	return nil
}

// —— 以下为变更路径拦截：内存变更成功后同步落快照 ——

// Save 实现 Store。ErrDup（无状态变化）不落快照。
func (s *SnapshotStore) Save(p *route.RoutePrescription) error {
	if err := s.Memory.Save(p); err != nil {
		return err
	}
	s.persistWarn()
	return nil
}

// Delete 实现 Store。无论目标是否存在均落快照（删除语义幂等，宁可多写一次）。
func (s *SnapshotStore) Delete(id string) {
	s.Memory.Delete(id)
	s.persistWarn()
}

// SaveRouteTable 实现 Store。
func (s *SnapshotStore) SaveRouteTable(t *route.RouteTable) {
	s.Memory.SaveRouteTable(t)
	s.persistWarn()
}

// SaveRateLimitTable 实现 Store。
func (s *SnapshotStore) SaveRateLimitTable(t *ratelimit.Table) {
	s.Memory.SaveRateLimitTable(t)
	s.persistWarn()
}

// SaveACLTable 实现 Store。
func (s *SnapshotStore) SaveACLTable(t *a2aproxy.ACLTable) {
	s.Memory.SaveACLTable(t)
	s.persistWarn()
}

// SaveA2ARateLimitTable 实现 Store。
func (s *SnapshotStore) SaveA2ARateLimitTable(t *a2aproxy.RateLimitTable) {
	s.Memory.SaveA2ARateLimitTable(t)
	s.persistWarn()
}

// SaveToolCatalog 实现 Store。
func (s *SnapshotStore) SaveToolCatalog(c *mcpsec.ToolCatalog) {
	s.Memory.SaveToolCatalog(c)
	s.persistWarn()
}

// SaveRBACPolicy 实现 Store。
func (s *SnapshotStore) SaveRBACPolicy(p *mcpsec.RBACPolicy) {
	s.Memory.SaveRBACPolicy(p)
	s.persistWarn()
}

// SaveMCPServer 实现 Store。
func (s *SnapshotStore) SaveMCPServer(sv *mcpsrv.Server) {
	s.Memory.SaveMCPServer(sv)
	s.persistWarn()
}

// DeleteMCPServer 实现 Store。仅在实际摘除时落快照。
func (s *SnapshotStore) DeleteMCPServer(id string) bool {
	removed := s.Memory.DeleteMCPServer(id)
	if removed {
		s.persistWarn()
	}
	return removed
}

// persistWarn 落快照；失败仅告警（内存为准，不阻断控制面操作）。
func (s *SnapshotStore) persistWarn() {
	if err := s.Persist(); err != nil {
		s.logf("警告: store: 快照写入失败（内存不受影响）: %v", err)
	}
}

// decodeSnapshot 解码并完整校验快照字节：JSON 结构 → 校验和 → 载荷。
// 任一失败即拒绝（返回错误，调用方 fail-open）。
func decodeSnapshot(b []byte) (*snapshotPayload, error) {
	var env snapshotEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("store: 快照解析失败（截断或损坏）: %w", err)
	}
	if !strings.HasPrefix(env.Checksum, checksumPrefix) {
		return nil, errors.New("store: 快照校验和缺失或格式非法，拒绝加载")
	}
	want, err := hex.DecodeString(strings.TrimPrefix(env.Checksum, checksumPrefix))
	if err != nil {
		return nil, fmt.Errorf("store: 快照校验和编码非法: %w", err)
	}
	got := sha256.Sum256(env.Payload)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, errors.New("store: 快照校验和不匹配（内容损坏或被篡改），拒绝加载")
	}
	var p snapshotPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, fmt.Errorf("store: 快照载荷解析失败: %w", err)
	}
	if p.SchemaVersion != snapshotSchemaVersion {
		return nil, fmt.Errorf("store: 快照 schema 版本不识别: got %d want %d，拒绝加载（防误读/防回退）",
			p.SchemaVersion, snapshotSchemaVersion)
	}
	return &p, nil
}

// readSnapshotFile 读取并解码磁盘快照；任何失败返回错误（调用方据此决定覆盖）。
func readSnapshotFile(path string) (*snapshotPayload, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeSnapshot(b)
}

// atomicWriteFile 原子写：同目录临时文件 → fsync → rename 原子替换 →
// 目录 fsync（best-effort；Windows 打不开目录，忽略）。
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return fmt.Errorf("store: 创建快照临时文件失败: %w", err)
	}
	tmp := f.Name()
	// 任一步失败都清理临时文件，避免残留垃圾。
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("store: 快照临时文件写入失败: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("store: 快照临时文件 fsync 失败: %w", err))
	}
	if err := f.Close(); err != nil {
		return fail(fmt.Errorf("store: 快照临时文件关闭失败: %w", err))
	}
	// 0600：快照含路由/策略/租户配置，收紧权限。
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fail(fmt.Errorf("store: 快照临时文件权限设置失败: %w", err))
	}
	if err := os.Rename(tmp, path); err != nil {
		return fail(fmt.Errorf("store: 快照原子替换失败: %w", err))
	}
	// 目录 fsync：保证 rename 落盘（Linux）；失败不影响正确性，忽略。
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// —— 版本号提取辅助（仅用于恢复日志展示；nil 表计 0）——

func tableVersion(t *route.RouteTable) int {
	if t == nil {
		return 0
	}
	return t.Version
}

// rlVersion 限流/预算表版本号（nil 计 0）。
func rlVersion(t *ratelimit.Table) int {
	if t == nil {
		return 0
	}
	return t.Version
}

func aclVersion(t *a2aproxy.ACLTable) int {
	if t == nil {
		return 0
	}
	return t.Version
}

func a2aRLVersion(t *a2aproxy.RateLimitTable) int {
	if t == nil {
		return 0
	}
	return t.Version
}

func catalogVersion(c *mcpsec.ToolCatalog) int {
	if c == nil {
		return 0
	}
	return c.Version
}

func rbacVersion(p *mcpsec.RBACPolicy) int {
	if p == nil {
		return 0
	}
	return p.Version
}

// logf 统一日志出口。
func (s *SnapshotStore) logf(format string, args ...any) {
	s.logger.Printf("store: "+format, args...)
}
