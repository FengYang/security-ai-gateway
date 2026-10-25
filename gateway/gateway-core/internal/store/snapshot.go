// P2-4 T-1.7：gateway-core 存储持久化（文件快照 + 原子写 + 启动恢复）。
//
// 设计要点（P2 多集群管理设计 v0.10 · T-1.7/U-1 裁决：本期以文件快照落地，
// PG/Redis 仅登记口径不实现）：
//   - 内存为准：Memory 仍是事实源，快照只是重启恢复的旁路；
//     快照写入失败**只告警不阻断**（失败计数 + 告警升级，见 PersistFailures）；
//   - 显式开关：GATEWAY_CORE_STORE_SNAPSHOT_PATH 非空才启用（main 装配处接线）；
//     空 = 纯内存，零行为变化；
//   - 原子写：临时文件 + fsync + rename 原子替换，杜绝半写/截断文件被读到；
//   - 完整性：快照整体携带 SHA-256 校验和，截断/篡改/损坏 → 拒绝加载；
//   - **防回退以内容级判据为主（QA P2-2）**：快照内含单调递增的 revision；
//     写盘前比对磁盘 revision，磁盘 revision ≥ 待写 revision ⇒ 拒绝覆盖
//     （磁盘更新 ⇒ 本进程状态陈旧，回写即回退）；时钟 saved_at **仅作辅助判据**
//     （时钟异常只告警，不作为拒绝依据，避免时钟回拨/漂移造成误拒）；
//     schema 版本号不识别 → 拒绝加载；
//   - **防回退拒绝不造成永久停滞（QA P2-新）**：拒绝时把本地基线推进到磁盘
//     revision（下一写用 diskRev+1 > 磁盘 ⇒ 不再被同一判据反复拒绝），
//     并把拒绝计入失败指标 + 升级告警（"失去持久化"必须可观测）；
//   - fail-open：损坏快照拒绝加载后回退空内存启动并明确告警——理由：core
//     重启可用性优先，策略/路由配置可由管理面重新下发；若因快照损坏拒绝启动，
//     整个网关控制面失联，代价远大于短暂回退空态。
//
// 快照内容覆盖（**覆盖边界口径，QA P3 口径项 / team-lead 登记项**）：
//
//		**快照覆盖 = `store.Memory` 的状态域全集。**
//
//	  - Memory 的**每一个字段**都必须在 snapshotCoverage 清单中登记，且明确归类为
//	    「持久化 / 派生 / 非状态」之一（清单即口径的书面形式）；
//	  - 新增状态域时**必须**同步：① 登记清单 ② 纳入 buildPayload（写）③ 纳入
//	    restore（读）。漏任一步 ⇒ TestSnapshotCoversAllMemoryFields 失败
//	    （"漏域 = 重启后静默丢配置"，不报错、不可观测，最危险）；
//	  - **不属于 store.Memory 的控制面状态不在快照覆盖范围内**：例如 api.Server
//	    上的 applied 配置版本缓存（configversion.Cache）——它是插件上报的**观测
//	    缓存**（可重报），不是策略/路由配置；重启后为空、插件下次拉取即恢复，
//	    心跳的 applied_config_version 随之恢复。若将来出现**必须跨重启保留**的
//	    控制面状态，须先落到 store.Memory（否则会静默丢失）。
//
// 快照内容覆盖（当前登记）：路由处方、默认路由表、限流/预算表、A2A ACL 表、
// A2A 复合限流表、MCP 工具目录、RBAC 授权策略、MCP 后端注册域。
//
// —— 防回退**总口径**（P2-4 T-1.7，**不依赖部署配置**）——
//
//	**"revision 单调 + 内容不回退"由两道机制共同保证：**
//
//	  1. **内容级版本判据（主防线）**：按表逐个比较自报版本，磁盘更新 ⇒ 拒绝写盘
//	     （磁盘内容逐字节不变）；本地缺表 / 同版本内容漂移 ⇒ 保守拒绝 + 告警。
//	     详见 snapshotcontent.go。
//	  2. **写者串行化（lockfile 互斥）**：临界区覆盖"读盘 → 比较 → 写盘"整段，
//	     消除 TOCTOU（比较与写之间的时间窗口）；第二写者阻塞等待或明确失败，
//	     **绝不覆盖**他人快照。详见 snapshotlock.go。
//
//	⇒ 即便出现"两进程共享同一快照路径"的异常部署形态，也不会发生内容回退。
//
// —— 部署侧约束（**gateway-core 侧口径记录；deploy/ 属他人域，未在本仓修改**）——
//
//   - gateway-core 的**多副本 overlay 必须带 `maxSurge=0`**（与
//     deploy/k8s-overlays/multicluster/ 现有口径一致），杜绝滚动更新期间新旧
//     Pod 并存、共享同一快照路径；
//
//   - 基线部署 replicas=1 + RWO PVC（旧实例退净后再起新实例）。
//
//     以上是**部署侧加固**，不是唯一保障：代码层的写者锁与内容判据独立成立，
//     不依赖部署形态（部署约束只是"少一次冲突"，不是"防回退的手段"）。
//
// —— 可观测性口径 ——
//
//   - `RollbackRejects()`：**revision 判据**拒绝次数；>0 ⇒ 出现过多写者窗口
//     （建议接入告警；本仓只提供计数与文案，告警接线点不在 gateway-core 域）。
//   - `ContentBlocks()`：**内容判据**拦截次数；>0 ⇒ 磁盘内容比本地新、本次写盘
//     被**主动放弃**（**独立告警文案**，与"防回退拒绝"不共用，二者可分别归因）。
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

const (
	// snapshotSchemaVersion 快照 schema 版本：结构不兼容变更时递增；
	// 加载端只认当前版本，其余拒绝（防旧代码误读新格式 / 新代码误读旧格式）。
	snapshotSchemaVersion = 1
	// checksumPrefix 校验和字段前缀（算法显式化，便于后续演进）。
	checksumPrefix = "sha256:"
	// tmpPattern 原子写临时文件命名模式（隐藏文件，落在目标同目录保证 rename 原子性）。
	tmpPattern = ".gateway-core-snapshot-*.tmp"
	// precheckPattern 启动期可写性自检的临时文件命名模式。
	precheckPattern = ".gateway-core-snapshot-precheck-*"
	// DefaultFlushInterval 合并写窗口：窗口内的多次变更合并为一次全量落盘。
	DefaultFlushInterval = 200 * time.Millisecond
	// persistWarnThreshold 连续写失败达到该次数后告警升级（错误级措辞 + 计数）。
	persistWarnThreshold = 3
	// maxRollbackAutoRetries 防回退拒绝后的**自动重试上限**（QA P2-新）：
	// 拒绝时基线已推进到磁盘 revision（下一写必然 > 磁盘），自动重试通常一次即成；
	// 设上限避免与"持续推进的写者"无限对撞（忙循环）。
	maxRollbackAutoRetries = 3
	// renameRetryAttempts 原子替换的重试次数（Windows 瞬时 sharing violation 退避）。
	renameRetryAttempts = 5
	// renameRetryDelay 原子替换重试的退避间隔。
	renameRetryDelay = 20 * time.Millisecond
	// contentBlockRepeatLogEvery 内容回退拦截的**重复告警**节流：同一冲突集合
	// 连续出现时，每 N 次才打一条"重复"告警（避免每 200ms 合并写窗口刷屏）。
	contentBlockRepeatLogEvery = 10
)

// rollbackRetryDelay 防回退拒绝后的自动重试延迟（错开重试，避免紧贴磁盘抖动）。
//
// ⚠️ 变量而非常量：单测需要**拉长**该延迟以构造"重试窗口内磁盘被他人更新"的
// 确定性时序（见 TestSnapshotAutoRetryAbandonsOnNewerDiskContent）。
var rollbackRetryDelay = 50 * time.Millisecond

// rollbackRejectError 防回退拒绝错误（QA P2-新）。
//
// 携带"基线推进后的下一 revision"，供上层做**有界自动重试**；
// 用类型而非字符串匹配判定（避免脆弱的错误文案耦合）。
type rollbackRejectError struct {
	msg     string // 面向运维的错误文案（含磁盘/待写 revision）
	nextRev int64  // 基线推进后的下一 revision（= 磁盘 revision + 1）
}

// Error 实现 error 接口。
func (e *rollbackRejectError) Error() string { return e.msg }

// coverageKind Memory 字段的快照覆盖归类。
type coverageKind int

const (
	// coveragePersisted 状态域：写入快照载荷（重启可恢复）。
	coveragePersisted coverageKind = iota
	// coverageDerived 派生域：由其它状态域无损重建，不单独持久化。
	coverageDerived
	// coverageNonState 非状态：锁等运行期设施，无持久化语义。
	coverageNonState
)

// memoryFieldCoverage 单个 Memory 字段的快照覆盖登记（**覆盖边界口径的书面形式**）。
type memoryFieldCoverage struct {
	// Field Memory 结构体字段名（与源码一致）。
	Field string
	// Kind 覆盖归类（持久化 / 派生 / 非状态）。
	Kind coverageKind
	// Payload 持久化字段在 snapshotPayload 中的字段名（仅 Kind=coveragePersisted 有值）。
	Payload string
	// Note 说明（评审检查点：新增字段时在此写清为何这样归类）。
	Note string
}

// snapshotCoverage **快照覆盖清单**：store.Memory 的字段全集登记。
//
// 口径（QA P3 口径项 / team-lead 登记项）：**快照覆盖 = store.Memory 的状态域全集**。
// 本清单是该口径的**唯一书面事实源**，由 TestSnapshotCoversAllMemoryFields 强制：
//   - Memory 新增字段而未登记 ⇒ 测试失败（必须先决策"是否纳入快照"）；
//   - 登记为持久化但未真正写入载荷 ⇒ 测试失败（防"登记了却漏写"）；
//   - 载荷字段名写错 ⇒ 测试失败（防"写到了别的字段"）。
//
// ⚠️ 新增 Memory 字段时的**强制流程**：① 在本清单登记（并写清 Note）
// ② 在 buildPayload 中写入 ③ 在 restore 中恢复 ④ 跑本用例。
// 漏 ② 或 ③ 的后果是"重启后静默丢配置"——不报错、不可观测，最危险。
var snapshotCoverage = []memoryFieldCoverage{
	{Field: "mu", Kind: coverageNonState, Note: "读写锁，非状态域"},
	{Field: "byID", Kind: coveragePersisted, Payload: "Prescriptions", Note: "处方集合（按 ID 字典序输出，保证字节级确定性）"},
	{Field: "byT", Kind: coverageDerived, Note: "tenant→处方ID 索引：由 byID 无损重建（顺序口径见 restore 注释）"},
	{Field: "routeTable", Kind: coveragePersisted, Payload: "RouteTable", Note: "默认路由表"},
	{Field: "rateLimitTable", Kind: coveragePersisted, Payload: "RateLimitTable", Note: "限流/预算表"},
	{Field: "aclTable", Kind: coveragePersisted, Payload: "ACLTable", Note: "A2A ACL 策略表（独立策略域 R-6）"},
	{Field: "a2aRLTable", Kind: coveragePersisted, Payload: "A2ARateLimitTable", Note: "A2A 复合限流表（独立策略域 R-6）"},
	{Field: "toolCatalog", Kind: coveragePersisted, Payload: "ToolCatalog", Note: "MCP 工具目录"},
	{Field: "rbacPolicy", Kind: coveragePersisted, Payload: "RBACPolicy", Note: "MCP RBAC 授权策略"},
	{Field: "mcpServers", Kind: coveragePersisted, Payload: "MCPServers", Note: "MCP 后端注册域（按 ID 字典序输出）"},
}

// snapshotPayload 快照业务载荷：store 全部状态域 + 元数据。
type snapshotPayload struct {
	SchemaVersion int `json:"schema_version"`
	// Revision 内容级单调递增版本（**防回退主判据**，QA P2-2）：
	// 每次成功落盘 +1；加载时采纳磁盘值作为后续写盘基线。
	// 旧版快照缺该字段 = 0（兼容读，视为"最旧"）。
	Revision int64 `json:"revision"`
	// SavedAt unix 秒（**防回退辅助判据**：仅用于时钟异常告警，不作为拒绝依据）。
	SavedAt       int64                      `json:"saved_at"`
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
// 仅拦截变更方法，在内存变更成功后请求落快照。快照写入失败只告警不回滚——
// 内存是事实源，符合 T-1.7「内存为准」口径。
//
// 写盘时机（QA P3-5：处方签发热路径曾"每张处方一次全量快照 + fsync"）：
// **合并写**——变更只置脏标记，由后台 flusher 在合并窗口（默认 200ms）内
// 合并为一次全量落盘。**崩溃窗口语义**：进程被强杀（SIGKILL/掉电）时，
// 最近一个窗口内（≤ 200ms）的变更可能未落盘而丢失；优雅退出（Close）会强制
// 补写。窗口内变更可由管理面重新下发（处方本就可重发），故可接受。
// 需"每次变更即落盘"的严格场景：SetFlushInterval(0)。
//
// 接口实现完全经内嵌提升，未改动 store.Store 接口签名。
type SnapshotStore struct {
	*Memory

	path     string      // 快照文件路径；"" = 持久化关闭（零行为变化）
	disabled bool        // 持久化关闭（path 为空或 Prepare 失败后降级）
	logger   *log.Logger // nil 时用 log.Default()

	// ---- 状态（由 mu 保护）----
	mu          sync.Mutex
	revision    int64  // 已落盘/已加载的快照 revision（防回退基准）
	dirty       bool   // 有未落盘变更
	consecFails uint64 // 连续写失败次数（告警升级用）
	totalFails  uint64 // 累计写失败次数（可观测）
	lastFailErr error  // 最近一次写失败原因
	flushTimer  *time.Timer
	closed      bool
	// flushInterval 合并写窗口（0 = 每次变更同步落盘）。
	flushInterval time.Duration
	// rollbackRejects 防回退拒绝累计次数（可观测；>0 ⇒ 出现过多写者窗口）。
	rollbackRejects uint64
	// autoRetries 防回退拒绝后的自动重试次数（有界；成功落盘后归零）。
	autoRetries int
	// contentBlocks 内容回退拦截累计次数（可观测；>0 ⇒ 磁盘内容比本地新，
	// 本次写盘被主动放弃——**与 rollbackRejects 分开计数、分开归因**）。
	contentBlocks uint64
	// contentAlertKey 最近一次内容冲突集合的标识（告警去重：同一集合不重复刷屏）。
	contentAlertKey string
	// contentBlockRepeats 同一冲突集合连续出现的次数（告警节流用）。
	contentBlockRepeats int

	writeMu sync.Mutex // 串行化快照写盘（防回退检查 + rename）
}

// NewSnapshotStore 构造快照持久化存储。
//
// path 为空 = 显式关闭持久化（纯内存、零行为变化，仅保留告警便于排障）；
// 构造不读盘，恢复由调用方显式调用 LoadSnapshot（main 处 fail-open 接线）。
func NewSnapshotStore(mem *Memory, path string, logger *log.Logger) *SnapshotStore {
	if logger == nil {
		logger = log.Default()
	}
	ss := &SnapshotStore{Memory: mem, path: path, logger: logger, flushInterval: DefaultFlushInterval}
	if path == "" {
		ss.disabled = true
		ss.closed = true
		logger.Printf("[store] 快照持久化未启用（纯内存，重启丢失）")
		return ss
	}
	return ss
}

// SetFlushInterval 设置合并写窗口（0 = 每次变更同步落盘；默认 DefaultFlushInterval）。
func (s *SnapshotStore) SetFlushInterval(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.mu.Lock()
	s.flushInterval = d
	s.mu.Unlock()
}

// Prepare 启动准备：父目录创建 + 同目录可写性自检 + 路径类型校验。
//
// 校验项（QA P3-9 / 符号链接问题）：
//   - 父目录不存在 → MkdirAll（0750）；
//   - 目录不可写 → 创建/删除临时文件实测（拒绝静默失效）；
//   - 快照路径是**符号链接** → 拒绝（rename 只替换链接本身，其目标挂载点将停止
//     被更新且不报错——静默失效比报错更危险）；
//   - 快照路径是目录 → 拒绝。
//
// 失败语义：返回错误由调用方处置（main 侧：告警并降级为纯内存，不阻断启动）。
func (s *SnapshotStore) Prepare() error {
	if s.disabled {
		return nil
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建快照父目录失败: %w", err)
	}
	// 可写性实测：同目录创建并删除临时文件。
	f, err := os.CreateTemp(dir, precheckPattern)
	if err != nil {
		return fmt.Errorf("快照目录不可写: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return s.checkPathType()
}

// checkPathType 校验快照路径类型（符号链接 / 目录 → 拒绝）。
func (s *SnapshotStore) checkPathType() error {
	fi, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // 尚不存在：首写时由原子写创建
		}
		return fmt.Errorf("检查快照路径失败: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("快照路径是符号链接，拒绝使用（rename 仅替换链接本身，其目标将停止被更新）: %s", s.path)
	}
	if fi.IsDir() {
		return fmt.Errorf("快照路径是目录，拒绝使用: %s", s.path)
	}
	return nil
}

// Disable 关闭持久化（降级为纯内存），用于启动准备失败时的显式降级。
func (s *SnapshotStore) Disable() {
	s.mu.Lock()
	s.disabled = true
	s.mu.Unlock()
	s.logf("警告: 快照持久化已关闭（降级为纯内存，重启丢失）")
}

// LoadSnapshot 从磁盘加载快照并恢复内存态。
//
// 返回 nil 的情形：文件不存在（首次启动，正常空内存启动）或恢复成功。
// 返回错误的情形（快照损坏/被篡改/不识别）：调用方应告警并以空内存启动
// （fail-open，理由见包注释），内存态保持空、不受半恢复污染。
//
// ⚠️ **读路径不获取写锁**（有意）：写盘采用"临时文件 + rename 原子替换"，
// 读者只会看到**替换前或替换后的完整文件**（不会出现半写/截断），因此读无需
// 与写互斥；更重要的是**启动期不得被陈旧锁阻塞**（锁只保护写侧临界区）。
func (s *SnapshotStore) LoadSnapshot() error {
	if s.disabled {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.logf("快照文件不存在，空内存启动: %s", s.path)
			return nil
		}
		return fmt.Errorf("读取快照失败: %w", err)
	}
	payload, err := decodeSnapshot(b)
	if err != nil {
		return err // 损坏快照：拒绝加载（截断/校验失败/schema 不识别）
	}
	if err := s.restore(payload); err != nil {
		return err
	}
	// 采纳磁盘 revision 作为后续写盘的防回退基线。
	s.mu.Lock()
	if payload.Revision > s.revision {
		s.revision = payload.Revision
	}
	s.mu.Unlock()
	s.logf("快照恢复完成: %s（revision=%d saved_at=%d 处方=%d 路由表=v%d 限流表=v%d ACL表=v%d A2A限流表=v%d 工具目录=v%d RBAC=v%d MCP后端=%d）",
		s.path, payload.Revision, payload.SavedAt, len(payload.Prescriptions),
		tableVersion(payload.RouteTable), rlVersion(payload.RateLimitTable),
		aclVersion(payload.ACLTable), a2aRLVersion(payload.A2ARateLimitTable),
		catalogVersion(payload.ToolCatalog), rbacVersion(payload.RBACPolicy),
		len(payload.MCPServers))
	return nil
}

// Persist 立即同步落盘当前状态（绕开合并写窗口；运维/测试用）。
func (s *SnapshotStore) Persist() error {
	if s.disabled {
		return nil
	}
	return s.persistAt(time.Now().Unix())
}

// Flush 强制把待写变更落盘（合并写窗口到期前的显式刷盘；优雅退出用）。
func (s *SnapshotStore) Flush() error {
	if s.disabled {
		return nil
	}
	s.mu.Lock()
	s.dirty = false
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}
	s.mu.Unlock()
	return s.persistAt(time.Now().Unix())
}

// Close 停止合并写定时器并补写最后状态（优雅退出不丢窗口内变更）。
func (s *SnapshotStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	dirty := s.dirty
	s.mu.Unlock()
	if !dirty {
		return nil // 无待写变更：不必产生额外写盘
	}
	return s.Flush()
}

// PersistFailures 返回累计写失败次数（可观测；>0 表示曾发生写失败）。
func (s *SnapshotStore) PersistFailures() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalFails
}

// LastPersistError 返回最近一次写失败原因（nil = 从未失败）。
func (s *SnapshotStore) LastPersistError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFailErr
}

// persist 变更后请求落盘：默认合并写（窗口内多次变更合并为一次全量写）。
func (s *SnapshotStore) persist() {
	if s.disabled {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.dirty = true
	interval := s.flushInterval
	if interval <= 0 {
		// 严格模式：每次变更同步落盘。
		s.mu.Unlock()
		s.flushNow()
		return
	}
	if s.flushTimer == nil {
		s.flushTimer = time.AfterFunc(interval, s.flushNow)
	}
	s.mu.Unlock()
}

// flushNow 执行一次落盘（合并写定时器回调）。
func (s *SnapshotStore) flushNow() {
	s.mu.Lock()
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}
	if !s.dirty || s.disabled || s.closed {
		s.dirty = false
		s.mu.Unlock()
		return
	}
	s.dirty = false
	s.mu.Unlock()
	if err := s.persistAt(time.Now().Unix()); err != nil {
		// 失败计数与告警升级已在 persistAt 内统一处理；此处仅保留脏标记以便后续重试。
		s.mu.Lock()
		if !s.closed {
			s.dirty = true
		}
		s.mu.Unlock()
		// 防回退拒绝：基线已推进 ⇒ 自动重试（有界）以尽快把待写状态落盘。
		s.scheduleRollbackRetry(err)
	}
}

// scheduleRollbackRetry 防回退拒绝后的**有界自动重试**（QA P2-新）。
//
// 基线已在拒绝分支推进到磁盘 revision ⇒ 下一次写用 diskRev+1（> 磁盘）⇒
// 通常一次即成功；此处做有限次自动重试，避免"被拒后必须等下一次变更才落盘"
// 的空窗（窗口内变更本就该在退出前补写）。
//
// 非防回退错误（I/O 故障、编码失败等）**不自动重试**：重试无意义且会放大故障。
// 重试次数有上限（maxRollbackAutoRetries），避免与"持续推进的写者"无限对撞。
//
// ⚠️ **重试前必须重读磁盘做内容比对**（第三道防线，P2-4 T-1.7）：
// 重试会**重新走完整的写盘路径**——重新获取写者锁、**重新读盘**、**重新执行
// 内容级版本判据**。因此若磁盘内容在这段窗口内已被他人推进（本地更旧），
// 重试会被**内容级判据拦下** ⇒ 走"放弃写盘 + 独立告警 + 独立计数"
// （ContentBlocks），**不会**用旧内容覆盖磁盘。
// （历史缺陷：此前重试路径只比对 revision，而覆盖方写出的 revision 仍单调递增
// ⇒ 内容回退完全静默通过——QA 实跑复现：磁盘 rev=6/路由表=v9 → 覆盖后 rev=7/
// 路由表=v3，零告警。）
func (s *SnapshotStore) scheduleRollbackRetry(cause error) {
	var rre *rollbackRejectError
	if !errors.As(cause, &rre) {
		return // 非防回退错误：不自动重试
	}
	s.mu.Lock()
	if s.closed || s.disabled || !s.dirty {
		s.mu.Unlock()
		return
	}
	if s.autoRetries >= maxRollbackAutoRetries {
		s.mu.Unlock()
		s.logf("警告: 防回退自动重试已达上限（%d 次），待下次变更/显式刷盘/优雅退出再试", maxRollbackAutoRetries)
		return
	}
	s.autoRetries++
	attempt := s.autoRetries
	s.flushTimer = time.AfterFunc(rollbackRetryDelay, s.flushNow)
	s.mu.Unlock()
	s.logf("警告: 防回退拒绝后自动重试落盘（第 %d 次，延迟 %s）：下一次写入使用 revision=%d",
		attempt, rollbackRetryDelay, rre.nextRev)
}

// persistAt 组装并原子写盘（revision 自增 + 内容级防回退比对）。
func (s *SnapshotStore) persistAt(savedAt int64) error {
	if s.disabled {
		return nil
	}
	return s.writeSnapshotAt(s.nextRevision(), savedAt)
}

// nextRevision 分配下一个 revision（内容级单调递增；本地基线 +1）。
func (s *SnapshotStore) nextRevision() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision + 1
}

// writeSnapshotAt 以指定 revision 写盘（内部；测试可注入 revision 验证防回退）。
//
// —— 三道防线（P2-4 T-1.7，详见包注释的总口径）——
//
//	① **写者锁（lockfile 互斥）**：临界区覆盖"读盘 → 比较 → 写盘"**整段**。
//	   必须锁住比较与写之间的整段，否则存在 TOCTOU（两个写者先后通过判据、随后
//	   互相覆盖）。获取锁失败 ⇒ **明确失败，绝不覆盖**持锁者的快照。
//	② **内容级版本判据（主防线）**：按表逐个比较自报版本；磁盘更新 / 本地缺表 /
//	   同版本内容漂移 ⇒ **拒绝写入**（磁盘内容逐字节不变）。
//	③ **revision 单调判据（兜底）**：磁盘 revision ≥ 待写 revision ⇒ 拒绝覆盖
//	   （陈旧进程不得覆盖他人已推进的快照）。
//
// 时钟（saved_at）**仅辅助**：磁盘 saved_at 晚于本次 ⇒ 告警但仍以 revision 为准
// （时钟回拨/漂移不得造成误拒）。
func (s *SnapshotStore) writeSnapshotAt(revision int64, savedAt int64) error {
	if s.disabled {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// 路径类型校验：符号链接/目录 → 拒绝写入（静默失效比报错更危险）。
	if err := s.checkPathType(); err != nil {
		s.recordFailure(err)
		return err
	}

	// —— ① 写者锁：临界区覆盖"读盘 → 比较 → 写盘"整段（消除 TOCTOU）——
	// 获取失败 ⇒ 明确失败（绝不覆盖持锁者的快照）。
	lock := newSnapshotLock(s.path, s.logger)
	if err := lock.acquire(); err != nil {
		werr := fmt.Errorf("获取快照写锁失败（本次写盘已放弃，不覆盖其它写者的快照）: %w", err)
		s.recordFailure(werr)
		s.logf("错误: 快照写锁获取失败，本次写盘已放弃（不覆盖其它写者的快照）: %v", err)
		return werr
	}
	defer lock.release()

	// 磁盘快照（**锁内读取**：与比较、写盘同属临界区）。
	disk, curErr := readSnapshotFile(s.path)
	diskReadable := true
	switch {
	case curErr == nil:
	case errors.Is(curErr, fs.ErrNotExist):
		diskReadable = false // 无既有快照：正常首写
	default:
		// 磁盘快照不可解析（损坏）：允许覆盖修复（告警）。
		diskReadable = false
		s.logf("警告: 磁盘快照不可解析，将以新快照覆盖修复: %v", curErr)
	}

	// 本地载荷（**锁内采集**：与磁盘读取同一临界区 ⇒ 比较的是同一时刻的视图）。
	payload, err := s.collectPayload(revision, savedAt)
	if err != nil {
		s.recordFailure(err)
		return err
	}

	// —— ② 内容级版本判据（主防线）——
	// 磁盘内容比本地新 ⇒ 放弃本次写盘（磁盘内容逐字节不变），**不重试**、
	// **不推进基线**；独立计数 + 独立告警文案（与"防回退拒绝"分开归因）。
	if diskReadable {
		if conflicts := compareContent(disk, payload); len(conflicts) > 0 {
			return s.blockContentWrite(conflicts)
		}
	}

	// —— ③ revision 单调判据（兜底）——
	if diskReadable && disk.Revision >= revision {
		// 防回退拒绝：磁盘快照更新或持平 ⇒ 本进程状态陈旧，回写即回退。
		//
		// —— 多写者语义（QA P2-新）——
		// 触发场景：**两个进程共享同一快照路径**（K8s 滚动更新 maxSurge>1 且同节点
		// RWO PVC 仍可双挂；或旧实例未退净即起新实例）。此时"磁盘 revision ≥ 待写
		// revision"是**必须发生**的安全行为：陈旧进程不得用旧状态覆盖他人已推进的快照。
		//
		// 早期实现的两处缺陷（QA P2-新，本分支修复）：
		//  1) 本地基线不推进 ⇒ nextRevision() 恒返回同一值 ⇒ 每次写都被拒 ⇒
		//     进程**永久失去持久化能力**（直到重启才恢复）；
		//  2) 拒绝分支不走 recordFailure ⇒ PersistFailures() 恒 0、
		//     LastPersistError() 恒 nil ⇒ "失去持久化"完全不可观测（静默降级）。
		//
		// 本期修复口径（**推进基线 + 计入失败指标 + 告警升级**）：
		//  - 本地基线推进到 diskRev ⇒ 下一次写用 diskRev+1（> 磁盘）⇒ 消除永久停滞；
		//  - 走 recordFailure ⇒ 失败计数 + 最近错误可查 + 连续 ≥3 次升级为错误级告警；
		//  - 内存态不回滚（内存为准），本进程后续变更仍会尝试落盘。
		//
		// ⚠️ 基线推进**仅作兜底**：内容级判据（②）才是主防线——它保证"内容不回退"；
		// 本分支只保证"revision 单调"。基线推进后本进程写入的是"较旧内容 + 更大
		// revision"，故内容新旧性由 ② 保证、由 ①（写者锁）保证同一时刻只有一个写者。
		err := &rollbackRejectError{
			msg: fmt.Sprintf("拒绝覆盖更新的快照（防回退）：磁盘 revision=%d ≥ 待写 revision=%d", disk.Revision, revision),
			// 基线推进后下一写用的 revision（> 磁盘 ⇒ 必然被接受）。
			nextRev: disk.Revision + 1,
		}
		s.mu.Lock()
		if disk.Revision > s.revision {
			s.revision = disk.Revision // 基线推进：下一写用 diskRev+1，消除永久停滞
		}
		s.rollbackRejects++
		s.mu.Unlock()
		// 计入失败指标 + 告警升级（复用既有通道）⇒ "失去持久化"可观测。
		s.recordFailure(err)
		s.logf("警告: 防回退拒绝回写（多写者窗口）：磁盘 revision=%d ≥ 待写 revision=%d；本地基线已推进至 revision=%d，下一次写入将使用 revision=%d",
			disk.Revision, revision, disk.Revision, disk.Revision+1)
		return err
	}
	if diskReadable && disk.SavedAt > savedAt {
		// 时钟异常仅告警：防回退以 revision 为准（QA P2-2）。
		s.logf("警告: 快照时钟异常（磁盘 saved_at=%d 晚于本次 %d），防回退以 revision 为准（磁盘 revision=%d）",
			disk.SavedAt, savedAt, disk.Revision)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		s.recordFailure(fmt.Errorf("快照载荷编码失败: %w", err))
		return fmt.Errorf("快照载荷编码失败: %w", err)
	}
	sum := sha256.Sum256(payloadBytes)
	env := snapshotEnvelope{
		Payload:  payloadBytes,
		Checksum: checksumPrefix + hex.EncodeToString(sum[:]),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		s.recordFailure(fmt.Errorf("快照信封编码失败: %w", err))
		return fmt.Errorf("快照信封编码失败: %w", err)
	}
	if err := atomicWriteFile(s.path, envBytes); err != nil {
		s.recordFailure(err)
		return err
	}
	s.mu.Lock()
	if revision > s.revision {
		s.revision = revision
	}
	s.consecFails = 0
	s.autoRetries = 0 // 落盘成功：防回退自动重试计数归零
	s.mu.Unlock()
	return nil
}

// blockContentWrite 内容回退拦截：放弃本次写盘（磁盘内容逐字节不变）。
//
// 语义（与"防回退拒绝"**刻意区分**）：
//   - **不重试**（重试无意义：本地内容确实更旧，重试仍会被拦）；
//   - **不推进本地基线**（基线推进只对 revision 判据的拒绝生效）；
//   - 独立计数（ContentBlocks）+ **独立告警文案**（便于与"多写者窗口"归因区分）。
//
// 处置建议（写进告警文案）：以磁盘为准重载（重启进程或显式调用 LoadSnapshot），
// 或终止陈旧写者；**不得**通过"放宽判据"绕过。
func (s *SnapshotStore) blockContentWrite(conflicts []contentConflict) error {
	key := contentConflictKey(conflicts)
	s.mu.Lock()
	s.contentBlocks++
	total := s.contentBlocks
	repeat := 0
	if key == s.contentAlertKey {
		s.contentBlockRepeats++
		repeat = s.contentBlockRepeats
	} else {
		s.contentAlertKey = key
		s.contentBlockRepeats = 0
	}
	s.mu.Unlock()

	err := &contentBlockError{conflicts: conflicts}
	// 计入通用写失败指标（"本次写盘未发生"必须可观测）。
	s.recordFailure(err)
	switch {
	case repeat == 0:
		s.logf("错误: 快照内容回退拦截（磁盘内容比本地新；本次写盘已放弃，磁盘快照内容逐字节不变）: %s；处置：以磁盘为准重载（重启进程或显式调用 LoadSnapshot）或终止陈旧写者",
			contentConflictSummary(conflicts))
	case repeat%contentBlockRepeatLogEvery == 0:
		s.logf("警告: 快照内容回退拦截重复发生（累计 %d 次，冲突集合未变化）: %s", total, contentConflictSummary(conflicts))
	}
	return err
}

// ContentBlocks 返回**内容回退拦截**的累计次数（可观测）。
//
// >0 表示曾出现"磁盘内容比本地新"而被拦截的写盘：本地进程状态陈旧（多写者窗口
// 的典型症状），本次写盘被**主动放弃**，磁盘内容保持不变。
// 与 RollbackRejects()（revision 判据拒绝次数）**分开计数、分开归因**。
func (s *SnapshotStore) ContentBlocks() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.contentBlocks
}

// RollbackRejects 返回防回退拒绝的累计次数（可观测）。
//
// >0 表示曾因"磁盘快照 revision ≥ 待写 revision"而拒绝回写，通常意味着
// 出现了多写者窗口（两进程共享同一快照路径），需运维核查部署形态。
func (s *SnapshotStore) RollbackRejects() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rollbackRejects
}

// recordFailure 记录写失败并升级告警（连续失败达阈值 → 错误级措辞）。
func (s *SnapshotStore) recordFailure(err error) {
	s.mu.Lock()
	s.totalFails++
	s.consecFails++
	total, consec := s.totalFails, s.consecFails
	s.lastFailErr = err
	s.mu.Unlock()
	if consec >= persistWarnThreshold {
		s.logf("错误: 快照写入失败（累计 %d 次、连续 %d 次；快照持久化已不可靠）: %v", total, consec, err)
		return
	}
	s.logf("警告: 快照写入失败（累计 %d 次）: %v", total, err)
}

// collectPayload 在**读锁内**完成状态采集（返回未序列化的载荷结构体）。
//
// QA P3-8：此前"锁内浅拷贝 + 锁外 marshal"存在并发改写竞态与快照不一致风险；
// 现改为在读锁内直接采集，得到一致的原子视图（代价：写者短暂阻塞，
// 控制面非热路径，可接受）。
//
// 采集与序列化分离的原因：内容级判据需要**载荷结构体**（逐域比较版本与内容），
// 而写盘需要**载荷字节**（算校验和）；二者必须来自**同一份**采集结果，
// 否则比较的与写入的可能是两个不同时刻的视图。
func (s *SnapshotStore) collectPayload(revision, savedAt int64) (*snapshotPayload, error) {
	m := s.Memory
	m.mu.RLock()
	defer m.mu.RUnlock()

	p := &snapshotPayload{
		SchemaVersion:     snapshotSchemaVersion,
		Revision:          revision,
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
	return p, nil
}

// buildPayload 采集 + 序列化（既有签名保持不变，供既有调用与测试使用）。
func (s *SnapshotStore) buildPayload(revision, savedAt int64) ([]byte, error) {
	p, err := s.collectPayload(revision, savedAt)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("快照载荷编码失败: %w", err)
	}
	return b, nil
}

// restore 将快照载荷整体恢复进内存（先在锁外构造完整新态，校验全部通过后
// 一次性换入，避免半恢复污染）。
//
// ⚠️ 顺序口径（QA P3-10，仅注释不改行为）：byT 索引按处方 ID 字典序重建，
// 故 ListByTenant 的**返回顺序**与原始写入顺序可能不同（集合内容一致）；
// 处方本体也按 ID 字典序输出，保证快照字节级确定性。
func (s *SnapshotStore) restore(p *snapshotPayload) error {
	byID := make(map[string]*route.RoutePrescription, len(p.Prescriptions))
	byT := make(map[string][]string)
	for _, rx := range p.Prescriptions {
		if rx == nil || rx.PrescriptionID == "" {
			return errors.New("快照含空处方条目，拒绝加载")
		}
		if _, dup := byID[rx.PrescriptionID]; dup {
			return fmt.Errorf("快照处方 ID 重复: %s，拒绝加载", rx.PrescriptionID)
		}
		byID[rx.PrescriptionID] = rx
		byT[rx.Tenant] = append(byT[rx.Tenant], rx.PrescriptionID)
	}
	servers := make(map[string]*mcpsrv.Server, len(p.MCPServers))
	for _, sv := range p.MCPServers {
		if sv == nil || sv.ID == "" {
			return errors.New("快照含空 MCP 后端条目，拒绝加载")
		}
		if _, dup := servers[sv.ID]; dup {
			return fmt.Errorf("快照 MCP 后端 ID 重复: %s，拒绝加载", sv.ID)
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

// —— 以下为变更路径拦截：内存变更成功后请求落快照（默认合并写）——

// Save 实现 Store。ErrDup（无状态变化）不请求落盘。
func (s *SnapshotStore) Save(p *route.RoutePrescription) error {
	if err := s.Memory.Save(p); err != nil {
		return err
	}
	s.persist()
	return nil
}

// Delete 实现 Store。无论目标是否存在均请求落盘（删除语义幂等，宁可多写一次）。
func (s *SnapshotStore) Delete(id string) {
	s.Memory.Delete(id)
	s.persist()
}

// SaveRouteTable 实现 Store。
func (s *SnapshotStore) SaveRouteTable(t *route.RouteTable) {
	s.Memory.SaveRouteTable(t)
	s.persist()
}

// SaveRateLimitTable 实现 Store。
func (s *SnapshotStore) SaveRateLimitTable(t *ratelimit.Table) {
	s.Memory.SaveRateLimitTable(t)
	s.persist()
}

// SaveACLTable 实现 Store。
func (s *SnapshotStore) SaveACLTable(t *a2aproxy.ACLTable) {
	s.Memory.SaveACLTable(t)
	s.persist()
}

// SaveA2ARateLimitTable 实现 Store。
func (s *SnapshotStore) SaveA2ARateLimitTable(t *a2aproxy.RateLimitTable) {
	s.Memory.SaveA2ARateLimitTable(t)
	s.persist()
}

// SaveToolCatalog 实现 Store。
func (s *SnapshotStore) SaveToolCatalog(c *mcpsec.ToolCatalog) {
	s.Memory.SaveToolCatalog(c)
	s.persist()
}

// SaveRBACPolicy 实现 Store。
func (s *SnapshotStore) SaveRBACPolicy(p *mcpsec.RBACPolicy) {
	s.Memory.SaveRBACPolicy(p)
	s.persist()
}

// SaveMCPServer 实现 Store。
func (s *SnapshotStore) SaveMCPServer(sv *mcpsrv.Server) {
	s.Memory.SaveMCPServer(sv)
	s.persist()
}

// DeleteMCPServer 实现 Store。仅在实际摘除时请求落盘。
func (s *SnapshotStore) DeleteMCPServer(id string) bool {
	removed := s.Memory.DeleteMCPServer(id)
	if removed {
		s.persist()
	}
	return removed
}

// decodeSnapshot 解码并完整校验快照字节：JSON 结构 → 校验和 → 载荷。
// 任一失败即拒绝（返回错误，调用方 fail-open）。
func decodeSnapshot(b []byte) (*snapshotPayload, error) {
	var env snapshotEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("快照解析失败（截断或损坏）: %w", err)
	}
	if !strings.HasPrefix(env.Checksum, checksumPrefix) {
		return nil, errors.New("快照校验和缺失或格式非法，拒绝加载")
	}
	want, err := hex.DecodeString(strings.TrimPrefix(env.Checksum, checksumPrefix))
	if err != nil {
		return nil, fmt.Errorf("快照校验和编码非法: %w", err)
	}
	got := sha256.Sum256(env.Payload)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, errors.New("快照校验和不匹配（内容损坏或被篡改），拒绝加载")
	}
	var p snapshotPayload
	if err := json.Unmarshal(env.Payload, &p); err != nil {
		return nil, fmt.Errorf("快照载荷解析失败: %w", err)
	}
	if p.SchemaVersion != snapshotSchemaVersion {
		return nil, fmt.Errorf("快照 schema 版本不识别: got %d want %d，拒绝加载（防误读/防回退）",
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
		return fmt.Errorf("创建快照临时文件失败: %w", err)
	}
	tmp := f.Name()
	// 任一步失败都清理临时文件，避免残留垃圾。
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("快照临时文件写入失败: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("快照临时文件 fsync 失败: %w", err))
	}
	if err := f.Close(); err != nil {
		return fail(fmt.Errorf("快照临时文件关闭失败: %w", err))
	}
	// 0600：快照含路由/策略/租户配置，收紧权限。
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fail(fmt.Errorf("快照临时文件权限设置失败: %w", err))
	}
	if err := renameWithRetry(tmp, path); err != nil {
		return fail(fmt.Errorf("快照原子替换失败: %w", err))
	}
	// 目录 fsync：保证 rename 落盘（Linux）；失败不影响正确性，忽略。
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// renameWithRetry 原子替换（rename）：对**瞬时**共享冲突做有界重试。
//
// 背景（Windows）：目标文件若正被其它句柄打开（并发读方、杀软扫描、备份进程等），
// rename 覆盖会瞬时返回 sharing violation（Access is denied）——这是**瞬时窗口**，
// 不是权限故障。短暂退避后重试即可跨过；真实错误（如只读目录）重试耗尽后照常报错。
//
// 退避上限 = renameRetryAttempts × renameRetryDelay（默认 5×20ms=100ms），
// 对合并写（默认 200ms 窗口）的吞吐影响可忽略。
func renameWithRetry(oldPath, newPath string) error {
	var err error
	for attempt := 0; attempt < renameRetryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(renameRetryDelay)
		}
		if err = os.Rename(oldPath, newPath); err == nil {
			return nil
		}
	}
	return err
}

// —— 版本号提取辅助（仅用于恢复日志展示；nil 表计 0）——

func tableVersion(t *route.RouteTable) int {
	if t == nil {
		return 0
	}
	return t.Version
}

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

// logf 统一日志出口（统一前缀 "[store]"，避免重复 "store: store:" —— QA P3-7）。
func (s *SnapshotStore) logf(format string, args ...any) {
	s.logger.Printf("[store] "+format, args...)
}
