// Package main — T-4 租户分区编排：存储与协作者接口（P2-3 §6.1/§6.2.6/§6.3/§7.2）。
//
// 定位：admin 管理面，非密码原语——不做任何密码运算，仅承担
// 「入参校验 → 配额/隔离(D-11)校验 → 写 desired（控制面）→ 写审计 → 发射指标」。
// 三类外部协作者以接口形式注入，便于单测 mock，也便于 T-1 组协调器落地后用
// GroupConfig/密钥目录/etcd 真实实现替换（Wave A：以内存实现 + 单测覆盖，
// 不依赖未冻结的 GroupConfig 契约，不接真实 HSM，不宣称 S3-b/生产合规）。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// partitionNameRE 分区/租户命名（§6.1：`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`）。
const partitionNameRE = `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`

// PartitionDesiredOut 下发到控制面的分区期望态（§6.2.6 DesiredState.Partitions 子集）。
// 真实实现写 etcd / K8s CRD；Wave A 用内存实现计数版本号。
type PartitionDesiredOut struct {
	Tenant        string
	Partition     string
	Members       []string
	QuotaSessions int
	QuotaQPS      int
	Action        string // apply | remove
	Version       uint64
}

// DesiredPublisher 控制面 desired 下发接口。
type DesiredPublisher interface {
	PublishDesired(ctx context.Context, pd PartitionDesiredOut) (version uint64, err error)
}

// MemberInfo 成员注册信息（来自 GroupConfig.members；一成员一分区/登录域，D-11）。
type MemberInfo struct {
	Partition   string
	MaxSessions int
}

// MemberRegistry 成员注册表（D-11 隔离校验与配额上限来源）。
type MemberRegistry interface {
	Member(id string) (MemberInfo, bool)
}

// KeyRefStore 活动 KeyRef 计数（删除前 drain + 无活动 KeyRef 校验，§6.3）。
type KeyRefStore interface {
	ActiveKeyRefCount(ctx context.Context, partition string) (int, error)
}

// ---- in-memory 实现（单测 + 进程内默认；T-1 后由 GroupConfig 真实实现替换） ----

// memMemberRegistry 内存成员注册表。
type memMemberRegistry struct {
	mu      sync.RWMutex
	members map[string]MemberInfo
}

// newMemMemberRegistry 构造内存成员注册表（initial 可为 nil）。
func newMemMemberRegistry(initial map[string]MemberInfo) *memMemberRegistry {
	m := &memMemberRegistry{members: map[string]MemberInfo{}}
	for k, v := range initial {
		m.members[k] = v
	}
	return m
}

// Member 实现 MemberRegistry。
func (m *memMemberRegistry) Member(id string) (MemberInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.members[id]
	return info, ok
}

// staticKeyRefStore 默认活动 KeyRef 计数（Wave A 未接密钥目录；返回固定值）。
// 删除守卫生效依赖 T-1 密钥目录接入；单测用 memKeyRefStore 注入不同值。
type staticKeyRefStore struct{ n int }

func (s staticKeyRefStore) ActiveKeyRefCount(ctx context.Context, partition string) (int, error) {
	return s.n, nil
}

// memKeyRefStore 内存活动 KeyRef 计数（按分区）。
type memKeyRefStore struct {
	mu     sync.RWMutex
	counts map[string]int
}

func newMemKeyRefStore(initial map[string]int) *memKeyRefStore {
	s := &memKeyRefStore{counts: map[string]int{}}
	for k, v := range initial {
		s.counts[k] = v
	}
	return s
}

func (s *memKeyRefStore) ActiveKeyRefCount(ctx context.Context, partition string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.counts[partition], nil
}

// memDesiredPublisher 内存 desired 下发器（仅计数返回版本号，不做真实 etcd 写）。
type memDesiredPublisher struct {
	mu      sync.Mutex
	version uint64
	log     []PartitionDesiredOut
}

// PublishDesired 实现 DesiredPublisher；每次调用版本号 +1 并返回。
func (p *memDesiredPublisher) PublishDesired(ctx context.Context, pd PartitionDesiredOut) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.version++
	pd.Version = p.version
	p.log = append(p.log, pd)
	return p.version, nil
}

// lastVersion 返回最近一次下发的版本号（测试与 CAS 校验辅助）。
func (p *memDesiredPublisher) lastVersion() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// ---- 分区记录存储 ----

// partitionRecord 已开通分区（按 partition 唯一；tenant 亦唯一，§6.1）。
type partitionRecord struct {
	Tenant        string
	Partition     string
	Members       []string
	QuotaSessions int
	QuotaQPS      int
	Version       uint64
	Drain         bool
	CreatedAt     int64
	UpdatedAt     int64
}

// partitionStore 内存分区存储（partition 主键 + tenant→partition 反向唯一）。
type partitionStore struct {
	mu       sync.RWMutex
	byPart   map[string]*partitionRecord
	byTenant map[string]string // tenant -> partition
}

func newPartitionStore() *partitionStore {
	return &partitionStore{
		byPart:   map[string]*partitionRecord{},
		byTenant: map[string]string{},
	}
}

// get 按 partition 取记录。
func (s *partitionStore) get(partition string) *partitionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byPart[partition]
}

// getByTenant 按 tenant 取记录。
func (s *partitionStore) getByTenant(tenant string) *partitionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.byTenant[tenant]; ok {
		return s.byPart[p]
	}
	return nil
}

// put 写入（调用方须持有写锁外的业务校验）。
func (s *partitionStore) put(rec *partitionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byPart[rec.Partition] = rec
	s.byTenant[rec.Tenant] = rec.Partition
}

// remove 删除（返回是否曾存在）。
func (s *partitionStore) remove(partition string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byPart[partition]
	if !ok {
		return false
	}
	delete(s.byPart, partition)
	delete(s.byTenant, rec.Tenant)
	return true
}

// list 返回全部分区（可选按 tenant 过滤）。
func (s *partitionStore) list(tenant string) []*partitionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*partitionRecord, 0, len(s.byPart))
	for _, rec := range s.byPart {
		if tenant != "" && rec.Tenant != tenant {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// ---- 幂等存储（§6.3：Idempotency-Key 24h） ----

// idemRecord 幂等缓存条目。
type idemRecord struct {
	Method   string
	Path     string
	BodySHA  string
	Status   int
	Response []byte
}

// idemStore 内存幂等存储（24h TTL 由调用方在落库时携带时间戳；此处仅做同键同体复用）。
type idemStore struct {
	mu sync.RWMutex
	m  map[string]*idemRecord
}

func newIdemStore() *idemStore { return &idemStore{m: map[string]*idemRecord{}} }

func (s *idemStore) get(key string) *idemRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[key]
}

func (s *idemStore) put(key string, rec *idemRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = rec
}

// bodySHA256 计算请求体 SHA-256（十六进制）。
func bodySHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newOperationID 生成 16 字节随机十六进制 operation_id（op- 前缀）。
func newOperationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 密码学随机不可用时退化为时间派生（极端降级，不依赖也不暴露密钥）。
		return fmt.Sprintf("op-%016x", time.Now().UnixNano())
	}
	return "op-" + hex.EncodeToString(b[:])
}
