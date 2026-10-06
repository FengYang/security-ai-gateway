package main

// tenant_key_runtime.go —— 二级租户 KEK 的进程装配（P0-4 §6，B6 子任务 #9）。
//
// 组成：
//   - cryptoRootWrapper：一级根（Enclave seal key）→ KEK 的 WrapKey/UnwrapKey（teecore.RootWrapper）
//   - tenantKeyAudit：KEK 生命周期事件落审计哈希链（teecore.AuditSink）
//   - tenantKeyPersist：变更后 Snapshot→Enclave.Seal 原子落盘（teecore.ChangeHook；重启经 Unseal 恢复）
//   - runTenantKeyScanner：周期扫描 last_rotated_at 超 90 天的 KEK 并轮换（扫描间隔默认 24h）

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/teecore"
)

const (
	// tenantKeyMaxAge 二级 KEK 轮换年龄（主方案 §4.4.3：90 天）。
	tenantKeyMaxAge = 90 * 24 * time.Hour
	// tenantKeySealContext 密封落盘的 Enclave 上下文标签。
	tenantKeySealContext = "tenant_keys"
)

// ---- 一级根封装 ----

// cryptoRootWrapper 以 Enclave seal key（一级根）经 cryptop WrapKey 封装 KEK。
type cryptoRootWrapper struct {
	prov cryptop.Provider
	root []byte
}

func (w *cryptoRootWrapper) Wrap(plain []byte) ([]byte, error) {
	return w.prov.WrapKey(w.root, plain)
}

func (w *cryptoRootWrapper) Unwrap(wrapped []byte) ([]byte, error) {
	return w.prov.UnwrapKey(w.root, wrapped)
}

// ---- 生命周期审计 ----

// tenantKeyAudit 把 KEK 创建/轮换/销毁落审计哈希链。
type tenantKeyAudit struct{ chain *auditChain }

func (a *tenantKeyAudit) KeyLifecycle(tenant, action string, epoch uint64) {
	// 载荷 = 动作|租户|KEK 版本的规范化摘要（不涉密钥字节）
	payload := fmt.Sprintf("otpmask/key/%s|%s|%d", action, tenant, epoch)
	sha, err := hashHexByAlg(hashAlgTag(), []byte(payload))
	if err != nil {
		log.Printf("[tenant-key] 生命周期审计摘要失败（事件不落链）: %v", err)
		return
	}
	a.chain.append(AuditEvent{
		TenantID:  tenant,
		RequestID: "-",
		Action:    action,
		Result:    "ok",
		PayloadSHA: sha,
		HashAlg:   hashAlgTag(),
	})
}

// ---- 密封落盘 ----

// tenantKeyPersist 接收 KEK 变更，异步把最新快照密封写盘。
// 写盘期间再变更只置 dirty（合并重写），杜绝重叠/乱序写。
type tenantKeyPersist struct {
	path string
	encl Enclave
	root teecore.RootWrapper
	tkm  *teecore.TenantKeyManager

	mu     sync.Mutex
	saving bool
	dirty  bool
}

// KeysChanged 实现 teecore.ChangeHook。
func (p *tenantKeyPersist) KeysChanged() {
	p.mu.Lock()
	if p.saving {
		p.dirty = true
		p.mu.Unlock()
		return
	}
	p.saving = true
	p.mu.Unlock()
	go p.saveLoop()
}

func (p *tenantKeyPersist) saveLoop() {
	for {
		if err := p.saveOnce(); err != nil {
			log.Printf("[tenant-key] 密封落盘失败（下次变更重试）: %v", err)
		}
		p.mu.Lock()
		if p.dirty {
			p.dirty = false
			p.mu.Unlock()
			continue
		}
		p.saving = false
		p.mu.Unlock()
		return
	}
}

func (p *tenantKeyPersist) saveOnce() error {
	snaps, err := p.tkm.Snapshot(p.root)
	if err != nil {
		return err
	}
	data, err := encodeTenantKeyFile(snaps)
	if err != nil {
		return err
	}
	sealed, err := p.encl.Seal(data, tenantKeySealContext)
	if err != nil {
		return fmt.Errorf("encl.Seal: %w", err)
	}
	return writeFileAtomic(p.path, sealed, 0o600)
}

// loadTenantKeyFile 读取并解封 KEK 状态；文件不存在返回 (nil,nil)。
func loadTenantKeyFile(path string, encl Enclave) ([]teecore.TenantSnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data, err := encl.Unseal(raw, tenantKeySealContext)
	if err != nil {
		return nil, fmt.Errorf("encl.Unseal: %w", err)
	}
	return decodeTenantKeyFile(data)
}

// ---- 文件 JSON 结构 ----

type tenantKeyFileDTO struct {
	Version int                  `json:"version"`
	Tenants []tenantKeyEntryDTO  `json:"tenants"`
}

type tenantKeyEntryDTO struct {
	Tenant          string     `json:"tenant"`
	Epoch           uint64     `json:"epoch"`
	LastRotate      time.Time  `json:"last_rotate"`
	WrappedKEK      []byte     `json:"wrapped_kek"`
	WrappedHistory  [][]byte   `json:"wrapped_history,omitempty"`
}

func encodeTenantKeyFile(snaps []teecore.TenantSnapshot) ([]byte, error) {
	dto := tenantKeyFileDTO{Version: 1, Tenants: make([]tenantKeyEntryDTO, 0, len(snaps))}
	for _, sn := range snaps {
		dto.Tenants = append(dto.Tenants, tenantKeyEntryDTO{
			Tenant:         sn.Tenant,
			Epoch:          sn.Epoch,
			LastRotate:     sn.LastRotate,
			WrappedKEK:     sn.WrappedKEK,
			WrappedHistory: sn.WrappedHistory,
		})
	}
	return json.Marshal(&dto)
}

func decodeTenantKeyFile(data []byte) ([]teecore.TenantSnapshot, error) {
	var dto tenantKeyFileDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("tenant-key 文件 JSON 解析失败: %w", err)
	}
	if dto.Version != 1 {
		return nil, fmt.Errorf("tenant-key 文件版本 %d 不支持", dto.Version)
	}
	out := make([]teecore.TenantSnapshot, 0, len(dto.Tenants))
	for _, e := range dto.Tenants {
		out = append(out, teecore.TenantSnapshot{
			Tenant:         e.Tenant,
			Epoch:          e.Epoch,
			LastRotate:     e.LastRotate,
			WrappedKEK:     e.WrappedKEK,
			WrappedHistory: e.WrappedHistory,
		})
	}
	return out, nil
}

// ---- 轮换扫描器 ----

// runTenantKeyScanner 启动后立即扫描一次，随后每 interval 扫描到期租户并轮换。
// 失败逐个隔离，不影响其它租户；属进程级 goroutine（随进程退出终止）。
func runTenantKeyScanner(tkm *teecore.TenantKeyManager, interval time.Duration) {
	scan := func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[tenant-key] 扫描 panic（已恢复）: %v", r)
			}
		}()
		for _, tenant := range tkm.DueTenants(time.Now(), tenantKeyMaxAge) {
			ref, err := tkm.RotateTenant(tenant)
			if err != nil {
				log.Printf("[tenant-key] 周期轮换失败 tenant=%s: %v", tenant, err)
				continue
			}
			log.Printf("[tenant-key] 周期轮换 tenant=%s ref=%s", tenant, ref)
		}
	}
	scan()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		scan()
	}
}

// ---- 通用：原子写文件 ----

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path) // Windows: 替换已存在目标
}
